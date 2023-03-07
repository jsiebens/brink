package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/server"
	"github.com/jsiebens/brink/internal/util"
	"github.com/jsiebens/brink/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

func StartServer(ctx context.Context, config *config.Config) error {
	v, r := version.GetReleaseInfo()
	logrus.Infof("Starting brink relay server. Version %s - %s", v, r)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	version.RegisterRoutes(e)

	s, err := newServer(config.Relay)
	if err != nil {
		return err
	}

	s.RegisterRoutes(e)

	return server.Start(ctx, config, e)
}

type Server struct {
	sync.RWMutex
	transports map[string]*httputil.ReverseProxy
	publicKey  key.PublicKey
	privateKey key.PrivateKey
}

func newServer(config config.Relay) (*Server, error) {
	var privateKey *key.PrivateKey

	if config.PrivateKey == "" {
		pkey, err := key.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		privateKey = pkey
	} else {
		pkey, err := key.ParsePrivateKey(config.PrivateKey)
		if err != nil {
			return nil, err
		}
		privateKey = pkey
	}

	s := &Server{
		privateKey: *privateKey,
		publicKey:  privateKey.Public(),
		transports: make(map[string]*httputil.ReverseProxy),
	}

	return s, nil
}

func (s *Server) RegisterRoutes(e *echo.Echo) {
	e.GET("/r/connect", s.connect, s.checkApiToken)
	e.Any("/p/*", s.proxy)
	e.Any("/a/*", s.proxy)
}

func (s *Server) getReverseProxy() *httputil.ReverseProxy {
	randomClient := func() *httputil.ReverseProxy {
		for _, m := range s.transports {
			return m
		}
		return nil
	}

	s.RLock()
	defer s.RUnlock()

	return randomClient()
}

func (s *Server) addReverseProxy(id string, proxy *httputil.ReverseProxy) {
	s.Lock()
	defer s.Unlock()
	s.transports[id] = proxy
}

func (s *Server) removeReverseProxy(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.transports, id)
}

func (s *Server) proxy(c echo.Context) error {
	proxy := s.getReverseProxy()
	if proxy == nil {
		return echo.ErrServiceUnavailable
	}

	proxy.ServeHTTP(c.Response(), c.Request())
	return nil
}

func (s *Server) connect(c echo.Context) error {
	req := c.Request()
	ctx := req.Context()
	clientId := util.GenerateSessionId()

	conn, err := s.acceptHTTP(c.Response(), c.Request())
	if err != nil {
		return err
	}

	// Setup client side of yamux
	mux, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	transport := &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return mux.Open()
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	u, _ := url.Parse("http://localhost")
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = transport

	s.addReverseProxy(clientId, proxy)

	select {
	case <-ctx.Done():
	case <-mux.CloseChan():
	}

	s.removeReverseProxy(clientId)

	return nil
}

func (s *Server) checkApiToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		keyHeader := c.Request().Header.Get(api.KeyHeader)
		tokenHeader := c.Request().Header.Get(api.TokenHeader)

		if tokenHeader == "" {
			return echo.ErrForbidden
		}

		publicKey, err := key.ParsePublicKey(keyHeader)
		if err != nil {
			return echo.ErrNotFound
		}

		var token api.Token
		if err := s.privateKey.OpenBase58(*publicKey, tokenHeader, &token); err != nil {
			return echo.ErrForbidden
		}

		now := time.Now().UTC()

		if now.After(token.ExpirationTime) {
			return echo.ErrForbidden
		}

		return next(c)
	}
}

func (s *Server) acceptHTTP(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	next := r.Header.Get("Upgrade")
	if next == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing next protocol")
	}
	if next != api.UpgradeHeaderValue {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "unknown next protocol")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "make request over HTTP/1")
	}

	w.Header().Set("Upgrade", api.UpgradeHeaderValue)
	w.Header().Set("Connection", "upgrade")
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, brw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacking client connection: %w", err)
	}

	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("flushing hijacked HTTP buffer: %w", err)
	}

	return conn, nil
}
