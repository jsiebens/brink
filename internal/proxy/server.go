package proxy

import (
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/auth"
	"github.com/jsiebens/brink/internal/auth/templates"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/mon"
	"github.com/jsiebens/brink/internal/server"
	"github.com/jsiebens/brink/internal/util"
	"github.com/jsiebens/brink/internal/version"
	"github.com/labstack/echo/v4"
	stream "github.com/nknorg/encrypted-stream"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const authCachePrefix = "pa_"
const proxyCachePrefix = "pp_"

func StartServer(config *config.Config) error {
	v, r := version.GetReleaseInfo()
	logrus.Infof("Starting brink proxy server. Version %s - %s", v, r)

	c, err := cache.NewCache(config.Cache)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = templates.NewTemplates()

	version.RegisterRoutes(e)

	var sessionRegistry auth.SessionRegistry

	if config.Auth.RemoteServer == "" {
		logrus.Info("registering oidc routes")

		authServer, err := auth.NewServer(config.Auth, cache.Prefixed(c, authCachePrefix))
		if err != nil {
			return err
		}
		authServer.RegisterRoutes(e, false)

		sessionRegistry = authServer
	} else {
		logrus.Info("configuring remote auth server, skipping oidc routes")
		remoteSessionRegistry, err := auth.NewRemoteSessionRegistry(config.Auth)
		if err != nil {
			return err
		}
		sessionRegistry = remoteSessionRegistry
	}

	logrus.Info("registering proxy routes")

	proxyServer, err := NewServer(config.Proxy, cache.Prefixed(c, proxyCachePrefix), sessionRegistry)
	if err != nil {
		return err
	}
	proxyServer.RegisterRoutes(e)

	return server.Start(config, e)
}

func NewServer(config config.Proxy, cache cache.Cache, registry auth.SessionRegistry) (*Server, error) {
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

	targetFilters, err := parseTargetFilters(config.Policies)
	if err != nil {
		return nil, err
	}

	checksum, err := util.Checksum(&config.Policies)
	if err != nil {
		return nil, err
	}

	s := &Server{
		privateKey:      *privateKey,
		sessionRegistry: registry,
		sessions:        cache,
		policy:          config.Policies,
		targetFilters:   targetFilters,
		checksum:        checksum,
	}

	internalHandler := echo.New()
	internalHandler.HideBanner = true
	internalHandler.HidePort = true
	internalHandler.Use(mon.Middleware())
	internalHandler.GET("/p/connect", s.proxy())
	internalHandler.POST("/p/session", s.createSession)
	internalHandler.POST("/p/token", s.checkSessionToken)
	s.internalHandler = internalHandler

	return s, nil
}

type Server struct {
	privateKey      key.PrivateKey
	internalHandler http.Handler
	sessionRegistry auth.SessionRegistry
	sessions        cache.Cache
	policy          map[string]config.Policy
	targetFilters   map[string][]TargetFilter
	checksum        string
}

type session struct {
	PublicKey  key.PublicKey
	PrivateKey key.PrivateKey
}

func (s *Server) RegisterRoutes(e *echo.Echo) {
	e.GET("/p/key", s.key)
	e.GET("/p/upgrade", s.upgrade)
}

func (s *Server) key(c echo.Context) error {
	return c.String(http.StatusOK, s.privateKey.Public().String())
}

func (s *Server) upgrade(c echo.Context) error {
	conn, err := s.acceptHTTP(c.Response(), c.Request())
	if err != nil {
		return err
	}

	is := http.Server{}
	is.Handler = s.internalHandler
	return is.Serve(util.NewOneConnListener(conn, nil))
}

func (s *Server) createSession(c echo.Context) error {
	var req = api.CreateSessionRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	target := req.Target

	if target != "" && !s.validateTarget(target) {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("access to target [%s] is denied", target))
	}

	privateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()

	sessionId := util.GenerateSessionId()

	resp, err := s.registerSession(sessionId, publicKey.String(), req.AuthToken, target)
	if err != nil {
		return err
	}

	if target != "" {
		if err := s.sessions.Set(sessionId, &session{PublicKey: publicKey, PrivateKey: *privateKey}); err != nil {
			return err
		}
	}

	return c.JSON(http.StatusOK, &resp)
}

func (s *Server) checkSessionToken(c echo.Context) error {
	req := api.SessionTokenRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	response, err := s.sessionRegistry.CheckSessionToken(&req)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) proxy() echo.HandlerFunc {
	rd := remotedialer.New(s.authorizeClient, remotedialer.DefaultErrorWriter)
	return func(context echo.Context) error {
		req := context.Request()
		clientId := req.Header.Get(api.IdHeader)
		clientAuth := req.Header.Get(api.AuthHeader)

		if clientId == "" || clientAuth == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing id and/or auth header")
		}

		logrus.
			WithField("_cid", clientId).
			Info("Client connected")

		rd.ServeHTTP(context.Response(), context.Request())

		logrus.
			WithField("_cid", clientId).
			Info("Client disconnected")

		return nil
	}
}

func (s *Server) authorizeClient(req *http.Request) (string, bool, remotedialer.ConnectAuthorizer, error) {
	clientId := req.Header.Get(api.IdHeader)
	clientAuth := req.Header.Get(api.AuthHeader)

	if clientId == "" || clientAuth == "" {
		return "", false, nil, fmt.Errorf("missing id and/or auth header")
	}

	var se = session{}

	defer s.sessions.Delete(clientId)
	if ok, err := s.sessions.Get(clientId, &se); err != nil || !ok {
		return "", false, nil, nil
	}

	privateKey := se.PrivateKey
	publicKey := s.sessionRegistry.GetPublicKey()

	var u = &api.SessionToken{}
	if err := privateKey.OpenBase58(publicKey, clientAuth, u); err != nil {
		return "", false, nil, fmt.Errorf("invalid token")
	}

	now := time.Now().UTC()

	if now.After(u.ExpirationTime) || u.Checksum != s.checksum {
		return "", false, nil, fmt.Errorf("token is expired")
	}

	if !s.validateRolesAndTarget(u.Roles, u.Target) {
		return "", false, nil, fmt.Errorf("access to target [%s] is denied", u.Target)
	}

	logrus.
		WithField("_cid", clientId).
		WithField("id", u.UserID).
		WithField("name", u.Username).
		WithField("email", u.Email).
		Info("Client authorized")

	return clientId, true, s.connectAuthorizer(clientId, u), nil
}

func (s *Server) connectAuthorizer(clientId string, token *api.SessionToken) remotedialer.ConnectAuthorizer {
	return func(proto, address string) bool {
		result := token.Target == address

		if result {
			logrus.
				WithField("_cid", clientId).
				WithField("addr", address).Info("Connection allowed")
		} else {
			logrus.
				WithField("_cid", clientId).
				WithField("addr", address).Info("Connection declined")
		}

		return result
	}
}

func (s *Server) registerSession(id, key, authToken, target string) (*api.SessionTokenResponse, error) {
	var apiPolicies = map[string]api.Policy{}

	for n, p := range s.policy {
		apiPolicies[n] = api.Policy{
			Subs:    p.Subs,
			Emails:  p.Emails,
			Filters: p.Filters,
		}
	}

	request := api.RegisterSessionRequest{
		SessionId:  id,
		SessionKey: key,
		AuthToken:  authToken,
		Target:     target,
		Policies:   apiPolicies,
		Checksum:   s.checksum,
	}

	return s.sessionRegistry.RegisterSession(&request)
}

func (s *Server) validateRolesAndTarget(roles []string, target string) bool {
	n := strings.SplitN(target, ":", 2)

	host := n[0]
	port, err := strconv.ParseUint(n[1], 10, 64)

	if err != nil {
		return false
	}

	for _, r := range roles {
		for _, t := range s.targetFilters[r] {
			if t.validate(host, port) {
				return true
			}
		}
	}

	return false
}

func (s *Server) validateTarget(target string) bool {
	n := strings.SplitN(target, ":", 2)

	host := n[0]
	port, err := strconv.ParseUint(n[1], 10, 64)

	if err != nil {
		return false
	}

	for _, r := range s.targetFilters {
		for _, t := range r {
			if t.validate(host, port) {
				return true
			}
		}
	}

	return false
}

func (s *Server) acceptHTTP(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	next := r.Header.Get("Upgrade")
	if next == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing next protocol")
	}
	if next != api.UpgradeHeaderValue {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "unknown next protocol")
	}

	rawKey := r.Header.Get(api.HandshakeHeaderName)
	if rawKey == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing key header")
	}

	clientPublicKey, err := key.ParsePublicKey(rawKey)
	if err != nil {
		return nil, err
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

	return stream.NewEncryptedStream(conn, &stream.Config{
		Cipher:          key.NewBoxCipher(s.privateKey, *clientPublicKey),
		SequentialNonce: false, // only when key is unique for every stream
		Initiator:       false, // only on the dialer side
	})
}
