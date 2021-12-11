package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/cache"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"
	"net/http"
	"time"
)

const (
	IdHeader   = "x-proxiro-id"
	AuthHeader = "x-proxiro-auth"
)

func StartServer(config *Config) error {
	url, err := util.NormalizeTargetUrl(config.AuthServer)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	server := &Server{
		client:            resty.New(),
		authServerBaseUrl: url.String(),
		sessions:          cache.NewMemoryCache(),
	}

	e.GET("/version", version.GetReleaseInfoHandler)
	e.Any("/p/connect", server.Proxy())
	e.POST("/p/session", server.CreateSession)

	if config.Tls.KeyFile == "" {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}

type Server struct {
	client            *resty.Client
	sessions          cache.Cache
	authServerBaseUrl string
}

type session struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
}

func (s *Server) CreateSession(c echo.Context) error {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sessionId := util.GenerateSessionId()

	if err := s.sessions.Set(sessionId, &session{PublicKey: publicKey, PrivateKey: privateKey}); err != nil {
		return err
	}

	response := api.SessionResponse{
		SessionId:      sessionId,
		SessionAuthUrl: s.authServerBaseUrl + "/a/auth/" + hex.EncodeToString(publicKey[:]),
	}

	return c.JSON(http.StatusOK, &response)
}

func (s *Server) Proxy() echo.HandlerFunc {
	rd := remotedialer.New(s.authorized, remotedialer.DefaultErrorWriter)
	rd.ClientConnectAuthorizer = s.allowAll
	return echo.WrapHandler(rd)
}

func (s *Server) authorized(req *http.Request) (string, bool, error) {
	id := req.Header.Get(IdHeader)
	auth := req.Header.Get(AuthHeader)

	if id == "" || auth == "" {
		return "", false, fmt.Errorf("missing id and/or auth header")
	}

	var se = session{}

	ok, err := s.sessions.Get(id, &se)
	defer s.sessions.Delete(id)

	if err != nil || !ok {
		return "", false, nil
	}

	publicKey, err := s.getPublicKey()
	if err != nil {
		return "", false, err
	}

	var u = &api.UserToken{}
	if err := util.OpenBase58(auth, u, publicKey, se.PrivateKey); err != nil {
		return "", false, fmt.Errorf("invalid token")
	}

	now := time.Now().UTC()

	if now.After(u.ExpirationTime) {
		return "", false, fmt.Errorf("token is expired")
	}

	logrus.
		WithField("id", u.UserID).
		WithField("name", u.Username).
		WithField("email", u.Email).
		Info("Client authorized")

	return req.Header.Get(IdHeader), true, nil
}

func (s *Server) allowAll(network, address string) bool {
	logrus.WithField("network", network).WithField("addr", address).Info("Connection allowed")
	return true
}

func (s *Server) getPublicKey() (*[32]byte, error) {
	var result api.KeyResponse
	var errMsg api.MessageResponse

	resp, err := s.client.R().
		SetResult(&result).
		SetError(&errMsg).
		SetContext(context.Background()).
		Get(s.authServerBaseUrl + "/a/key")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return util.ParseKey(result.Key)
}
