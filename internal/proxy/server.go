package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/box"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	IdHeader   = "x-brink-id"
	AuthHeader = "x-brink-auth"
)

func NewServer(config config.Proxy, cache cache.Cache, registrar SessionRegistrar) (*Server, error) {
	targetFilters, err := parseTargetFilters(config.Policy.Targets)
	if err != nil {
		return nil, err
	}

	checksum, err := util.Checksum(&config.Policy)
	if err != nil {
		return nil, err
	}

	server := &Server{
		sessionRegistrar: registrar,
		sessions:         cache,
		policy:           config.Policy,
		targetFilters:    targetFilters,
		checksum:         checksum,
	}

	return server, nil
}

type Server struct {
	sessionRegistrar SessionRegistrar
	sessions         cache.Cache
	policy           config.Policy
	targetFilters    []TargetFilter
	checksum         string
}

type session struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
}

func (s *Server) RegisterRoutes(e *echo.Echo) {
	e.GET("/p/connect", s.proxy())
	e.POST("/p/session", s.createSession)
	e.POST("/p/auth", s.authSession)
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

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sessionId := util.GenerateSessionId()

	if target != "" {
		if err := s.sessions.Set(sessionId, &session{PublicKey: publicKey, PrivateKey: privateKey}); err != nil {
			return err
		}
	}

	resp, err := s.registerSession(sessionId, hex.EncodeToString(publicKey[:]), target)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, &resp)
}

func (s *Server) authSession(c echo.Context) error {
	req := api.AuthenticationRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	response, err := s.sessionRegistrar.AuthenticateSession(c.Request().Header.Get(AuthHeader), &req)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) proxy() echo.HandlerFunc {
	rd := remotedialer.New(s.authorizeClient, remotedialer.DefaultErrorWriter)
	return echo.WrapHandler(rd)
}

func (s *Server) authorizeClient(req *http.Request) (string, bool, remotedialer.ConnectAuthorizer, error) {
	id := req.Header.Get(IdHeader)
	auth := req.Header.Get(AuthHeader)

	if id == "" || auth == "" {
		return "", false, nil, fmt.Errorf("missing id and/or auth header")
	}

	var se = session{}

	ok, err := s.sessions.Get(id, &se)
	defer s.sessions.Delete(id)

	if err != nil || !ok {
		return "", false, nil, nil
	}

	publicKey, err := s.sessionRegistrar.GetPublicKey()
	if err != nil {
		return "", false, nil, err
	}

	var u = &api.SessionToken{}
	if err := util.OpenBase58(auth, u, publicKey, se.PrivateKey); err != nil {
		return "", false, nil, fmt.Errorf("invalid token")
	}

	now := time.Now().UTC()

	if now.After(u.ExpirationTime) || u.Checksum != s.checksum {
		return "", false, nil, fmt.Errorf("token is expired")
	}

	if !s.validateTarget(u.Target) {
		return "", false, nil, fmt.Errorf("access to target [%s] is denied", u.Target)
	}

	logrus.
		WithField("id", u.UserID).
		WithField("name", u.Username).
		WithField("email", u.Email).
		Info("Client authorized")

	return id, true, s.connectAuthorizer(u), nil
}

func (s *Server) connectAuthorizer(token *api.SessionToken) remotedialer.ConnectAuthorizer {
	return func(proto, address string) bool {
		result := token.Target == address

		if result {
			logrus.
				WithField("id", token.UserID).
				WithField("name", token.Username).
				WithField("email", token.Email).
				WithField("addr", address).Info("Connection allowed")
		} else {
			logrus.
				WithField("id", token.UserID).
				WithField("name", token.Username).
				WithField("email", token.Email).
				WithField("addr", address).Info("Connection declined")
		}

		return result
	}
}

func (s *Server) registerSession(id, key, target string) (*api.SessionResponse, error) {
	request := api.RegisterSessionRequest{
		SessionId:  id,
		SessionKey: key,
		Target:     target,
		Policy: api.Policy{
			Subs:    s.policy.Subs,
			Emails:  s.policy.Emails,
			Filters: s.policy.Filters,
		},
		Checksum: s.checksum,
	}

	return s.sessionRegistrar.RegisterSession(&request)
}

func (s *Server) validateTarget(target string) bool {
	n := strings.SplitN(target, ":", 2)

	host := n[0]
	port, err := strconv.ParseUint(n[1], 10, 64)

	if err != nil {
		return false
	}

	for _, t := range s.targetFilters {
		if t.validate(host, port) {
			return true
		}
	}

	return false
}
