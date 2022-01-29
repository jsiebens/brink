package proxy

import (
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func NewServer(config config.Proxy, cache cache.Cache, registrar SessionRegistrar) (*Server, error) {
	targetFilters, err := parseTargetFilters(config.Policies)
	if err != nil {
		return nil, err
	}

	checksum, err := util.Checksum(&config.Policies)
	if err != nil {
		return nil, err
	}

	server := &Server{
		sessionRegistrar: registrar,
		sessions:         cache,
		policy:           config.Policies,
		targetFilters:    targetFilters,
		checksum:         checksum,
	}

	return server, nil
}

type Server struct {
	sessionRegistrar SessionRegistrar
	sessions         cache.Cache
	policy           map[string]config.Policy
	targetFilters    map[string][]TargetFilter
	checksum         string
}

type session struct {
	PublicKey  key.PublicKey
	PrivateKey key.PrivateKey
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

	privateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return err
	}
	publicKey := privateKey.Public()

	sessionId := util.GenerateSessionId()

	if target != "" {
		if err := s.sessions.Set(sessionId, &session{PublicKey: publicKey, PrivateKey: *privateKey}); err != nil {
			return err
		}
	}

	resp, err := s.registerSession(sessionId, publicKey.String(), target)
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

	response, err := s.sessionRegistrar.AuthenticateSession(&req)
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
	id := req.Header.Get(api.IdHeader)
	auth := req.Header.Get(api.AuthHeader)

	if id == "" || auth == "" {
		return "", false, nil, fmt.Errorf("missing id and/or auth header")
	}

	var se = session{}

	defer s.sessions.Delete(id)
	if ok, err := s.sessions.Get(id, &se); err != nil || !ok {
		return "", false, nil, nil
	}

	privateKey := se.PrivateKey
	publicKey := s.sessionRegistrar.GetPublicKey()

	var u = &api.SessionToken{}
	if err := privateKey.OpenBase58(publicKey, auth, u); err != nil {
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
		Target:     target,
		Policies:   apiPolicies,
		Checksum:   s.checksum,
	}

	return s.sessionRegistrar.RegisterSession(&request)
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
