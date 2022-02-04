package proxy

import (
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/auth"
	"github.com/jsiebens/brink/internal/auth/templates"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/server"
	"github.com/jsiebens/brink/internal/util"
	"github.com/jsiebens/brink/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
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
		remoteSessionRegistrar, err := auth.NewRemoteSessionRegistrar(config.Auth)
		if err != nil {
			return err
		}
		sessionRegistry = remoteSessionRegistrar
	}

	logrus.Info("registering proxy routes")

	proxyServer, err := NewServer(config.Proxy, cache.Prefixed(c, proxyCachePrefix), sessionRegistry)
	if err != nil {
		return err
	}
	proxyServer.RegisterRoutes(e)

	return server.Start(config, e)
}

func NewServer(config config.Proxy, cache cache.Cache, registrar auth.SessionRegistry) (*Server, error) {
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
	sessionRegistrar auth.SessionRegistry
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
	e.POST("/p/token", s.checkSessionToken)
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

	response, err := s.sessionRegistrar.CheckSessionToken(&req)
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
