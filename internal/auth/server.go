package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/go-bexpr"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/auth/providers"
	"github.com/jsiebens/brink/internal/auth/templates"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/server"
	"github.com/jsiebens/brink/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/mitchellh/pointerstructure"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

const authCachePrefix = "a_"

func StartServer(ctx context.Context, config *config.Config) error {
	v, r := version.GetReleaseInfo()
	logrus.Infof("Starting brink auth server. Version %s - %s", v, r)

	c, err := cache.NewCache(config.Cache)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = templates.NewTemplates()

	version.RegisterRoutes(e)

	authServer, err := NewServer(config.Auth, cache.Prefixed(c, authCachePrefix))
	if err != nil {
		return err
	}
	authServer.RegisterRoutes(e, true)

	return server.Start(ctx, config, e)
}

func NewServer(config config.Auth, cache cache.Cache) (*Server, error) {
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

	provider, err := providers.NewProvider(&config.Provider)
	if err != nil {
		return nil, err
	}

	server := &Server{
		privateKey: *privateKey,
		publicKey:  privateKey.Public(),
		serverUrl:  config.UrlPrefix,
		provider:   provider,
		sessions:   cache,
	}

	return server, nil
}

type Server struct {
	publicKey       key.PublicKey
	privateKey      key.PrivateKey
	serverUrl       string
	provider        providers.AuthProvider
	sessions        cache.Cache
	enableEndpoints bool
}

type session struct {
	PublicKey    key.PublicKey
	Policies     map[string]api.Policy
	Target       string
	Checksum     string
	AuthToken    string
	SessionToken string
	Error        string
}

type oauthState struct {
	SessionId string
}

func (s *Server) RegisterRoutes(e *echo.Echo, enableEndpoints bool) {
	if enableEndpoints {
		e.POST("/a/session", s.registerSession, s.checkApiToken)
		e.POST("/a/token", s.checkSessionToken, s.checkApiToken)
	}

	e.GET("/a/:id", s.login)
	e.GET("/a/callback", s.callbackOAuth)
	e.GET("/a/success", s.success)
	e.GET("/a/unauthorized", s.unauthorized)
	e.GET("/a/error", s.callbackError)
}

func (s *Server) GetPublicKey() key.PublicKey {
	return s.publicKey
}

func (s *Server) RegisterSession(req *api.RegisterSessionRequest) (*api.SessionTokenResponse, error) {
	publicKey, err := key.ParsePublicKey(req.SessionKey)
	if err != nil {
		return nil, err
	}

	if req.AuthToken != "" {
		var u = &api.AuthToken{}
		err := s.privateKey.OpenBase58(s.publicKey, req.AuthToken, u)

		now := time.Now().UTC()

		if err == nil && now.Before(u.ExpirationTime) && u.Checksum == req.Checksum {
			st := api.SessionToken{
				UserID:         u.UserID,
				Username:       u.Username,
				Email:          u.Email,
				Roles:          u.Roles,
				Target:         req.Target,
				ExpirationTime: now.Add(5 * time.Minute).UTC(),
				Checksum:       req.Checksum,
			}

			sessionToken, err := s.privateKey.SealBase58(*publicKey, st)
			if err != nil {
				return nil, err
			}

			response := api.SessionTokenResponse{
				SessionId:    req.SessionId,
				SessionToken: sessionToken,
				AuthToken:    req.AuthToken,
			}

			return &response, nil
		}

		identity, err := s.provider.ExchangeIDToken(req.AuthToken)
		if err == nil {
			authorized, roles, err := s.evaluatePolicies(req.Policies, identity)
			if err != nil {
				return nil, err
			}

			if !authorized {
				return nil, echo.NewHTTPError(http.StatusUnauthorized)
			}

			st := api.SessionToken{
				UserID:         identity.UserID,
				Username:       identity.Username,
				Email:          identity.Email,
				Roles:          roles,
				Target:         req.Target,
				ExpirationTime: now.Add(5 * time.Minute).UTC(),
				Checksum:       req.Checksum,
			}

			sessionToken, err := s.privateKey.SealBase58(*publicKey, st)
			if err != nil {
				return nil, err
			}

			response := api.SessionTokenResponse{
				SessionId:    req.SessionId,
				SessionToken: sessionToken,
				AuthToken:    req.AuthToken,
			}

			return &response, nil
		}
	}

	if !s.provider.IsInteractive() {
		return nil, echo.NewHTTPError(http.StatusUnauthorized)
	}

	if err := s.sessions.Set(req.SessionId, &session{PublicKey: *publicKey, Policies: req.Policies, Target: req.Target, Checksum: req.Checksum}); err != nil {
		return nil, err
	}

	response := api.SessionTokenResponse{
		SessionId: req.SessionId,
		AuthUrl:   s.createUrl("/a/%s", req.SessionId),
	}

	return &response, nil
}

func (s *Server) CheckSessionToken(req *api.SessionTokenRequest) (*api.SessionTokenResponse, error) {
	se := session{}

	ok, err := s.sessions.Get(req.SessionId, &se)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}

	if se.Error != "" {
		_ = s.sessions.Delete(req.SessionId)
		return nil, echo.NewHTTPError(http.StatusUnauthorized, se.Error)
	}

	if se.SessionToken != "" {
		_ = s.sessions.Delete(req.SessionId)
		return &api.SessionTokenResponse{
			AuthToken:    se.AuthToken,
			SessionToken: se.SessionToken,
		}, nil
	}

	return &api.SessionTokenResponse{}, nil
}

func (s *Server) registerSession(c echo.Context) error {
	req := api.RegisterSessionRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	response, err := s.RegisterSession(&req)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, &response)
}

func (s *Server) checkSessionToken(c echo.Context) error {
	req := api.SessionTokenRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	response, err := s.CheckSessionToken(&req)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, response)
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

func (s *Server) login(c echo.Context) error {
	sessionId := c.Param("id")
	se := session{}

	ok, err := s.sessions.Get(sessionId, &se)

	if err != nil {
		return err
	}

	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}

	state, err := s.createOAuthState(sessionId)
	if err != nil {
		return err
	}

	authUrl := s.provider.GetLoginURL(s.createUrl("/a/callback"), state)

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) callbackOAuth(c echo.Context) error {
	state, err := s.readOAuthState(c.QueryParam("state"))
	if err != nil {
		return nil
	}

	se := session{}
	ok, err := s.sessions.Get(state.SessionId, &se)
	if err != nil {
		return err
	}

	if !ok {
		return c.Redirect(http.StatusFound, "/a/error")
	}

	callbackError := c.QueryParam("error")

	if callbackError != "" {
		if err := s.sessions.Set(state.SessionId, session{Error: callbackError}); err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, "/a/error")
	}

	publicKey := se.PublicKey

	identity, err := s.getOAuthUser(c)
	if err != nil {
		return err
	}

	authorized, roles, err := s.evaluatePolicies(se.Policies, identity)
	if err != nil {
		return err
	}

	if authorized {
		at := &api.AuthToken{
			UserID:         identity.UserID,
			Username:       identity.Username,
			Email:          identity.Email,
			Roles:          roles,
			ExpirationTime: time.Now().Add(24 * time.Hour).UTC(),
			Checksum:       se.Checksum,
		}

		authToken, err := s.privateKey.SealBase58(s.publicKey, at)
		if err != nil {
			return err
		}

		st := &api.SessionToken{
			UserID:         identity.UserID,
			Username:       identity.Username,
			Email:          identity.Email,
			Roles:          roles,
			Target:         se.Target,
			ExpirationTime: time.Now().Add(5 * time.Minute).UTC(),
			Checksum:       se.Checksum,
		}

		sessionToken, err := s.privateKey.SealBase58(publicKey, st)
		if err != nil {
			return err
		}

		if err := s.sessions.Set(state.SessionId, session{SessionToken: sessionToken, AuthToken: authToken}); err != nil {
			return err
		}

		return c.Redirect(http.StatusFound, "/a/success")
	} else {
		if err := s.sessions.Set(state.SessionId, session{Error: "unauthorized"}); err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, "/a/unauthorized")
	}
}

func (s *Server) success(c echo.Context) error {
	return c.Render(http.StatusOK, "success.html", nil)
}

func (s *Server) unauthorized(c echo.Context) error {
	return c.Render(http.StatusOK, "unauthorized.html", nil)
}

func (s *Server) callbackError(c echo.Context) error {
	return c.Render(http.StatusOK, "error.html", nil)
}

func (s *Server) evaluatePolicies(policies map[string]api.Policy, identity *providers.Identity) (bool, []string, error) {
	var roles []string

	for role, policy := range policies {
		ok, _ := s.evaluatePolicy(policy, identity)
		if ok {
			roles = append(roles, role)
		}
	}

	return len(roles) != 0, roles, nil
}

func (s *Server) evaluatePolicy(policy api.Policy, identity *providers.Identity) (bool, error) {
	for _, sub := range policy.Subs {
		if identity.UserID == sub {
			return true, nil
		}
	}

	for _, email := range policy.Emails {
		if identity.Email == email {
			return true, nil
		}
	}

	for _, f := range policy.Filters {
		if f == "*" {
			return true, nil
		}

		evaluator, err := bexpr.CreateEvaluator(f)
		if err != nil {
			return false, err
		}

		result, err := evaluator.Evaluate(identity.Attr)
		if err != nil && !errors.Is(err, pointerstructure.ErrNotFound) {
			return false, err
		}

		if result {
			return true, nil
		}
	}

	return false, nil
}

func (s *Server) createOAuthState(sessionId string) (string, error) {
	stateMap := oauthState{SessionId: sessionId}
	return s.privateKey.SealBase58(s.publicKey, stateMap)
}

func (s *Server) readOAuthState(state string) (*oauthState, error) {
	stateMap := &oauthState{}
	if err := s.privateKey.OpenBase58(s.publicKey, state, stateMap); err != nil {
		return nil, err
	}
	return stateMap, nil
}

func (s *Server) getOAuthUser(c echo.Context) (*providers.Identity, error) {
	redirectUrl := s.createUrl("/a/callback")
	return s.provider.Exchange(redirectUrl, c.QueryParam("code"))
}

func (s *Server) createUrl(format string, a ...interface{}) string {
	path := fmt.Sprintf(format, a...)
	return strings.TrimSuffix(s.serverUrl, "/") + "/" + strings.TrimPrefix(path, "/")
}
