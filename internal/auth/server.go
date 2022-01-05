package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hashicorp/go-bexpr"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/auth/providers"
	"github.com/jsiebens/proxiro/internal/cache"
	"github.com/jsiebens/proxiro/internal/config"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/mitchellh/pointerstructure"
	"net/http"
	"strings"
	"time"
)

func NewServer(config *config.Config, cache cache.Cache) (*Server, error) {
	publicKey, privateKey, err := util.ParseOrGenerateKey(config.Key)
	if err != nil {
		return nil, err
	}

	provider, err := providers.NewOIDCProvider(&config.Oidc)
	if err != nil {
		return nil, err
	}

	server := &Server{
		publicKey:  publicKey,
		privateKey: privateKey,
		serverUrl:  config.ServerUrl,
		provider:   provider,
		sessions:   cache,
	}

	return server, nil
}

type Server struct {
	publicKey  *[32]byte
	privateKey *[32]byte
	serverUrl  string
	provider   providers.AuthProvider
	sessions   cache.Cache
}

type session struct {
	Key          string
	Filters      []string
	AuthToken    string
	SessionToken string
	Checksum     string
	Error        string
}

type oauthState struct {
	SessionId string
	Key       string
}

func (s *Server) RegisterRoutes(e *echo.Echo) {
	e.GET("/a/key", s.key)
	e.POST("/a/session", s.registerSession)
	e.POST("/a/auth", s.authSession)
	e.GET("/a/:id", s.login)
	e.GET("/a/callback", s.callbackOAuth)
	e.GET("/a/success", s.success)
	e.GET("/a/unauthorized", s.unauthorized)
	e.GET("/a/error", s.callbackError)
}

func (s *Server) GetPublicKey() (*[32]byte, error) {
	return s.publicKey, nil
}

func (s *Server) RegisterSession(req *api.RegisterSessionRequest) (*api.SessionResponse, error) {
	if err := s.sessions.Set(req.SessionId, &session{Key: req.SessionKey, Filters: req.Filters, Checksum: req.Checksum}); err != nil {
		return nil, err
	}

	response := api.SessionResponse{
		SessionId: req.SessionId,
	}

	return &response, nil
}

func (s *Server) AuthenticateSession(authToken string, req *api.AuthenticationRequest) (*api.AuthenticationResponse, error) {
	se := session{}

	ok, err := s.sessions.Get(req.SessionId, &se)

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}

	switch req.Command {
	case "start":
		if authToken != "" {
			var u = &api.UserToken{}
			err := util.OpenBase58(authToken, u, s.publicKey, s.privateKey)

			now := time.Now().UTC()

			if err == nil && now.Before(u.ExpirationTime) && u.Checksum == se.Checksum {
				publicKey, err := util.ParseKey(se.Key)
				if err != nil {
					return nil, err
				}

				u.ExpirationTime = now.Add(5 * time.Minute).UTC()
				sessionToken, err := util.SealBase58(u, publicKey, s.privateKey)
				if err != nil {
					return nil, err
				}

				_ = s.sessions.Delete(req.SessionId)
				return &api.AuthenticationResponse{
					AuthToken:    authToken,
					SessionToken: sessionToken,
				}, nil
			}
		}

		response := api.AuthenticationResponse{
			AuthUrl: s.createUrl("/a/%s", req.SessionId),
		}

		return &response, nil
	case "token":
		if se.Error != "" {
			_ = s.sessions.Delete(req.SessionId)
			return nil, echo.NewHTTPError(http.StatusUnauthorized, se.Error)
		}

		if se.SessionToken != "" {
			_ = s.sessions.Delete(req.SessionId)
			return &api.AuthenticationResponse{
				AuthToken:    se.AuthToken,
				SessionToken: se.SessionToken,
			}, nil
		}

		return &api.AuthenticationResponse{}, nil
	}

	return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid request")
}

func (s *Server) key(c echo.Context) error {
	key, _ := s.GetPublicKey()
	return c.JSON(http.StatusOK, &api.KeyResponse{Key: hex.EncodeToString(key[:])})
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

func (s *Server) authSession(c echo.Context) error {
	req := api.AuthenticationRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	response, err := s.AuthenticateSession(c.Request().Header.Get(proxy.AuthHeader), &req)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, response)
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

	state, err := s.createOAuthState(sessionId, se.Key)
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

	publicKey, err := util.ParseKey(se.Key)
	if err != nil {
		return err
	}

	identity, err := s.getOAuthUser(c)
	if err != nil {
		return err
	}

	authorized, err := s.evaluateIdentity(se.Filters, identity)
	if err != nil {
		return err
	}

	if authorized {
		u := &api.UserToken{
			Checksum:       se.Checksum,
			UserID:         identity.UserID,
			Username:       identity.Username,
			Email:          identity.Email,
			ExpirationTime: time.Now().Add(5 * time.Minute).UTC(),
		}

		sessionToken, err := util.SealBase58(u, publicKey, s.privateKey)
		if err != nil {
			return err
		}

		u.ExpirationTime = time.Now().Add(24 * time.Hour).UTC()
		authToken, err := util.SealBase58(u, s.publicKey, s.privateKey)
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

func (s *Server) evaluateIdentity(filters []string, identity *providers.Identity) (bool, error) {
	for _, f := range filters {
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

func (s *Server) createOAuthState(sessionId, key string) (string, error) {
	stateMap := oauthState{SessionId: sessionId, Key: key}
	return util.SealBase58(stateMap, s.publicKey, s.privateKey)
}

func (s *Server) readOAuthState(state string) (*oauthState, error) {
	stateMap := &oauthState{}
	if err := util.OpenBase58(state, stateMap, s.publicKey, s.privateKey); err != nil {
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
