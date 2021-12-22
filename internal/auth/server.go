package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hashicorp/go-bexpr"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/auth/providers"
	"github.com/jsiebens/proxiro/internal/auth/templates"
	"github.com/jsiebens/proxiro/internal/cache"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/mitchellh/pointerstructure"
	"golang.org/x/crypto/nacl/box"
	"net/http"
	"strings"
	"time"
)

func StartServer(config *Config) error {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = templates.NewTemplates()

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	oidc := &providers.OIDCAuthConfig{
		Issuer:       config.Oidc.Issuer,
		ClientID:     config.Oidc.ClientID,
		ClientSecret: config.Oidc.ClientSecret,
	}

	provider, err := providers.NewOIDCProvider(oidc)
	if err != nil {
		return err
	}

	server := &Server{
		publicKey:  publicKey,
		privateKey: privateKey,
		serverUrl:  config.ServerUrl,
		provider:   provider,
		sessions:   cache.NewMemoryCache(),
	}

	e.GET("/version", version.GetReleaseInfoHandler)
	e.GET("/a/key", server.Key)
	e.POST("/a/session", server.RegisterSession)
	e.POST("/a/auth", server.Auth)
	e.GET("/a/callback", server.CallbackOAuth)
	e.GET("/a/success", server.Success)
	e.GET("/a/unauthorized", server.Unauthorized)
	e.GET("/a/error", server.CallbackError)

	if config.Tls.KeyFile == "" {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
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

func (s *Server) Key(c echo.Context) error {
	resp := api.KeyResponse{Key: hex.EncodeToString(s.publicKey[:])}
	return c.JSON(http.StatusOK, &resp)
}

func (s *Server) RegisterSession(c echo.Context) error {
	req := api.RegisterSessionRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	if err := s.sessions.Set(req.SessionId, &session{Key: req.SessionKey, Filters: req.Filters, Checksum: req.Checksum}); err != nil {
		return err
	}

	response := api.SessionResponse{
		SessionId:      req.SessionId,
		SessionAuthUrl: s.createUrl("/a/auth"),
	}

	return c.JSON(http.StatusOK, &response)
}

func (s *Server) Auth(c echo.Context) error {
	req := api.AuthenticationRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	se := session{}

	ok, err := s.sessions.Get(req.SessionId, &se)

	if err != nil {
		return err
	}

	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session id")
	}

	switch req.Command {
	case "start":

		authToken := c.Request().Header.Get(proxy.AuthHeader)

		if authToken != "" {
			var u = &api.UserToken{}
			err := util.OpenBase58(authToken, u, s.publicKey, s.privateKey)

			now := time.Now().UTC()

			if err == nil && now.Before(u.ExpirationTime) && u.Checksum == se.Checksum {
				publicKey, err := util.ParseKey(se.Key)
				if err != nil {
					return err
				}

				u.ExpirationTime = now.Add(5 * time.Minute).UTC()
				sessionToken, err := util.SealBase58(u, publicKey, s.privateKey)
				if err != nil {
					return err
				}

				_ = s.sessions.Delete(req.SessionId)
				return c.JSON(http.StatusOK, &api.AuthenticationResponse{
					AuthToken:    authToken,
					SessionToken: sessionToken,
				})
			}
		}

		state, err := s.createOAuthState(req.SessionId, se.Key)
		if err != nil {
			return err
		}

		authUrl := s.provider.GetLoginURL(s.createUrl("/a/callback"), state)

		response := api.AuthenticationResponse{
			AuthUrl: authUrl,
		}

		return c.JSON(http.StatusOK, &response)
	case "token":
		if se.Error != "" {
			_ = s.sessions.Delete(req.SessionId)
			return echo.NewHTTPError(http.StatusUnauthorized, se.Error)
		}

		if se.SessionToken != "" {
			_ = s.sessions.Delete(req.SessionId)
			return c.JSON(http.StatusOK, &api.AuthenticationResponse{
				AuthToken:    se.AuthToken,
				SessionToken: se.SessionToken,
			})
		}

		return c.JSON(http.StatusOK, &api.AuthenticationResponse{})
	}

	return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
}

func (s *Server) CallbackOAuth(c echo.Context) error {
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

func (s *Server) Success(c echo.Context) error {
	return c.Render(http.StatusOK, "success.html", nil)
}

func (s *Server) Unauthorized(c echo.Context) error {
	return c.Render(http.StatusOK, "unauthorized.html", nil)
}

func (s *Server) CallbackError(c echo.Context) error {
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
