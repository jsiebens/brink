package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/auth/providers"
	"github.com/jsiebens/proxiro/internal/cache"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/nacl/box"
	"net/http"
	"strings"
	"time"
)

func StartServer(config *Config) error {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

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
	e.POST("/a/auth/:key", server.Auth)
	e.GET("/a/callback", server.CallbackOAuth)
	e.GET("/a/success", server.Success)
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
	Token string
	Error string
}

type oauthState struct {
	SessionId string
	Key       string
}

func (s *Server) Key(c echo.Context) error {
	resp := api.KeyResponse{Key: hex.EncodeToString(s.publicKey[:])}
	return c.JSON(http.StatusOK, &resp)
}

func (s *Server) Auth(c echo.Context) error {
	key := c.Param("key")
	req := api.AuthenticationRequest{}

	if err := c.Bind(&req); err != nil {
		return err
	}

	switch req.Command {
	case "start":
		state, err := s.createOAuthState(req.SessionId, key)
		if err != nil {
			return err
		}

		authUrl := s.provider.GetLoginURL(s.createUrl("/a/callback"), state)

		response := api.AuthenticationResponse{
			AuthUrl: authUrl,
		}

		return c.JSON(http.StatusOK, &response)
	case "token":
		var resp = session{}

		ok, err := s.sessions.Get(req.SessionId, &resp)

		if err != nil {
			return err
		}

		if ok {
			_ = s.sessions.Delete(req.SessionId)
		}

		if resp.Error != "" {
			return echo.NewHTTPError(http.StatusUnauthorized, resp.Error)
		} else {
			return c.JSON(http.StatusOK, &api.AuthenticationResponse{Token: resp.Token})
		}
	}

	return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
}

func (s *Server) CallbackOAuth(c echo.Context) error {
	state, err := s.readOAuthState(c.QueryParam("state"))
	if err != nil {
		return nil
	}

	callbackError := c.QueryParam("error")

	if callbackError != "" {
		if err := s.sessions.Set(state.SessionId, session{Error: callbackError}); err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, "/a/error")
	}

	publicKey, err := util.ParseKey(state.Key)
	if err != nil {
		return err
	}

	identity, err := s.getOAuthUser(c)
	if err != nil {
		return err
	}

	u := &api.UserToken{
		UserID:         identity.UserID,
		Username:       identity.Username,
		Email:          identity.Email,
		ExpirationTime: time.Now().Add(5 * time.Minute).UTC(),
	}

	token, err := util.SealBase58(u, publicKey, s.privateKey)
	if err != nil {
		return err
	}

	if err := s.sessions.Set(state.SessionId, session{Token: token}); err != nil {
		return err
	}

	return c.Redirect(http.StatusFound, "/a/success")
}

func (s *Server) Success(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

func (s *Server) CallbackError(c echo.Context) error {
	return c.String(http.StatusBadRequest, "NOK")
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
