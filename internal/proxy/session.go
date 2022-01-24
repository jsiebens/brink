package proxy

import (
	"context"
	"github.com/go-resty/resty/v2"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	"github.com/labstack/echo/v4"
	"net/http"
)

type SessionRegistrar interface {
	GetPublicKey() key.PublicKey
	RegisterSession(request *api.RegisterSessionRequest) (*api.SessionResponse, error)
	AuthenticateSession(authToken string, request *api.AuthenticationRequest) (*api.AuthenticationResponse, error)
}

func NewRemoteSessionRegistrar(config config.Auth) (SessionRegistrar, error) {
	url, err := util.NormalizeHttpUrl(config.RemoteServer)
	if err != nil {
		return nil, err
	}
	publicKey, err := key.ParsePublicKey(config.RemotePublicKey)
	if err != nil {
		return nil, err
	}
	return &remoteSessionRegistrar{resty.New(), url, *publicKey}, nil
}

type remoteSessionRegistrar struct {
	client            *resty.Client
	authServerBaseUrl string
	publicKey         key.PublicKey
}

func (r *remoteSessionRegistrar) GetPublicKey() key.PublicKey {
	return r.publicKey
}

func (r *remoteSessionRegistrar) RegisterSession(req *api.RegisterSessionRequest) (*api.SessionResponse, error) {
	var result api.SessionResponse
	var errMsg api.MessageResponse

	resp, err := r.client.R().
		SetBody(req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(context.Background()).
		Post(r.authServerBaseUrl + "/a/session")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, echo.NewHTTPError(resp.StatusCode(), errMsg)
	}

	return &result, nil
}

func (r *remoteSessionRegistrar) AuthenticateSession(authToken string, req *api.AuthenticationRequest) (*api.AuthenticationResponse, error) {
	var result api.AuthenticationResponse
	var errMsg api.MessageResponse

	resp, err := r.client.R().
		SetHeader(AuthHeader, authToken).
		SetBody(req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(context.Background()).
		Post(r.authServerBaseUrl + "/a/auth")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, echo.NewHTTPError(resp.StatusCode(), errMsg)
	}

	return &result, nil
}
