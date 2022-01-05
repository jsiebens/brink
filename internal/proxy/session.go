package proxy

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/labstack/echo/v4"
	"net/http"
)

type SessionRegistrar interface {
	GetPublicKey() (*[32]byte, error)
	RegisterSession(request *api.RegisterSessionRequest) (*api.SessionResponse, error)
	AuthenticateSession(authToken string, request *api.AuthenticationRequest) (*api.AuthenticationResponse, error)
}

type remoteSessionRegistrar struct {
	client            *resty.Client
	authServerBaseUrl string
}

func (r *remoteSessionRegistrar) GetPublicKey() (*[32]byte, error) {
	var result api.KeyResponse
	var errMsg api.MessageResponse

	resp, err := r.client.R().
		SetResult(&result).
		SetError(&errMsg).
		SetContext(context.Background()).
		Get(r.authServerBaseUrl + "/a/key")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return util.ParseKey(result.Key)
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
