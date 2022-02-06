package auth

import (
	"context"
	"github.com/go-resty/resty/v2"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	"github.com/labstack/echo/v4"
	"net/http"
	"time"
)

type SessionRegistry interface {
	GetPublicKey() key.PublicKey
	RegisterSession(request *api.RegisterSessionRequest) (*api.SessionTokenResponse, error)
	CheckSessionToken(request *api.SessionTokenRequest) (*api.SessionTokenResponse, error)
}

func NewRemoteSessionRegistry(config config.Auth) (SessionRegistry, error) {
	url, err := util.NormalizeHttpUrl(config.RemoteServer)
	if err != nil {
		return nil, err
	}
	publicKey, err := key.ParsePublicKey(config.RemotePublicKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &remoteSessionRegistry{
		client:            resty.New(),
		authServerBaseUrl: url,
		remotePublicKey:   *publicKey,
		localPrivateKey:   *privateKey,
		localPublicKey:    privateKey.Public().String(),
	}, nil
}

type remoteSessionRegistry struct {
	client            *resty.Client
	authServerBaseUrl string
	remotePublicKey   key.PublicKey

	localPrivateKey key.PrivateKey
	localPublicKey  string
}

func (r *remoteSessionRegistry) GetPublicKey() key.PublicKey {
	return r.remotePublicKey
}

func (r *remoteSessionRegistry) RegisterSession(req *api.RegisterSessionRequest) (*api.SessionTokenResponse, error) {
	token, err := r.localPrivateKey.SealBase58(r.remotePublicKey, &api.Token{ExpirationTime: time.Now().UTC().Add(5 * time.Minute)})
	if err != nil {
		return nil, err
	}

	var result api.SessionTokenResponse
	var errMsg api.MessageResponse

	resp, err := r.client.R().
		SetHeader(api.KeyHeader, r.localPublicKey).
		SetHeader(api.TokenHeader, token).
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

func (r *remoteSessionRegistry) CheckSessionToken(req *api.SessionTokenRequest) (*api.SessionTokenResponse, error) {
	token, err := r.localPrivateKey.SealBase58(r.remotePublicKey, &api.Token{ExpirationTime: time.Now().UTC().Add(5 * time.Minute)})
	if err != nil {
		return nil, err
	}

	var result api.SessionTokenResponse
	var errMsg api.MessageResponse

	resp, err := r.client.R().
		SetHeader(api.KeyHeader, r.localPublicKey).
		SetHeader(api.TokenHeader, token).
		SetBody(req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(context.Background()).
		Post(r.authServerBaseUrl + "/a/token")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, echo.NewHTTPError(resp.StatusCode(), errMsg)
	}

	return &result, nil
}
