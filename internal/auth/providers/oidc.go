package providers

import (
	"context"
	"fmt"
	"github.com/jsiebens/brink/internal/config"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCProvider struct {
	clientID     string
	clientSecret string
	scopes       []string
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

func NewOIDCProvider(c *config.Provider) (*OIDCProvider, error) {
	defaultScopes := []string{oidc.ScopeOpenID, "email", "profile"}
	provider, err := oidc.NewProvider(context.Background(), c.Issuer)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: c.ClientID, SkipClientIDCheck: c.ClientID == ""})

	return &OIDCProvider{
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		scopes:       append(defaultScopes, c.Scopes...),
		provider:     provider,
		verifier:     verifier,
	}, nil
}

func (p *OIDCProvider) GetLoginURL(redirectURI, state string) string {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       p.scopes,
	}

	return oauth2Config.AuthCodeURL(state)
}

func (p *OIDCProvider) ExchangeIDToken(rawIdToken string) (*Identity, error) {
	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(context.Background(), rawIdToken)
	if err != nil {
		return nil, err
	}

	sub, email, name, tokenClaims, err := p.getTokenClaims(idToken)
	if err != nil {
		return nil, err
	}

	return &Identity{
		UserID:   sub,
		Username: name,
		Email:    email,
		Attr: map[string]interface{}{
			"provider": "oidc",
			"token":    tokenClaims,
		},
	}, nil
}

func (p *OIDCProvider) Exchange(redirectURI, code string) (*Identity, error) {
	oauth2Config := oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     p.provider.Endpoint(),
		Scopes:       p.scopes,
	}

	oauth2Token, err := oauth2Config.Exchange(context.Background(), code)

	if err != nil {
		return nil, err
	}

	// Extract the ID Token from OAuth2 token.
	rawIdToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIdToken) == "" {
		return nil, fmt.Errorf("id_token missing")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.verifier.Verify(context.Background(), rawIdToken)
	if err != nil {
		return nil, err
	}

	sub, email, name, tokenClaims, err := p.getTokenClaims(idToken)
	if err != nil {
		return nil, err
	}

	userInfoClaims, err := p.getUserInfoClaims(oauth2Config, oauth2Token)
	if err != nil {
		return nil, err
	}

	return &Identity{
		UserID:   sub,
		Username: name,
		Email:    email,
		Attr: map[string]interface{}{
			"provider": "oidc",
			"token":    tokenClaims,
			"userinfo": userInfoClaims,
		},
	}, nil
}

func (p *OIDCProvider) IsInteractive() bool {
	return p.provider.Endpoint().AuthURL != ""
}

func (p *OIDCProvider) getTokenClaims(idToken *oidc.IDToken) (string, string, string, map[string]interface{}, error) {
	var raw = make(map[string]interface{})
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", "", "", nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if err := idToken.Claims(&raw); err != nil {
		return "", "", "", nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	return claims.Sub, claims.Email, claims.Name, raw, nil
}

func (p *OIDCProvider) getUserInfoClaims(config oauth2.Config, token *oauth2.Token) (map[string]interface{}, error) {
	var raw = make(map[string]interface{})

	source := config.TokenSource(context.Background(), token)

	info, err := p.provider.UserInfo(context.Background(), source)
	if err != nil {
		return nil, err
	}

	if err := info.Claims(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %v", err)
	}

	return raw, nil
}
