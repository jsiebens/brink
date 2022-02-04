package providers

import (
	"fmt"
	"github.com/jsiebens/brink/internal/config"
)

func NewProvider(c *config.Provider) (AuthProvider, error) {
	switch c.Type {
	case "oidc":
		return NewOIDCProvider(c)
	case "github":
		return NewGitHubProvider(c)
	default:
		return nil, fmt.Errorf("invalid provider type '%s'", c.Type)
	}
}

type AuthProvider interface {
	GetLoginURL(redirectURI, state string) string
	Exchange(redirectURI, code string) (*Identity, error)
	ExchangeIDToken(rawIdToken string) (*Identity, error)
	IsInteractive() bool
}

type Identity struct {
	UserID   string
	Username string
	Email    string
	Attr     map[string]interface{}
}
