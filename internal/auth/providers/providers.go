package providers

type AuthProvider interface {
	GetLoginURL(redirectURI, state string) string
	Exchange(redirectURI, code string) (*Identity, error)
}

type Identity struct {
	UserID   string
	Username string
	Email    string
	Attr     map[string]interface{}
}
