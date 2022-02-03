package api

import "time"

const (
	IdHeader    = "x-brink-id"
	AuthHeader  = "x-brink-auth"
	KeyHeader   = "x-brink-api-key"
	TokenHeader = "x-brink-api-token"
)

type CreateSessionRequest struct {
	AuthToken string `json:"auth_token,omitempty"`
	Target    string `json:"target,omitempty"`
}

type SessionTokenRequest struct {
	SessionId string `json:"session_id"`
}

type RegisterSessionRequest struct {
	AuthToken  string            `json:"auth_token,omitempty"`
	SessionId  string            `json:"session_id,omitempty"`
	SessionKey string            `json:"session_key,omitempty"`
	Policies   map[string]Policy `json:"policies,omitempty"`
	Target     string            `json:"target,omitempty"`
	Checksum   string            `json:"cs,omitempty"`
}

type Policy struct {
	Subs    []string `json:"subs,omitempty"`
	Emails  []string `json:"emails,omitempty"`
	Filters []string `json:"filters,omitempty"`
}

type SessionTokenResponse struct {
	SessionId    string `json:"session_id,omitempty"`
	AuthUrl      string `json:"auth_url,omitempty"`
	AuthToken    string `json:"auth_token,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type KeyResponse struct {
	Key string `json:"key"`
}

type Token struct {
	ExpirationTime time.Time `json:"exp,omitempty"`
}

type AuthToken struct {
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"user_name,omitempty"`
	Email          string    `json:"email,omitempty"`
	Roles          []string  `json:"roles,omitempty"`
	ExpirationTime time.Time `json:"exp,omitempty"`
	Checksum       string    `json:"cs,omitempty"`
}

type SessionToken struct {
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"user_name,omitempty"`
	Email          string    `json:"email,omitempty"`
	Roles          []string  `json:"roles,omitempty"`
	Target         string    `json:"target,omitempty"`
	ExpirationTime time.Time `json:"exp,omitempty"`
	Checksum       string    `json:"cs,omitempty"`
}
