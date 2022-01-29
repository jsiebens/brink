package api

import "time"

const (
	IdHeader    = "x-brink-id"
	AuthHeader  = "x-brink-auth"
	KeyHeader   = "x-brink-api-key"
	TokenHeader = "x-brink-api-token"
)

type AuthenticationRequest struct {
	Command   string `json:"command"`
	AuthToken string `json:"auth_token"`
	SessionId string `json:"session_id"`
}

type AuthenticationResponse struct {
	AuthUrl      string `json:"auth_url"`
	AuthToken    string `json:"auth_token"`
	SessionToken string `json:"session_token"`
}

type CreateSessionRequest struct {
	Target string `json:"target"`
}

type RegisterSessionRequest struct {
	SessionId  string            `json:"session_id"`
	SessionKey string            `json:"session_key"`
	Policies   map[string]Policy `json:"policies"`
	Target     string            `json:"target"`
	Checksum   string            `json:"cs"`
}

type Policy struct {
	Subs    []string `json:"subs"`
	Emails  []string `json:"emails"`
	Filters []string `json:"filters"`
}

type SessionResponse struct {
	SessionId string `json:"session_id"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type KeyResponse struct {
	Key string `json:"key"`
}

type Token struct {
	ExpirationTime time.Time `json:"exp"`
}

type AuthToken struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"user_name"`
	Email          string    `json:"email"`
	Roles          []string  `json:"roles"`
	ExpirationTime time.Time `json:"exp"`
	Checksum       string    `json:"cs"`
}

type SessionToken struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"user_name"`
	Email          string    `json:"email"`
	Roles          []string  `json:"roles"`
	Target         string    `json:"target"`
	ExpirationTime time.Time `json:"exp"`
	Checksum       string    `json:"cs"`
}
