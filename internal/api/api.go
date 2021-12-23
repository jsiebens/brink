package api

import "time"

type AuthenticationRequest struct {
	Command   string `json:"command"`
	SessionId string `json:"session_id"`
}

type AuthenticationResponse struct {
	AuthUrl      string `json:"auth_url"`
	AuthToken    string `json:"auth_token"`
	SessionToken string `json:"session_token"`
}

type CreateSessionRequest struct {
	Target  string `json:"target"`
}

type RegisterSessionRequest struct {
	SessionId  string   `json:"session_id"`
	SessionKey string   `json:"session_key"`
	Filters    []string `json:"filters"`
	Checksum   string   `json:"cs"`
}

type SessionResponse struct {
	SessionId      string `json:"session_id"`
	SessionAuthUrl string `json:"session_auth_url"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type KeyResponse struct {
	Key string `json:"key"`
}

type UserToken struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"user_name"`
	Email          string    `json:"email"`
	ExpirationTime time.Time `json:"exp"`
	Checksum       string    `json:"cs"`
}
