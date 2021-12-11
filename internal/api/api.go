package api

import "time"

type AuthenticationRequest struct {
	Command   string `json:"command"`
	SessionId string `json:"session_id"`
}

type AuthenticationResponse struct {
	AuthUrl string `json:"auth_url"`
	Token   string `json:"token"`
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
}
