package domain

import "errors"

var (
	// General errors
	ErrDatabase        = errors.New("database error")
	ErrInvalidInput    = errors.New("invalid input")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
	ErrTokenGeneration = errors.New("token generation failed")

	// Session errors
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session expired")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
	ErrTokenRevoked        = errors.New("token has been revoked")

	// User errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")

	// Token errors
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
	ErrNoClaims     = errors.New("no claims found in context")
)
