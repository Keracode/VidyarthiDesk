package dto

import (
	"time"

	"github.com/google/uuid"
)

// LoginReq represents login request body
//
//	@Description	Login request payload
type LoginReq struct {
	Email    string `json:"email" example:"admin" validate:"required" minLength:"3" maxLength:"50"`
	Password string `json:"password" example:"password" validate:"required,min=6" minLength:"6"`
}

// LoginRes represents login response
//
//	@Description	Login response with tokens
type LoginRes struct {
	AuthToken    string `json:"authToken" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refreshToken" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// UserRes represents user information response
//
//	@Description	User information structure
type UserRes struct {
	ID        uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Email     string    `json:"email" example:"user@example.com"`
	Name      string    `json:"name" example:"John Doe"`
	CreatedAt time.Time `json:"createdAt" example:"2024-01-01T00:00:00Z"`
	UpdatedAt time.Time `json:"updatedAt" example:"2024-01-15T10:30:00Z"`
}
