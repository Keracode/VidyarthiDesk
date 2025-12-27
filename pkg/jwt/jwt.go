package jwt

import (
	"errors"
	"time"

	"github.com/Keracode/vidyarthidesk-backend/internal/domain"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserId   uuid.UUID
	Name     string
	Email    string
	Expiry   time.Time
	IssuedAt time.Time
}

func GenerateJwtToken(secret string, claim Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    claim.UserId.String(),
		"name":  claim.Name,
		"email": claim.Email,
		"iat":   claim.IssuedAt.Unix(),
		"exp":   claim.Expiry.Unix(),
	})

	return t.SignedString([]byte(secret))
}
func ParseJwtToken(secret string, tokenString string) (*Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrInvalidToken
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrExpiredToken
		}
		return nil, domain.ErrInvalidToken
	}

	if !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	// Extract user ID
	userIdStr, ok := claims["id"].(string)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	// Extract name
	name, ok := claims["name"].(string)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	// Extract email
	email, ok := claims["email"].(string)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	// Extract timestamps
	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	return &Claims{
		UserId:   userId,
		Name:     name,
		Email:    email,
		IssuedAt: time.Unix(int64(iat), 0),
		Expiry:   time.Unix(int64(exp), 0),
	}, nil
}

func GetClaims(c fiber.Ctx) (*Claims, error) {
	claims := c.Locals("claims")
	if claims == nil {
		return nil, domain.ErrNoClaims
	}

	userClaims, ok := claims.(*Claims)
	if !ok {
		return nil, domain.ErrNoClaims
	}

	return userClaims, nil
}
