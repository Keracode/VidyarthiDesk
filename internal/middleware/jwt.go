package middleware

import (
	"strings"

	"github.com/Keracode/vidyarthidesk-backend/internal/dto"
	"github.com/Keracode/vidyarthidesk-backend/pkg/jwt"
	"github.com/gofiber/fiber/v3"
)

func JWTMiddleware(jwtSecret string) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
				Error:   "Unauthorized",
				Message: "Missing authorization header",
			})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
				Error:   "Unauthorized",
				Message: "Invalid authorization header format",
			})
		}

		tokenString := parts[1]

		claims, err := jwt.ParseJwtToken(jwtSecret, tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
				Error:   "Unauthorized",
				Message: "Invalid or expired token",
			})
		}

		c.Locals("claims", claims)

		return c.Next()
	}
}
