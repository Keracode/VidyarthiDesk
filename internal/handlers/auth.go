package handlers

import (
	"errors"

	"github.com/Keracode/vidyarthidesk-backend/internal/domain"
	"github.com/Keracode/vidyarthidesk-backend/internal/dto"
	"github.com/Keracode/vidyarthidesk-backend/internal/services"
	"github.com/Keracode/vidyarthidesk-backend/pkg/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

type AuthHandler struct {
	service *services.AuthService
}

func NewAuthHandler(service *services.AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

// Login godoc
//
// @Summary      User login
// @Description  Authenticate user with email and password. Returns JWT access token and refresh token stored in session.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      dto.LoginReq  true  "Login credentials"
// @Success      200      {object}  dto.LoginRes  "Successfully authenticated"
// @Failure      400      {object}  dto.ErrorRes  "Invalid request body or validation error"
// @Failure      401      {object}  dto.ErrorRes  "Invalid email or password"
// @Failure      500      {object}  dto.ErrorRes  "Internal server error"
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c fiber.Ctx) error {
	sess := session.FromContext(c)
	var body dto.LoginReq

	userAgent := c.Get("User-Agent")
	ip := c.IP()

	if err := c.Bind().Body(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(dto.ErrorRes{
			Error:   err.Error(),
			Message: "Invalid  Request Body",
		})
	}

	res, err := h.service.Login(c.Context(), body, userAgent, ip)
	if err != nil {
		return h.handleError(c, err)
	}

	sess.Set("refreshToken", res.RefreshToken)
	return c.Status(fiber.StatusOK).JSON(res)
}

// RefreshToken godoc //
// @Summary      Refresh access token
// @Description  Generate new access token and refresh token using existing refresh token from session. Old refresh token is revoked.
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  dto.LoginRes  "New tokens generated successfully"
// @Failure      401  {object}  dto.ErrorRes  "No refresh token in session, token expired, or token revoked"
// @Failure      500  {object}  dto.ErrorRes  "Internal server error"
// @Router       /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c fiber.Ctx) error {
	sess := session.FromContext(c)
	refreshToken, ok := sess.Get("refreshToken").(string)
	if !ok || refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: "No refresh token found in session",
		})
	}

	res, err := h.service.RefreshToken(c.Context(), refreshToken)
	if err != nil {
		return h.handleError(c, err)
	}

	sess.Set("refreshToken", res.RefreshToken)
	return c.Status(fiber.StatusOK).JSON(res)
}

// GetMe godoc
//
// @Summary      Get current user
// @Description  Get the authenticated user's information from JWT token
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  dto.UserRes   "Current user information"
// @Failure      401  {object}  dto.ErrorRes  "user not found"
// @Failure      500  {object}  dto.ErrorRes  "Internal server error"
// @Router       /auth/me [get]
func (h *AuthHandler) Me(c fiber.Ctx) error {
	claims, err := jwt.GetClaims(c)
	if err != nil {
		return h.handleError(c, err)
	}

	res, err := h.service.GetMe(c.Context(), claims)
	if err != nil {
		return h.handleError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

func (h *AuthHandler) handleError(c fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Invalid credentials",
			Message: "Email or password is incorrect",
		})
	case errors.Is(err, domain.ErrInvalidRefreshToken):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error: "Invalid or expired refresh token",
		})
	case errors.Is(err, domain.ErrSessionExpired):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error: "Session expired",
		})
	case errors.Is(err, domain.ErrTokenRevoked):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: "Token has been revoked",
		})
	case errors.Is(err, domain.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: domain.ErrInvalidToken.Error(),
		})
	case errors.Is(err, domain.ErrExpiredToken):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: domain.ErrExpiredToken.Error(),
		})
	case errors.Is(err, domain.ErrNoClaims):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: domain.ErrNoClaims.Error(),
		})
	case errors.Is(err, domain.ErrUserNotFound):
		return c.Status(fiber.StatusUnauthorized).JSON(dto.ErrorRes{
			Error:   "Unauthorized",
			Message: domain.ErrUserNotFound.Error(),
		})
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(dto.ErrorRes{
			Error: "Internal server error",
		})
	}
}
