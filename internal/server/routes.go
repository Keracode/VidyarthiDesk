package server

import (
	"github.com/Keracode/vidyarthidesk-backend/internal/handlers"
	"github.com/Keracode/vidyarthidesk-backend/internal/middleware"
	"github.com/Keracode/vidyarthidesk-backend/internal/repository"
	"github.com/Keracode/vidyarthidesk-backend/internal/services"
	"github.com/gofiber/fiber/v3"
	"github.com/yokeTH/gofiber-scalar/scalar/v3"
)

func (s *WebServer) RegisterRoutes() {
	repos := repository.NewRepositories(s.DB.Queries)

	authService := services.NewAuthService(
		repos.User,
		repos.Session,
		repos.RefreshToken,
		s.Config.JWTSecret,
	)
	authHandler := handlers.NewAuthHandler(authService)

	s.App.Get("/", s.HandleIndexRotue)

	s.App.Get("/docs/*", scalar.New(scalar.Config{
		Title:    "VidyarthiDesk API Documentation",
		BasePath: "/",
		Path:     "/docs",
		Theme:    scalar.ThemeKepler,
	}))

	api := s.App.Group("/api")

	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/refresh", authHandler.RefreshToken)

	protected := api.Group("/", middleware.JWTMiddleware(s.Config.JWTSecret))

	protected.Get("/auth/me", authHandler.Me)
}

func (s *WebServer) HandleIndexRotue(c fiber.Ctx) error {
	return c.SendString("Index Router")
}
