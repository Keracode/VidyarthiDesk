package server

import (
	"context"
	"errors"
	"sync"

	"github.com/Keracode/vidyarthidesk-backend/config"
	"github.com/Keracode/vidyarthidesk-backend/internal/db"
	"github.com/Keracode/vidyarthidesk-backend/internal/middleware"
	"github.com/gofiber/fiber/v3"
)

type WebServer struct {
	*fiber.App
	DB     *db.Store
	Config *config.Config
}

func (s *WebServer) Shutdown(ctx context.Context) error {
	var wg sync.WaitGroup
	var errs []error

	wg.Go(func() {
		if err := s.ShutdownWithContext(ctx); err != nil {
			errs = append(errs, err)
		}
	})

	if s.DB != nil {
		wg.Go(func() {
			s.DB.Close(ctx)
		})
	}

	wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (s *WebServer) SetupMiddleware() {
	s.App.Use(middleware.SetupCORS())

	s.App.Use(middleware.SetupSession())
}

func New(cfg *config.Config) *WebServer {
	db := db.ConnectDB(cfg.DBString, cfg.MaxDBConns)

	var server = &WebServer{
		App: fiber.New(fiber.Config{
			AppName: "NTTF ERP API",
		}),
		DB:     db,
		Config: cfg,
	}

	server.SetupMiddleware()

	return server
}
