package services

import (
	"context"
	"errors"
	"time"

	"github.com/Keracode/vidyarthidesk-backend/internal/domain"
	"github.com/Keracode/vidyarthidesk-backend/internal/dto"
	"github.com/Keracode/vidyarthidesk-backend/pkg/hash"
	"github.com/Keracode/vidyarthidesk-backend/pkg/ip"
	"github.com/Keracode/vidyarthidesk-backend/pkg/jwt"
	"github.com/google/uuid"
)

type AuthService struct {
	userRepo         domain.UserRepository
	sessionRepo      domain.SessionRepository
	refreshTokenRepo domain.RefreshTokenRepository
	jwtSecret        string
}

func NewAuthService(userRepo domain.UserRepository, sessionRepo domain.SessionRepository, refreshTokenRepo domain.RefreshTokenRepository, jwtSecret string) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		jwtSecret:        jwtSecret,
	}
}

func (s *AuthService) Login(ctx context.Context, data dto.LoginReq, userAgent string, ipAddr string) (*dto.LoginRes, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, data.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}

		return nil, err
	}

	if err = hash.CompareHash(data.Password, user.Password); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	authToken, err := jwt.GenerateJwtToken(s.jwtSecret, jwt.Claims{
		UserId:   user.ID,
		Name:     user.Name,
		Email:    user.Email,
		IssuedAt: time.Now(),
		Expiry:   time.Now().Add(2 * time.Hour),
	})
	if err != nil {
		return nil, domain.ErrTokenGeneration
	}

	session := domain.Session{
		UserID:    user.ID,
		UserAgent: userAgent,
		IpAddress: *ip.StringToNetIpAddr(ipAddr),
	}

	sessionId, err := s.sessionRepo.Create(ctx, &session)
	if err != nil {
		return nil, err
	}

	refreshTokenString := uuid.NewString()
	hashedToken := hash.HashToken(refreshTokenString)

	refreshToken := domain.RefreshToken{
		SessionID: sessionId,
		Token:     hashedToken,
	}

	if _, err := s.refreshTokenRepo.Create(ctx, &refreshToken); err != nil {
		return nil, err
	}

	return &dto.LoginRes{
		AuthToken:    authToken,
		RefreshToken: refreshTokenString,
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenString string) (*dto.LoginRes, error) {
	hashedToken := hash.HashToken(refreshTokenString)

	refreshToken, session, err := s.refreshTokenRepo.GetWithSession(ctx, hashedToken)
	if err != nil {
		return nil, err
	}

	if refreshToken.IsRevoked {
		return nil, domain.ErrTokenRevoked
	}

	if session.ExpiresAt.Before(time.Now()) || refreshToken.ExpiresAt.Before(time.Now()) {
		return nil, domain.ErrSessionExpired
	}

	user, err := s.userRepo.GetUserById(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	newRefresh := uuid.NewString()
	newRefreshHash := hash.HashToken(newRefresh)
	authToken, err := jwt.GenerateJwtToken(s.jwtSecret, jwt.Claims{
		UserId:   user.ID,
		Name:     user.Name,
		Email:    user.Email,
		IssuedAt: time.Now(),
		Expiry:   time.Now().Add(2 * time.Hour),
	})
	if err != nil {
		return nil, domain.ErrTokenGeneration
	}

	refreshToken.SessionID = session.Id
	refreshToken.Token = newRefreshHash

	_, err = s.refreshTokenRepo.Create(ctx, &refreshToken)
	if err != nil {
		return nil, err
	}

	err = s.refreshTokenRepo.Revoke(ctx, hashedToken)
	if err != nil {
		return nil, err
	}

	return &dto.LoginRes{
		AuthToken:    authToken,
		RefreshToken: newRefresh,
	}, nil
}

func (s *AuthService) GetMe(ctx context.Context, claim *jwt.Claims) (*dto.UserRes, error) {
	user, err := s.userRepo.GetUserById(ctx, claim.UserId)
	if err != nil {
		return nil, err
	}

	return &dto.UserRes{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}
