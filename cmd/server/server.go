package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/zukigit/learn-openapi/api"
)

type CustomClaims struct {
	jwt.RegisteredClaims
}

type Server struct {
	users     map[string]string // email -> password
	jwtSecret []byte
}

func NewServer() *Server {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("secret is empty")
	}

	return &Server{
		users:     make(map[string]string),
		jwtSecret: []byte(secret),
	}
}

func (s *Server) PostSignup(ctx context.Context, req api.PostSignupRequestObject) (api.PostSignupResponseObject, error) {
	email := string(req.Body.Email)

	if _, exists := s.users[email]; exists {
		return api.PostSignup409Response{}, nil
	}

	s.users[email] = string(req.Body.Password)

	id := uuid.New()
	user := api.User{
		Id:    &id,
		Email: &req.Body.Email,
	}

	return api.PostSignup201JSONResponse(user), nil
}

func (s *Server) PostLogin(ctx context.Context, req api.PostLoginRequestObject) (api.PostLoginResponseObject, error) {
	email := string(req.Body.Email)
	password, exists := s.users[email]

	if !exists || password != req.Body.Password {
		return api.PostLogin401Response{}, nil
	}

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	resp := api.Token{
		Token: &tokenString,
	}

	return api.PostLogin200JSONResponse(resp), nil
}
