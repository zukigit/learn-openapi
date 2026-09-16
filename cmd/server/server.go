package main

import (
	"context"

	"github.com/google/uuid"
	"github.com/zukigit/learn-openapi/api"
)

type Server struct {
	users map[string]string // email -> password
}

func NewServer() *Server {
	return &Server{
		users: make(map[string]string),
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

	token := "mock-jwt-token-" + uuid.New().String()
	resp := api.Token{
		Token: &token,
	}

	return api.PostLogin200JSONResponse(resp), nil
}
