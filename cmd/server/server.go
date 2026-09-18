package main

// The StrictServerInterface implementation: one method per operation in
// api/openapi.yaml. Each gets a typed RequestObject in and returns a typed
// ResponseObject out — no manual JSON encoding, no manual status codes
// (mostly), impossible to return a shape the spec doesn't allow.

import (
	"context"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/zukigit/learn-openapi/api"
)

// ---------------------------------------------------------------------------
// Internal model vs API models
// ---------------------------------------------------------------------------

// todo is the INTERNAL record — what the server actually stores.
//
// Note the split from the API models (api.Todo, api.NewTodo, ...): the spec
// types describe what crosses the wire; this struct is storage. They happen
// to look alike here, but keeping them separate means a storage change (a
// database, private fields) can never leak into the public API by accident.
type todo struct {
	id          uuid.UUID
	owner       string // creator's email, taken from the JWT `sub` claim
	title       string
	description string
	status      string
	createdAt   time.Time
	updatedAt   time.Time
}

// toAPI converts the internal record into the spec's Todo response model.
// description is optional in the spec, so it maps to a *string — nil (i.e.
// omitted from the JSON) when empty, a value only when set.
func (t *todo) toAPI() api.Todo {
	id := t.id
	createdAt := t.createdAt
	updatedAt := t.updatedAt
	var description *string
	if t.description != "" {
		description = &t.description
	}
	return api.Todo{
		Id:          &id,
		Title:       t.title,
		Description: description,
		Status:      api.TodoStatus(t.status),
		CreatedAt:   &createdAt,
		UpdatedAt:   &updatedAt,
	}
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

// Server implements the generated api.StrictServerInterface (see
// api/api.gen.go) and holds all application state.
type Server struct {
	jwtSecret []byte

	// Learning-only in-memory state. A real service would use a database.
	// mu guards both maps against concurrent requests.
	mu    sync.Mutex
	users map[string]string // email -> password (plaintext! fine here, never in prod)
	todos map[uuid.UUID]*todo
}

// NewServer builds the Server. The JWT signing secret comes from the
// JWT_SECRET env var, with a hardcoded fallback so the learning server runs
// with zero setup.
func NewServer() *Server {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-secret-do-not-use-in-prod"
		log.Println("warning: JWT_SECRET not set, using insecure dev secret")
	}
	return &Server{
		jwtSecret: []byte(secret),
		users:     make(map[string]string),
		todos:     make(map[uuid.UUID]*todo),
	}
}

// ---------------------------------------------------------------------------
// Auth handlers (POST /signup, POST /login)
// ---------------------------------------------------------------------------

// Signup implements POST /signup (operationId: signup).
//
// The request body was already decoded into api.Credentials by the strict
// handler — including the format: email check from the validator middleware.
func (s *Server) Signup(ctx context.Context, req api.SignupRequestObject) (api.SignupResponseObject, error) {
	email := string(req.Body.Email)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[email]; exists {
		// Returning the generated 409 type is all it takes: correct status
		// code, correct Error body, correct Content-Type.
		return api.Signup409JSONResponse(api.Error{Message: "email already registered"}), nil
	}

	s.users[email] = req.Body.Password

	return api.Signup201JSONResponse(api.User{
		Id:    uuid.New(),
		Email: req.Body.Email,
	}), nil
}

// Login implements POST /login (operationId: login).
// Successful login mints the JWT that the auth middleware later verifies.
func (s *Server) Login(ctx context.Context, req api.LoginRequestObject) (api.LoginResponseObject, error) {
	email := string(req.Body.Email)

	s.mu.Lock()
	password, exists := s.users[email]
	s.mu.Unlock()

	// Same error for "no such user" and "wrong password" — don't tell an
	// attacker which emails exist.
	if !exists || password != req.Body.Password {
		return api.Login401JSONResponse{UnauthorizedJSONResponse: api.UnauthorizedJSONResponse{Message: "invalid credentials"}}, nil
	}

	claims := jwt.RegisteredClaims{
		Subject:   email, // the `sub` claim — becomes "current user" downstream
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	return api.Login200JSONResponse(api.Token{Token: signed}), nil
}

// ---------------------------------------------------------------------------
// Todo handlers
// ---------------------------------------------------------------------------

// ListTodos implements GET /todos (operationId: listTodos).
//
// Everything the client can vary arrives in req.Params — typed query params
// (limit/offset/status/sort) plus the X-Request-ID header param. Optional
// params are pointers: nil means "client omitted it", and applying the
// spec's `default:` value is OUR job — defaults in the spec document the
// behavior (and make validation pass when omitted), they are not injected.
func (s *Server) ListTodos(ctx context.Context, req api.ListTodosRequestObject) (api.ListTodosResponseObject, error) {
	user := userFromContext(ctx)

	// Apply the spec's defaults for omitted params.
	limit := 20 // components/parameters/Limit  -> default: 20
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	offset := 0 // components/parameters/Offset -> default: 0
	if req.Params.Offset != nil {
		offset = *req.Params.Offset
	}
	sortKey := "-created_at" // default: newest first
	if req.Params.Sort != nil {
		sortKey = string(*req.Params.Sort)
	}
	// req.Params.XRequestID: validated (uuid format) but unused — the spec
	// documents it for tracing, so a proxy could log it. We simply accept it.

	s.mu.Lock()
	matched := make([]*todo, 0, len(s.todos))
	for _, t := range s.todos {
		if t.owner != user {
			continue // every user sees only their own todos
		}
		if req.Params.Status != nil && string(*req.Params.Status) != t.status {
			continue // status filter requested and doesn't match
		}
		matched = append(matched, t)
	}
	s.mu.Unlock() // done with the map; sorting needs no lock

	switch sortKey {
	case "created_at": // oldest first
		sort.Slice(matched, func(i, j int) bool { return matched[i].createdAt.Before(matched[j].createdAt) })
	case "title": // alphabetical
		sort.Slice(matched, func(i, j int) bool { return matched[i].title < matched[j].title })
	default: // "-created_at": newest first
		sort.Slice(matched, func(i, j int) bool { return matched[i].createdAt.After(matched[j].createdAt) })
	}

	// Slice out the requested page: skip `offset` items, take up to `limit`.
	total := len(matched)
	items := make([]api.Todo, 0, limit)
	for i, t := range matched {
		if i < offset {
			continue
		}
		if len(items) == limit {
			break
		}
		items = append(items, t.toAPI())
	}

	return api.ListTodos200JSONResponse(api.TodoList{
		Items: items,
		Pagination: api.Pagination{
			Total:  total,  // matching items before paging
			Limit:  limit,  // page size actually used
			Offset: offset, // items skipped before this page
		},
	}), nil
}

// CreateTodo implements POST /todos (operationId: createTodo).
func (s *Server) CreateTodo(ctx context.Context, req api.CreateTodoRequestObject) (api.CreateTodoResponseObject, error) {
	user := userFromContext(ctx)
	body := req.Body // api.NewTodo: title required, description/status optional

	// Defaults for omitted optional fields (mirrors NewTodo in the spec).
	status := string(api.NewTodoStatusTodo)
	if body.Status != nil {
		status = string(*body.Status)
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}

	now := time.Now().UTC()
	t := &todo{
		id:          uuid.New(),
		owner:       user,
		title:       body.Title,
		description: description,
		status:      status,
		createdAt:   now,
		updatedAt:   now,
	}

	s.mu.Lock()
	s.todos[t.id] = t
	s.mu.Unlock()

	// The 201 in the spec declares a Location response header — which is why
	// the generated response type has a Headers field. Set it, and the
	// generated Visit method writes it before the body. One spec line,
	// zero manual http.Header fiddling.
	location := "/todos/" + t.id.String()
	return api.CreateTodo201JSONResponse{
		Body:    t.toAPI(),
		Headers: api.CreateTodo201ResponseHeaders{Location: &location},
	}, nil
}

// findTodo returns the todo with the given id IF it belongs to the caller.
// "Not found" and "someone else's" produce the same nil so the API never
// leaks which ids exist.
func (s *Server) findTodo(id uuid.UUID, owner string) *todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.todos[id]
	if t == nil || t.owner != owner {
		return nil
	}
	return t
}

// GetTodo implements GET /todos/{id} (operationId: getTodo).
// The {id} path param arrives already typed as a UUID — the validator
// middleware guarantees it's well-formed, so no parse errors possible here.
func (s *Server) GetTodo(ctx context.Context, req api.GetTodoRequestObject) (api.GetTodoResponseObject, error) {
	t := s.findTodo(req.Id, userFromContext(ctx))
	if t == nil {
		return api.GetTodo404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: "todo not found"}}, nil
	}
	return api.GetTodo200JSONResponse(t.toAPI()), nil
}

// ReplaceTodo implements PUT /todos/{id} (operationId: replaceTodo).
//
// PUT semantics: the body is the COMPLETE new state (same NewTodo shape as
// POST), so omitted fields are reset to their defaults. Compare UpdateTodo
// below, where omitted fields keep their values.
func (s *Server) ReplaceTodo(ctx context.Context, req api.ReplaceTodoRequestObject) (api.ReplaceTodoResponseObject, error) {
	user := userFromContext(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.todos[req.Id]
	if t == nil || t.owner != user {
		return api.ReplaceTodo404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: "todo not found"}}, nil
	}

	// Reset everything from the body.
	t.title = req.Body.Title
	t.description = ""
	if req.Body.Description != nil {
		t.description = *req.Body.Description
	}
	t.status = string(api.NewTodoStatusTodo)
	if req.Body.Status != nil {
		t.status = string(*req.Body.Status)
	}
	t.updatedAt = time.Now().UTC()

	return api.ReplaceTodo200JSONResponse(t.toAPI()), nil
}

// UpdateTodo implements PATCH /todos/{id} (operationId: updateTodo).
//
// PATCH semantics: only the fields PRESENT in the body change. "Present in
// the JSON" surfaces in Go as a non-nil pointer — the whole reason optional
// schema properties generate pointer fields. (minProperties: 1 in the spec
// guarantees at least one field is present.)
func (s *Server) UpdateTodo(ctx context.Context, req api.UpdateTodoRequestObject) (api.UpdateTodoResponseObject, error) {
	user := userFromContext(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.todos[req.Id]
	if t == nil || t.owner != user {
		return api.UpdateTodo404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: "todo not found"}}, nil
	}

	if req.Body.Title != nil {
		t.title = *req.Body.Title
	}
	if req.Body.Description != nil {
		t.description = *req.Body.Description
	}
	if req.Body.Status != nil {
		t.status = string(*req.Body.Status)
	}
	t.updatedAt = time.Now().UTC()

	return api.UpdateTodo200JSONResponse(t.toAPI()), nil
}

// DeleteTodo implements DELETE /todos/{id} (operationId: deleteTodo).
func (s *Server) DeleteTodo(ctx context.Context, req api.DeleteTodoRequestObject) (api.DeleteTodoResponseObject, error) {
	user := userFromContext(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.todos[req.Id]
	if t == nil || t.owner != user {
		return api.DeleteTodo404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: "todo not found"}}, nil
	}
	delete(s.todos, req.Id)

	// 204 = success with an empty body. The spec declares this response with
	// no `content` block, which is why the generated type has no fields.
	return api.DeleteTodo204Response{}, nil
}
