package main

// Middleware: everything that happens to a request BEFORE it reaches a
// handler — logging, plus the request validator (which also enforces the
// spec's `security` section via the AuthenticationFunc callback).

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/golang-jwt/jwt/v5"

	"github.com/zukigit/learn-openapi/api"
)

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

// ctxUser is the context key under which the authenticated user's email
// (the JWT's `sub` claim) is stored. An unexported custom type is the
// collision-proof idiom for context keys.
type ctxKey int

const ctxUser ctxKey = iota

// withUser returns a context carrying the authenticated user.
func withUser(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, ctxUser, email)
}

// userFromContext pulls the authenticated user back out. Empty string means
// the request was never authenticated (shouldn't happen behind the middleware).
func userFromContext(ctx context.Context) string {
	user, _ := ctx.Value(ctxUser).(string)
	return user
}

// writeError emits the API's uniform error body — exactly the
// components/schemas/Error shape from the spec: {"message": "..."}.
// Every non-2xx response in this service goes through here or through a
// generated *JSONResponse type; the wire format never drifts from the spec.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.Error{Message: msg})
}

// ---------------------------------------------------------------------------
// Logging middleware
// ---------------------------------------------------------------------------

// statusRecorder remembers the status code a handler wrote, so the logging
// middleware can report it after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware logs one line per request: method, path, status, duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.RequestURI(), rec.status, time.Since(start))
	})
}

// ---------------------------------------------------------------------------
// Authentication — ENFORCES the spec's `security` section
// ---------------------------------------------------------------------------

// authError marks failures coming from the authentication callback so the
// validation middleware can answer them with 401 instead of 400.
type authError struct{ message string }

func (e *authError) Error() string { return e.message }

// Authenticate is the kin-openapi "AuthenticationFunc": it turns the spec's
// DECLARED security into ENFORCED security.
//
// Here is how the spec drives it: for every operation that carries security
// requirements, the validator calls this function; operations declared with
// `security: []` (like /signup and /login) are skipped entirely — public by
// spec, public in code, no hardcoded path list to maintain. Adding or
// removing `security` in openapi.yaml changes real behavior here.
//
// It implements the `bearerJWT` scheme from components/securitySchemes:
// "Authorization: Bearer <token>", token verified with the server's secret.
// On success it stamps the token's `sub` claim (the user's email) into the
// request context, where strict handlers read it via userFromContext.
func (s *Server) Authenticate(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	r := input.RequestValidationInput.Request

	// The spec says type: http / scheme: bearer — i.e. this exact header
	// format: "Authorization: Bearer <token>".
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return &authError{"missing or invalid Authorization header"}
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		// Only accept OUR signing method. Deriving the algorithm from the
		// token header instead would let attackers forge tokens
		// ("alg: none" / algorithm-confusion attacks).
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return &authError{"invalid or expired token"}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return &authError{"token has no subject claim"}
	}

	// Authenticated: carry the user onward for the handlers. Swapping the
	// request inside the validation input propagates the context to whoever
	// serves it next.
	input.RequestValidationInput.Request = r.WithContext(withUser(r.Context(), sub))
	return nil
}

// ---------------------------------------------------------------------------
// Request validation middleware — makes the spec's constraints real
// ---------------------------------------------------------------------------

// NewRequestValidator builds the middleware that validates every request
// against the OpenAPI spec at runtime.
//
// WHY THIS EXISTS (the #1 oapi-codegen gotcha): the generated strict
// handlers decode JSON into typed structs, but encoding/json does not
// enforce schema constraints. {"title": ""} violates minLength: 1 in the
// spec, yet decodes into a Go string happily. This middleware closes the
// gap: every constraint in openapi.yaml (required, minLength, enum,
// minimum/maximum, additionalProperties, format, ...) is checked here,
// and violations get the 400 response the spec promises.
//
// It also runs the security checks described above, and it validates
// against the spec EMBEDDED IN THE BINARY (api.GetSpec, enabled by
// `embedded-spec: true` in config.yaml) — so the running server always
// matches the exact spec version it was compiled from.
func NewRequestValidator(spec *openapi3.T, auth openapi3filter.AuthenticationFunc) (func(http.Handler) http.Handler, error) {
	// kin-openapi requires a validated spec before building a router.
	if err := spec.Validate(context.Background()); err != nil {
		return nil, err
	}

	// kin-openapi's own gorilla/mux router: matches incoming requests to
	// operations declared in the spec. (Yes — gorilla again, the same
	// library the server itself routes with.)
	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Match the request against an operation in the spec.
			route, pathParams, err := router.FindRoute(r)
			if err != nil {
				// The outer gorilla/mux router only dispatches real API
				// routes here, so a miss means "right path, wrong method".
				writeError(w, http.StatusMethodNotAllowed, err.Error())
				return
			}

			// 2. Validate: security (via the auth callback), then path/
			//    query/header params, then the request body.
			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParams,
				Route:      route,
				Options: &openapi3filter.Options{
					AuthenticationFunc: auth,
				},
			}
			if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
				// Security failures are 401s, everything else is a 400.
				// errors.As digs the authError out of the validator's
				// wrapping (SecurityRequirementsError unwraps to []error).
				var aerr *authError
				if errors.As(err, &aerr) {
					writeError(w, http.StatusUnauthorized, aerr.message)
				} else {
					writeError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			// 3. Pass the request on. ValidateRequest restores the body
			//    after reading it, and the auth callback may have swapped
			//    in a new request carrying the user's context — so forward
			//    the validator's request, not our earlier copy.
			next.ServeHTTP(w, input.Request)
		})
	}, nil
}
