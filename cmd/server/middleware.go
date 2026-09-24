package main

// Middleware: everything that happens to a request BEFORE it reaches a
// handler. The heavy lifting is done by existing libraries, not by us:
//
//   - request validation + security enforcement come from the oapi-codegen
//     ecosystem's nethttp-middleware (a thin wrapper over kin-openapi's
//     openapi3filter — the same validator engine the hand-rolled version
//     used to call directly);
//   - JWT verification is golang-jwt/jwt/v5.
//
// What remains hand-written is only what no library can know:
//
//   1. LoggingMiddleware     — one log line per request.
//   2. Server.AuthMiddleware — verifies OUR tokens with OUR secret and
//                              stamps the user into the request context.
//   3. enforceSecurity       — the kin-openapi AuthenticationFunc: turns
//                              the spec's DECLARED security into ENFORCED
//                              security.
//   4. NewRequestValidator   — thin wiring: hands the spec and the
//                              AuthenticationFunc to the library middleware.

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
	"github.com/golang-jwt/jwt/v5"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

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
// Authentication — two pieces, one job each
// ---------------------------------------------------------------------------
//
// The spec's `security` section says WHICH operations need auth; the JWT
// says WHO is calling. Enforcing that takes two pieces:
//
//	AuthMiddleware  (runs first, on every request) verifies the bearer
//	                token, if any, and stamps the user into the request
//	                context.
//	enforceSecurity (invoked by the validator, only for operations that
//	                carry security requirements) rejects requests whose
//	                context carries no user — the 401.
//
// Operations declared with `security: []` (like /signup and /login) never
// reach enforceSecurity: public by spec, public in code, no hardcoded path
// list to maintain. Adding or removing `security` in openapi.yaml changes
// real behavior.
//
// Why verify in a middleware instead of inside the AuthenticationFunc?
// The library serves the request object it was handed, so a request
// swapped inside the AuthenticationFunc never reaches the handler (see
// https://github.com/oapi-codegen/nethttp-middleware/issues/60). The user
// has to be in the context BEFORE validation starts.

// AuthMiddleware implements the `bearerJWT` scheme from
// components/securitySchemes: "Authorization: Bearer <token>", verified
// with the server's secret. On success the token's `sub` claim (the user's
// email) is stamped into the request context, where strict handlers read
// it via userFromContext.
//
// It deliberately does NOT reject requests: public operations must work
// with a missing — or even garbage — Authorization header. Whether a user
// is REQUIRED is the spec's call, enforced one step later by
// enforceSecurity.
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if sub, err := s.verifyBearer(strings.TrimPrefix(auth, "Bearer ")); err == nil {
				r = r.WithContext(withUser(r.Context(), sub))
			}
			// Invalid token: leave the context untouched. If the operation
			// requires auth, enforceSecurity answers with a 401; if it's
			// public, the request proceeds unauthenticated — exactly what
			// the spec's `security: []` promises.
		}
		next.ServeHTTP(w, r)
	})
}

// verifyBearer checks the token with the server's secret and returns its
// `sub` claim (the user's email).
func (s *Server) verifyBearer(tokenString string) (string, error) {
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
		return "", errors.New("invalid or expired token")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("token has no subject claim")
	}
	return sub, nil
}

// enforceSecurity is the kin-openapi "AuthenticationFunc" handed to the
// validation middleware. The validator calls it for every operation that
// carries security requirements, with one job: is the caller authenticated?
//
// The token itself was already verified by AuthMiddleware — so "who signed
// it, and is the signature valid?" reduces here to "did a valid bearer
// token reach this far?" Any error returned is wrapped by the validator in
// a SecurityRequirementsError, which the library middleware answers with
// the 401 the spec promises.
func enforceSecurity(ctx context.Context, _ *openapi3filter.AuthenticationInput) error {
	if userFromContext(ctx) == "" {
		return errors.New("missing or invalid Authorization header")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request validation middleware — makes the spec's constraints real
// ---------------------------------------------------------------------------

// NewRequestValidator builds the middleware that validates every request
// against the OpenAPI spec at runtime, using the oapi-codegen ecosystem's
// nethttp-middleware library (a thin wrapper over kin-openapi's
// openapi3filter). The library does everything the hand-rolled version
// used to do:
//
//   - matches requests to operations declared in the spec (its internal
//     router is kin-openapi's gorilla/mux router — the same one as before);
//   - enforces the `security` section via the enforceSecurity callback;
//   - checks every constraint in openapi.yaml (required, minLength, enum,
//     minimum/maximum, additionalProperties, format, ...);
//   - maps failures to the right status codes: 401 security failures,
//     400 validation failures, 405 wrong method, 404 unknown path.
//
// WHY VALIDATION EXISTS (the #1 oapi-codegen gotcha): the generated strict
// handlers decode JSON into typed structs, but encoding/json does not
// enforce schema constraints. {"title": ""} violates minLength: 1 in the
// spec, yet decodes into a Go string happily. This middleware closes the
// gap — and it validates against the spec EMBEDDED IN THE BINARY
// (api.GetSpec, enabled by `embedded-spec: true` in config.yaml), so the
// running server always matches the exact spec version it was compiled
// from.
//
// Our ErrorHandler just re-shapes the library's errors into the uniform
// components/schemas/Error body ({"message": "..."}) the spec promises.
func NewRequestValidator(spec *openapi3.T) (func(http.Handler) http.Handler, error) {
	// kin-openapi requires a validated spec before building a router.
	if err := spec.Validate(context.Background()); err != nil {
		return nil, err
	}

	return nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: enforceSecurity,
		},
		// The spec documents `servers` for Swagger UI. The library warns
		// that servers can trigger Host-header validation — but our "/"
		// server entry matches any host, so the warning doesn't apply.
		SilenceServersWarning: true,
		ErrorHandler: func(w http.ResponseWriter, message string, statusCode int) {
			writeError(w, statusCode, message)
		},
	}), nil
}
