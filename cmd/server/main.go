package main

// Wiring: builds the gorilla/mux router, the middleware chain, the generated
// API routes, and the docs endpoints — then starts the server.

import (
	_ "embed"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/zukigit/learn-openapi/api"
)

// The Swagger UI page served at /docs: a tiny HTML shell that loads
// swagger-ui from a CDN and points it at /openapi.json. No npm needed.
//
//go:embed static/docs.html
var docsHTML []byte

const addr = ":8080"

func main() {
	server := NewServer()

	// The spec, embedded in the binary by codegen (`embedded-spec: true`
	// in config.yaml). The validator uses this same copy — so the running
	// server always matches the spec it was compiled from.
	spec, err := api.GetSpec()
	if err != nil {
		log.Fatalf("loading embedded spec: %v", err)
	}
	validator, err := NewRequestValidator(spec)
	if err != nil {
		log.Fatalf("building request validator: %v", err)
	}

	// StrictHandler adapts our typed methods (Signup, ListTodos, ...) into
	// plain http.Handler endpoints that decode requests / encode responses.
	strictHandler := api.NewStrictHandler(server, nil)

	// The server-wide gorilla/mux router.
	r := mux.NewRouter()

	// The API routes live on a SUBROUTER so the middleware chain applies
	// only to them — not to /docs or /openapi.json. Middleware order =
	// request flow order, each wrapping the next:
	//
	//   logging -> auth (JWT -> context) -> spec validation (security +
	//   params + body) -> strict handler
	apiRouter := r.NewRoute().Subrouter()
	apiRouter.Use(LoggingMiddleware)
	apiRouter.Use(server.AuthMiddleware)
	apiRouter.Use(validator)

	// Generated glue from oapi-codegen (config.yaml: gorilla-server: true):
	// registers every operation from the spec — GET /todos, POST /todos,
	// GET /todos/{id}, ... — including the {id} path-variable extraction.
	api.HandlerFromMux(strictHandler, apiRouter)

	// The raw spec. GetSpecJSON returns the embedded bytes untouched.
	r.Path("/openapi.json").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		data, err := api.GetSpecJSON()
		if err != nil {
			http.Error(w, "spec unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	// Interactive docs.
	r.Path("/docs").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(docsHTML)
	})

	// Default: send browsers to the docs.
	r.Path("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/docs", http.StatusFound)
	})

	log.Printf("listening on http://localhost%s (docs at /docs, spec at /openapi.json)", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
