# learn-openapi

Learning OpenAPI with Go, spec-first: `api/openapi.yaml` is the single source
of truth, [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) turns
it into typed server glue, and the server is plain `gorilla/mux` + stdlib
(net/http) — no web framework.

## Layout

| Path | What it is |
| --- | --- |
| `api/openapi.yaml` | The API contract — heavily commented, start here |
| `api/api.gen.go` | Generated types, strict interface, route glue (DO NOT EDIT) |
| `config.yaml` | oapi-codegen config (gorilla-server, strict-server, embedded spec) |
| `cmd/server/main.go` | Wiring: gorilla/mux router, middleware chain, docs endpoints |
| `cmd/server/server.go` | Handlers — one method per operation in the spec |
| `cmd/server/middleware.go` | Logging + request validation + JWT auth (spec-driven) |

## Workflow

```sh
# after editing api/openapi.yaml, regenerate:
oapi-codegen -config config.yaml api/openapi.yaml

# run (JWT_SECRET optional, dev fallback if unset):
go run ./cmd/server
```

Then open http://localhost:8080/docs (Swagger UI) or fetch the raw spec at
`/openapi.json`.

## What the example covers

- Full CRUD: `GET/POST /todos`, `GET/PUT/PATCH/DELETE /todos/{id}` (PUT =
  full replace, PATCH = partial update), plus `POST /signup` and `POST /login`
- Path / query / header parameters, reusable `$ref` components
  (schemas, parameters, responses, securitySchemes)
- Validation keywords enforced at runtime (`required`, `minLength`,
  `maxLength`, `enum`, `minimum`/`maximum`, `minProperties`,
  `additionalProperties`, `format`) via a kin-openapi middleware built on the
  embedded spec
- JWT security: `bearerJWT` scheme enforced per-operation straight from the
  spec's `security` section (public endpoints opt out with `security: []`)
- Pagination (`limit`/`offset`), a uniform `Error` body, response headers
  (`Location` on 201), and 204-no-content on delete
- Swagger UI served by the Go binary itself

## Try it

```sh
curl -X POST localhost:8080/signup -d '{"email":"a@a.com","password":"password1"}'
TOKEN=$(curl -s -X POST localhost:8080/login -d '{"email":"a@a.com","password":"password1"}' | jq -r .token)
curl -X POST localhost:8080/todos -H "Authorization: Bearer $TOKEN" -d '{"title":"learn"}'
curl localhost:8080/todos -H "Authorization: Bearer $TOKEN"
```
