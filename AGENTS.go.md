# Go Rules

Apply these rules when Go files, Go modules, or Go services are present.

## Dependency Guardrails

* **Prefer the Go standard library:** Add dependencies only when they materially reduce risk or complexity.
* **Approved common Go packages:** `golang.org/x/crypto`, `golang.org/x/sync`, `golang.org/x/net`, `github.com/go-chi/chi/v5`, `github.com/jackc/pgx/v5`, `github.com/google/uuid`, `go.uber.org/zap`, and `github.com/rs/zerolog` are acceptable when needed.
* **JWT handling:** Do not use abandoned JWT packages. Prefer `github.com/golang-jwt/jwt/v5` only after validating algorithm allowlists, issuer, audience, expiry, and key source.
* **Keep `go.mod` clean:** Do not add unused modules. Run `go mod tidy` after dependency changes.

## Cryptography

* **Randomness:** Use `crypto/rand` for tokens, identifiers, nonces, salts, passwords, and keys. Never use `math/rand` or `math/rand/v2` for security-sensitive values.
* **Password storage:** Use `golang.org/x/crypto/argon2` (Argon2id) or `golang.org/x/crypto/bcrypt` with reviewed parameters.
* **Constant-time comparison:** Compare secrets, MACs, and tokens with `crypto/subtle.ConstantTimeCompare` or `hmac.Equal`, not `==` or `bytes.Equal`.

## Implementation Rules

* **Explicit errors:** Never ignore errors. Do not use `_ =` to discard an error. Return or wrap errors with context using `fmt.Errorf("context: %w", err)`.
* **No production panics:** Do not use `panic()` in production paths. Return errors up the stack and fail securely.
* **Strong typing:** Define explicit structs and interfaces for payloads, configs, and internal data. Avoid `interface{}`, `any`, and `map[string]any` unless interoperating with a generic library boundary and immediately validating into a typed structure.
* **Context handling:** Propagate `context.Context`. Always call `defer cancel()` after creating a context with timeout or cancellation.
* **Concurrency safety:** Protect shared state with `sync.Mutex`, `sync.RWMutex`, channels, or atomic operations. Design goroutines with cancellation paths to avoid leaks.
* **SQL safety:** Use parameterized queries through `database/sql`, `pgx`, or another approved driver. String concatenation for SQL is forbidden.
* **Structured logging:** Use structured JSON logging with `log/slog`, `zap`, or `zerolog`. Logs must not contain secrets, tokens, private data, or raw untrusted payloads.
* **HTTP safety:** Set timeouts on HTTP clients and servers. Close response bodies with `defer resp.Body.Close()` after checking that `resp` is non-nil.
* **Tests:** Add focused tests for security-sensitive logic, input validation, authorization decisions, parsing, error paths, and concurrency behavior.

## Go Verification

Before presenting, committing, or opening a PR for Go changes:

1. Run `go fmt ./...`.
2. Run `go vet ./...`.
3. Run the relevant package tests, preferably `go test ./...`.
4. Run `go mod tidy` when dependencies change.
5. Run `govulncheck ./...` when it is installed or configured in the repository. If it is not available, say so rather than skipping it silently.
