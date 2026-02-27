# Repository Hardening TODO (2026-02-27)

## Goal
Close all high-impact gaps identified in the deep repository review across API security, container hardening, CI security scanning, metrics safety, maintainability, and coverage.

## 1) API security and error handling
- [x] Stop returning raw internal errors to API clients for 5xx paths.
- [x] Add structured server-side logging for internal API errors.
- [x] Add HTTP security headers middleware (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`).
- [x] Wire CORS middleware in server setup with explicit config-driven allowed origins.
- [x] Reorder middleware so rate limiting executes before auth/RBAC enforcement.

## 2) Runtime/container hardening
- [x] Add non-root runtime user to `Dockerfile`.
- [x] Add non-root runtime user to `Dockerfile.runtime`.
- [x] Set ECS container `user` in `infra/aws/compute.py`.
- [x] Set ECS container `readonlyRootFilesystem=true` in `infra/aws/compute.py`.

## 3) CI/dependency security scanning
- [x] Add `gosec` scan job to `.github/workflows/ci.yml`.
- [x] Add `govulncheck` scan job to `.github/workflows/ci.yml`.
- [x] Add container image scan (`trivy`) to `.github/workflows/ci.yml`.
- [x] Add Python dependency updates for `infra/` to `.github/dependabot.yml`.

## 4) Metrics reliability
- [x] Reduce API metrics label cardinality by using route patterns/templates instead of raw URL paths.

## 5) Maintainability follow-through
- [x] Decompose `internal/api/server.go` by extracting common error + response helpers into dedicated files.
- [x] Remove duplicate config loading path by making `internal/config` consume shared app-level env parsing logic.

## 6) Coverage follow-through
- [x] Add targeted tests for low-coverage high-risk areas touched by this hardening pass.

## 7) Validation gate
- [x] Run `go test ./...`.
- [x] Run `golangci-lint run`.
- [x] Run `go vet ./...`.
- [x] Run `go run ./cmd/cerebro policy validate`.
