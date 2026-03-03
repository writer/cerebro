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

---

# Okta Identity Lineage (Role-to-Resource Tracing)

## Goal
Bring Okta identity data to the same depth as AWS IAM / GCP IAM so we can trace the full lineage from users through roles and group memberships to application access, then correlate with actual usage via system logs — enabling stale-access detection, overprivilege analysis, and toxic-combination discovery across the identity layer.

## Current state
The Okta provider syncs five tables today: `okta_users`, `okta_groups`, `okta_applications`, `okta_policy_passwords`, `okta_system_logs`. Users have a flat `is_admin` boolean and groups have no membership data, so we cannot trace who has access to what or whether they are actually using it.

## Phase 1 — New sync tables

### 1a) Group memberships (`okta_group_memberships`)
- [x] New table: `okta_group_memberships` (group_id, user_id, user_login, user_email).
- [x] Fetch via `GET /api/v1/groups/{id}/users` for each group (paginated, 200/page).
- [x] Use concurrent workers (similar to MFA factor fan-out) bounded by rate limits.
- [x] This is the equivalent of IAM role membership in AWS / group bindings in GCP.

### 1b) App assignments (`okta_app_assignments`)
- [x] New table: `okta_app_assignments` (app_id, app_label, assignee_id, assignee_type [USER|GROUP], status, created).
- [x] Fetch user assignments via `GET /api/v1/apps/{id}/users` per app.
- [x] Fetch group assignments via `GET /api/v1/apps/{id}/groups` per app.
- [x] This tells us exactly which users and groups are entitled to which applications.

### 1c) Admin role assignments (`okta_admin_roles`)
- [x] New table: `okta_admin_roles` (user_id, user_login, role_type, role_label, status, created).
- [x] Fetch via `GET /api/v1/users/{id}/roles` for users in the existing admin set (already computed by `fetchAdminUserSet`).
- [x] Replaces the flat `is_admin` boolean with granular roles (Super Admin, Org Admin, App Admin, Read-Only Admin, Help Desk Admin, etc.).

## Phase 2 — Lineage graph edges

### 2a) Relationship extraction
- [x] Add Okta relationship types to `RelationshipExtractor`:
  - `okta_user` → `okta_group` (via `okta_group_memberships`)
  - `okta_group` → `okta_application` (via `okta_app_assignments` where assignee_type=GROUP)
  - `okta_user` → `okta_application` (via `okta_app_assignments` where assignee_type=USER, direct assignment)
  - `okta_user` → `okta_admin_role` (via `okta_admin_roles`)
- [x] Wire these into the security graph so they participate in attack-path and toxic-combo analysis.

### 2b) Activity correlation (system logs as the usage layer)
- [x] Enrich system log parsing to extract structured `(actor_id, target_app_id, event_type)` tuples from `user.authentication.sso`, `app.oauth2.token.grant`, and similar event types.
- [x] Build a materialised view or query that joins `okta_app_assignments` against `okta_system_logs` to identify:
  - Assigned but never-used apps (stale entitlements).
  - Apps accessed by users who are NOT assigned (anomaly / shadow access via direct URL).
  - Last-used timestamps per user-app pair.

## Phase 3 — Policies

### 3a) Stale access policies
- [x] `identity-okta-stale-app-assignment-30d` — user assigned to app but no SSO event in 30 days.
- [x] `identity-okta-stale-app-assignment-90d` — same, 90-day threshold.
- [x] `identity-okta-stale-group-membership-90d` — user in group but no login activity in 90 days.

### 3b) Overprivilege policies
- [x] `identity-okta-superadmin-count` — flag if more than N users hold Super Admin.
- [x] `identity-okta-admin-no-mfa` — admin role holders without MFA enrolled (already partially covered, make granular).
- [x] `identity-okta-group-grants-admin-app` — groups that grant access to admin-level applications.

### 3c) Toxic combination policies
- [x] `identity-okta-admin-plus-app-owner` — user is both Okta admin and owner of a high-privilege application.
- [x] `identity-okta-external-user-internal-app` — external/contractor user assigned to internal-only applications.

## Phase 4 — Fix existing query policy errors
- [x] Replace `NOW()` with `CURRENT_TIMESTAMP()` in 7 identity-okta policies that fail on Snowflake.
- [x] Replace `SIMILAR TO` with `RLIKE` in 2 identity-okta policies that fail on Snowflake.

## Rate limit considerations
- Group membership and app assignment endpoints are per-group / per-app, not bulk. With 200 groups and 116 apps that's ~316 paginated API calls. Okta's default rate limit is 600 req/min for most endpoints. The existing rate-limit backoff code handles this, but we should:
  - [x] Parallelise with a bounded worker pool (10 concurrent, matching the MFA pattern).
  - [x] Log progress every 50 groups/apps so operators see forward motion on large tenants.

## Lineage chain (end state)
```
User ──membership──▶ Group ──assignment──▶ Application
  │                                            ▲
  ├──direct-assignment─────────────────────────┘
  │
  └──admin-role──▶ Admin Role (Super, Org, App, …)

System Logs: actor_id ──event──▶ target_app_id  (actual usage overlay)
```
