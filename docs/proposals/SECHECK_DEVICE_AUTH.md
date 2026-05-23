# SeCheck Device Auth and Telemetry Integration: Modern Enterprise Design

## Status

**Proposal**. Replaces the closed [`feat/secheck-device-auth` branch (PR #409)](https://github.com/writer/cerebro/pull/409). PR #409 was structured against the pre-bootstrap `internal/api/`, `internal/runtime/`, and `internal/providers/` packages, all of which have been removed from `main`. This proposal targets the current bootstrap service, NATS JetStream append log, and Postgres state store.

## Why this exists

The Writer Security Checkup ("SeCheck") agent is a Go binary deployed via MDM (Kandji on macOS, Intune on Windows) to engineer workstations. The agent talks to Cerebro to:

1. Pull a device-keyed enriched findings stream (CVE x installed package x KEV x EPSS).
2. Locally validate whether each finding still affects this exact box.
3. Push remediation, verification, and posture telemetry back.

PR #409 demonstrated the protocol shape (enroll, token, telemetry ingest) but had seven architectural gaps that block production deployment. This document re-architects the integration against the current `bootstrap` service, fixes those gaps, and documents the boundary it adds.

## Scope discipline

This proposal explicitly crosses one [non-goal boundary](../NON_GOALS.md): the bootstrap service does not currently accept third-party push traffic. SeCheck agents push telemetry from outside the cluster (engineer laptops on residential ISPs and coffee-shop Wi-Fi). That is a new affordance.

This document satisfies the "What would change this" criterion in `NON_GOALS.md` by:

- Citing the relevant entry (Source CDK: "Sources are the only path to the outside world").
- Modelling SeCheck push as a **distinct platform capability**, not a Source: it is *first-party* device telemetry from a fleet Cerebro authenticates and authorizes per-device, not a third-party API integration. Sources remain the only path for *third-party* outside-world traffic.
- Updating `docs/NON_GOALS.md` in the same change to record the new boundary entry: "Agent push surface (device-keyed write)".

## Goals

- A modern, enterprise-grade auth and telemetry surface for the SeCheck agent that compares favorably with how Google/Uber/Facebook secure first-party fleet agents.
- Roaming-workforce-safe: agents on residential ISPs, hotel Wi-Fi, mobile hotspots, and coffee shops should authenticate, refresh, and report without operator intervention.
- AWS-native: signing keys live in AWS KMS or Secrets Manager; the request path can sit behind ALB + AWS WAF + VPC endpoints; observability flows to CloudWatch and X-Ray via OpenTelemetry.
- No silent fallbacks. Every dependency (Postgres state store, signing-key source, append-log) either runs configured or the route fails closed.
- One implementation path per capability. The agent-push surface uses the same auth pipeline (`bootstrap/auth.go`) as everything else, the same audit emitter (`emitAccessAuditEvent`), the same scope mechanism (`authorizeHTTPRequestScope`), and the same Postgres state store.

## Non-goals (in this proposal)

- A Source CDK plugin for SeCheck. SeCheck pushes; Sources pull. Wrong shape.
- A new long-term store. State persists in the existing `internal/statestore/postgres` driver.
- A new graph projection. SeCheck observations are findings/findingevidence rows, projected through the existing append-log fan-in.
- Agent-side feature work (validation, classifier, MCP tools). That all lives in `WriterInternal/security`.

## PR #409 findings: gap matrix

| # | PR #409 gap | Current proposal |
|---|---|---|
| 1 | JSON-file-backed device store; single-writer; no replay-safety | Postgres-backed via `internal/statestore/postgres/deviceauth.go`; multi-replica safe; tx-bounded refresh-token rotation |
| 2 | HS256 signing key from a single env var; no rotation, no JWKS, no `kid` | EdDSA (Ed25519) signing keys with `kid` header; key material delivered via AWS KMS (sign API) or Secrets Manager + multi-key set; `/.well-known/device-jwks.json` published for verifiers |
| 3 | No rate limit on `/devices/enroll`; bootstrap-token brute-force exposure | Per-IP token bucket on enroll (1 req / 5s, burst 3) and per-device on `/devices/token` (1 req / 1s, burst 5); state in Postgres so multi-replica is consistent; AWS WAF rate-based rule layered in front |
| 4 | Admin endpoints not visibly RBAC-gated | New scopes `platform.devices.enroll`, `platform.devices.token`, `platform.devices.bootstrap_tokens.write`, `platform.devices.read`, `security.devices.findings.read`, `platform.telemetry.ingest`; mapped through the existing `authorizeHTTPRequestScope` switch |
| 5 | No audit-log writes on auth events | All enroll, token-issue, refresh-rotate, family-revoke, bootstrap-token-create events flow through the existing `emitAccessAuditEvent` plus a new `cerebro.devices.lifecycle` event emitter for non-HTTP transitions (TTL expiry, replay revoke) |
| 6 | Hardware UUID is the binding; spoofable on rooted devices | Documented as v1; v2 adds Apple App Attest (macOS) and Windows TPM-backed key attestation; agent-side bound-key DPoP-style proof on token requests in v2 |
| 7 | No idempotency keys on telemetry ingest | Required `Idempotency-Key` header, deduped via `device_telemetry_idempotency` Postgres table with 24h retention; replays return 200 with cached response |

## Architecture

```
+------------------------------------------------------------------+
|                          AWS Edge                                |
|                                                                  |
|   Route 53 -> AWS WAF (rate-based + geo + bot rules)             |
|        -> ALB (TLS 1.3, mTLS optional for service callers)       |
|        -> Cerebro bootstrap (private subnet, 3+ replicas)        |
|                                                                  |
|   Signing keys: AWS KMS asymm. CMK (Ed25519) - sign() API only;  |
|                 private key never leaves KMS                     |
|   Persistent state: Aurora Postgres (Multi-AZ)                   |
|   Append log: NATS JetStream (existing)                          |
+------------------------------+-----------------------------------+
                               |
                               | TLS 1.3 + JWT (Ed25519, kid)
                               | W3C traceparent end-to-end
                               | Idempotency-Key on writes
                               |
+------------------------------+-----------------------------------+
|                       Cerebro bootstrap                          |
|                                                                  |
|  +-------------------+   +-------------------+                   |
|  | bootstrap/auth.go |-->| internal/         |                   |
|  | (extended)        |   |  deviceauth/      |                   |
|  +-------------------+   |   - jwt(EdDSA)    |                   |
|        |                 |   - jwks          |                   |
|        |                 |   - rotation      |                   |
|        v                 |   - postgres      |                   |
|  +-------------------+   +-------------------+                   |
|  | route mounts      |                                           |
|  |                   |                                           |
|  |  /platform/devices/enroll          [public, bootstrap-tok]    |
|  |  /platform/devices/token           [public, refresh|bootstrap]|
|  |  /platform/devices/{id}            [device|admin]             |
|  |  /platform/devices/{id}:revoke     [admin]                    |
|  |  /platform/devices/bootstrap-tokens [admin]                   |
|  |  /platform/telemetry/ingest        [device, idempotent]       |
|  |  /security/devices/{id}/findings   [device|user]              |
|  |  /.well-known/device-jwks.json     [public]                   |
|  +-------------------+                                           |
|        |                                                         |
|        v                                                         |
|  +-------------------+   +-------------------+                   |
|  | append log fan-in |-->| findings/         |                   |
|  | (existing)        |   | findingevidence/  |                   |
|  +-------------------+   | workflowevents/   |                   |
|                          +-------------------+                   |
+------------------------------------------------------------------+
                               |
                               | observability
                               v
                    OpenTelemetry -> CloudWatch + X-Ray
                    Access audit -> existing cerebro.api.access events
                    Lifecycle audit -> new cerebro.devices.lifecycle events
```

## Wire protocol

### Enroll: `POST /platform/devices/enroll`

Public. Authenticated by single-use bootstrap token only.

**Request**

```http
POST /platform/devices/enroll HTTP/1.1
Host: cerebro.writer.com
Content-Type: application/json
Idempotency-Key: <uuid>
traceparent: 00-<trace>-<span>-01
User-Agent: secheck/1.4.2 (darwin/arm64)
X-Cerebro-Bootstrap-Token: <single-use, MDM-delivered>

{
  "hardware_uuid": "<UUID, hex digest, lowercase>",
  "serial_number": "<MDM-known serial>",
  "hostname":      "<short>",
  "os_type":       "darwin|windows",
  "os_version":    "14.5.0",
  "agent_version": "1.4.2",
  "tenant_id":     "writer"
}
```

**Response (201)**

```json
{
  "device_id":          "<server-generated uuid>",
  "access_token":       "<EdDSA JWT, kid set, 10 min ttl>",
  "refresh_token":      "<opaque 256-bit, hashed at rest>",
  "refresh_expires_at": "<RFC3339>",
  "scopes": [
    "platform.devices.read",
    "platform.telemetry.ingest",
    "security.devices.findings.read"
  ]
}
```

**Server-side**:

1. Body capped at 4 KiB via `http.MaxBytesReader`.
2. Per-IP rate limit: 1 req / 5 s, burst 3.
3. Bootstrap-token consume is one Postgres transaction: row lock the bootstrap-token, verify hash, verify hardware-UUID binding, verify expiry, mark consumed, insert device row, insert refresh-token row, commit. Replay returns 409.
4. Issue Ed25519 access token via `internal/deviceauth.JWTIssuer` (key signed by AWS KMS in production, in-process for tests).
5. Emit access-audit event + new `cerebro.devices.lifecycle` event with `{"action":"enroll","device_id":...,"tenant_id":...,"client_ip":...}`.

### Token refresh: `POST /platform/devices/token`

Public. Authenticated by **either** bootstrap-token (re-enroll) or refresh-token (normal refresh).

**Request**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "<opaque>",
  "device_id": "<uuid>"
}
```

**Response (200)**

Same shape as enroll. The previous refresh token is **single-use** -- consuming it issues a new pair (`generation += 1`, same `family_id`). If a stale generation is presented, the entire family is revoked (`replay-detected`) and the device must re-enroll. This matches RFC 6819 §5.2.2.3 token-replay handling.

**Server-side**:

1. Per-device rate limit: 1 req / 1 s, burst 5.
2. The rotation transaction:
   - Lock the refresh-token row.
   - If `consumed=true`, set `family_revoked=true` for all rows with the same `family_id`, return 401 `replay_detected`.
   - If expired, return 401 `expired`.
   - If device is not `active`, return 401 `device_inactive`.
   - Insert new refresh-token row with `generation = consumed.generation + 1`, mark consumed.
   - Commit.
3. Issue new access token (Ed25519, 10 min TTL, `kid` from current signing key).
4. Audit event.

### Telemetry ingest: `POST /platform/telemetry/ingest`

Authenticated by device JWT. Required `Idempotency-Key`. Body cap 256 KiB.

```json
{
  "device_id":     "<uuid>",
  "agent_version": "1.4.2",
  "occurred_at":   "<RFC3339>",
  "events": [
    {
      "kind":      "verify|remediate|posture|heartbeat",
      "event_id":  "<agent-side uuid>",
      "finding_id":"<cerebro finding id>",
      ...
    }
  ]
}
```

**Server-side**:

1. JWT verified, `device_id` claim must match body `device_id`.
2. Idempotency key checked against `device_telemetry_idempotency`. Cache hit returns the cached 200 body (24h retention). Different body for same key returns 409 `idempotency_conflict`.
3. Events appended to JetStream subject `cerebro.devices.telemetry`.
4. Projection writes `findings`, `findingevidence`, and `workflowevents` rows through existing projectors.
5. 200 response cached against the idempotency key.

### Findings feed: `GET /security/devices/{device_id}/findings`

Authenticated by device JWT (must match path `device_id`) **or** a user with `security.devices.findings.read`.

Query params: `since=<RFC3339>`, `severity=`, `limit=` (max 500). Results joined from `internal/findings` and `internal/vulndb` (the existing KEV/EPSS/NVD enrichment).

### JWKS: `GET /.well-known/device-jwks.json`

Public. Returns active + retiring public keys with `kid`, alg `EdDSA`, kty `OKP`, crv `Ed25519`. Cached 5 min, served from Postgres-backed key set.

## Security design

### Token format and rotation

- **Algorithm**: EdDSA (Ed25519). Smaller signatures than RS256, faster verify, modern.
- **kid header**: every token carries the issuing key id. Rotation is a JWKS publish + a `current_kid` flip in config. Old keys remain in the JWKS for the access-token TTL (10 min) plus skew.
- **Signing path**: production uses AWS KMS asymmetric sign-only CMKs. The private key never leaves KMS. CI / dev uses an in-process Ed25519 signer with secrets from `CEREBRO_DEVICE_AUTH_DEV_SIGNING_KEY` (refused if `APP_ENV=production`).
- **TTLs**: access 10 min, refresh 30 days sliding (renewed on every successful refresh). 30 days fits a roaming engineer reasonably; if the agent goes offline >30 days the user re-auths via the AI button (re-enroll flow trips bootstrap-token issuance through MDM).
- **Refresh rotation**: single-use, family-scoped, replay-revoking. Identical to PR #409's design but in a Postgres transaction rather than a JSON-file lock.

### Secrets and key management

- Bootstrap-token plaintext is never stored. Only a `sha256` hash is in `device_bootstrap_tokens.token_hash`.
- Refresh-token plaintext is never stored. Only a `sha256` hash is in `device_refresh_tokens.token_hash`.
- AWS KMS holds Ed25519 signing keys per-environment. Cerebro IAM role gets `kms:Sign`, never `kms:Decrypt` on these CMKs.
- Optional: envelope encryption of admin-readable token metadata via AWS KMS GenerateDataKey. Out of scope for v1.

### Network layer

- ALB enforces TLS 1.3 with modern cipher set (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256).
- AWS WAF rule set: rate-based per-IP, AWS-managed core, AWS-managed known-bad-inputs, custom rule blocking `/platform/devices/enroll` from non-allowlisted geographies (Phase 2 -- requires policy decision on engineers traveling internationally).
- Optional client mTLS for service-to-service callers (admin tooling, CI). Device agents use bearer JWTs; the cert pinning happens at the OS-managed CA bundle level.

### Roaming workforce considerations

- Refresh TTL is 30 days sliding; the agent stays signed in across multi-day disconnects.
- IP changes are expected and not a denial signal. We log `client_ip`, `country`, and `asn` (via WAF) on each refresh into the audit stream so security can post-hoc review anomalies, but do not block on them in v1.
- Phase 2 introduces device-bound key DPoP proofs (the agent generates an Ed25519 keypair at enroll, the public key is stored on the device record, every refresh request is signed with it). This pins refresh tokens to a hardware-bound private key that never leaves the OS keychain. That eliminates the "stolen refresh token" class of attack regardless of geography.

### Observability

- W3C `traceparent` propagated on every request.
- OpenTelemetry traces shipped to AWS X-Ray via the OTel collector sidecar already in the bootstrap deploy.
- Existing `cerebro.api.access` audit events cover HTTP-level access.
- New `cerebro.devices.lifecycle` events cover non-HTTP transitions: TTL expiries, family revokes, scheduled maintenance revokes.
- Prometheus counters: `cerebro_devices_enroll_total`, `cerebro_devices_token_total{outcome}`, `cerebro_devices_telemetry_events_total`, `cerebro_devices_refresh_replays_total` (alerts > 0).

### Failure modes

- KMS unavailable: enrollment, refresh, and any new token issuance return 503 `signing_unavailable`. Existing access tokens continue to verify against the JWKS cached locally. SLO: KMS read latency p99 < 50 ms; falls back to the in-memory JWKS cache for verification on KMS read failure.
- Postgres unavailable: every device-auth route returns 503. Fail-closed by default per `docs/NON_GOALS.md` ("Routes that need a configured store fail closed").
- NATS unavailable: telemetry ingest returns 503. Idempotency-key lookup still works against Postgres; the agent retries with the same key.

## Permission model

The new scopes slot cleanly into the namespace split documented in `docs/PLATFORM_TRANSITION_ARCHITECTURE.md`:

| Scope | Intent | Required for |
|---|---|---|
| `platform.devices.enroll` | Issue device identity from a bootstrap token | (public route, scope checked on internal callers) |
| `platform.devices.token` | Refresh device tokens | (public route, scope checked on internal callers) |
| `platform.devices.read` | Read own device record | `GET /platform/devices/{id}` (device or admin) |
| `platform.devices.bootstrap_tokens.write` | Mint MDM bootstrap tokens | `POST /platform/devices/bootstrap-tokens` (admin) |
| `platform.devices.revoke` | Revoke a device | `POST /platform/devices/{id}:revoke` (admin) |
| `platform.telemetry.ingest` | Write device telemetry | `POST /platform/telemetry/ingest` (device) |
| `security.devices.findings.read` | Read per-device findings | `GET /security/devices/{id}/findings` (device or user) |

Device JWTs carry only the scopes appropriate for an agent (`platform.devices.read`, `platform.telemetry.ingest`, `security.devices.findings.read`). Admin scopes never appear on a device JWT.

## Persistence schema

Tables are owned by `internal/statestore/postgres/deviceauth.go`, created via the existing `ensureStatements` lazy-init pattern.

```sql
CREATE TABLE IF NOT EXISTS device_records (
  device_id        TEXT PRIMARY KEY,
  hardware_uuid    TEXT NOT NULL,
  serial_number    TEXT,
  hostname         TEXT,
  tenant_id        TEXT NOT NULL,
  os_type          TEXT NOT NULL,
  os_version       TEXT,
  agent_version    TEXT,
  status           TEXT NOT NULL DEFAULT 'active',
  enrolled_at      TIMESTAMPTZ NOT NULL,
  last_seen_at     TIMESTAMPTZ NOT NULL,
  revoked_at       TIMESTAMPTZ,
  metadata         JSONB,
  UNIQUE (tenant_id, hardware_uuid)
);

CREATE TABLE IF NOT EXISTS device_bootstrap_tokens (
  token_id         TEXT PRIMARY KEY,
  token_hash       BYTEA NOT NULL,
  hardware_uuid    TEXT NOT NULL,
  tenant_id        TEXT NOT NULL,
  scopes           TEXT[] NOT NULL DEFAULT '{}',
  expires_at       TIMESTAMPTZ NOT NULL,
  consumed_at      TIMESTAMPTZ,
  consumed_by      TEXT,
  created_at       TIMESTAMPTZ NOT NULL,
  UNIQUE (token_hash)
);

CREATE TABLE IF NOT EXISTS device_refresh_tokens (
  token_hash       BYTEA PRIMARY KEY,
  device_id        TEXT NOT NULL REFERENCES device_records(device_id) ON DELETE CASCADE,
  family_id        TEXT NOT NULL,
  generation       INTEGER NOT NULL,
  scopes           TEXT[] NOT NULL DEFAULT '{}',
  created_at       TIMESTAMPTZ NOT NULL,
  expires_at       TIMESTAMPTZ NOT NULL,
  consumed_at      TIMESTAMPTZ,
  family_revoked   BOOLEAN NOT NULL DEFAULT FALSE,
  superseded       BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS device_refresh_tokens_family_idx
  ON device_refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS device_signing_keys (
  kid              TEXT PRIMARY KEY,
  algorithm        TEXT NOT NULL,
  public_key_pem   TEXT NOT NULL,
  kms_key_arn      TEXT,
  status           TEXT NOT NULL DEFAULT 'active',
  promoted_at      TIMESTAMPTZ NOT NULL,
  retired_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS device_telemetry_idempotency (
  idempotency_key  TEXT PRIMARY KEY,
  device_id        TEXT NOT NULL,
  request_hash     BYTEA NOT NULL,
  response_status  INTEGER NOT NULL,
  response_body    BYTEA NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL,
  expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS device_telemetry_idempotency_expiry_idx
  ON device_telemetry_idempotency(expires_at);
```

A scheduled job (`internal/sourceops` cron) purges `device_telemetry_idempotency` rows past `expires_at` daily.

## Phasing

| Phase | Scope | This PR |
|---|---|---|
| 1a | Design proposal + NON_GOALS update + `internal/deviceauth/` package skeleton (JWT issuer, in-memory store, unit tests) | **yes** |
| 1b | Postgres schema + driver implementation in `internal/statestore/postgres/deviceauth.go` | follow-on |
| 1c | Route mounts in `internal/bootstrap/app.go`; auth-pipeline extension to recognize device JWTs | follow-on |
| 1d | OpenAPI updates + `make openapi-sync` | follow-on |
| 2  | DPoP-style device-bound proofs; Apple App Attest; Windows TPM attestation | future |
| 3  | Geo / ASN anomaly scoring on refresh; AWS WAF custom rules | future |

## Testing

Unit tests for v1a (this PR):

- `JWTIssuer.IssueAccess` returns a valid Ed25519-signed token with the expected claims and `kid`.
- `JWTVerifier.Verify` accepts a fresh token, rejects an expired one, rejects one with an unknown `kid`, rejects one with the wrong audience, rejects one with no scopes.
- Refresh-rotation: fresh token consume succeeds; double-consume revokes the family; a generation N-1 token after a successful generation N rotation is rejected; replay revokes the family.
- Bootstrap-token consume: consume succeeds once and the token is marked consumed; second consume returns `bootstrap_token_already_consumed`; expired token rejected; hardware-UUID mismatch rejected.

Follow-on PR test surface (1b/1c/1d):

- `httptest`-driven coverage of every route with happy + error paths.
- Postgres-driver tests against a containerized `pgx` instance via the existing `Open()` test pattern.
- Idempotency-key replay tests (same key + same body returns cached, same key + different body returns 409).
- Rate-limiter tests (per-IP and per-device buckets).
- Race tests on concurrent refresh-rotation.

## Open questions

- AWS KMS asymmetric sign latency: acceptable for token issuance? Proposed cache: pre-sign a batch is not possible (each token is unique), but the path is rare (10-min token TTL means ~144 signs/day/device for a fleet of N devices = N * 144 KMS calls/day). For 5,000 devices that's 720k/day, well inside service quotas.
- Where does the agent's MDM-delivered bootstrap token come from? Proposal: a Cerebro admin endpoint mints them, the security team stages them in Kandji/Intune managed config, and Kandji/Intune delivers the per-device value at check-in. That keeps Cerebro out of the MDM API path.
- Do we need a separate ingress for telemetry vs. control-plane traffic? For v1, no -- both ride the same ALB with separate target groups. Phase 3 may split if telemetry volume warrants its own NLB.
