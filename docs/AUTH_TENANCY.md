# Auth And Tenancy

This guide explains Cerebro's public authentication and tenant-scoping model for hosted deployments.

Use it with:

- [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md) for the exact variable reference.
- [`docs/HOSTING.md`](./HOSTING.md) for proxy and TLS guidance.
- [`docs/MCP_DROID_SETUP.md`](./MCP_DROID_SETUP.md) for MCP OAuth setup.
- [`api/openapi.yaml`](../api/openapi.yaml) for protected HTTP routes.

## Default behavior

API auth and rate limiting are enabled by default outside acknowledged dev mode. For local-only unauthenticated development, use the Makefile target that sets both dev-mode variables:

```bash
make serve-dev
```

Equivalently, an explicitly acknowledged local shell can set:

```bash
CEREBRO_DEV_MODE=1
CEREBRO_DEV_MODE_ACK=1
```

When auth is enabled, non-public HTTP routes and Connect RPCs require a valid credential. Tenant mismatch checks happen before service logic.

## Public routes

These routes remain public when auth is enabled:

```text
GET /health
GET /healthz
GET /livez
GET /openapi.yaml
GET /.well-known/oauth-protected-resource
GET /.well-known/oauth-protected-resource/api/v1/mcp
GET /.well-known/oauth-authorization-server
GET /.well-known/device-jwks.json
GET /oauth/authorize
GET /oauth/callback
POST /oauth/token
POST /oauth/revoke
POST /oauth/register
POST /platform/devices/enroll
POST /platform/devices/token
```

All other HTTP routes should be treated as protected in shared deployments.

## API key credentials

The simplest auth mode is `CEREBRO_API_KEYS`:

```bash
CEREBRO_API_AUTH_ENABLED=true
CEREBRO_API_KEYS='<key>:<principal>:<tenant-id>'
```

Format:

```text
key[:principal[:tenant_id]]
```

Examples:

| Shape | Meaning |
| --- | --- |
| `<key>` | valid key with default principal metadata |
| `<key>:<principal>` | valid key with named principal |
| `<key>:<principal>:<tenant-id>` | valid key scoped to one tenant |

Prefer tenant-scoped keys for shared environments.

Clients can send the key as either:

```http
Authorization: Bearer <key>
```

or:

```http
X-Cerebro-API-Key: <key>
```

Prefer `Authorization: Bearer` unless an integration cannot set it.

## Structured credentials

Use `CEREBRO_API_CREDENTIALS_JSON` when you need explicit credential metadata, scopes, allowed tenants, or hashed keys.

Shape:

```json
[
  {
    "key": "<key>",
    "principal": "<principal>",
    "tenant_id": "<tenant-id>",
    "allowed_tenants": ["<tenant-id>"],
    "scopes": ["<scope>"],
    "roles": ["<role>"]
  }
]
```

Store this JSON as a secret. Do not commit live credentials.

Use `key_sha256` instead of `key` when your deployment process can precompute the SHA-256 hash and keep the raw key only in the client secret store.

## Capability tokens

Capability tokens are HMAC-signed bearer tokens used by flows such as MCP OAuth.

Relevant variables:

```bash
CEREBRO_CAPABILITY_TOKEN_SECRETS=<secret-1>,<secret-2>
CEREBRO_CAPABILITY_TOKEN_AUDIENCE=cerebro-api
```

Operational guidance:

- Keep at least one active signing secret configured.
- Rotate by adding the new secret, rolling clients, then removing the old secret.
- Keep the audience stable for clients that validate it.
- Treat capability secrets like API signing keys.

## Tenant selection

Cerebro accepts tenant hints from request bodies, query parameters, headers, and URNs depending on the route. Common forms:

```http
X-Cerebro-Tenant: <tenant-id>
```

```text
?tenant_id=<tenant-id>
```

```json
{"tenant_id":"<tenant-id>"}
```

When a credential is scoped to a tenant, requests for other tenants return `403`. This prevents tenant mismatches before route-specific logic runs.

Use `CEREBRO_ALLOWED_TENANTS` to restrict unscoped credentials:

```bash
CEREBRO_ALLOWED_TENANTS=<tenant-id>,<another-tenant-id>
```

## Scopes

Structured credentials and capability tokens can carry scopes. Scope enforcement is route-aware. A missing or insufficient scope returns `403`.

Recommended pattern:

1. Start with a narrow credential per integration.
2. Grant only the route families the integration needs.
3. Use separate credentials for humans, automation, MCP clients, source jobs, and device flows.
4. Rotate each credential independently.

Current route scopes include:

| Scope | Route family |
| --- | --- |
| `cerebro.cosmo.security.read` | Read-only source, finding, report, graph, GRC, MCP, and platform status routes. |
| `cerebro.finding_candidates.promote` | Promote or reject finding candidates. |
| `cerebro.findings.write` | Resolve, suppress, assign, set due dates, add notes, and link tickets on findings. |
| `cerebro.grc.inventory.write` | Mutate GRC inventory scope, reports, and triage state. |
| `cerebro.connector_credentials.read` | Read connector credential metadata. |
| `cerebro.connector_credentials.write` | Create, rotate, or revoke connector credentials. |
| `cerebro.runtime_response.write` | Execute runtime response actions and revoke runtime blocklist entries. |
| `cerebro.graph_actions.write` | Execute and reconcile eligible provider-backed graph actions such as access-approvals Okta user suspend/unsuspend and first-party Cerebro device revocation. |
| `cerebro.reports.run` | Start report runs. |
| `cerebro.knowledge.write` | Write platform knowledge decisions, actions, recommendations, and outcomes. |
| `cerebro.workflow.replay` | Replay workflow events. |
| `cerebro.sources.preview` | Check, discover, or read source previews. |
| `cerebro.connector_definitions.write` | Create, validate, update, or promote connector definitions. |
| `cerebro.connectors.write` | Run connector preflight and connection write operations. |
| `cerebro.jobs.write` | Create jobs and cancel platform jobs. |
| `cerebro.source_runtimes.write` | Create, sync, evaluate, ingest, or write claims through source runtimes. |

## Roles

Structured API credentials and MCP OAuth clients or entitlements can carry `roles`. Roles expand to route scopes before authorization checks run. A role-bearing credential must still be tenant-scoped with `tenant_id` or `allowed_tenants`.

Role aliases are normalized exactly like scopes. Prefer the explicit `cerebro.*` names for shared deployments:

| Role | Included access |
| --- | --- |
| `cerebro.viewer` | Read-only Cerebro routes. Aliases: `viewer`, `reader`, `read_only`. |
| `cerebro.analyst` | Viewer access plus finding candidate promotion, finding lifecycle writes, and GRC inventory writes. Aliases: `analyst`, `editor`. |
| `cerebro.finding_manager` | Viewer access plus finding candidate promotion and finding lifecycle writes. |
| `cerebro.grc_reviewer` | Viewer access plus GRC inventory writes. |
| `cerebro.connector_manager` | Viewer access plus connector credential, definition, and connection writes. |
| `cerebro.responder` | Viewer access plus runtime response writes. |
| `cerebro.source_manager` | Viewer access plus report runs, source previews, and source-runtime writes. |
| `cerebro.job_manager` | Viewer access plus platform job writes. |
| `cerebro.admin` | All Cerebro RBAC scopes. Aliases: `admin`, `owner`. |

## Public origin

Set `CEREBRO_PUBLIC_ORIGIN` to the canonical HTTPS origin:

```bash
CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com
```

Rules:

- Use `http` or `https`.
- Do not include path, query, fragment, or user info.
- Prefer `https` for every shared deployment.
- Keep it identical to the origin clients use.

Cerebro uses this for proxy-aware URL reconstruction and DPoP `htu` checks.

## Trusted proxies

When Cerebro runs behind a proxy, configure which proxy hops can supply forwarded headers:

```bash
CEREBRO_TRUSTED_PROXY_CIDRS=10.0.0.0/8
CEREBRO_TRUSTED_PROXY_COUNT=1
```

The proxy should:

- terminate TLS,
- strip inbound `X-Forwarded-*` headers from untrusted clients,
- set `X-Forwarded-For`,
- set `X-Forwarded-Host`,
- set `X-Forwarded-Proto`,
- preserve `Authorization`,
- preserve `DPoP` for device-authenticated requests.

Do not trust forwarded headers directly from the public internet.

## MCP OAuth

MCP OAuth mode requires:

```bash
CEREBRO_API_AUTH_ENABLED=true
CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com
CEREBRO_STATE_STORE_DRIVER=postgres
CEREBRO_POSTGRES_DSN=<postgres-dsn>
CEREBRO_CAPABILITY_TOKEN_SECRETS=<hmac-secret>
```

Then configure the relevant `CEREBRO_MCP_OAUTH_*` variables from [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md) and [`docs/MCP_DROID_SETUP.md`](./MCP_DROID_SETUP.md).

## Device auth

Device-authenticated telemetry is for first-party fleet agents. It requires:

- API auth,
- device-auth signing keys,
- issuer and audience settings,
- DPoP settings,
- a compatible state store,
- one replica unless shared DPoP replay state is configured.

For general OSS hosting, start with API keys or structured credentials before enabling device auth.

## Rotation playbooks

### API key rotation

1. Add the new key alongside the old key.
2. Roll clients to the new key.
3. Confirm auth success with the new key.
4. Remove the old key.
5. Restart or roll the service if your platform requires it for env var changes.

### Capability secret rotation

1. Add the new signing secret while keeping the old secret.
2. Roll token issuers to sign with the new secret.
3. Wait for tokens signed with the old secret to expire.
4. Remove the old secret.

### Provider credential rotation

1. Add the new provider secret to your secret manager.
2. Update the source runtime secret reference or injected env var.
3. Run a low-page source check or sync.
4. Revoke the old provider credential.

## Auth troubleshooting

| Symptom | Check |
| --- | --- |
| `401 unauthorized` | missing header, wrong key, malformed bearer token, capability token invalid |
| `403 tenant forbidden` | credential tenant does not match request tenant |
| `403 scope forbidden` | credential lacks route scope |
| DPoP failure | public origin, proxy headers, DPoP header preservation, method and URL match |
| MCP OAuth failure | API auth, public origin, Postgres, capability secrets, OAuth client config |
| Works locally but not through proxy | forwarded headers, `Authorization` preservation, trusted proxy config |
