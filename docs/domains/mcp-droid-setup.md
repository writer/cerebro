# MCP native Droid setup

This guide covers the Cerebro MCP endpoint from the perspective of native Droid and other Streamable HTTP MCP clients. It focuses on the production-quality contract, local client setup, OAuth behavior, compatibility pitfalls, and the validation path for changes.

## Endpoint contract

Cerebro serves MCP at:

```text
POST /api/v1/mcp
```

The endpoint is a stateless Streamable HTTP MCP endpoint:

- Clients send JSON-RPC MCP requests with `POST`.
- Successful request/response operations return `Content-Type: application/json`.
- Fire-and-forget JSON-RPC notifications can return `202 Accepted` with an empty body.
- The server does not issue `Mcp-Session-Id` for stateless responses.
- `GET /api/v1/mcp` is not an SSE endpoint and returns `405 Method Not Allowed`.

Do not advertise or emulate a stateful SSE session on this route. Native Droid uses the MCP SDK Streamable HTTP client for `type: "http"` servers, and it treats stateful session/SSE signals as part of the transport contract.

## Task profile

Set `X-Cerebro-MCP-Toolsets: task` when the client should start with a bounded,
task-level tool list. The profile exposes six tools:

| Tool | Result |
| --- | --- |
| `cerebro.health` | Service readiness |
| `cerebro.version` | Running build identity |
| `cerebro.risk.explain` | Finding, evidence, asset, and optional graph context |
| `cerebro.evidence.packet` | Evidence packet for the requested question and authorized scope |
| `cerebro.sources.health` | Configured source coverage and current blind spots |
| `cerebro.action.plan` | Ranked remediation candidates without execution |

Each task result returns `state` as `complete`, `partial`, or `blocked`, plus a
dependency list. `partial_reasons` identifies missing graph data, stale or
failed source coverage, and other optional inputs that changed the result.
Clients should show these reasons with the result instead of treating a partial
result as complete.

Task tools do not mutate resources. `cerebro.action.plan` stops at
`next_state: proposal`; approval and execution remain separate operations.
The evidence-packet task accepts only `observe`, `explain`, `recommend`, and
`dry_run` action stages.

Requests without a toolset keep the full tool list for compatibility. Existing
domain tools remain available as expert tools. Use
`X-Cerebro-MCP-Toolsets: expert` for that profile, or the existing domain
toolsets such as `graph`, `risk`, `findings`, and `assessments` for narrower access.

## Assessment operations

Set `X-Cerebro-MCP-Toolsets: assessments` to expose the assessment lifecycle:

| Tool | Required scope | Result |
| --- | --- | --- |
| `cerebro.assessments.plan.create` | security read + GRC inventory write | Persisted plan draft with server-owned identity and digest |
| `cerebro.assessments.plan.publish` | security read + GRC inventory write | Published immutable plan revision using `expected_version` |
| `cerebro.assessments.plan.get` | security read | One tenant-scoped plan revision |
| `cerebro.assessments.run.request` | security read + GRC inventory write | Recoverable run; repeated key and body return the existing run |
| `cerebro.assessments.run.get` | security read | Current state, pinned input manifest, result availability, and hashes |
| `cerebro.assessments.results.list` | security read | Bounded result page with recomputed payload and predecessor-digest verification |
| `cerebro.assessments.run.diff` | security read | Complete bounded comparison with the explicit or pinned baseline |
| `cerebro.assessments.result.explain` | security read | Verified result, manifest, evidence, findings, and exact provenance follow-up calls |
| `cerebro.assessments.remediation.propose` | security read | Non-mutating work request for the existing approval-gated GRC work endpoint |

Start result paging with `after_sequence: 0` and no predecessor digest. For each
following page, pass the preceding response's
`verification.next_previous_digest` as `expected_previous_digest`. A page fails
if its run ID, sequence, result boundaries, canonical payload digest, or
predecessor link does not match.

Plan creation, plan publication, and run requests are the only mutating tools in
this profile. They call the existing assessment domain service, preserve its
append-first records and Postgres projections, and require the same GRC write
scope as the HTTP routes. Run requests are idempotent. The other assessment
tools are read-only. Remediation remains a proposal and requires a separate
call to `POST /grc/work-items` with `cerebro.findings.write`.

## Tool/domain parity

MCP tools are adapters over existing Cerebro domain surfaces, not a parallel
product API. Each tool must map to an HTTP route, Connect RPC, report contract,
or explicitly named composite of those surfaces. Agent-oriented tools such as
investigation context and risk action planning may bundle multiple reads, but
their source domain surfaces must stay listed in the MCP parity test.

Action and remediation workflows are exposed only as proposal tools with
`dry_run=true`, `readOnlyHint=true`, and a response that describes the required
write scope without applying the action. Domain-owned assessment plan and run
writes may execute only through the existing assessment service, with the same
tenant, write-scope, optimistic-concurrency, idempotency, append-log, and
projection contracts as their HTTP routes.

Agent control-loop tools expose the security-agent control plane without adding
write access. `cerebro.agent.control_plane` returns the evidence packet, claim
verification, agent work, verifier, action ladder, eval, memory, connector gate,
and simulation contracts. `cerebro.agent.claims.verify` verifies an agent
conclusion as an `agent-claim-verification` record with supporting evidence,
counterevidence, missing evidence, freshness state, coverage caveats, a verdict,
and the highest allowed next action stage. `cerebro.agent.work.contract` returns
the `agent-work-ledger` state model and closure contract for resumable
investigations.

## Native Droid client configuration

For the local compose/dev key, one command is enough:

```bash
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key" \
  --header "X-Cerebro-MCP-Toolsets: task"
```

Use an HTTP MCP server entry. Keep the URL on the MCP route itself, not just the origin.

```json
{
  "mcpServers": {
    "cerebro-local": {
      "type": "http",
      "url": "http://127.0.0.1:8080/api/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${CEREBRO_API_KEY:-local-dev-key}",
        "X-Cerebro-MCP-Toolsets": "task"
      },
      "disabled": false
    },
    "cerebro-prod": {
      "type": "http",
      "url": "https://<cerebro-origin>/api/v1/mcp",
      "disabled": false,
      "headers": {
        "X-Cerebro-MCP-Toolsets": "task"
      },
      "oauth": {
        "scopes": ["cerebro.cosmo.security.read"],
        "callbackPort": 53682
      }
    }
  }
}
```

For most Droid setups, omit `oauth.clientId`. Omitting it lets Droid use dynamic client registration and register the local callback redirect it actually needs, such as:

```text
http://localhost:53682/callback
```

Only configure a static `oauth.clientId` when that client is known to allow the exact Droid redirect URI and requested scopes.

## Instant source preview tools

The source-preview tools work before durable stores are configured:

- `cerebro.sources.list`
- `cerebro.sources.check`
- `cerebro.sources.discover`
- `cerebro.sources.read`

Example agent instruction:

```text
Call cerebro.sources.read with source_id=github and config
{"owner":"writer","repo":"cerebro","per_page":"5"}. Summarize the live
security and compliance evidence, and cite that it came from live source
preview rather than durable graph state.
```

For private repos or alert families, pass provider credentials through the MCP client or shell environment. Do not commit real bearer tokens, GitHub tokens, OAuth client secrets, or API keys in `.factory/mcp.json`.

## OAuth flow

Cerebro exposes MCP OAuth metadata so clients can discover authorization behavior from the resource server:

```text
/.well-known/oauth-protected-resource/api/v1/mcp
```

When an unauthenticated client calls `POST /api/v1/mcp`, Cerebro returns `401` with a `WWW-Authenticate: Bearer ...` challenge that includes resource metadata and scope information. Droid then:

1. Discovers the protected-resource metadata.
2. Discovers the authorization server.
3. Registers or loads an OAuth client.
4. Opens the browser authorization flow.
5. Receives the callback on the configured local port.
6. Exchanges the authorization code for tokens.
7. Reconnects to `POST /api/v1/mcp` with `Authorization: Bearer <token>`.

Do not log tokens, authorization codes, client secrets, refresh tokens, or full browser callback URLs.

## Initialize response compatibility

Native Droid validates the server initialize response with the MCP SDK schema. The response must keep capability fields schema-compatible with the SDK.

Expected shape:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "tools": { "listChanged": false },
      "resources": { "subscribe": false, "listChanged": false },
      "prompts": { "listChanged": false }
    },
    "serverInfo": {
      "name": "cerebro",
      "title": "Cerebro",
      "version": "<release-version>"
    }
  }
}
```

Avoid non-standard primitive values under `capabilities.experimental`. For example, do not return:

```json
{
  "capabilities": {
    "experimental": {
      "stateless": true
    }
  }
}
```

Some MCP SDK versions validate experimental capability values as object-shaped values. A boolean there can make the authenticated reconnect fail even when OAuth token exchange succeeds.

## Troubleshooting

### `Authentication flow did not start`

Likely causes:

- The configured `oauth.callbackPort` is already bound by another Droid process.
- A stale Droid/tmux validation session is still running.
- The MCP config has multiple enabled remote OAuth servers trying to reserve incompatible callback ports.

Checks:

```bash
lsof -nP -iTCP:<callback-port> -sTCP:LISTEN
```

Fix:

- Stop stale Droid sessions that own the port, or use a free callback port.
- Prefer one active Droid authentication attempt per callback port.

### Browser shows `redirect_uri is not registered for client`

Likely cause:

- A static OAuth client is configured, but its allowed redirects do not include Droid's local callback URI.

Fix:

- Remove `oauth.clientId` from the Droid MCP entry and let dynamic client registration create a compatible client.
- If a static client is required, register the exact callback URI and scope set with the authorization server.

### OAuth token exchange succeeds, then reconnect fails

This means OAuth completed, but the MCP SDK could not complete `client.connect()` against the authenticated transport.

Check the server response for:

- Invalid initialize response schema.
- Unexpected `Mcp-Session-Id` on a stateless endpoint.
- `GET /api/v1/mcp` advertising SSE behavior for an HTTP server.
- Wrong `Content-Type`; JSON-RPC responses should return `application/json`.
- `401` after successful authentication, usually from missing scopes, expired tokens, or tenant/auth mapping.

Useful local validation:

```bash
go test ./internal/bootstrap -run 'TestMCP' -count=1
go test ./internal/bootstrap -count=1
make mcp-contract-check mcp-sdk-compat
make lint-bootstrap openapi-check openapi-lint
```

When debugging with an MCP SDK probe, keep token handling local and redacted. Print only response status, selected headers, server version, and whether capabilities contain unexpected fields.

### Droid shows connected but fewer tools than expected

Check:

- The caller has the needed OAuth scopes.
- Tool registration did not fail server-side.
- The deployment is running the expected Cerebro image tag.
- The MCP tools UI is not filtering disabled tools.

For a healthy production connection, the Droid MCP details screen should show:

```text
Status: connected
Type: HTTP
Tools: <enabled>/<total> enabled
```

## Server-side implementation rules

Keep the MCP route small and predictable:

- Return JSON-RPC errors as JSON-RPC envelopes.
- Keep response bodies bounded and redacted.
- Keep all production tools read-only unless a future change adds explicit dry-run or approval semantics.
- Preserve tenant authorization before service logic runs.
- Do not expose source credentials, runtime config secrets, tokens, or raw sensitive asset attributes.
- Add tests for any transport, auth, or initialize response contract change.

Compatibility regression tests should cover:

- Initialize capabilities are SDK-compatible.
- Stateless responses do not emit `Mcp-Session-Id`.
- `GET /api/v1/mcp` is not an SSE endpoint.
- OAuth-authenticated MCP responses preserve stateless behavior.

## Release and deployment checklist

For public runtime changes:

1. Run focused MCP tests first.
2. Run the bootstrap package tests.
3. Run lint/OpenAPI validation when route behavior or docs mention route behavior.
4. Open a PR and wait for CI.
5. Merge after checks pass.
6. Confirm the next public release tag includes the merge commit.
7. Promote the new image tag through the deployment repository.
8. Wait for deployment verification.
9. Re-test native Droid through `/mcp`.

For native Droid validation, verify both:

- OAuth authentication completes.
- The server reconnects as `connected` and tool listing is populated.

For a deployed endpoint with a short-lived bearer/API token available locally, run:

```bash
CEREBRO_BASE_URL=https://<cerebro-origin> CEREBRO_MCP_BEARER_TOKEN=<redacted> scripts/mcp_smoke.py
```

## Security notes

- Never paste OAuth tokens, refresh tokens, authorization codes, or client secrets into PRs, logs, issues, or docs.
- Sanitize MCP tool outputs before sharing screenshots or terminal captures.
- Prefer counts, statuses, headers, and versions over raw records when reporting validation evidence.
- Keep environment-specific hostnames, account IDs, and deployment internals in their environment repository or runbook, not in public documentation.
