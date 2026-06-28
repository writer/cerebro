# Deployment Readiness

This guide turns the hosting contract into a rollout checklist. It uses public, environment-agnostic names only. Keep real account IDs, hostnames, tenant IDs, secret paths, source schedules, approval gates, and incident contacts in the deployment repository or platform records for the environment.

Use it with:

- [Hosting](hosting.md) for the runtime contract.
- [Runtime profiles](runtime-profiles.md) for profile-specific config and checks.
- [Cloud deployment](cloud-deployment.md) for the Pulumi templates.
- [Operations runbook](operations-runbook.md) for rollout, rollback, and incident handling.
- [Release contract](release-contract.md) for source runtime and deployment metadata.

## Operator Journey

1. Pick the runtime profile: lightweight API, durable API, durable sync, or graph-enabled.
2. Add capability layers such as MCP OAuth, device auth, OTEL, cache, or graph-agent LLM when the rollout needs them.
3. Select an immutable image tag and record the config version that will run with it.
4. Provision the backing stores required by the profile and capability layers.
5. Put every secret-bearing value in a secret manager or orchestrator secret object.
6. Configure API auth, tenant scope, public origin, and trusted proxy settings.
7. Configure liveness on `/livez` or `/healthz` and readiness on `/health`.
8. Add scheduled jobs separately from the API service when source sync or graph ingest is needed.
9. Run `cerebro deploy preflight` from the same image and config that will serve traffic.
10. Shift traffic only after readiness passes and the preflight receipt has no failed checks.
11. Run the profile-specific post-deploy checks and save the final image tag plus config version in deployment records.

## Readiness Receipt

Run:

```bash
cerebro deploy preflight --format json
```

The receipt reports variable names and service names instead of secret values. Failed-check details redact URL credentials and credential-shaped key/value fields before output.

Important fields:

| Field | Use |
| --- | --- |
| `runtime_profile` | Confirms which profile the current config activates. |
| `enabled_capabilities` | Shows enabled runtime surfaces such as API auth, Postgres state, JetStream append log, Neo4j graph, MCP OAuth, device auth, OTEL, cache, or graph-agent LLM. |
| `required_backing_services` | Lists backing services the deployment must operate for the selected config. |
| `required_secret_names` | Lists secret-bearing environment variable names. Values stay in the secret manager. |
| `operator_actions` | Lists deployment tasks that cannot be verified from process config alone. |
| `checks` | Records pass/fail checks for config load, serve safety, dependency open, dependency close, and configured probes. |

Text output is available for terminal use:

```bash
cerebro deploy preflight --format text
```

## Required Gates

Before a shared deployment receives traffic:

| Gate | Command or evidence | Blocks rollout when |
| --- | --- | --- |
| Image selected | immutable image tag in deployment record | image is untagged or mutable in a production stack |
| Config loads | `cerebro deploy preflight` | `config.load` fails |
| Serve safety | `cerebro deploy preflight` | auth or rate limiting is unsafe outside acknowledged dev mode |
| Dependencies open | `cerebro deploy preflight` | configured stores or provider probes fail |
| Liveness | `curl -fsS https://cerebro.example.com/livez` | process does not serve HTTP |
| Readiness | `curl -fsS https://cerebro.example.com/health` | configured dependency is unavailable |
| Auth smoke | authenticated request to `/sources` | protected route rejects the intended credential |
| Profile smoke | command from [Runtime profiles](runtime-profiles.md) | selected profile cannot perform its expected work |
| Observability | log, metric, and trace arrival in the collector | operators cannot see route, dependency, or job failures |
| Rollback record | previous image tag and config version | rollback path is unknown |

## Private And Public Docs

Public docs in this repository should contain:

- runtime profiles and required backing services,
- environment variable names,
- command shapes,
- placeholder hostnames and secret refs,
- generic failure modes,
- checks that can run without private account state.

Deployment repositories or platform records should contain:

- account IDs, projects, subscriptions, regions, and clusters,
- real hostnames, DNS zones, and certificate ARNs,
- secret names, secret paths, and credential rotation records,
- tenant assignments, runtime IDs, source schedules, and provider rate-limit choices,
- production approval gates, emergency contacts, and incident links,
- environment-specific dashboards, alert thresholds, and paging routes.

When a private value is needed to explain an operation, write the public doc with a placeholder and link to the owning deployment record from the private repository.

## Schedule Readiness

Source sync and graph ingest jobs use the same image but should not run inside the API service process. For each scheduled job, deployment records should capture:

| Field | Why it matters |
| --- | --- |
| Runtime ID | Stable cursor and graph projection identity. |
| Tenant ID | Scope for events, claims, findings, and graph entities. |
| Command | Exact CLI command and page limits. |
| Cadence | Provider rate limit, freshness, and cost control. |
| Overlap policy | Cursor-sensitive runtimes should forbid concurrent runs. |
| Retry policy | Provider failures should not create unbounded traffic. |
| Resource limits | Background work should not starve the API service. |
| Failure route | Operators need a ticket, page, or follow-up path. |

Do not publish live runtime IDs, tenant IDs, provider credentials, or cadence values in this repository.

## Release Handoff

Deployment automation should consume:

- the selected image tag,
- the signed `cerebro-runtime-contract-<target>.json` when produced,
- the deployment-owned config version,
- the `cerebro deploy preflight` receipt,
- post-deploy health check results.

The release contract names required source secrets, runtime profiles, backing services, optional capability gates, and post-deploy checks. It does not define live schedules, concrete secrets, account state, hostnames, or approval gates.
