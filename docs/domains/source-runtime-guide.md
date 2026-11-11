# Source Runtime Guide

Source runtimes are Cerebro's durable connection between a source integration and a tenant-scoped stream of events, claims, findings, and graph projections. This guide explains the public runtime model, CLI and HTTP operations, scheduling patterns, and safe configuration practices.

Use it with:

- [`docs/start/getting-started.md`](../start/getting-started.md) for a local SDK source walkthrough.
- [`docs/reference/config-env-vars.md`](../reference/config-env-vars.md) for source secret allowlist variables.
- [`docs/operations/operations-runbook.md`](../operations/operations-runbook.md) for sync operations.
- [`api/openapi.yaml`](../../api/openapi.yaml) for the HTTP route contract.
- [`sources/*/catalog.yaml`](../../sources) for source capability declarations.

## Mental model

A source runtime answers:

- which source integration to run,
- which tenant owns the data,
- what source-specific config to use,
- what cursor was last synced,
- when the runtime last advanced,
- which generated claims, findings, and graph projections can be traced back to it.

The current implementation supports:

- stateless source preview commands with no runtime persistence,
- persisted source runtimes stored in Postgres,
- source runtime sync backed by Postgres plus NATS JetStream,
- graph ingest from either direct source reads or persisted source runtimes.

## Dependency matrix

| Operation | Dependencies |
| --- | --- |
| `source list` | none |
| `source check/discover/read` | none beyond provider-specific config and credentials |
| `source-runtime put/get/list` | Postgres |
| `source-runtime sync` | Postgres plus NATS JetStream |
| source runtime claims and findings routes | Postgres |
| `graph ingest-runtime` | Postgres plus Neo4j or Aura, and often NATS for replay-oriented flows |
| source config `env:` references | environment variable plus allowlist configuration |

The production package includes the credential-free `source_worker` binary.
`CEREBRO_SOURCE_WORKER` selects its absolute path; when unset, Cerebro uses the
`source_worker` sibling next to the Go executable. Closed production dispatch
includes `azure` with `family=authorization_policy` and SentinelOne with
`family=agent`, `activity`, `application`, `exclusion`, `group`, `site`, or
`threat`. Those runtimes must store an opaque `env:` or `credential:` reference.
The trusted host resolves and redeems it once; raw credential bytes are never
sent to the Rust worker. Application inventory resumes across its agent-discovery
and inventory-fetch requests with one bounded opaque cursor. SentinelOne source
preview remains on its compatibility path until the preview credential adapter
is promoted separately.

## Cloud identity scan

Cloud-identity collection, scheduled scanning, excess-privilege/shared-principal
detection, and triage are owned entirely by VulnView (the private Security
monorepo). Cerebro's former `cloud_identity` source -- its Kubernetes
manifest/Helm/Argo CD/Crossplane/Terraform collection pipeline, federated
GCP identity resolution, and the S3 evidence handoff that published
principal evidence to VulnView -- is retired; Cerebro no longer collects
cloud-identity evidence itself. VulnView's own collector, detector, and
plan catalog (`platforms/services/vulnview/cloud-identity-*`) own that
pipeline now; see the Security repo's own docs for how it collects,
schedules, and detects.

Cerebro imports VulnView's output -- cloud-identity findings alongside
every other VulnView finding source -- through the standardized export
described next.

## VulnView standardized findings

The `vulnview` source's single `finding` family reads VulnView's
standardized, lifecycle-tracked finding export,
`GET /exports/findings?source=<source>`, one runtime per VulnView finding
source (`nuclei`, `caido`, `port`, `dns`, `prowler`, `cloud_identity`,
`github`; the required `source` setting selects it). It replaces the
former per-provider `vulnerability`, `dns_alert`, `cloud_identity_finding`,
and `cloud_identity_assessment` families and events: VulnView is the
detection authority for every source it exports, including cloud-identity
posture, and Cerebro's rule engine never re-derives a verdict from an
imported finding. See
[`sources/vulnview/finding_exports.go`](../../sources/vulnview/finding_exports.go)
and
[`internal/sourceprojection/vulnview.go`](../../internal/sourceprojection/vulnview.go).

Cerebro used to derive two standalone native findings from this feed
directly: `vulnview-actionable-external-finding` (one Cerebro finding per
open, actionable-severity external-attack-surface `vulnview.finding`) and
`vulnview-external-asset-concentrated-signal` (one Cerebro finding per
external asset with concentrated graph evidence). Both are retired
(`internal/findings/vulnview_signal_rule.go`,
`internal/findings/vulnview_graph_rule.go`): no lifecycle transition of any
`vulnview.finding` -- open, fixed, reopened, accepted-risk,
false-positive-triaged, triage-expired, or a replayed/reordered version --
ever opens or reopens either rule's finding again. A single upstream
VulnView finding is a source observation and graph evidence, not a
standalone Cerebro verdict; a genuinely distinct composed attack path has
its own existing graph-rule contract. Rows opened before retirement,
including ones owned by a legacy runtime
(`writer-vulnview-vulnerability`, `writer-vulnview-dns-alert`) that no
longer emits events, are closed through the existing `cerebro closeout`
procedure (`internal/findings/closeout.go`'s `CloseoutSelector`) scoped to
the tenant and the two retired rule IDs; no runtime filter is required.

The family pages VulnView's cursor-feed export route
(`sourcecdk.CursorFeedPage`: `items`, `nextCursor`, `hasMore`) and
implements `sourcecdk.CheckpointAwareSource`/`Family.ReadWithCheckpoint`
rather than the plain `Read` path, so every pull -- including an empty
page or VulnView's terminal (`hasMore:false`) page -- returns a resumable
`sourcecdk.CursorEnvelope` checkpoint carrying VulnView's raw `nextCursor`
as `Token`. A later sync resumes from that exact VulnView cursor instead
of restarting the whole feed. The checkpoint watermark is the max of the
prior checkpoint's watermark and the newest emitted event's `OccurredAt`,
so it never regresses. Within one page, only the highest `version` per
`findingId` is kept (the feed can repeat a finding across a read-resume
lookback).

Each `vulnview.finding` event's `OccurredAt` is the export item's
`updatedAt`. The projected `vulnview.finding` entity carries strict
`observation_version` set to VulnView's per-finding `version`, which
orders writes: VulnView samples `updatedAt` before its conditional write
commits, so a concurrent writer can commit a higher version with an
earlier `updatedAt`, and `observation_version` (not `at`) is what must
order those writes (see
[`internal/projectionmeta/observation.go`](../../internal/projectionmeta/observation.go)).
A stale observation changes nothing -- not its attributes, typed
`source_id`/`runtime_id`, or label -- whether it reaches the graph store
directly or within the same graph-ingest page as the newer one.

Each export item's `provenance` object also carries VulnView's durable
integration attribution, flattened onto bounded event attributes and
registered as finding-owned (retractable) attributes:
`provenance_integrations` and `provenance_repository_integrations` (sorted,
comma-joined `kind:id` pairs naming VulnView integration records, for
example `cloud_account:prof-example` or `github:<integration-id>`, from
`provenance.integrations`/`provenance.repositoryIntegrations`) and
`provenance_integration_attribution` (`run`, `not_applicable`, or
`unknown`, from `provenance.integrationAttribution`). Like every other
owned attribute, a newer version that omits one retracts it -- an
attribution change never fabricates an identity for a source with no
integration concept (`nuclei`, `caido`, `port`, `dns`) or a historical row
with no provable attribution, and it never reopens or changes the
finding's status. See
[`sources/vulnview/records.go`](../../sources/vulnview/records.go)'s
`attributesForFinding` and
[`internal/sourceprojection/vulnview.go`](../../internal/sourceprojection/vulnview.go)'s
`vulnViewFindingAttributesOwnedKeys`.

An external attack-surface finding (`nuclei`, `caido`, `port`, `dns`) links
from the existing VulnView `external.asset` entity via `has_evidence`, the
same asset-URN scheme the `asset` family already mints. Other sources'
`asset` values (cloud principals, cloud resource IDs, repositories) are not
network hosts, so they stay finding attributes rather than minting
`external.asset` nodes. A `cloud_identity` finding links from the canonical
AWS role / GCP service account principal via `has_evidence` -- the same
URN other provider projections already mint for that principal -- and,
only when the export marks its consumer list `consumersComplete` AND
every member canonicalizes to an actual `kubernetes_service_account` URN
(a valid, non-null cluster/namespace/serviceAccount plus a cloud account
or project qualifier that itself resolves through the same canonical
parser other provider projections use -- a nonblank but malformed
qualifier, e.g. an AWS `cloudAccount` that is not a 12-digit account id,
does not canonicalize; optional descriptive fields are not required), to
each consumer Kubernetes service account via `associated_with`, asserted as one Contract C9 guarded link
set owned by the finding rather than a plain link. The set also carries
each consumer's minimal Kubernetes service account stub as a CreateOnly
`Endpoints` entry instead of an ordinary projected entity: the store
materializes an absent endpoint only inside the same guarded operation
that accepts this exact set, after retracting superseded assertions and
before asserting the new links, so a stale or losing observation can
never leak a consumer stub into the graph ahead of (or instead of) the
winning decision, and an existing (provider-owned or previously accepted)
endpoint is left untouched. The finding owns the set because its own
version orders it; a principal's several findings have independent
version sequences. A guarded link set's apply is atomic and complete: the
store retracts this tenant/source/runtime's other `associated_with`
assertions from the finding and asserts exactly the desired set, so a
consumer VulnView no longer reports is correctly dropped instead of
accumulating forever. A partial/unavailable consumer list
(`consumersComplete: false`), an absent/null consumers container, or any
member that fails to canonicalize (missing identity field, missing both
cloud account/project, a cloud account/project qualifier present but not
parseable into a real canonical identity, or an explicit null member)
downgrades the whole observation to an `Incomplete` set instead of
silently dropping just that
member: the store advances the scope's ordering guard for this
observation without touching any previously accepted links or
materializing any endpoint, so an older complete replay can never undo a
newer downgraded observation. A genuinely complete, empty consumer list
still clears the scope authoritatively, and valid duplicate consumers
dedupe into one link/endpoint. The projector only canonicalizes a
principal subject that is well-formed for its claimed provider and kind: a
raw `k8s://` placeholder subject, a Kubernetes-placeholder `principal_kind`
(`aws_kubernetes_service_account` / `gcp_kubernetes_service_account`), a
non-ARN AWS value, or a non-email/non-`principal://` GCP value all leave
the finding's `gap_codes` attribute as the only signal, never a dangling
`has_evidence` link. A fully resolved GCP `principal://` subject always
canonicalizes, regardless of kind. See
[`internal/sourceprojection/vulnview_cloud_identity.go`](../../internal/sourceprojection/vulnview_cloud_identity.go)
and [`internal/ports/projection.go`](../../internal/ports/projection.go)
for the `ProjectedLinkSet.Endpoints` contract.

Inventory families `site`, `scan`, and `asset` are unchanged: they are not
findings, and AWS exposure corroboration continues to consume them.

## Source preview

Preview source behavior before creating a persisted runtime:

```bash
./bin/cerebro source list
./bin/cerebro source check <source-id> key=value
./bin/cerebro source discover <source-id> key=value
./bin/cerebro source read <source-id> key=value page_limit=1
```

HTTP equivalents:

```bash
curl -fsS "http://127.0.0.1:8080/sources"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/check?key=value"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/discover?key=value"
curl -fsS "http://127.0.0.1:8080/sources/<source-id>/read?key=value&page_limit=1"
```

Use preview routes to validate credentials, permissions, paging, and emitted event shape before storing a runtime.

## Create a runtime

CLI:

```bash
./bin/cerebro source-runtime put <runtime-id> <source-id> \
  tenant_id=<tenant-id> \
  key=value
```

HTTP:

```bash
curl -fsS -X PUT "https://cerebro.example.com/source-runtimes/<runtime-id>" \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "runtime": {
      "id": "<runtime-id>",
      "source_id": "<source-id>",
      "tenant_id": "<tenant-id>",
      "config": {
        "key": "value"
      }
    }
  }'
```

Runtime IDs should be stable and descriptive enough for operators. Avoid embedding secrets, customer names, private hostnames, or temporary incident details in IDs.

## Read and list runtimes

```bash
./bin/cerebro source-runtime get <runtime-id>
./bin/cerebro source-runtime list tenant_id=<tenant-id> source_id=<source-id> limit=20
```

HTTP:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes?tenant_id=<tenant-id>&source_id=<source-id>&limit=20"

curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>"
```

Responses redact sensitive runtime config where the implementation marks config as sensitive.

The Rust platform also serves tenant-bound registry operations from the same
Postgres table:

```bash
curl -fsS -X PUT \
  -H "X-Cerebro-Tenant: <tenant-id>" \
  -H "Authorization: Bearer ${CEREBRO_RUST_TENANT_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://cerebro.example.com/v1/source-runtimes/<runtime-id>" \
  -d '{"runtime":{"source_id":"<source-id>","config":{"family":"<family>","token":"credential:<credential-id>:token"}}}'

curl -fsS \
  -H "X-Cerebro-Tenant: <tenant-id>" \
  -H "Authorization: Bearer ${CEREBRO_RUST_TENANT_TOKEN}" \
  "https://cerebro.example.com/v1/source-runtimes?source_id=<source-id>&limit=20"
```

The authenticated identity supplies the tenant; a body tenant must match it.
Rust filters GET and LIST in Postgres before constructing a response, so a
missing runtime and a runtime owned by another tenant are indistinguishable.
Sensitive config accepts only `env:`, `credential:`, or `aws-sm:` references
and is always returned as `[redacted]`. Registry writes cannot supply a cursor,
checkpoint, or last-sync time. Unchanged definitions keep durable progress;
configuration changes clear it so only a fenced sync can advance it again.

## Sync a runtime

CLI:

```bash
./bin/cerebro source-runtime sync <runtime-id> page_limit=100
```

HTTP:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/sync?page_limit=100"
```

Rust-authoritative catalog families can also sync through the write-capable
`serve-neo4j` or `serve-neo4j-consumer` Rust platform route:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${CEREBRO_RUST_TENANT_TOKEN}" \
  -H "X-Cerebro-Tenant: <tenant-id>" \
  "https://cerebro.example.com/v1/source-runtimes/<runtime-id>/sync"
```

That route accepts only the runtime ID. Rust loads the tenant, source, family,
configuration, and cursor from the durable runtime record, verifies the
authenticated tenant before resolving credentials, and holds the renewable
Postgres lease through provider collection and the fenced graph commit. A
concurrent holder returns a conflict; provider, configuration, and durable-store
failures remain distinct and do not fall back to the Go writer.

The example uses the Rust platform's tenant-HMAC mode. In OIDC mode, the signed
identity supplies the tenant and must carry the `cerebro:write` scope; do not
send a tenant selected independently from that identity.

Operational guidance:

- Default to small page limits during onboarding.
- Use `page_limit=100` as the current practical maximum for high-throughput sync jobs.
- Avoid concurrent sync for the same runtime unless the source and persistence path are known to be concurrency-safe.
- Watch provider rate limits and partial-page errors.
- Treat cursor advancement as the sign that sync is healthy.
- For `azure.authorization_policy`, treat a lease-loss error as a fenced retry.
  The failed worker cannot commit its checkpoint; the next lease generation
  refetches the singleton and deduplicates the tenant-scoped event identity.

## Family freshness probes

Some source families can make a cheap metadata call before the expensive read path. Cerebro calls this a family freshness probe. If the provider canary is unchanged, the source returns a `not_modified` short circuit and persists the refreshed probe checkpoint; if it changed, the source continues into the normal read path.

Use `sourcecdk.Family.Probe` or a checkpoint-aware source read for this pattern. Store probe metadata in `sourcecdk.CursorEnvelope.Extra` with:

```text
canary_kind
canary_resource_id
canary_observed_at
canary_updated_at
canary_hash
canary_confidence=authoritative|heuristic
canary_skip_count
canary_full_read_at
canary_reconcile_reason=initial|changed|short_circuit|max_skip_count|max_skip_age
```

Treat authoritative canaries, such as documented delta tokens, differently from heuristic canaries, such as newest audit-log event probes. Heuristic probes are dirty signals: they are useful for skipping likely unchanged scans, but they still need periodic full reconciliation if the provider does not document complete coverage.

Use `sourcecdk.FamilyFreshnessReadOptions` to make that policy explicit:

- set `MaxSkipCount` and `MaxSkipAge` for heuristic canaries so they cannot skip forever,
- set `ProbeErrorMode=fail_open` only when a failed metadata call can safely fall through to the normal read path,
- store opaque canary resource IDs and hashes only; do not persist provider document IDs, actor names, raw filter phrases, tenant names, or other customer-shaped metadata in `CursorEnvelope.Extra`.

Runtime telemetry records bounded freshness labels such as source, family, confidence, skip count, and forced-reconciliation reason. It must not emit canary hashes or provider resource IDs.

## Bootstrap runtimes from JSON

The CLI can load a list of runtimes from an environment variable:

```bash
export SOURCE_RUNTIMES_JSON='[
  {
    "id": "<runtime-id>",
    "source_id": "<source-id>",
    "tenant_id": "<tenant-id>",
    "config": {
      "key": "value"
    }
  }
]'

./bin/cerebro source-runtime bootstrap env=SOURCE_RUNTIMES_JSON
```

Use this for local experiments and platform-driven bootstrap flows. Do not put live provider tokens in the JSON. Use `env:` references for sensitive values.

Linux limits a single environment string to 128 KiB on 4 KiB-page hosts, and a larger value fails the container's exec before the CLI starts. For a larger document, set the variable to `gzip+base64:` followed by the standard padded base64 encoding of the gzip-compressed JSON; the CLI decompresses it (up to 16 MiB) before parsing. Plain JSON stays supported.

## Secrets and `env:` references

Source config can reference environment variables with values like:

```text
env:PROVIDER_API_TOKEN
```

The environment variable must be present at runtime and allowed by configuration. Use:

```bash
CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST=PROVIDER_API_TOKEN,ANOTHER_ALLOWED_SECRET
```

If a source uses constrained cloud role assumptions, use:

```bash
CEREBRO_AWS_ASSUME_ROLE_ARNS=<role-arn-allowlist>
```

Security rules:

1. Declare secret names, not secret values, in deploy manifests.
2. Inject secret values through your platform.
3. Allow only the env vars each source needs.
4. Keep provider credentials least-privilege.
5. Rotate source credentials like any other production secret.

## Runtime health

HTTP:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/health?tenant_id=<tenant-id>&limit=20"
```

Invalid event inspection:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/invalid-events?limit=20"
```

The Rust platform serves the tenant-bound runtime view at:

```bash
curl -fsS -H "Authorization: Bearer ${CEREBRO_OIDC_TOKEN}" \
  "https://cerebro.example.com/v1/source-runtimes/<runtime-id>/invalid-events"
```

Missing and cross-tenant runtime IDs return the same empty event list. The
response includes only bounded validation diagnostics; it never includes the
rejected provider payload or source-runtime credential references.

Use these during onboarding and after source code changes. Invalid events usually mean a source emitted data that failed validation or projection constraints.

## Claims and findings

Runtime-scoped claim and finding routes include:

```text
GET  /source-runtimes/{runtimeID}/claims
POST /source-runtimes/{runtimeID}/claims
GET  /source-runtimes/{runtimeID}/findings
GET  /source-runtimes/{runtimeID}/finding-candidates
GET  /source-runtimes/{runtimeID}/finding-evidence
GET  /source-runtimes/{runtimeID}/finding-evaluation-runs
POST /source-runtimes/{runtimeID}/finding-candidates/evaluate
POST /source-runtimes/{runtimeID}/finding-rules/evaluate
POST /source-runtimes/{runtimeID}/findings/evaluate
```

The SDK source is useful for application-owned inventory or posture claims. SDK runtimes may declare comma- or newline-separated `inventory_urns` for preview discovery, but durable inventory and posture evidence should still be written as runtime claims. See [`docs/start/getting-started.md`](../start/getting-started.md) for a local claim write.

Aperio is the canonical SaaS detection-pack producer for `aperio_saas_dr`. Its runtime should write findings, OAuth
grant topology, lifecycle refs, and response-action evidence through the same source-runtime claim and finding
contracts. See [Aperio integration contract](aperio-integration-contract.md) for the shared claim vocabulary and
ownership boundaries.

## Graph ingest from runtime

When graph is enabled:

```bash
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=100
```

HTTP:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  "https://cerebro.example.com/source-runtimes/<runtime-id>/graph-ingest-runs?page_limit=100"
```

Inspect graph ingest runs:

```bash
./bin/cerebro graph ingest-runs runtime_id=<runtime-id> limit=20
./bin/cerebro graph ingest-run <run-id>
```

### Projection identity changes

Projection identity changes must be handled as graph rebuilds, not as dual
writes of old and new URNs. When a source projection moves from a lossy
normalization to a collision-resistant key, run a dry-run rebuild for the
runtime, review the projected entity count and sample URNs, then rerun graph
ingest for the affected runtime:

```bash
./bin/cerebro graph rebuild <runtime-id> dry_run=true mode=replay preview_limit=20
./bin/cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Cosmo fact, message, session, and survey-feedback projections use hashed
external identifiers so raw keys containing `:`, `/`, whitespace, or mixed
delimiters cannot collide into the same graph URN. The raw provider key remains
available in attributes such as `record_id`, `key`, `ticket_id`, and
`thread_key`; use those attributes to reconcile old dash-normalized graph nodes
before pruning stale projection rows. Do not dual-write legacy Cosmo URNs: the
legacy normalization was ambiguous, and preserving it would reintroduce the
collision class the rebuild is meant to remove.

## Scheduling guidance

Use your scheduler or orchestrator to run sync jobs:

```bash
cerebro source-runtime sync <runtime-id> page_limit=100
```

Then, if graph projection is separate:

```bash
cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Recommendations:

- Use one schedule per runtime and operation.
- Forbid overlapping jobs for cursor-sensitive runtimes.
- Separate API service resources from scheduled job resources.
- Start with conservative cadence and page limits.
- Monitor provider errors, cursor advancement, invalid events, and graph ingest status.

## Source manifest and release handoff

Sources may include:

- `sources/<source-id>/catalog.yaml`, which describes source capabilities,
- `sources/<source-id>/deploy.yaml`, which declares source-level secret names and canonical runtime config,
- Source health receipts are derived at deploy-contract render time from connector, source catalog, and runtime metadata.

Catalogs may declare family-level freshness probes under `families[].freshness_probe`.
Use `confidence: authoritative` only for provider tokens or resource versions that
prove the scoped collection is unchanged. Use `confidence: heuristic` for cheap
signals such as newest updated resources or newest audit-log events; these can
reduce API calls, but runtimes must still force reconciliation after the declared
skip duration, skip count, reconciliation interval, manifest-version change, or
runtime config-hash change. GitHub audit-log canaries are a high-confidence broad
organization dirty signal when credentials can read the audit log, but they are
still heuristic and do not replace periodic family-specific reconciliation.

The deploy manifest intentionally declares what the source needs, not when or where your platform should schedule it. Deployment cadence and concrete secrets belong in your deployment system.

See [`docs/operations/release-contract.md`](../operations/release-contract.md) for how source manifests contribute to `cerebro-runtime-contract.json`.

## Troubleshooting quick map

| Symptom | Likely layer | First check |
| --- | --- | --- |
| `source-runtime put` fails | Postgres/config | `CEREBRO_STATE_STORE_DRIVER`, `CEREBRO_POSTGRES_DSN`, `/health` |
| sync returns unavailable | Postgres or JetStream | state store, append log, `/health` |
| sync does not advance | source/provider | credentials, rate limits, runtime config, cursor |
| invalid events appear | source validation | invalid event route, source emitted kinds, catalog |
| tenant forbidden | auth/tenant | credential tenant, request `tenant_id`, `X-Cerebro-Tenant` |
| graph ingest fails | graph dependency | Neo4j config, `graph health`, ingest run status |
