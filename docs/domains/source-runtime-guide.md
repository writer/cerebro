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

`cloud_identity` runs one bounded Kubernetes-used AWS/GCP principal cohort.
It emits `cloud_identity.principal_evidence` and `cloud_identity.coverage`;
native rules produce `cloud-identity-excess-privilege` and
`cloud-identity-shared-principal`. It is implemented entirely in Cerebro,
without a security-reviewer service or reviewer-validation dependency.

The `cohort` runtime requires a JSON `scan_plan`: a stable `scope`, `targets`
with provider/account or project, cluster/environment, cluster `region`
(required for AWS so EKS reads use the cluster's own regional endpoint),
pinned manifest inputs and Terraform roots, and `services` mapping image
prefixes to application repositories/source roots. A service mapping may list
`workloads` (controller names) to separate logical services that share one
image; equal-prefix mappings that still tie between services leave the workload
unclassified with an `ambiguous_service_mapping` gap rather than picking one.
A manifest input may list Argo CD `applications`: only those
Application/ApplicationSet names are expanded from an app-of-apps render, and
each expanded Application pins its own `targetRevision` to a commit for the
run. Cluster names must be unique across targets, because workload IDs,
service-account subjects, and resolved cluster identifiers are keyed by cluster.
A Terraform root may declare `metadata_bindings` that map reviewed data-source
traversals (for example a bootstrap remote-state `project_id` output) to the
target's own project ID, project number, region, or account; bound values always
come from scan inputs and no Terraform state is read. One run inventories all
targets before grouping consumers by canonical cloud principal. See
[`sources/cloud_identity/deploy.yaml`](../../sources/cloud_identity/deploy.yaml)
and [`internal/cloudidentity/collection_models.go`](../../internal/cloudidentity/collection_models.go)
for the executable configuration contract.

Collection uses the existing GitHub App, AWS organization scan role, and GCP
Workload Identity Federation. GitHub installation routing uses lowercase owner
keys, either `github_installations` JSON or separate `github_installation_<owner>`
config entries. Credentials resolve through the normal source secret boundary;
they are not included in events or model prompts. Terraform module and external
chart reads require `allowed_modules`, `registry_modules`, and
`allowed_chart_repositories` allowlists; an allowlisted registry module may
resolve to its upstream github.com repository without a second allowlist entry,
and only the official `registry.terraform.io/` host prefix is accepted on
registry sources. Repositories are materialized from one archive per commit,
with every file verified against the commit's git tree, within bounded file,
entry, and decompressed-byte budgets.

Supported inputs include raw Kubernetes YAML, Helm with local/vendored/allowlisted
remote dependencies (disabled dependencies are neither fetched nor gapped), Argo
Applications including multi-source values, chart-relative `valueFiles`,
`valuesObject` and parameters (typed like Helm `--set`, or strings with
`forceString`), list-based ApplicationSets, Crossplane XRole-style compositions
(exactly named `function-environment-configs` by reference, inline
`function-go-templating` with a deterministic function allowlist, and
`function-auto-ready`; legacy claims map to their XRD's composite type) expanded
once per target so claims and the Compositions deployed by other charts meet,
Upbound/Config Connector IAM resources including the namespaced `.m.upbound.io`
groups and disabled custom roles, and statically resolvable Terraform HCL (remote
Git/registry modules with subdirectories and their sibling directories,
`terraform.tfvars`, `terraform.tfvars.json`, and `*.auto.tfvars[.json]` in
Terraform's precedence, `aws_caller_identity`/`aws_region`/`google_project` and
the default Google provider project from supplied inputs). Module inputs and
outputs are evaluated only when identity, trust, grant, or boundary expressions
depend on them. JSON Terraform configuration (`.tf.json`) is not parsed and
leaves that module's declarations incomplete. Rendering and HCL evaluation do not
run repository code, Terraform providers, `plan`, or `apply`. Helm renders
client-side like Argo CD: `lookup` returns empty and DNS lookups are disabled.
Charts whose templates or fully coalesced values (chart and subchart defaults
plus overrides) use random or certificate-generation functions are rendered
twice; differing identity-relevant output (names, namespaces, ServiceAccount
annotations, workload service accounts, images, configuration, IAM resources,
and the full content of custom resources such as composites, including their
metadata) is a coverage gap, while differences confined to generated data are
accepted. Identical time-derived values across both renders cannot be detected.
Unsupported generators and functions, malformed values, dynamic values, missing
modules, denied files, and access denials produce scoped coverage gaps.

Inventory uncertainty is scoped by observed trust. A target-level gap (render,
repository, or composition failures; invalid identity annotations) leaves a
principal incomplete when it has consumers in that target, when its observed
trust could admit that target's workloads (the cluster's OIDC provider, EKS Pod
Identity, or the project's Workload Identity pool), or when its trust is
unknown. An unrendered shared ServiceAccount affects only principals whose trust
could admit that subject. Gaps about an already-identified workload, such as an
unmapped image, stay with that workload's own principal.

### Automatic promotion

Excess permissions become a finding only when the consumer inventory and trust
scope are closed, every consumer has a digest-pinned image-to-source mapping and
content-bound investigation, and deterministic validation establishes a conservative
required-permission set. The model proposes citations/operations; it cannot set
validation or promotion flags. Known conditional/dependent permissions remain in
that required set rather than being treated as unused.

Source analysis can prove completeness for a bounded set of direct Go SDK calls
in the files of a Linux build without custom tags. Test files, `testdata`, and
files Go never compiles (names starting with `_` or `.`) are ignored;
production files excluded by build constraints keep the scope incomplete when
they use a cloud SDK. Lexical shadowing of clients, builtins, and imports is
honored, and every evaluated expression is inspected. Python/JavaScript
patterns, unknown wrappers/dependencies, replaced SDK modules, unsupported call
forms, ambiguous receivers, and operations without a verified primary and
dependent permission set remain incomplete. The supported operation profiles
live in the AWS/GCP definition adapters.

An image establishes the deployed application revision only when the deployed
workload reference itself names a verified digest and its OCI source labels name
the repository and a full commit ID agreed by every potentially runnable image
in an index. Tag-only references never establish it: current registry tag
immutability says nothing about the digest a tag named when the workload was
deployed, so excess for tag-deployed workloads stays incomplete. Branch or short
revisions, missing labels, unclassifiable or truncated index entries,
disagreeing images, and digest mismatches never establish exact provenance.

The rule compares the union of consumer requirements with desired IaC and live
IAM independently. A supported finding identifies `iac`, `live`, or `both`;
tentative excess on an incomplete opposite side is not promoted with it.
Unknown evidence is not a clean result: `NotAction` and wildcard-service grants
need the complete AWS action catalog; resource complements (`NotResource`),
partial or conditional denies, boundary intersections that cannot be proven,
Allow conditions whose effect cannot be determined (principal-bound keys,
unsupported operators, GCP CEL other than literal `true`/`false`), and GCP
project ID/number comparisons without a resolved mapping make that side
incomplete instead of clear. Deleted or disabled custom roles grant nothing;
unresolved roles stay unknown. Drift is reported only between two complete
sides. Trust must restrict assumption to reviewed consumers: IRSA by exact
subject and the consumer cluster's resolved OIDC provider; EKS Pod Identity by
association evidence plus session-tag conditions naming the reviewed cluster,
namespace, and service account; GSAs by exact Workload Identity members, treating
unresolved roles and roles with credential-minting permissions (`getAccessToken`,
`getOpenIdToken`, `signBlob`, `signJwt`, `implicitDelegation`) on the account or
its ancestors as assumption-capable. Every ancestor binding is discovered and its
role resolved individually; denied role lookups remain gaps. `actAs` is not
treated as assumption.

Native rules and graph projections measure freshness at evaluation time, not the
event's occurrence time; evidence older than 48 hours, or dated in the future,
neither opens nor closes findings and projects as not current. Automatic closeout
requires complete, validated, fresh evidence on both sides and preserves existing
lifecycle replay ordering. Sharing is independent: two positively mapped distinct
services whose workloads are positively linked to one resolved principal suffice
even when other observation coverage is partial. A positive link requires
effective assumption: an IRSA statement allowing `sts:AssumeRoleWithWebIdentity`
for that subject, EKS Pod Identity association evidence plus a statement allowing
`sts:AssumeRole` and `sts:TagSession`, or an unconditional GSA binding to a
resolved role with `getAccessToken`, `signBlob`, or `signJwt`. Sharing closes only
when every workload is classified and linked, the inventory and live trust are
complete and reconciled, and every trust role is resolved.

### Scheduling and native findings

Use a daily cohort schedule; manual runs are supported and no webhook is required.
The orchestrator phase limit must accommodate the source's `timeout`, for example
`orchestrator run runtime_id=<cohort-runtime> phase_timeout=3h`.

This scan emits native Cerebro findings only. It does not publish tickets or
require Jira credentials, signed publication actors, or an approval workflow.

The scan never mutates IAM/cloud resources, probes permissions by attempting
operations, applies infrastructure, or creates remediation PRs.


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
