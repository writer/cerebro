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
It emits `cloud_identity.principal_evidence` and `cloud_identity.coverage`.
Cerebro owns collection, evidence validation, canonical identity
resolution, coverage, and graph context; it has no excess-privilege or
shared-principal decision logic of its own. VulnView is the detection
authority for that posture: see "Evidence handoff and VulnView posture"
below.

The `cohort` runtime requires a JSON `scan_plan`: a stable `scope`, `targets`
with provider/account or project, cluster/environment, cluster `region`
(required for AWS so EKS reads use the cluster's own regional endpoint),
pinned manifest inputs and Terraform roots, and plan-level `services`
mapping image prefixes to application repositories/source roots. A target
may also declare its own `services`, appended after the plan's own
`services` for that target's own inventory passes only (its own provider
pass, and an extra federated-GCP pass for an AWS target with a paired GCP
`project`), never visible to another target. A service mapping may list
`workloads` (controller names) to separate logical services that share one
image; equal-prefix mappings that still tie between services leave the workload
unclassified with an `ambiguous_service_mapping` gap rather than picking one.
A manifest input may list Argo CD `applications`: only those
Application/ApplicationSet names are expanded from an app-of-apps render, and
each expanded Application pins its own `targetRevision` to a commit for the
run. Cluster names need not be globally unique: workload IDs, service-account
subjects, and resolved cluster identifiers are keyed by cluster name
qualified by the cluster's owning AWS account or GCP project (preferring
the target's AWS account, then its GCP project), so two clusters that
share a name in different accounts/projects never collide. A target with
neither a known account nor project never mints a workload/service-account
identifier for its consumers.
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
registry sources. A non-GitHub module source address may instead be routed
through `module_source_overrides` (a JSON object mapping the module call's
`source`, with any `//subdir`/`?query` removed and compared
case-insensitively, to a `github.com/<owner>/<repo>//<subdir>?ref={version}`
template): the module call's own exact `version` substitutes for
`{version}`, and the resolved owner/repo must still appear in
`allowed_modules` or `allowed_repositories`. Repositories are materialized
from one archive per commit, with every file verified against the commit's
git tree, within bounded file, entry, and decompressed-byte budgets.

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

### Input assertions and known gaps

A target or Terraform root may declare `input_assertions`: facts the plan
generator's own (possibly private) inputs already proved about a pinned
input, re-checked once per run against the input actually materialized at
`source` through the same shared repository cache every other collection
read uses, so a pin identical to a manifest/Terraform input pin observes
the exact same materialization. Each assertion names a `kind` --
`file_digest` (a file's exact sha256), `directory_entries` (a directory's
immediate children, optionally filtered by a `path.Match` `pattern`),
`hcl_value` (a statically evaluable top-level or `locals` HCL attribute,
optionally narrowed by a dot-separated `selector` and/or reduced to
`keys_only`), or `data_value` (a parsed YAML/JSON file, narrowed the same
way, or projected to specific `fields`) -- and the `expected` value to
compare against. A target-level assertion failure becomes an **inventory**
gap (`cloud_identity.input_assertion_failed`, scoped to the target), which
demotes `consumer_inventory_complete` the same way any other target-scoped
gap does; a Terraform-root-level assertion failure becomes a **declaration**
gap on that same target, demoting its declared policy side instead. An
unreadable assertion source repository is itself a failure, never silently
skipped.

A target may also declare `known_gaps`: coverage problems the plan
generator already detected in its own private inputs, each a `{"code",
"message"}` pair. Every entry becomes an inventory gap
(`cloud_identity.plan_known_gap`, scoped to the target, message
`"<code>: <message>"`); the supplied `code` is informational only and is
never used to scope the resulting gap -- it demotes the declaring target's
own cohorts exactly like any other target-scoped gap, regardless of what
code the generator happened to supply.

Terraform-contract values that only exist in remote state are listed in a
manifest input's `unresolved_values`; the renderer binds an unmistakable
marker so charts still render, and reports
`cloud_identity.manifest.unresolved_value_in_object` for each rendered object
the marker reaches. Only identity-bearing objects (ServiceAccounts, workload
service-account bindings, ACK and Crossplane IAM objects) demote the
affected principals. Markers confined to other objects stay visible as gaps
without making consumer inventory incomplete.

### Federated GCP identity

GCP workload identity federation through a custom (non-GKE) pool resolves
before generic GKE canonicalization, so a federated target's ServiceAccount
hosted on another cloud is never aliased to the project's GKE pool. Every
declared impersonation of a Google service account through the exact pool
subject is resolved, not only the first match, and each one is kept only
when that account's own live IAM policy confirms the exact pool member with
a role resolved with an impersonation permission (an unresolved or
view-only role never confirms); a binding that fails live confirmation
leaves the ServiceAccount's placeholder cohort in place (alongside any
other bindings that did confirm) with
`cloud_identity.gcp.custom_pool_binding_not_live`. Every directly granted
pool subject (`principal://.../workloadIdentityPools/<pool>/subject/system:serviceaccount:<ns>:<sa>`)
likewise becomes its own principal, and a ServiceAccount can simultaneously
resolve onto more than one Google service account and a direct principal.
Pool identity is always the pool's project number plus pool id. Provider
facts attached to evidence (`gcp_workload_identity_providers`) come only
from live reads of the pool's providers, which need
`iam.workloadIdentityPoolProviders.list` on the pool's project. A pool whose
providers cannot be listed carries
`cloud_identity.gcp.workload_identity_provider_unreadable`, and VulnView
never treats it as admitting. Each resolved custom-pool cohort, including a
Google service account already named by a ServiceAccount annotation, also
carries the AWS reader's own `aws_eks_oidc_issuer:<cluster>` for EVERY
distinct cluster/account/region among its own federated-target consumers
(resolved on both the IRSA and the EKS Pod Identity path; a ServiceAccount
annotation shared across more than one federated target carries every one
of those clusters' issuers, not only its first consumer's), letting the
detector cross-check that a declared provider's issuer actually belongs to
this cluster; when no AWS observation resolved a given cluster's issuer, or
two of a cohort's own clusters share a name but resolve different issuers,
the cohort carries `cloud_identity.gcp.custom_pool_issuer_unresolved`
instead of a fabricated, borrowed, or silently overwritten value.
The graph `can_impersonate` edge uses the same validated
gate: a role Definitions actually resolved with an impersonation
permission, a binding with no condition (or every condition the literal CEL
expression `true`), and an exact subject match whose `principal://` project
number equals the collected `gcp_project_number:<project>` -- an unresolved
role, an unknown or different project number, or any other condition never
confirms the edge.

### Evidence handoff and VulnView posture

After each collection pass, the source optionally publishes an immutable,
content-addressed evidence bundle to a VulnView-owned S3 intake bucket
(`evidence_handoff_bucket`, `evidence_handoff_stream`, optional
`evidence_handoff_region`; disabled when no bucket is configured). The
bundle is a deterministic gzip of the same principal-evidence and coverage
payloads this run already emitted, written with a conditional create so a
retried publish of identical content is idempotent. The publish outcome
(`published`, `failed`, or `disabled`, with a non-secret-bearing failure
code) is recorded on the `cloud_identity.coverage` event's `handoff` field.
A failed or disabled publish never drops the collection's own events. See
[`sources/internal/cloudidentity/handoff.go`](../../sources/internal/cloudidentity/handoff.go).

VulnView verifies each published bundle (digest, size, freshness, schema)
before running its own excess-privilege and shared-principal detectors
against it, then reconciles the result into durable findings and run
history. Cerebro imports VulnView's authoritative output back through the
existing `vulnview` source's `cloud_identity_finding` and
`cloud_identity_assessment` families (`/exports/findings` and
`/exports/assessments`, both scoped to `source=cloud_identity`), emitting
`vulnview.cloud_identity_finding`, `vulnview.cloud_identity_run`, and
`vulnview.cloud_identity_assessment` events. These events join the graph
through the same canonical AWS role / GCP service account URNs the
`cloud_identity` source and the AWS/GCP provider sources already use, via
`has_evidence` links; they carry upstream severity as `source_severity`
and never match a Cerebro finding rule, since VulnView's verdict is not
re-derived locally. See
[`sources/vulnview/cloud_identity_exports.go`](../../sources/vulnview/cloud_identity_exports.go)
and
[`internal/sourceprojection/vulnview_cloud_identity.go`](../../internal/sourceprojection/vulnview_cloud_identity.go).

Both families page VulnView's cursor-feed export routes
(`sourcecdk.CursorFeedPage`: `items`, `nextCursor`, `hasMore`) and implement
`sourcecdk.CheckpointAwareSource`/`Family.ReadWithCheckpoint` rather than the
plain `Read` path, so every pull -- including an empty page or VulnView's
terminal (`hasMore:false`) page -- returns a resumable
`sourcecdk.CursorEnvelope` checkpoint carrying VulnView's raw `nextCursor` as
`Token`. A later sync resumes from that exact VulnView cursor instead of
restarting the whole feed or (for `cloud_identity_assessment`) replaying
run history already reconciled. The checkpoint watermark is the max of the
prior checkpoint's watermark and the newest emitted event's `OccurredAt`, so
it never regresses. `Pull.NextCursor` (the in-sync continuation cursor) is
only set when VulnView reports `hasMore`.

`cloud_identity_run`/`cloud_identity_assessment` record and event IDs are a
SHA-256 digest of a length-prefixed canonical tuple (run: `scanId`,
`runId`; assessment: `scanId`, `runId`, `checkId`, `provider`,
`principalId`), not a lossy `/`/`:`-to-`-` replacement join: two distinct
principal IDs that only differ in separator placement (for example two AWS
role ARNs `role/a-b` and `role/a/b`) can never alias to the same ID.
`OccurredAt` is deterministic, never `time.Now()`: an assessment event uses
`collectedAt`, else `evaluatedAt`, else `completedAt`; a run event uses
`finishedAt`, else `completedAt`.

The stable `vulnview.cloud_identity_assessment` graph entity carries `at`
(the assessment's source time, RFC3339 UTC) and
`observation_precedence:"strict"`, so a late-arriving older run can never
regress it with stale posture. The `vulnview.cloud_identity_finding` entity
opts in the same way and also carries `observation_version`, VulnView's
per-finding `version`, which orders its writes instead of `at`: VulnView
samples `updatedAt` before its conditional write commits, so a concurrent
writer can commit a higher version with an earlier `updatedAt`. A stale
observation of either entity changes nothing -- not its attributes, typed
`source_id`/`runtime_id`, or label -- whether it reaches the graph store
directly or within the same graph-ingest page as the newer one (see
[`internal/projectionmeta/observation.go`](../../internal/projectionmeta/observation.go)).
`at` on the finding stays the version's `updated_at` (sub-second precision
kept) and only orders writes whose versions are equal or unparseable. The
projector only canonicalizes a principal
subject that is well-formed for its claimed provider and kind: a raw
`k8s://` placeholder subject, a Kubernetes-placeholder `principal_kind`
(`aws_kubernetes_service_account` / `gcp_kubernetes_service_account`), a
non-ARN AWS value, or a non-email/non-`principal://` GCP value all surface
as the `missing_or_invalid_principal_subject` gap instead of a dangling
`has_evidence` link. A fully resolved GCP `principal://` subject always
canonicalizes, regardless of kind.

Cloud-identity fingerprints used by collection and evidence identity use
the typed helpers in
[`internal/cloudidentity/digest.go`](../../internal/cloudidentity/digest.go).
Structured values are marshaled once before `DigestJSON`; byte and string
fingerprints retain their historical JSON encodings. Encoding failures
surface as errors or explicit gaps, not fabricated digests.

### Scheduling

Use a daily cohort schedule; manual runs are supported and no webhook is
required. The orchestrator phase limit must accommodate the source's
`timeout`, for example
`orchestrator run runtime_id=<cohort-runtime> phase_timeout=3h`.

This scan does not publish tickets or require Jira credentials, signed
publication actors, or an approval workflow. It never mutates IAM/cloud
resources, probes permissions by attempting operations, applies
infrastructure, or creates remediation PRs.

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
