# Runtime Connector Ingest: Unified Pull + Deposit Contract

- Status: Draft for review (no code yet)
- Date: 2026-06-22
- Repos: `writer/cerebro` (backend), `writer/cerebro-web` (UI)
- Related: [`non-goals.md`](non-goals.md), [`source-cdk-extraction.md`](source-cdk-extraction.md), [`architecture.md`](../reference/architecture.md)

## 1. TL;DR

Cerebro users should be able to add a new source at runtime (define it, validate it,
preview it, promote it, and have it ingest) without writing Go or opening a GitHub PR.
Today the relevant surface is framed around code generation and PR scaffolding, which is
the wrong model.

The cleanest path is the one the rest of the industry already uses for no-code connectors:
a declarative manifest interpreted by a single runtime engine. Cerebro already has roughly
90% of this (the `connectordefinitions` manifest plus the `catalogruntime` JSON-API
executor). This spec finishes the wiring and adds a second, narrow ingest transport so we
can support **both** directions:

- **Pull** (default, the Airbyte model): Cerebro fetches from the source on a schedule.
  No governance change required.
- **Deposit** (the bounded exception, the Vanta case): the customer pushes typed records to
  a connector-scoped inbox that only appends to the log of record. Requires one narrow
  `non-goals.md` amendment.

Both transports share one manifest, one normalization step, and one projection pipeline, so
replay, tenancy, and graph rebuild are identical regardless of direction. We also model the
connector the way Kafka Connect and Airbyte do: a definition (blueprint) plus a runtime
instance with explicit status and lifecycle.

Two honest caveats from the research: the single hard blocker for end-to-end ingestion is
projector registration for dynamic definitions (G2), not the executor; and custom tests are
the one piece that is genuinely net-new, because findings rules are compiled Go today and a
runtime-authored test needs a declarative (CEL-based) layer (section 7.8). Custom tests are
therefore sequenced as a separate effort, off the connector critical path.

## 2. Problem statement

The "Source CDK" / codegen surface in `cerebro-web` presents code-generation and GitHub-PR
framing:

- `src/lib/connectors.ts` exposes `SourceCDKScaffoldPlan` with `files` and `pr_body`, and a
  `SourceCDKPromotionPlanMetrics.generated_files` metric.
- `src/app/connectors/source-cdk/page.tsx` surfaces a "Generated files" readiness view.

The stated intent is the opposite: let a Cerebro user promote a new source at runtime, the
way Vanta lets an admin stand up a custom integration from the dashboard with no code and no
repo change.

## 3. Goals and non-goals

Goals:

- Define, validate, live-preview, and promote a source at runtime with no Go and no GitHub.
- Promotion actually activates ingestion (today it does not).
- Custom resource schemas and custom tests authored at runtime.
- Support both pull and deposit ingest under one contract.
- Move `sourcegen` codegen to an internal-only hardening utility, off the customer surface.

Non-goals (unchanged by this work):

- Not a plugin marketplace; sources remain in-process and budgeted (`non-goals.md`, the 300
  LOC rule in `source-cdk-extraction.md`).
- Deposit is not a generic unbounded write API. It is typed, connector-scoped, and only
  appends to the log of record. It never writes Postgres state or the Neo4j graph directly.
- No fourth store, no capability fallbacks (`non-goals.md` storage section is untouched).

## 4. Current state (evidence)

Already built in `cerebro`:

- `internal/connectordefinitions/definition.go`: the declarative manifest (transport, auth
  including OAuth/JWT/sigv4/apikey, pagination, incremental, projection) plus
  `Normalize` / `Validate` / `Promote`. Validation already advertises "the safe declarative
  JSON API executor".
- `internal/bootstrap/connector_definitions.go`: tenant-scoped CRUD, validate, and promote,
  persisted to Postgres via `ports.ConnectorDefinitionStore`
  (`internal/ports/connectordefinitions.go`).
- `sources/internal/catalogruntime/source.go`: the generic JSON-API executor
  (`NewDefinition` -> `jsonapi.Source` with `Check` / `Discover` / `Read`), exposed via the
  thin adapter `sources/catalogruntime/source.go`.
- `internal/sourceregistry/registry.go` `DynamicDefinitionSource(...)`: adapts a stored
  definition into a runnable source.
- `internal/sourceruntime/service.go` `lookupDynamicConnectorSource(...)`: `Sync` already
  runs dynamic tenant definitions through that adapter.
- `internal/sourceruntime/lease.go` `SyncWithLease(...)`: a durable, renewable runtime lease
  (`SourceRuntimeLeaseStore`) already coordinates syncs across replicas and an orchestrator.
  Scheduling is lease-based and orchestrator-driven; we do not need to build a scheduler.
- `internal/bootstrap/auth_api_client_credentials.go` `exchangeAPIClientCredentialsToken(...)`:
  an OAuth2 `client_credentials` grant already mints a tenant- and scope-scoped capability
  token via `issueCapabilityToken`. This is Vanta's exact token model.
- `internal/connectordefinitions/definition.go` `ProjectionSpec`,
  `ProjectionEntitySpec` (entity type, URN kind, id attributes), `ProjectionRelationshipSpec`,
  and `ResourceFamily` (`IDField`, `Event`, validated `urn_kind`): custom resource schema and
  custom graph edges are already fully modeled and validated.

Conclusion: the pull/read engine for dynamic definitions already exists and runs, scheduling
and capability-token issuance already exist, and the custom-resource schema is already
modeled. The missing pieces are instance lifecycle/projection wiring, the deposit transport,
a declarative custom-test layer, and the UI.

### Confirmed gaps

- **G1: promote does not activate, and definition-vs-instance is not surfaced.**
  `internal/bootstrap/connector_definitions.go` `handlePromoteConnectorDefinition` only
  advances the stage and persists. A connector definition is a blueprint; ingestion runs from
  a `SourceRuntime` instance (`internal/bootstrap/connectors.go:1226` builds
  `SourceRuntime{Id, SourceId, TenantId, Config}`). The gap is a clear promote ->
  instantiate -> activate flow, plus an explicit instance status and lifecycle (Kafka Connect
  has `RUNNING` / `PAUSED` / `FAILED` / `STOPPED` + `pause` / `resume` / `stop` / `restart`);
  Cerebro has neither status nor lifecycle ops on a runtime today.
- **G2: dynamic definitions have no projector.**
  `internal/sourceprojection/catalogruntime.go` `registerCatalogRuntimeProjectors` loads
  `connectorcatalog.BuiltinRuntime()` and registers projectors only for built-in catalog entries
  (wired from `internal/sourceprojection/registry.go`). A tenant's dynamic definition has
  no registered projector, so even successfully pulled events never project into the graph.
  This is the single hard blocker for end-to-end ingestion of a custom source.
- **G3: no deposit transport**, and `non-goals.md` currently forbids third-party push.
- **G4: UI is codegen-framed** (`cerebro-web`), not runtime-activation-framed.
- **G5: custom tests have no runtime path.** `internal/findings` rules are compiled Go: the
  `Rule` interface (`registry.go`) plus a `builtinRegistry` built at `init()` from
  `builtinRulePacks()`. There is no data-driven rule loader, so Vanta-style custom tests
  require a new declarative-rule layer (section 7.8), not just wiring.
- **G6: capability credentials are static config.** The `client_credentials` grant reads
  `cfg.Auth.APICredentials` (static config), so there is no runtime path to mint, scope,
  rotate, or revoke a per-connector credential. Deposit needs dynamic per-connector
  credential registration (section 7.3).

## 5. Prior art (gh CLI study)

| Project | Runtime model | Codegen at runtime? | Ingest | Lesson for Cerebro |
|---|---|---|---|---|
| Airbyte Low-Code CDK | Declarative manifest run by one interpreter | No | Pull | Manifest == Cerebro's `connectordefinitions`; live preview contract |
| Kafka Connect | Compiled connector plugin; instances configured at runtime via REST | Plugin yes, instance no | Pull | Definition-vs-instance split; explicit lifecycle + status |
| OTel Collector | Config-driven receivers feeding one consumer pipeline | No | Push and pull | Push/pull are sibling transports into one pipeline |
| Vector | Config-driven sources | No | Push and pull | Same runtime serves `http_server` (push) and `prometheus` (pull) |
| Steampipe / CloudQuery | Compiled Go plugin binary per source | Yes | Pull | The codegen world Cerebro is leaving |
| Meltano / Singer | Python tap code per source | Yes | Pull | Same |
| RudderStack | Config-driven, write-key auth | No | Push | Per-source token + messageId dedup == deposit shape |
| Vanta | Dashboard-defined integration | No | Push | The runtime-promotion outcome we want |
| OPA Gatekeeper / CEL | Data-driven policies/expressions loaded at runtime | No | n/a | How to author tests at runtime without compiling code |

Findings:

- Airbyte's `declarative_component_schema.yaml` (5,296 lines) describes a `DeclarativeSource`,
  and a single engine (`manifest_declarative_source.py` / `concurrent_declarative_source.py`)
  validates and runs any manifest with no per-connector code. Its vocabulary (ApiKey / Basic
  / Bearer / JWT / OAuth / SessionToken auth, Cursor / Offset / Page pagination, datetime
  incremental cursors, dpath extraction, dynamic schema discovery) is the same set Cerebro's
  `connectordefinitions` already models.
- Airbyte ships a live builder backend (`connector_builder/connector_builder_handler.py`:
  `read_stream` with a record limit, `resolve_manifest`) that does a bounded test-read and
  returns sample records. That is the contract a no-code builder UI needs.
- Everyone who does runtime, no-code connectors does it via pull. The compiled-plugin
  projects are the model Cerebro is leaving (build and ship an artifact, like today's
  `sourcegen` path).
- Vanta is the lone push case, and structurally so: as pure SaaS it cannot reach a
  customer's internal or on-prem systems to pull, so the customer must push.
- Kafka Connect proves the definition-vs-instance split. The connector plugin is compiled,
  but instances are created and reconfigured at runtime over REST
  (`POST /connectors`, `PUT /connectors/{name}/config`) and carry an explicit lifecycle
  (`pause` / `resume` / `stop` / `restart`) and status state machine (`UNASSIGNED`,
  `RUNNING`, `PAUSED`, `FAILED`, `RESTARTING`, `STOPPED`). Cerebro already has the analogue:
  a `ConnectorDefinition` (blueprint) and a `SourceRuntime{Id, SourceId, TenantId, Config}`
  (instance). What is missing is the explicit instance status and lifecycle ops.
- OTel Collector and Vector prove push and pull are sibling transports into one pipeline. An
  OTel receiver "translates data from any format to the collector's internal format" and
  feeds one consumer whether it is push (Zipkin) or pull (Prometheus scrape). Vector serves
  push (`http_server`, `splunk_hec`, `syslog`) and pull (`http_client`, `prometheus`,
  `*_metrics`) sources from one config-driven runtime. This is exactly section 7.4.
- RudderStack proves the deposit shape in Go: a per-source write key resolves the source
  (`authReqCtxForWriteKey`, `ErrSourceNotFound`) via query param or HTTP Basic auth, and a
  dedup service (`services/dedup`) deduplicates on a message id. That maps to a
  connector-scoped capability token plus an idempotency key.
- OPA Gatekeeper and CEL show how user-authored tests run at runtime without compiled code:
  Gatekeeper splits reusable logic (`ConstraintTemplate`) from per-instance parameters
  (`Constraint`); CEL (`cel-go`) is a non-Turing-complete, sandbox-safe expression language
  (the same one Kubernetes `ValidatingAdmissionPolicy` uses for runtime-authored checks).

Implication: lead with pull (it is both the industry standard and ~90% built), and treat
deposit as the bounded exception for genuinely unreachable data. Model the connector as a
definition (blueprint) plus a runtime instance with explicit status and lifecycle, and treat
custom tests as a separate declarative-rule effort (section 7.8) because Cerebro's findings
rules are compiled Go today.

## 6. Governance constraints

From `non-goals.md`:

- "Sources are the only path to the outside world" (line ~50): anything reaching the outside
  world is a Source. The pull path satisfies this directly.
- "Agent push surface (device-keyed write) is bounded to first-party fleet agents" (line 74):
  "Third-party services and unmanaged callers do not write to the platform: they integrate
  via the Source CDK's pull contract." The entry also states the rule for new cases:
  "Distinct affordance gets distinct entry," and that a new push posture "belongs to its own
  design proposal and its own `docs/engineering/non-goals.md` entry; reusing the SeCheck
  shape by default is not the answer."

Therefore:

- Pull requires no governance change.
- Deposit is a new third-party write affordance. It must not reuse the device-JWT shape, and
  it must land as its own `non-goals.md` entry (proposed in section 11), ratified by a
  Platform CODEOWNER in the implementation PR that enables deposit.

## 7. Design: one contract, two transports

### 7.1 The manifest is the single contract

The connector definition stays the single source of truth. Add an `ingest` block:

```jsonc
// connectordefinitions.Definition (new field, illustrative)
"ingest": {
  "mode": "pull",            // "pull" (default) | "deposit"
  "deposit": {               // present only when mode == "deposit"
    "resource_families": ["user_account", "review_record"],
    "full_state_sync": true  // omitted ids in a sync are tombstoned
  }
}
```

Custom resource schema is already expressible: `ResourceFamily` plus `ProjectionSpec` /
`ProjectionEntitySpec` / `ProjectionRelationshipSpec` (`definition.go`) declare the entity
type, URN kind, id field, attributes, and graph edges, and they are already validated. That
is the "custom resources" feature, and it requires no new model.

`ResourceFamily` is pull-shaped today (`Path`, `Method`, `RecordSelector`, `Pagination`,
`Incremental`). For `mode = deposit` those pull-only fields become optional: a deposit family
is defined by `IDField`, its `Event` mapping, and its `Projection`. Validation should branch
on `ingest.mode` so a deposit family is not rejected for missing a `Path`.

### 7.2 Pull transport (lead; no governance change)

For reachable APIs, the existing `catalogruntime` JSON-API executor fetches on a schedule.
The only new work is activation (7.5) and projector registration (7.6).

### 7.3 Deposit transport (bounded exception)

This section is proposed design only. Deposit remains blocked by the current non-goal until
the section 11 amendment lands with the implementation that enables this transport.

For data Cerebro cannot reach (internal apps, on-prem inventory, CI/CD events), the customer
POSTs typed records to a connector-scoped inbox:

- **Auth (mechanism exists, runtime issuance is the gap):** the OAuth2 `client_credentials`
  grant already mints tenant- and scope-scoped capability tokens
  (`auth_api_client_credentials.go` `exchangeAPIClientCredentialsToken` ->
  `issueCapabilityToken`). This is Vanta's exact `client_credentials` model and a distinct
  trust shape from the device JWT. The gap (G6) is that credentials come from static config
  (`cfg.Auth.APICredentials`). Deposit needs runtime per-connector credential registration:
  at connection creation, mint a `client_id` + hashed secret scoped to one tenant + one
  connector + its declared resource families, persisted to the existing credential store and
  rotatable/revocable. The customer presents it exactly like RudderStack's per-source write
  key (`authReqCtxForWriteKey` resolves the source).
- **Handler:** validates each record against the manifest's resource-family schema, then
  appends typed events to the log of record via `ports.AppendLog.Append`
  (`internal/ports/appendlog.go`). It never writes Postgres or Neo4j directly. It is
  idempotent on a record key (cf. the `Idempotency-Key` handling in `handleIngestTelemetry`,
  RudderStack's `services/dedup` on message id, and Vanta's `uniqueId`). With
  `full_state_sync`, ids absent from a sync window emit tombstone events.
- **Precedent:** this mirrors the shape of `internal/bootstrap/device_handlers.go`
  `handleIngestTelemetry` (bounded body, validate, normalize against a typed contract,
  idempotent append), but with connector-scoped capability auth instead of a device JWT.
- **Secrets:** the deposit `client_secret` and any pull credentials go to the credential
  store, never into the definition JSON or the runtime `Config` map. This matches Airbyte
  (secret-marked fields persisted to a secret manager) and Kafka Connect (`ConfigProvider`
  indirection); Cerebro already has the credential store (`credentialStoreID`,
  `connectorTransitKey`, encrypted submission) to reuse.

### 7.4 Convergence: one pipeline

Both transports emit `*cerebrov1.EventEnvelope`. From there the path is identical: the
dynamic projector registered in 7.6 (`ports.SourceProjector.Project`,
`internal/ports/projection.go:182`) turns events into graph entities. Because both transports
land only in the log of record, replay, tenancy, and graph rebuild are preserved.

```
pull:    catalogruntime executor --\
                                     >-- EventEnvelope --> AppendLog --> SourceProjector --> graph
deposit: connector inbox handler --/
```

### 7.5 Definition, instance, and lifecycle (fixes G1)

Follow the Kafka Connect and Airbyte split: a `ConnectorDefinition` is the blueprint
(promoted through stages); a `SourceRuntime{Id, SourceId, TenantId, Config}` is the running
instance. Two distinct user actions:

- **Promote** a definition: publishes the blueprint and makes it instantiable. Stays in
  `handlePromoteConnectorDefinition` (`connector_definitions.go`).
- **Create a connection** from a promoted definition: provisions a `SourceRuntime` instance
  (this flow already exists at `connectors.go:1226`). For pull, the existing jobs
  orchestrator picks it up and syncs via `SyncWithLease` (`sourceruntime/lease.go`); we do
  not build a scheduler. For deposit, registration binds the inbox and mints the
  connector-scoped credential (7.3).

Add an explicit instance **status** and **lifecycle**, which Cerebro lacks today and every
runtime-connector system has (Kafka Connect: `RUNNING` / `PAUSED` / `FAILED` / `STOPPED`,
plus `pause` / `resume` / `stop` / `restart`). This is what the UI binds to and what makes a
failed custom source debuggable instead of silent.

### 7.6 Dynamic projector registration (fixes G2)

Register a catalog-runtime projector built from the tenant definition's projection spec:

- at activation (7.5), and
- at startup, by iterating stored active definitions, not just `connectorcatalog.BuiltinRuntime()`.

This reuses `registerCatalogRuntimeProjectorsForEntries`
(`internal/sourceprojection/catalogruntime.go:22`), which already builds projectors from a
projection spec; it just needs to be fed tenant definitions.

### 7.7 Live preview builder contract (Airbyte parity)

The builder's validate/preview action does a bounded test-read (`Check` then `Read` with a
record limit) and returns sample records plus logs, instead of generating files. This extends
the existing `/connector-definitions/validate` surface (or adds `/connector-definitions/preview`).
It is the direct analogue of Airbyte's `read_stream` builder command.

### 7.8 Custom tests (needs a new declarative-rule layer)

This is the one part of Vanta parity that is not mostly-built. Cerebro's findings rules are
compiled Go: the `Rule` interface and a `builtinRegistry` constructed at `init()` from
`builtinRulePacks()` (`internal/findings/registry.go`). There is no data-driven rule loader,
so "author a custom test at runtime" cannot reuse the existing seam as-is; that would be the
same codegen-vs-runtime mismatch we are fixing for connectors, one layer up.

The SOTA answer is a safe, non-Turing-complete expression layer rather than user-supplied
code:

- **CEL** (`cel-go`): non-Turing-complete, sandbox-safe, Go-native. It is what Kubernetes
  `ValidatingAdmissionPolicy` uses for runtime-authored checks, so it is a proven fit for
  "users write a boolean check that runs in our process." Recommended.
- **Gatekeeper's split** of `ConstraintTemplate` (reusable test logic) from `Constraint`
  (per-instance parameters) maps directly to Vanta's model of a reusable test plus
  per-customer configuration.

Proposed: a declarative `CustomTest` (CEL expression + parameters + target entity type/family
+ control mapping) evaluated against projected entities/events, adapted to the existing
`Rule` interface so the evaluation path and one-rule-per-evaluation contract are unchanged.
Because this introduces a runtime-authored detection surface distinct from the compiled
rulepack, it warrants its own short design note and a `non-goals.md` check before
implementation. It is sequenced after the connector work, not bundled into it.

## 8. Web changes (`cerebro-web`)

- `src/app/connectors/source-cdk/page.tsx`: reframe from "Generated files" / scaffold to a
  runtime activation view: validation state, live preview, promote, and per-instance status
  (`RUNNING` / `PAUSED` / `FAILED` / `STOPPED`), last sync, records ingested, and errors,
  with `pause` / `resume` / `restart` controls (the Kafka Connect status surface).
- `src/app/connectors/builder/page.tsx`: validate -> live preview records; promote ->
  publish; "Create connection" -> provision an instance; add an ingest-mode selector (pull
  endpoint config vs deposit credential + sample `curl`).
- `src/lib/connectors.ts`: replace `SourceCDKScaffoldPlan.files` / `pr_body` and the
  `generated_files` metric with definition/instance, status, and ingest-mode types.

## 9. Codegen to internal utility

`internal/sourcegen` and the `/promotion-plan` handler
(`internal/sourceplanapi/handlers.go`) move behind an internal admin/CLI surface. They become
the optional "harden a certified runtime connector into a built-in Go source" path described
in `source-cdk-extraction.md`, removed from the customer-facing UI. This keeps the documented
hardening pathway while taking codegen off the runtime product surface.

## 10. Phased plan

1. **P2 backend wiring (G2 first, then G1):** dynamic projector registration is the single
   hard blocker, so do it first; then the instance lifecycle/status (create connection ->
   activate -> orchestrator syncs). After this, a promoted pull definition ingests end to end
   and is observable. No governance change.
2. **P1 web reframe + live preview:** fix the wrong page; wire the Airbyte-style preview and
   the instance status surface.
3. **P3a custom resources:** deposit/pull-aware `ResourceFamily` + `ProjectionSpec` validation
   (mostly already modeled; mainly the deposit-family validation branch from 7.1).
4. **Codegen to internal:** move `sourcegen` / `/promotion-plan` off the customer surface.
5. **P3b deposit transport:** runtime per-connector credential issuance (G6) + the deposit
   handler, only after the section 11 amendment is ratified.
6. **P3c custom tests (separate effort):** the CEL-based declarative `CustomTest` layer (7.8),
   gated on its own design note. Largest net-new piece; not on the connector critical path.

## 11. Proposed `non-goals.md` amendment (for deposit)

New entry under "Source CDK", distinct from the device-push entry:

> ### Connector deposit ingest is a typed, connector-scoped, log-only write.
>
> - A promoted connector definition may declare `ingest.mode = deposit`. A third-party caller
>   holding a connector-scoped capability token may then POST records that match the
>   definition's declared resource families. The handler validates each record against the
>   manifest schema and appends typed events to the log of record only. It does not write
>   Postgres state or the Neo4j graph directly, cannot exceed the connector's declared schema,
>   and is tenant- and connector-scoped.
> - Why: some customer data (internal apps, on-prem inventory) cannot be pulled. Deposit gives
>   that data the same typed, replayable contract as a pull source while keeping the single
>   log-of-record invariant. It is a distinct trust shape from device-keyed push (Cerebro
>   issues, rotates, and revokes a connector-scoped capability token, not a device identity),
>   so it gets its own entry rather than reusing the SeCheck shape.
> - Enforced in: the deposit handler in `internal/bootstrap`, the capability-token scope set
>   wired through `authorizeHTTPRequestScope`, and the manifest schema validation in
>   `internal/connectordefinitions`.
> - What would change this: removing the per-connector schema bound, or allowing deposit to
>   write state or graph directly, would collapse it back into a generic write API and is out
>   of scope.

## 12. Risks and open questions

- Capability-token minting: the issuer exists (`exchangeAPIClientCredentialsToken` ->
  `issueCapabilityToken`); the open work (G6) is a runtime registry of per-connector
  credentials (mint / scope / rotate / revoke) to replace static `cfg.Auth.APICredentials`.
- Deposit retention, replay windows, rate limits, and abuse handling (bounded body like the
  device path; per-token rate limiting; dedup store like RudderStack's `services/dedup`).
- Full-state vs incremental deposit semantics and tombstoning.
- Whether a single source should support both transports simultaneously (pull backfill +
  deposit realtime). The contract allows it (OTel/Vector precedent); the UI may gate it.
- Instance status/lifecycle: confirm the `SourceRuntime` model and store can carry a status
  enum + last-sync/error fields, and that the orchestrator honors a paused/stopped instance.
- Custom tests (7.8): pick CEL vs a thin DSL; decide template+params modeling; confirm
  whether a runtime-authored detection surface needs its own `non-goals.md` entry.
- Scheduling ownership for activated pull runtimes: reuse the jobs orchestrator +
  `SyncWithLease` lease; no new scheduler.

## 13. Validation plan

- Backend: `make verify` (or the repo's lint + arch tests + unit tests), including
  `tools/archtests` and the Source CDK budget linters.
- Web: the repo's lint, typecheck, and unit tests.
- New tests: dynamic projector registration (end-to-end pull -> graph), connection
  activation + instance status/lifecycle transitions, deposit handler validation +
  idempotency + log-only behavior, per-connector credential mint/rotate/revoke, a preview
  test-read, and (when built) CEL `CustomTest` evaluation against projected entities.
