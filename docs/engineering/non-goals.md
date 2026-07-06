# Non-Goals

This document collects, in one place, the things Cerebro intentionally does not try to do. It exists because non-goals in this repo are otherwise scattered across [`ARCHITECTURE.md`](../reference/architecture.md), [`FINDINGS_PLATFORM_ARCHITECTURE.md`](../domains/findings-platform-architecture.md), and code-level guardrails, with no single index that a contributor, agent, or reviewer can read first.

Each section lists what Cerebro will not do, why that boundary exists, where in the codebase the boundary is enforced, and what evidence would justify revisiting the decision. The point is not to freeze scope. The point is to make scope drift expensive on purpose: if a change crosses one of these lines, the PR description should say so explicitly, and the corresponding entry in this document should be amended in the same change.

## How To Use This Document

- Treat each non-goal as a hard default. Crossing one is allowed; crossing one quietly is not.
- A PR that introduces a behavior listed below should cite the relevant entry, state which "What would change this" criterion has been met, and update this document.
- Reviewers should refuse changes that quietly bypass any non-goal, even when individual lines of code look reasonable in isolation.
- Agentic contributions follow the same rule. Pre-tool hooks, structural linters in `tools/linters/`, and arch tests in `tools/archtests/` are the mechanical backstops; this document is the human-readable contract they enforce.

## Storage And Durability

### One log of record. One state store. One graph projection. No fourth store.

- JetStream is the only writable long-term substrate. Postgres holds current state. Neo4j/Aura is a graph projection rebuilt from JetStream. Adding any other long-term store (SQLite-as-production, Kuzu, RedisGraph, DuckDB-as-warehouse, a separate "intelligence" store, a vector index treated as authoritative) is out of scope.
- Why: every additional store doubles the surfaces that need replay, tenancy, retention, and disaster-recovery thinking. The current three already pay for themselves; a fourth would have to clear a higher bar than its first happy-path use case.
- Enforced in: [`docs/reference/architecture.md`](../reference/architecture.md) "Store boundaries"; `tools/archtests`; and the `noinmemorydb` linter in `tools/linters/noinmemorydb`.
- What would change this: a documented capability that demonstrably cannot be served by JetStream, Postgres, or Neo4j without changing their operational profile, ratified in an architecture PR before any code lands.

### No in-memory or embedded database fallback in production.

- The bootstrap binary will not silently fall back to SQLite, BoltDB, or `:memory:` when JetStream/Postgres/Neo4j are absent. Routes that need a store either run with the configured store or fail closed.
- Why: in-memory fallbacks make local dev cheap by making production observability dishonest. The historical SQLite fallback produced exactly that gap, and the current arch-test stance is to reject it.
- Enforced in: `internal/config` driver wiring (no embedded driver registered), [`docs/reference/architecture.md`](../reference/architecture.md) "Kuzu and embedded/in-memory database backends are intentionally rejected by config and arch tests", and the `noinmemorydb` linter in `tools/linters/noinmemorydb`.
- What would change this: a separate, explicitly-named development binary (not the production server) that opts into an embedded store and is barred from CI artifacts and release images.

### No "if X fails, try Y" capability fallbacks.

- Each capability has exactly one implementation. Cerebro will not silently degrade a graph query to a SQL query, swap an LLM provider behind the caller's back, or substitute an action executor based on which dependency is reachable.
- Why: silent fallbacks hide the real failure mode and grow into a debugging tax that compounds with every new dependency. Typed capability errors are the contract.
- Enforced in: typed capability errors in runtime response paths and arch tests that reject silent fallback patterns.
- What would change this: a redundancy requirement that survives review on its own merits, with the redundancy modeled as a typed capability the caller can detect, not as a hidden swap.

### Snowflake is not a store of record.

- Cerebro's current `main` is the bootstrap service described in [`README.md`](../../README.md), [`docs/start/quick-reference.md`](../start/quick-reference.md), and [`docs/reference/architecture.md`](../reference/architecture.md). It does not require, and is not coupled to, the historical Snowflake-centered monolith. Documents that still assume Snowflake describe legacy behavior that is being retired, not target architecture.
- Why: tying Cerebro to one warehouse vendor conflicts with the cloud-agnostic runtime boundary in this document and the "boring, proven, operable" architecture described in [`docs/reference/architecture.md`](../reference/architecture.md).
- Enforced in: bootstrap config surface in [`internal/config`](../../internal/config), env vars in [`README.md`](../../README.md) "Configuration".
- What would change this: nothing inside this repo. Warehouse-shaped query workloads belong to a separate analytics layer that consumes Cerebro's events.

## Source CDK

### Sources are the only path to the outside world.

- Anything that talks to a third-party API, cloud SDK, file system mount, or webhook receiver is a Source. Application packages do not import `net/http`, `database/sql`, or vendor SDKs directly to reach the outside world.
- Why: the outside world is the highest-blast-radius surface in Cerebro. Funneling it through one CDK is what lets retries, pagination, error wrapping, replay, and tenant scoping be solved once instead of 46 times.
- Enforced in: arch tests in `tools/archtests`, [`docs/reference/architecture.md`](../reference/architecture.md) "Source CDK", and the Source CDK packages under `internal/sourcecdk`.
- What would change this: nothing for application packages. New "outside world" affordances must register as Sources or as a typed Source CDK extension reviewed under the same constraints.

### Sources are tiered: Standard connectors stay ≤300 LOC; Deep sources are bounded by the Depth Contract instead.

- **Standard connector (default).** A source may not exceed 300 LOC excluding generated code and fixtures. Within that budget, it may not call `net/http`, `database/sql`, `context.Background`, or `os.Getenv` directly. It may not write to JetStream, Postgres, or Neo4j. This is the tier every declarative catalog source lives in, and the LOC ratchet still forces shared concerns into the CDK.
- **Deep source (opt-in, gated).** A source that must reach GitHub/AWS-class provider coverage may exceed the flat LOC cap, but only in exchange for a stricter bar: it must satisfy the **Depth Contract** (`connectorcatalog.RuntimeDepth` score of 100 = verified `provider_api` proof, event + coverage contracts, read/discover fixture pairs, deploy manifest, and typed projector coverage) and carry a `>= fixture_validated` grade. A Deep source **may construct and use a vendored provider SDK client** (for example `aws-sdk-go-v2` or `github.com/digitalocean/godo`) through a Source CDK factory, the same way `aws` does. Deep tier removes the LOC ceiling; it does **not** remove any other boundary: `os.Getenv`, `context.Background`, and direct store writes remain forbidden, and provider I/O still funnels through the Source CDK. A source enters this tier only by being registered in `deepTierSourcePackages` in `tools/archtests/source_packages_test.go`, which swaps the LOC check for the Depth Contract check.
- Why: budgets force the CDK to absorb shared concerns, and that default must hold for the long tail of ~800 connectors. But a flat cap also makes genuine per-provider depth impossible, which is a real product gap for the high-value providers. Tiering keeps the cheap default cheap while making depth expensive in a measured, test-enforced way rather than as a quiet bypass. The legacy sources above the cap remain grandfathered as exact no-growth ceilings (`tools/archtests/source_packages_test.go`) and are migrated toward the Depth Contract over time.
- Enforced in: `tools/archtests/source_packages_test.go` (Standard LOC cap, grandfathered ratchet, and Deep-tier Depth Contract check), `tools/archtests/source_helper_duplication_test.go` (shared plumbing must live in `internal/sourcecdk`), `tools/linters/noenvoutsidecmd`, and `tools/linters/nobackgroundctx`.
- What would change this: nothing loosens the Standard default without a CDK affordance that demonstrably needs to be solved at the substrate. Promotion to Deep tier is the sanctioned path and requires meeting the Depth Contract; it is not a per-source LOC exception.

### Sources do not own normalization, persistence, or graph projection.

- A source emits typed events through `Source.Read`. Normalization, fingerprinting, persistence, and graph projection happen outside the source. Sources never see runtime IDs, finding IDs, or graph URNs.
- Why: this is the seam that makes replay, rebuild, and rule evaluation deterministic. If sources can mutate stores, replay loses its guarantees.
- Enforced in: `Source` interface in `internal/sourcecdk`; arch test that no `sources/*` package imports `internal/statestore`, `internal/appendlog`, or `internal/graphstore`.
- What would change this: nothing. Convenience for one source is not a reason to widen the contract for all of them.

### The CDK is not a plugin marketplace yet.

- Sources are in-process Go modules vendored in this repository. There is no first-party expectation that third parties drop binary plugins in at runtime, distribute sources via container images, or load them from a registry.
- Why: an in-process CDK is the smallest thing that proves the contract. Out-of-process plugins are a separate operational surface (signing, sandboxing, auth, blast radius) and should land only when the in-process surface has stabilized and the operational case is concrete.
- Enforced in: the in-process source registry in `internal/sourcecdk` and built-in source layout under `sources/`.
- What would change this: a documented operational threshold (source count, deploy blast radius, third-party authoring need) that justifies the cost of an out-of-process plugin contract, with a separate design doc covering signing, sandboxing, and lifecycle.

### Agent push surface (device-keyed write) is bounded to first-party fleet agents.

- Cerebro accepts push traffic only from first-party agents Cerebro itself authenticates and authorizes per-device. Third-party services and unmanaged callers do not write to the platform: they integrate via the Source CDK's pull contract.
- Why: a first-party agent is a substantively different trust shape from a third-party API. Cerebro provisions the device identity (bootstrap token via MDM), signs the JWTs, owns the rotation key material, and revokes the device. None of those affordances exist for third-party callers, and conflating them would erase the Source-CDK boundary that makes replay, rebuild, and rule evaluation deterministic. Distinct affordance gets distinct entry.
- Enforced in: [`internal/deviceauth`](../../internal/deviceauth) (token issuance, rotation, replay detection); the bootstrap auth pipeline in [`internal/bootstrap/auth.go`](../../internal/bootstrap/auth.go) (the device-JWT verifier sits next to the existing API-key and capability-token paths, not as a separate service); the `platform.devices.*`, `platform.telemetry.ingest`, and `security.devices.findings.read` scope set wired through `authorizeHTTPRequestScope`.
- What would change this: a second first-party agent class with materially different posture (e.g. server-side runtime agents, container sidecars). That belongs to its own design proposal and its own [`docs/engineering/non-goals.md`](non-goals.md) entry; reusing the SeCheck shape by default is not the answer.

## Graph And Cypher

### Neo4j is a projection, not a store of record.

- The graph is rebuildable from durable Cerebro records. Source runtime and workflow graph state must be reproducible from JetStream `entity.*`, `event.*`, or `workflow.v1.*` events. SDK/runtime claim graph state is currently reproducible from Postgres claim rows, as documented in [`DURABILITY_CONTRACT.md`](durability-contract.md), until a `claim.v1.*` event family exists. Direct `Neo4jSession.Run` writes from anywhere outside `internal/graphingest`, `internal/sourceprojection`, `internal/workflowprojection`, and the documented claim projection path are out of scope.
- Why: the graph drifts the moment two paths can write to it independently. Replayability is the property that lets findings, reports, and reasoning trust traversal results.
- Enforced in: [`docs/reference/architecture.md`](../reference/architecture.md) "Store boundaries", [`DURABILITY_CONTRACT.md`](durability-contract.md), workflow durability packages in `internal/workflowevents` and `internal/workflowprojection`, and graph write arch tests.
- What would change this: a workflow or claim concept whose durability genuinely cannot be modeled as either an event-and-projector pair or a documented current-state-backed rebuild source, ratified before code that writes to Neo4j directly is merged.

### The graph is not a general-purpose graph database product.

- Hard caps: ≤20 indexed attributes per node type, ≤6 hops per traversal query, ≤10 second p95 query budget, full rebuild ≤1 hour for a median tenant. Cerebro will not relax these to host customer graph workloads, run analytical SQL through Cypher, or expose unbounded read paths.
- Why: every cap above corresponds to an operational risk class. Removing them would make Cerebro responsible for query optimization across arbitrary tenant graphs, which is a different product.
- Enforced in: traversal limits enforced by the query translator in `internal/graphquery`, validator clauses in `internal/graphagent/validator.go`, and graph arch tests.
- What would change this: a tenant-scale or query-shape requirement that survives review and lands as a documented per-tenant configuration, not as silent removal of the cap.

### LLM-authored Cypher is read-only, LIMIT-bounded, tenant-scoped, and procedure-free.

- The Cypher safety validator in `internal/graphagent/validator.go` rejects any query that contains write or bulk-load tokens (`CREATE`, `MERGE`, `DELETE`, `REMOVE`, `SET`, `DROP`, `FOREACH`), `LOAD CSV`, `USING PERIODIC`, `apoc.trigger.*`, `apoc.periodic.*`, or any procedure `CALL`. It also requires every node pattern to carry the `Entity` label and inline `tenant_id: $tenant_id`, and rejects queries without a numeric `LIMIT` ≤ `MaxRows` (default 100). These constraints will not be loosened to support agent-authored data mutations or autonomous remediation through the graph.
- Why: LLM-authored Cypher is the largest agentic blast-radius surface in the codebase. The validator is the load-bearing safety boundary; weakening it has a multiplicative effect on every other risk in the system.
- Enforced in: `Validator.validate` and `allNodePatternsTenantScoped` in [`internal/graphagent/validator.go`](../../internal/graphagent/validator.go); validator test corpus in `internal/graphagent/validator_test.go`.
- What would change this: nothing for write tokens. New agent capabilities must travel through typed Action and workflow event surfaces, not through Cypher.

### The graph is not where org dynamics live as primitives.

- Bus factor, coordination fragility, privilege concentration, blast-radius posture, and similar derived analytics live on top of the shared graph as report runs and intelligence section views. They will not be promoted into standalone graph primitives, dedicated `/api/v1/*` resource trees, or new node categories until they require their own write lifecycle, durable IDs, approvals, or actuation semantics.
- Why: every promoted primitive is a permanent contract. Treating early views as report runs lets the platform iterate without growing a new tax surface.
- Enforced in: the current platform route layout in [`internal/bootstrap/routes.go`](../../internal/bootstrap/routes.go) and report/run contracts in [`internal/reports`](../../internal/reports).
- What would change this: a derived view that demonstrably needs durable IDs, approvals, or actuation, with the promotion proposed in a contract PR before the new resource ships.

## Findings Platform

### One rule per evaluation request. Always.

- The findings evaluation API selects exactly one rule per call. The bootstrap surface will not evaluate many rules in one request, run "all rules" against a runtime, or cross-tenant orchestrate evaluations.
- Why: the response carries one `RuleSpec` and persisted findings carry one `rule_id`. Multiplexing rules into one call breaks attribution, fingerprinting, and the durable evaluation run lineage that reports anchor on.
- Enforced in: [`docs/domains/findings-platform-architecture.md`](../domains/findings-platform-architecture.md) §3 "Generic Evaluation Service" and "Why the service selects exactly one rule per call"; the `?rule_id=` requirement on `POST /source-runtimes/{id}/findings/evaluate`.
- What would change this: a scheduler-owned orchestration layer that batches single-rule evaluations and persists the same evaluation-run lineage Cerebro already requires, designed in a separate doc.

### The findings platform does not own scheduling, leases, retries, or suppression workflows yet.

- The bootstrap surface intentionally does not provide cron-style rule scheduling, lease-based execution coordination, automatic retries, suppression assignment workflows, or control/check mapping. Today these live in product surfaces or are out of scope.
- Why: shipping these prematurely couples the rule registry to operational policy that is not yet stable. Keeping them out preserves the rule registry as a small, predictable seam.
- Enforced in: [`docs/domains/findings-platform-architecture.md`](../domains/findings-platform-architecture.md) "What This Does Not Solve Yet".
- What would change this: persistent operational pain expressed as a stable contract, not as ad-hoc scheduling glue inside individual rules.

### Findings are not a one-to-one mirror of upstream alerts.

- A finding is a remediable control gap or durable risk state. Source-native alerts and threats become evidence and graph context, not findings. SentinelOne threat records, GitHub Dependabot alerts, and Okta detections do not reproduce themselves as findings; they aggregate under control- or posture-shaped findings.
- Why: 1:1 mirroring imports upstream noise into Cerebro's lifecycle, makes fingerprinting unstable, and fragments remediation across vendor identifiers.
- Enforced in: [`AGENTS.md`](../../AGENTS.md) "Finding Rule Design Notes"; rule fingerprinting conventions in `internal/findings/`.
- What would change this: a control or posture story that genuinely requires per-alert lifecycle, not a feature request to "see all upstream alerts" through Cerebro.

### Findings persistence does not include free-form attachments.

- Persisted finding evidence is bounded to current finding attributes plus graph and report joins. Cerebro will not accept arbitrary file uploads into the findings store, mirror upstream PDF/HTML attachments, or expose a generic blob attachment surface from finding mutations.
- Why: file storage is a different operational surface (encryption, lifecycle, retention, scanning, signed URLs). The findings store is current-state, indexed, and tenant-scoped; it is not a content store.
- Enforced in: [`docs/domains/findings-platform-architecture.md`](../domains/findings-platform-architecture.md) "What This Does Not Solve Yet".
- What would change this: an explicit content-addressable storage layer designed and reviewed as its own subsystem, with finding evidence pointing into it by reference.

## Workflow And Action Engine

### The action engine is intentionally smaller than a workflow engine.

- `internal/actionengine` models `Signal`, `Trigger`, `Playbook`, `Step`, `Execution`, and `Event`. It is not a DAG runtime, not a long-running scheduler, and not a generic workflow product. Cerebro will not import Argo Workflows, Temporal, or Cadence-shaped semantics into the core just because remediation and runtime response can be expressed in those.
- Why: every workflow engine pays for itself only when DAG-level orchestration is actually needed. Cerebro's substrate is "the minimum model needed to unify remediation and runtime response" and growing it past that without evidence imports complexity that the rest of the system has to live with.
- Enforced in: the absence of a DAG/workflow runtime dependency and the current workflow event/projection packages.
- What would change this: a documented execution shape that genuinely requires DAG-level fan-out, conditional branching beyond per-step failure policies, or sub-workflow composition, ratified before code lands.

### Workflow durability is event-and-projection. Not graph-direct, not transactional outbox today, not optimistic.

- Decisions, actions, outcomes, finding notes, ticket links, and lifecycle status changes write a `workflow.v1.*` event before any graph mutation. Append failure prevents graph writes; graph failure leaves a replayable event behind. Cerebro will not write workflow nodes directly to Neo4j, swallow projection errors, or skip the event when the append log is configured.
- Why: the graph is a projection. Workflow writes that bypass the event are unreplayable and reintroduce the silent-drift class of bugs that workflow durability was designed to remove.
- Enforced in: `internal/workflowevents`, `internal/workflowprojection`, and graph write arch tests.
- What would change this: only a reviewed workflow durability proposal that preserves replay filters, finding workflow events, outbox behavior, and timeline reads. Skipping ahead is out of scope.

### No autonomous remediation through agents.

- The Agent primitive composes Events, Streams, Views, Rules, and Actions under a policy. It does not get a private path to mutate Postgres or Neo4j. It does not author Cypher writes. It does not call Actions without going through the typed Action contract, including approval gates and trusted actuation scope where required.
- Why: autonomous remediation is the failure mode that justifies most of the safety surface in Cerebro. Letting an Agent route around any of it would erase the reason the safety surface exists.
- Enforced in: `internal/graphagent/validator.go`; trusted runtime-response scope derivation in `internal/bootstrap/auth.go`; and mutation gating in `internal/runtimeresponse`.
- What would change this: nothing structural. Agent capabilities grow by adding typed Actions and Rules, not by widening Agent's direct surface.

## Runtime Response

### Runtime response will not mutate from unauthenticated identifiers.

- Runtime response mutations require a server-derived trusted actuation scope. Cerebro will not accept a runtime target identifier from an unauthenticated source, treat a finding payload as a containment authorization, or fail open when actuation scope is missing.
- Why: containment is the highest-stakes runtime side effect Cerebro performs. The trusted actuation scope is what keeps a malformed finding from triggering a real outage.
- Enforced in: runtime response authorization checks and trusted actuation scope derivation in `internal/bootstrap` and `internal/runtimeresponse`.
- What would change this: a stronger authorization model that subsumes trusted actuation scope; loosening current behavior is not on the table.

### Cerebro is not a replacement for the endpoint sensor or container runtime.

- Runtime response operates above an existing sensor or runtime substrate (eBPF agent, EDR, K8s API, cloud control plane). It will not ship a kernel agent, a container runtime, a node-side daemon, or its own packet path. It depends on those substrates and is honest about what is and is not covered when they are absent.
- Why: shipping runtime infrastructure is a separate engineering and operational discipline. Cerebro's value is in the typed control loop above it, not in re-implementing the substrate.
- Enforced in: capability errors when a remote tool provider is unconfigured.
- What would change this: nothing inside this repo.

### Runtime response is not yet a fully-distributed containment system.

- Today the runtime blocklist is process-local. Persisted/distributed propagation, provider-native credential revocation, and host/network isolation across common clouds are tracked as gaps, not promised. Cerebro will not pretend that policies "succeed" when the actuator path is missing.
- Why: silent-success in containment is worse than honest "not configured". The Follow-On Gaps section in the runtime response doc names the gaps so they cannot be glossed.
- Enforced in: runtime response capability checks and explicit actuator-path errors.
- What would change this: distributed blocklist propagation and provider-native actuator paths, designed and reviewed as separate work.

## Platform Vs Application Boundary

### Cerebro is not exclusively a security product.

- The platform exposes shared primitives such as graph, knowledge, source runtimes, workflow replay, jobs, and runtime response through typed bootstrap routes. Security, governance, and operations are application surfaces that use those primitives rather than redefining them.
- The platform vocabulary will not adopt security-first naming as default. "Security graph", "asset", "finding", "compliance", and "threat intel" are valid security application nouns; they are not the platform vocabulary.
- Why: collapsing platform into security ships a worse platform and a worse security product. Both layers benefit from explicit contracts.
- Enforced in: the current HTTP route surface in [`internal/bootstrap/routes.go`](../../internal/bootstrap/routes.go), [`docs/reference/api-reference.md`](../reference/api-reference.md), and [`docs/reference/api-contracts.md`](../reference/api-contracts.md).
- What would change this: nothing. New application surfaces (DataOps, ML observability, supply chain, GRC programs) follow the same boundary.

### Cerebro is not a CSPM, CNAPP, CWPP, EDR, SIEM, SOAR, or IDS replacement.

- Cerebro complements those categories; it does not replace them.
  - It does not retain raw logs forever or expose a SIEM-grade investigation UI.
  - It does not run an endpoint sensor.
  - It does not own response automation as its primary product surface; runtime response is a constrained subsystem with explicit gates, not a SOAR.
  - It does not author cloud posture from Cerebro's own scanners as the source of truth; cloud posture findings come from typed sources whose budgets are explicit.
- Why: Cerebro's value is the typed substrate (events, claims, evidence, decisions, workflows, the read graph, and the safety boundary). Promising a replacement promise would force the codebase to take on operational scope that is incompatible with that substrate.
- Enforced in: [`README.md`](../../README.md) "Runtime Boundaries" and the current route surface in [`docs/reference/api-reference.md`](../reference/api-reference.md).
- What would change this: nothing in this repo. Category-shaped products belong on top of Cerebro, not inside it.

## Operational And Distribution

### Cerebro does not ship an end-user web UI from this repository.

- The repo exposes JSON HTTP, Connect RPC, and CLI surfaces. It will not host an end-user web console, a dashboarding UI, an investigation workbench, or a chat surface.
- Why: a console is a separate product with separate distribution, accessibility, and security constraints. Pulling it into the bootstrap repo would couple every release of either to the other.
- Enforced in: cmd/cerebro entrypoints and the documented CLI, JSON HTTP, Connect RPC, SDK, and MCP surfaces in [`README.md`](../../README.md).
- What would change this: nothing. Console-shaped products consume Cerebro through its typed APIs from a separate repository.

### Cerebro does not host or proxy LLM providers.

- The platform integrates with LLM providers through typed clients and configured endpoints. It will not embed LLM weights, run a local inference engine, broker model calls between tenants as a service, or treat any LLM provider as a global default.
- Why: model hosting is a distinct operational surface (GPU lifecycle, model versioning, inference budgets). Treating it as part of Cerebro distorts both products.
- Enforced in: graph agent provider config in `internal/graphagent` and bootstrap config in [`internal/config`](../../internal/config).
- What would change this: nothing in this repo. Inference belongs in an LLM-serving layer that Cerebro consumes.

### Cerebro is not multi-cloud control plane code.

- Bootstrap and source code does not assume AWS, GCP, or Azure as the control plane. Sources may target cloud APIs as data sources; the runtime itself does not require any cloud's IAM, queue, or orchestration product.
- Why: cloud-agnosticism is a deliberate runtime boundary. The moment the control plane requires a specific cloud, "boring, proven, operable" stops being true for half the deployment surface.
- Enforced in: absence of cloud-specific runtime dependencies in `internal/bootstrap`.
- What would change this: a deployment shape that demonstrably cannot be served by Postgres, NATS, and Neo4j running in the operator's environment of choice.

### Cerebro will not maintain undocumented compatibility aliases indefinitely.

- Legacy `/graph/*` aliases for routes that have moved to `/platform/graph/*` exist only when there are real consumers. When no known consumer exists, the alias is removed quickly rather than preserved as silent drift.
- Why: indefinite aliasing turns the API surface into a museum of every past decision. Removal discipline keeps the contract honest.
- Enforced in: route registration in [`internal/bootstrap/routes.go`](../../internal/bootstrap/routes.go) and deprecation header behavior in `internal/bootstrap`.
- What would change this: a documented external consumer that justifies the alias for a defined window, tracked with a removal date.

## Vocabulary

These framings will not be adopted as Cerebro's product description:

- "Security graph" as a product surface noun. Cerebro exposes a graph; one of its applications is security.
- "AI security" as a positioning frame. Cerebro uses LLMs in narrow, validator-gated places. The substrate, not the LLM, is the product.
- "Autonomous remediation" or "self-healing security". Cerebro performs constrained Actions with typed approval and trusted actuation scope. It does not self-direct.
- "Replacement for [vendor product]". Cerebro is the platform underneath what those products would otherwise be the only source of truth for. Replacement framing misdescribes the seam.

Vocabulary creep in docs, code comments, marketing surfaces, and AI-generated artifacts is in scope for this document the same way capability creep is. Wording PRs that flatten Cerebro into a single category should cite this section and propose a more precise phrasing.

## Maintenance

This document is considered correct when:

- Every "Enforced in" pointer resolves to current code, doc, or linter content.
- Every newly merged PR that crosses a non-goal cites the relevant entry and updates this document in the same change.
- New non-goals discovered during review are added here rather than relitigated in PR threads.

Update mechanics: change this file in the same PR that introduces the boundary change, get review from the Platform CODEOWNER set, and update [`docs/start/quick-reference.md`](../start/quick-reference.md) and [`README.md`](../../README.md) where they reference the changed behavior.
