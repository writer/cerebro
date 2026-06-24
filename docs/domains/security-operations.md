# Security Operations

This document covers the security operations packages in Cerebro that support finding triage, event taxonomy, tool coverage mapping, and cross-event correlation.

It complements [Findings Platform Architecture](findings-platform-architecture.md), [GRC Architecture](grc-architecture.md), and [Architecture](../reference/architecture.md).

## Packages Covered

- `internal/proactivetriage` — proactive finding triage job runner
- `internal/securityevents` — canonical security event taxonomy
- `internal/securitytooling` — security tool control-mapping coverage normalization
- `internal/correlation` — built-in cross-event correlation hints

## proactivetriage — Proactive Finding Triage

`internal/proactivetriage` is a job runner that proactively triages open security findings. For each finding, it builds an agent evidence packet, searches for similar finding memory, generates recommendations via a pluggable recommender, and optionally writes triage recommendation actions.

### Pipeline

1. Load open findings via `FindingReader`
2. Build agent evidence packets using `agentplatform`
3. Search for similar past triage decisions via `MemorySearcher` (backed by `findingmemory`)
4. Generate recommendations via `Recommender` (uses an `Embedder` for similarity)
5. Optionally write triage actions via `ActionWriter` (backed by `knowledge`)

### Key Types

- `Service` — orchestrates the triage pipeline
- `FindingReader`, `MemorySearcher`, `Recommender`, `ActionWriter` — interface ports
- `RunRequest`, `RunResult` — job request and result
- `FindingTriageResult` — per-finding triage outcome with recommendations
- `Recommendation` — individual triage recommendation
- `Runner` — function adapter wrapping the service as a `jobs.Runner`

### Boundaries

- Triage logic, evidence packet construction, memory search, and recommendation generation stay behind this package
- The job scheduler in `internal/jobs` owns execution; this package owns the triage domain logic
- Recommendations are advisory; action dispatch remains in `internal/graphactions`

### Dependencies

`agentplatform`, `findingmemory`, `jobs`, `knowledge`, `ports`

### RBAC Ownership

`finding_manager` (finding lifecycle), `analyst` (risk scoring), `responder` (runtime response for actions)

## securityevents — Event Taxonomy

`internal/securityevents` defines canonical CloudEvent subject prefixes and event kind constants for the security platform namespace (`sec.*`). It provides a helper to check whether an event kind is already canonical.

### Constants

Finding lifecycle events:
- `FindingRecorded` — a finding was persisted
- `FindingStatusChanged` — finding status transitioned
- `FindingNoteAdded` — a note was attached to a finding
- `FindingTicketLinked` — an external ticket was linked
- `FindingExternalRefLinked` — an external reference was linked

Audit and tooling events:
- `APIAccessAudit` — API access audit event
- `ToolRegistered` — a security tool was registered
- `ToolHealth` — tool health signal

Prefix constants: `FindingsV1Prefix`, `AuditV1Prefix`, etc.

### Key Exports

- `IsCanonicalKind(kind string) bool` — checks if an event kind already has the `sec.` prefix

### Boundaries

- This is a shared taxonomy package with no dependencies on other internal packages
- Event producers and consumers across the platform reference these constants for consistent event routing

### RBAC Ownership

Cross-cutting shared taxonomy; primary consumers are `analyst` and `finding_manager` (finding lifecycle events), `viewer` (read)

## securitytooling — Tool Coverage Normalization

`internal/securitytooling` normalizes security tool control-mapping coverage values into posture states and generates tenant-scoped URNs for security tool control coverage records.

### Key Exports

- `CoverageStatus(coverage string) string` — classifies a coverage string into `"covered"`, `"gap"`, or `""` (unclassified)
- `ControlCoverageURN(tenantID, toolID, framework, controlID string) string` — builds a canonical URN for a tool-to-control coverage record

### Boundaries

- Pure normalization and URN construction; no store dependencies
- Consumed by GRC inventory and compliance coverage mapping

### RBAC Ownership

`grc_reviewer` (GRC inventory, posture/control mapping), `analyst`

## correlation — Cross-Event Correlation Hints

`internal/correlation/runtime` defines built-in correlation hints that identify multi-event security patterns across findings. Each hint specifies rule IDs, dimensions, a time window, a score bonus, matching reasons, and test cases.

### Built-In Hints

- `IdentityTamperThenCredentialChangeHint` — identity control tampering followed by credential creation within 24 hours. Provides a score bonus when both events appear in the same time window.

### Key Types

- `CorrelationHint` — hint definition with ID, name, rule IDs, dimensions, window, score bonus, reasons, and tests
- `CorrelationHintTest` — test case definition for validating a hint

### Key Exports

- `BuiltinHints()` — returns all built-in correlation hints
- `IdentityTamperThenCredentialChangeHint()` — returns the identity tamper + credential change hint

### Boundaries

- Hint definitions only; matching and scoring execution live in the findings and risk scoring packages
- No store dependencies; pure data definitions

### RBAC Ownership

`analyst` (risk scoring, dashboards), `finding_manager` (finding lifecycle)

## Code Map

- `internal/proactivetriage/service.go` — triage pipeline and job runner adapter
- `internal/securityevents/taxonomy.go` — event kind constants and canonical prefix helpers
- `internal/securitytooling/coverage.go` — coverage normalization and URN construction
- `internal/correlation/runtime/identity_tamper_then_cred_change.go` — built-in correlation hints
