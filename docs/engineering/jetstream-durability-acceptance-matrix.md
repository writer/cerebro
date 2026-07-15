# JetStream Durability Acceptance Matrix

This document reconciles issues #1300 through #1304 against repository state at
`v2.1.739` (`ec89d569`). It separates shipped behavior from remaining work so a
follow-on implementation can start at the actual boundary instead of rebuilding
merged foundations.

## Status Rules

- **Satisfied** means the acceptance criterion has an implementation path and
  test or checked-in operational evidence on `main`.
- **Partial** means a narrower mechanism exists but does not satisfy the full
  criterion.
- **Missing** means no repository-owned implementation was found.
- Runtime observations from the original incidents are context, not proof that
  a repository acceptance criterion remains satisfied. This matrix evaluates
  code, configuration, tests, and checked-in operations material.

## Outcome Summary

| Issue | Result | Disposition |
| --- | --- | --- |
| #1300, isolate findings publishes | 0 satisfied, 4 missing | Keep open. Implement a subject-to-stream router and a two-stream rollout. |
| #1301, publish SLO metrics | 4 satisfied | Closed. PRs #1307 and #1601 satisfy the original contract. |
| #1302, publisher bulkheads | 4 satisfied | Already closed by PR #1603. |
| #1303, durable recovery | 4 satisfied | Closed. PR #1594 satisfies the original contract; #1733 and #1734 track hardening. |
| #1304, NATS server stats | 0 satisfied, 1 partial, 3 missing | Keep open. Add a bounded monitoring-endpoint collector. |

Across the 20 original criteria, 12 are satisfied, one is partial, and seven
are missing.

## #1300: Isolate Findings Publishes

| Acceptance criterion | Status | Implementation evidence | Verification evidence | Remaining work |
| --- | --- | --- | --- | --- |
| Findings can be managed independently for retention, limits, and publish pressure. | Missing | `internal/appendlog/jetstream.Log` has one configured `streamName`; `applyExpectedStream` applies it to every message. | `docker-compose.yml` provisions only `CEREBRO_EVENTS` with `events.>`. | Provision a non-overlapping findings stream and route canonical `sec.findings.v1.*` subjects to it. |
| Stream/subject mapping is explicit and tested. | Missing | `eventSubject` correctly keeps canonical security subjects outside the `events` prefix, but there is no subject-to-stream mapping. | `TestAppendPublishesExpectedStreamHeader` covers only one global expected stream. | Add a typed route table, configuration validation, and routing tests for known and unknown subjects. |
| Existing readers continue or have a migration path. | Missing | Replay resolves one configured stream and current configuration documents one logical append-log stream. | No compatibility test exercises replay across general and findings streams. | Preserve general replay, add findings replay, define mixed-stream ordering/cursors, and test old/new reader overlap during migration. |
| Runbooks and telemetry identify the owning stream. | Missing | Publish telemetry records the configured expected stream and ACK stream when available. | Operations docs describe the global stream and findings bulkhead, not a findings stream owner. | Emit route/owner fields and document provisioning, cutover, rollback, lag, and capacity checks per stream. |

### Important finding

Canonical security event kinds intentionally publish as subjects such as
`sec.findings.v1.recorded`; they do not receive the default `events.` prefix.
The local Compose initializer currently provisions only `events.>`, while the
client sends the global `CEREBRO_EVENTS` expected-stream header for every
publish. The isolation implementation must correct this mapping explicitly. It
must not add `sec.>` to the general stream and call that isolation.

### Implementation handoff

1. Add a small route value to append-log configuration:
   `subject pattern -> stream name -> operational class`. The initial built-in
   routes should be `events.> -> CEREBRO_EVENTS -> general` and
   `sec.findings.v1.> -> CEREBRO_FINDINGS -> findings`. Reject overlapping
   patterns and reject a configured findings stream without a findings route.
2. Keep subject construction in `eventSubject`. Add a separate pure
   `streamRouteForSubject` function and use it when setting the
   `Nats-Expected-Stream` header. Unknown subjects must fail before publish when
   strict routing is configured.
3. Replace the single replay-stream assumption with a route-aware resolver.
   Single-family requests scan one stream. Mixed-family requests need a stable
   merge order and cursor containing stream identity plus sequence; raw sequence
   numbers from different streams are not comparable.
4. Provision both streams in local Compose and the owned deployment contract.
   Give findings independent max age, max bytes/messages, replica count, discard
   policy, and duplicate window. Do not use overlapping NATS subject ownership.
5. Use a staged production migration: provision empty stream, deploy dual-read
   capability, pause or drain finding publishers, change subject ownership,
   enable findings routing, verify canary and consumer state, then remove the
   compatibility read. Define the exact rollback point before subject ownership
   changes.
6. Emit `messaging.jetstream.route`, expected stream, ACK stream, stream mismatch,
   and route-resolution failure fields. Add per-stream publish SLO dashboards and
   capacity alerts.
7. Test route validation, expected-stream headers, general replay, findings
   replay, mixed replay ordering, cursor resume, a missing findings stream,
   stream mismatch, migration compatibility, and rollback configuration.

## #1301: Per-Subject Publish SLO Metrics

| Acceptance criterion | Status | Implementation evidence | Verification evidence | Remaining work |
| --- | --- | --- | --- | --- |
| Subject dimensions have bounded cardinality. | Satisfied | `boundedJetStreamMetricSubject` preserves `sec.findings.v1.recorded` and collapses unknown families. | `TestBoundedJetStreamMetricSubjectCollapsesUnknownFindingsSubjects`. | None for the original issue. Add route/stream dimensions only when #1300 lands. |
| Metrics cover success, failure, retries, exhaustion, and ACK latency. | Satisfied | `RecordJetStreamPublish` emits requests, retries, duration, and max-attempt exhaustion with status and error category. | `TestRecordJetStreamPublishMetricsAreLowCardinality` plus JetStream retry/exhaustion tests. | None. |
| Tests cover normalization and cardinality protection. | Satisfied | Subject normalization is a pure bounded helper. | Known, unknown findings, and dynamic `events.*` cases are asserted. Forbidden high-cardinality attributes are also checked. | None. |
| Metrics can drive alarms without parsing logs. | Satisfied | `docs/operations/observability.md` defines instruments and dimensions. | `docs/operations/observability/headroom-alerts.promql` contains publish failure, retry, exhaustion, and latency queries. | None. |

## #1302: Publisher Bulkheads

| Acceptance criterion | Status | Implementation evidence | Verification evidence | Remaining work |
| --- | --- | --- | --- | --- |
| Graph and finding publish paths use configurable concurrency limits. | Satisfied | The append-log client applies a global channel semaphore and a findings-specific semaphore configured by `CEREBRO_JETSTREAM_PUBLISH_MAX_IN_FLIGHT` and `CEREBRO_JETSTREAM_PUBLISH_FINDINGS_MAX_IN_FLIGHT`. | Config load/rejection tests and finding-subject routing tests. | Tune limits from production SLO data; no contract change required. |
| Saturation is observable. | Satisfied | Append telemetry includes enabled state, scopes, effective limit, and per-scope wait duration. | Global, findings-only, and combined bulkhead telemetry tests. | A queue-depth metric would be useful but is not required by the original criterion. |
| Cancellation and job deadlines remain correct. | Satisfied | Slot acquisition selects on `ctx.Done()` and releases already acquired scopes on later acquisition failure. | Deadline and global-slot-release tests. | None. |
| Tests cover bounded concurrency and failure propagation. | Satisfied | Channel capacity is the concurrency boundary; publish errors pass through the existing append error path. | Bulkhead capacity/deadline tests and the existing retry/failure suite run together in `internal/appendlog/jetstream`. | Add a race-focused multi-goroutine regression if the limiter implementation changes. |

## #1303: Durable Outbox or Dead Letter Recovery

| Acceptance criterion | Status | Implementation evidence | Verification evidence | Remaining work |
| --- | --- | --- | --- | --- |
| Exhausted publishes are durably recorded with required context. | Satisfied | `internal/appendlog/recovery` builds a deterministic record; `internal/statestore/postgres/append_log_dead_letters.go` stores subject, event/job/runtime/source context, retries, error category, hash, size, and envelope. | Recovery field tests plus Postgres schema/validation tests. | #1734 defines retention and payload governance. |
| The recovery path avoids JetStream recursion. | Satisfied | The wrapper writes directly through `AppendLogDeadLetterStore`; the production implementation is Postgres-backed. | Store failure is joined with the original publish error; non-exhausted errors are not recorded. | Keep Postgres the recovery owner. Do not move the only copy to a JetStream DLQ. |
| Operators can replay or discard records. | Satisfied | `cerebro append-log dead-letters list|replay|discard` reads Postgres, republishes only on replay, and records terminal state. | CLI argument tests and Postgres transition-conflict tests. | #1733 adds atomic replay ownership and lease recovery. |
| Tests cover persistence and replay/discard semantics. | Satisfied | Recovery, schema, bounded filters, pending-only upsert, terminal conflict, and CLI contracts are covered. | Focused packages passed in PR #1594 and remain in the repository suite. | #1733 adds concurrent replay tests; #1734 adds policy and cleanup tests. |

### Residual hardening

The original issue is complete, but the operator workflow is not yet safe for
uncoordinated automation. The current replay sequence reads a pending row,
publishes, and then marks it replayed. #1733 adds a Postgres claim/lease so two
operators cannot race that sequence. The table also stores a full envelope with
no retention or backlog contract; #1734 owns retention, sanitization, bounded
cleanup, metrics, and actor audit.

## #1304: NATS JetStream Server Stats

| Acceptance criterion | Status | Implementation evidence | Verification evidence | Remaining work |
| --- | --- | --- | --- | --- |
| Server stats are collected on an interval with timeouts and failure telemetry. | Missing | JetStream `Ping` performs account/stream checks when health is requested; there is no background monitoring-endpoint collector. | No `/jsz`, `/varz`, or `/connz` client or fixture exists. | Add an independently scheduled, timeout-bounded collector. |
| Metrics cover stream state, storage pressure, API errors/latency, and connection pressure. | Partial | Ping telemetry includes stream messages, bytes, sequences, consumers, subjects, and cluster leader/replicas. | JetStream canary and stream-state telemetry tests cover the client-derived subset. | Add storage limits/utilization, JetStream API totals/errors, connection counts/limits, pending bytes, and bounded consumer health from server endpoints. |
| Collection failure does not fail the app or collector task. | Missing | Health checks can report dependency failure, but no optional collector lifecycle exists. | No nonfatal collector test. | Keep scrape failure out of readiness and retry on the next interval with bounded error telemetry. |
| Parsers have representative fixture tests. | Missing | No server-monitoring parser package exists. | No `/jsz`, `/varz`, or `/connz` fixtures exist. | Add versioned fixtures, missing-field cases, oversized responses, malformed JSON, and forward-compatible unknown fields. |

### Implementation handoff

1. Add `CEREBRO_NATS_MONITOR_URL`, scrape interval, request timeout, and maximum
   response bytes. Do not infer the monitoring port from the NATS client URL;
   operators must opt in explicitly.
2. Create `internal/natsstats` with separate transport, parser, snapshot, and
   metric-projection layers. Use authenticated HTTP configuration where needed,
   prohibit redirects to a different host, and cap response bodies before JSON
   decoding.
3. Fetch `/varz`, `/jsz?streams=true&consumers=true`, and a bounded `/connz`
   view under one scrape deadline. A failure in one endpoint should mark only
   that endpoint stale and must not erase the last successful timestamp for the
   others.
4. Emit low-cardinality metrics for server up, scrape outcome/duration, memory,
   CPU, connections/limits, slow consumers, JetStream memory/file usage and
   limits, API total/errors, stream messages/bytes/consumer count, and consumer
   pending/redelivery state. Stream and durable consumer names are configuration
   inventory; cap them to explicitly selected names or a bounded allowlist.
5. Start the collector with the server lifecycle only when the monitor URL is
   configured. Scrape failures must not fail startup, liveness, readiness, or
   source work. Shutdown must cancel in-flight HTTP and stop the ticker.
6. Add fixtures for supported NATS response shapes, omitted optional sections,
   malformed data, server upgrades with unknown fields, authentication errors,
   timeouts, partial endpoint failure, response-size rejection, and clean
   cancellation.
7. Document least-privilege network access, authentication, interval tuning,
   dashboards, alerts, and the distinction between client publish SLOs and
   broker stats.

## Recommended Pull Request Order

1. **Findings stream route contract.** Pure configuration/router types,
   validation, and unit tests; no deployment cutover.
2. **Findings stream provisioning and replay.** Local/deployment configuration,
   route-aware replay, mixed cursor contract, compatibility tests, and runbook.
3. **Findings stream production cutover.** Environment-specific rollout with
   canary, dashboards, pause/drain steps, and rollback evidence.
4. **Dead-letter replay leases (#1733).** Atomic claims before any automated or
   bulk replay is added.
5. **Dead-letter governance (#1734).** Retention, sanitization, audit, capacity
   metrics, and bounded cleanup.
6. **NATS stats parser and fixtures.** Pure models/parsers with no runtime
   lifecycle coupling.
7. **NATS stats collector.** Safe transport, scheduler, OTEL metrics, operations
   docs, and failure-isolation tests.

Each implementation PR should update this matrix row-by-row. An issue closes
only when every original criterion is satisfied and residual production risks
have either an owner or an explicit accepted-risk decision.
