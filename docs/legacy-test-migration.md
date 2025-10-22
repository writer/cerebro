# Legacy Test Suite Migration Plan

The refactor that enabled OODA telemetry, deterministic benchmarks, and self-play tournaments introduced breaking changes to the earlier Phase‑0 integration suites. This document captures the gaps and the changes required to migrate those tests (and any dependent code) onto the current architecture.

## Primary Breaking Changes

| Area | Legacy Behaviour | Current Behaviour | Migration Action |
| --- | --- | --- | --- |
| ORM identifiers | Models exposed both `session_id`/`message_id`/`invocation_id` aliases and `id` PKs. | Only the UUID primary key `id` remains. | Replace usages of the alias properties with `.id`, or add compatibility `@property` accessors forwarding to `self.id` where public APIs require them. |
| Deprecated columns | Fields such as `AgentSession.is_active` were persisted. | Lean schema removed these flags in favour of telemetry-driven status. | Drop kwargs in tests or reintroduce columns via migration if the product still needs them. |
| Enum vocabulary | `ToolInvocationStatus` included values like `APPROVED`, `EXECUTED`, `FAILED`. | Enum now covers execution states: `PENDING`, `RUNNING`, `SUCCESS`, `ERROR`, `DRY_RUN`, `APPROVAL_REQUIRED`. | Update assertions/mocks to the new values; map “approved” workflows to `APPROVAL_REQUIRED → SUCCESS`. |
| Async session lifecycle | Tests shared a single `AsyncSession` instance across coroutines. | Runtime opens a fresh `AsyncSession` per operation via `async_session_factory()`. | Refactor fixtures/utilities to create per-task sessions; avoid committing concurrently on one session. |
| Runtime/tool facade | Tests mocked the old agent runtime and tool registry interfaces. | Runtime orchestration moved into `runtime_common`/telemetry services with new method signatures. | Rebuild mocks against the current interfaces (e.g. `AgentRuntimeFacade.create_session`, `send_message` returning chunks, telemetry callbacks). |
| Bulk ops idempotency | Expected IAM/config bulks to be idempotent via unique constraints. | Refactor removed constraints, so duplicates currently insert again. | Decide whether to restore DB uniqueness & conflict handling or relax the tests to mirror actual behaviour. |
| Engine config checks | Tests asserted `engine.pool.pre_ping is True`. | Async engine stores the flag on `pool._pre_ping`. | Change assertions to inspect `_pre_ping` (or expose a helper in `cerebro.core.database`). |
| Producer registry names | Class names contained provider prefixes (“GitHub…”, “S3…”). | Producers renamed/reorganised. | Update expectations to the new class names or expose a registry metadata layer. |
| Compliance / query APIs | Endpoints, scopes, and error handling evolved. | Security layer tightened around scoped JWTs and telemetry. | Revisit endpoint tests to align with current routes and scope requirements. |

## Failing Suites & Migration Work

| Test File / Suite | Failure Mode | Required Work |
| --- | --- | --- |
| `tests/integration/test_agent_core.py` | Missing alias IDs, deprecated columns, enum mismatches, shared session teardown errors. | Audit every model usage; add compatibility properties, update enums, refactor async fixtures to create per-operation sessions. |
| `tests/integration/test_live_agents.py` | Depends on old runtime/tool mocks and status enums. | Rebuild mocks for new runtime facade, update tool invocation statuses, adjust telemetry expectations. |
| `tests/agents/test_review_queue.py` | References legacy status enums and ID aliases. | Align with `ToolInvocationStatus` + ID changes. |
| `tests/agents/test_agent_integration.py`, `tests/integration/standalone_agent_test.py` | Same ORM API drift (ids/enums). | Apply same migration pattern as above. |
| `tests/test_performance_improvements.py` | Expects bulk insert idempotency and engine pre-ping attribute. | Restore unique constraints or adjust expectations; update engine assertion to `_pre_ping`. |
| `tests/test_producers.py` | Producer class names changed. | Update tests to match new naming or expose metadata mapping. |
| `tests/test_api_integration.py` | Endpoint responses/scopes changed. | Revalidate against current API contracts; update expected status codes as needed. |
| `tests/test_compliance.py`, `tests/test_identity_anomaly.py`, `tests/test_notifications.py` | Depend on removed mocks/services and legacy schema. | Recreate mocks for new pipeline or retire redundant coverage in favour of benchmarks + telemetry tests. |

## Migration Strategy

1. **Model Compatibility Pass**  
   - Add temporary compatibility properties (`session_id`, `message_id`, etc.) that forward to `.id` to unblock tests.
   - Reintroduce frequently used columns (`is_active`) only if still valuable; otherwise strip usages from tests.

2. **Enum & Workflow Alignment**  
   - Map legacy statuses to the new enum values across tests and helper factories.
   - Update approval workflows to treat `APPROVAL_REQUIRED` + `SUCCESS` as the approved path.

3. **Session Management Refactor**  
   - Update `tests/conftest.py` fixtures so each async helper uses its own `async_session_factory` context.
   - Adjust concurrent tests to open/close sessions inside the coroutine rather than sharing a module-level fixture.

4. **Runtime/Test Double Refresh**  
   - Mirror current runtime entry points in mocks (e.g. stub `AgentRuntimeFacade.create_session`, `send_message`, telemetry ingest).
   - Ensure tool registry/test helpers align with `ToolInvocationStatus` and telemetry events.

5. **Domain-Specific Suites**  
   - **Bulk ops**: restore `ON CONFLICT` safeguards or relax expectations based on product decision.  
   - **Producers**: update registry expectations to new class names.  
   - **Performance/Compliance/Notifications**: rebuild mocks compatible with new service layer.

6. **Verification**  
   - Run targeted pytest subsets per suite after migration.  
   - Once green, run full `pytest` with coverage to confirm no regressions.

## Next Steps

1. Implement compatibility properties & enum updates (high leverage: unlock many suites).  
2. Refactor async session fixtures (resolves teardown errors).  
3. Rework runtime mocks for integration suites.  
4. Triage domain-specific expectations (bulk ops, producers, compliance).  
5. Retire or modernise redundant tests once coverage overlaps with new benchmark framework.
