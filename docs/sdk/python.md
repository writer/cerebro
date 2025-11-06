
# Python SDK Guide

> Scope: internal Writer use only

The Python SDK (`src/cerebro_sdk`) powers backend automation, asynchronous workers, and compliance tooling. It wraps the Cerebro persistence layer with typed dataclasses, transaction-aware helpers, and domain-specific facades. Use this guide to understand package layout, development practices, and advanced Security Center capabilities.

## Package Layout

```
src/cerebro_sdk/
├── __init__.py            # Barrel exports for public API
├── agents/                # Agent managers, analytics, notifications, playbooks
├── analytics.py           # Runtime health & integration coverage clients
├── auth.py                # AuthSession and token helpers
├── client.py              # UnifiedCerebroSDK context manager
├── config.py              # Settings proxy utilities
├── findings.py            # Finding lifecycle management
├── integrations.py        # Integration state + sync orchestration
├── organizations.py       # Org/account/resource managers
├── pagination.py          # Cursor helpers mirroring TS SDK
├── security_center/       # Analytics, relations, GRC, evidence primitives
└── testing/               # Stub clients for unit tests
```

Tests live under `tests/unit/sdk/` (unit) and `tests/sdk/` (integration). They exercise agent flows, findings management, Security Center analytics, and evidence lifecycle behaviour.

## Development Workflow

```bash
uv pip install -e .[dev]    # install package and dev dependencies

PYTHONPATH=src pytest tests/unit/sdk
PYTHONPATH=src pytest tests/sdk -m "not slow"  # optional integration suite

ruff check src/cerebro_sdk tests/unit/sdk      # linting
mypy src/cerebro_sdk                            # type checking
```

The repository uses strict mypy settings (`no_implicit_optional`, `disallow_untyped_defs`, etc.). When adding modules, include type annotations for all public surfaces and keep dataclasses frozen where possible.

## Async Session Management

Most facades expect an `AsyncSession`. Use the shared session factory defined in `cerebro.core.database` to inherit standard configuration:

```python
from cerebro.core.database import async_session_factory
from cerebro_sdk import AuthSession

async def login_service_account(username: str, password: str) -> str:
    async with async_session_factory() as db:
        tokens = await AuthSession(db).login(username, password)
        return tokens.access_token
```

`UnifiedCerebroSDK` (in `client.py`) bundles frequently used facades. It accepts an `AsyncSession` or session factory and optionally a Prometheus registry / Celery app for instrumentation.

## Key Facades

| Module | Responsibilities |
| --- | --- |
| `auth.AuthSession` | Login, token verification, refresh expirations respecting platform settings. |
| `users.UserManager` / `organizations.OrganizationManager` | CRUD helpers returning typed records. |
| `findings.FindingService` | Listing, regenerating, and updating findings with append-only semantics. |
| `analytics.RuntimeHealthClient` | Runtime telemetry snapshots, coverage trend analysis. |
| `integrations.IntegrationService` | Sync state, issue tracking, provider health. |
| `agents.AgentManager` | Session creation, memory analytics, message handling. |
| `agents.AgentReviewManager` | Review workflows, comment exports, status transitions. |
| `agents.AgentToolingManager` | Tool invocation listing, approval routing, policy suggestions. |
| `agents.AgentNotificationManager` | Notification queue, delivery tracking, ticket lifecycle. |
| `security_center.analytics` | Vendor/customer health scoring, anomaly detection. |
| `security_center.grc` | Control mapping, evidence aggregation, lifecycle summaries. |
| `security_center.primitives` | Canonical `EntityProfile`, `EvidenceArtifact`, lifecycle policy evaluation. |

All managers surface domain-specific exceptions (`AgentNotFoundError`, `AgentValidationError`, etc.) that mirror API semantics.

## Security Center Evidence Lifecycle

Both SDKs now expose symmetric evidence primitives. The Python implementation lives in `security_center/primitives.py` and offers:

- `extract_evidence_artifacts(kind, entity_id, metadata)` – normalises metadata/attachments into typed `EvidenceArtifact`s.
- `evaluate_evidence_lifecycle(artifact, policy, now=None)` – computes status (`fresh`, `stale`, `expired`), age, TTL, and next refresh timestamp.
- `summarize_evidence_set(artifacts, policy, now=None)` – dedupes artifacts, aggregates lifecycle results, and produces stale/expired subsets.

Example:

```python
from datetime import datetime
from cerebro_sdk.security_center import (
    extract_evidence_artifacts,
    evaluate_evidence_lifecycle,
    LifecyclePolicy,
)

metadata = {"evidence": {"id": "soc2-audit", "collected_at": "2024-08-01T00:00:00Z"}}
artifacts = extract_evidence_artifacts(kind="vendor", entity_id="vendor-1", metadata=metadata)
policy = LifecyclePolicy(max_age_days=90, refresh_window_days=14)

snapshot = evaluate_evidence_lifecycle(artifacts[0], policy, now=datetime(2024, 10, 15))
assert snapshot.status == "stale"
```

Control mapping (`security_center/grc.py`) consumes these helpers to generate evidence bundles with lifecycle summaries, ensuring parity with the TypeScript SDK.

## Testing Strategy

Key suites under `tests/unit/sdk/` include:

- `test_security_center_primitives.py` – evidence extraction/lifecycle behaviour.
- `test_security_center_grc.py` – control mapping, evidence summaries, risk tolerances.
- `test_security_center_remediation.py` – severity classification and evidence collection for remedial actions.
- `test_security_center_alerts.py` – monitoring event evaluation and escalation routing.

When adding functionality:

1. Prefer pytest fixtures with deterministic data (see `tests/unit/sdk/conftest.py`).
2. Use `asyncio` fixtures for async flows (`pytest.mark.asyncio`).
3. Mirror TypeScript tests when introducing shared primitives to ensure behavioural parity.

## Linting & Type Safety

- `ruff check` enforces formatting, import hygiene, and bugbear rules.
- `mypy` runs in strict mode; add protocol definitions when mocking complex clients.
- Keep dataclasses `slots=True` and prefer `frozen=True` for immutable records.
- Place shared typing utilities in `cerebro_sdk.types` to avoid circular imports.

## Release Process

The Python package is distributed internally via the monorepo. Publishing steps:

1. Bump the version in `pyproject.toml` under `[project]`.
2. Run `uv build` or `python -m build` if a wheel/sdist is needed for external deployment.
3. Tag the commit (`git tag python-sdk-vX.Y.Z`) and push to trigger release automation.
4. Update consumers (automation runners, notebooks) via dependency bump PRs.

Document new modules here (and in specialised guides) so downstream teams can adopt changes without spelunking the codebase.

## Further Reading

- [SDK Overview](README.md)
- [Configuration, Auth, and Agents](auth-and-agents.md)
- [Integrations and Playbooks](integrations-and-playbooks.md)
- [Schema and Migrations](migrations.md)
- Unit tests under `tests/unit/sdk/` for executable examples
