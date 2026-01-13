# Cerebro Platform Development Plan

This document is the **engineering roadmap** for improving Cerebro’s codebase quality, reliability, and delivery velocity while continuing to expand provider/compliance coverage and agent capabilities.

It replaces “aspirational” bullets with a **prioritized, testable execution plan**: each workstream has concrete deliverables, acceptance criteria, owners, and validation gates.

## 0) Scope, Principles, and Definitions

### Scope

In scope:

* Repo-level quality improvements (tooling, CI, tests, typing, architecture, reliability, security posture, observability)
* Platform roadmap items that require codebase changes (providers, compliance frameworks, agents)
* Developer experience (local reproducibility, deterministic tests, faster feedback)

Out of scope (unless explicitly requested later):

* New end-user documentation (beyond updating this `PLAN.md`)
* UI/frontend work not represented in this repo

### Guiding principles

1. **Reproducible locally = trustworthy in CI** (no “CI-only magic”).
2. **Make failures loud** (flake, security scan, tests, type check) and prevent silent regressions.
3. **Incremental hardening**: tighten gates by package/subsystem; don’t block the whole org on legacy debt.
4. **Idempotent initialization**: importing modules must not cause duplicated registrations, external calls, or noisy logs.
5. **Contract-first** for SDK/API: OpenAPI + SDK generation must be deterministic and versioned.

### Definition of done (DoD) for roadmap items

Every roadmap item should include:

* Tests added/updated (unit/integration/e2e as appropriate)
* Type safety impact (mypy/typing plan)
* Operational readiness (logging/metrics/tracing)
* Rollout plan (feature flag, migration, backfill, or safe default)
* Validation commands that pass in CI

## 1) Repository Map (What’s Here)

Key top-level areas (as of 2026-01):

* `src/cerebro/`: main backend application (FastAPI, Celery tasks, providers, compliance, findings, agents)
* `src/cerebro_sdk/`: Python SDK façade used by internal workflows and services
* `sdk/ts/`: TypeScript SDK (OpenAPI-generated types + client tooling)
* `desktop-agent/`: Go-based desktop agent
* `infra/`: infrastructure code (Pulumi modules + validation)
* `scripts/`: dev tooling, smoke tests, OpenAPI export, benchmarking
* `tests/`: main pytest suite (unit + integration + e2e markers)
* `tests_unit/`: legacy/auxiliary tests (not part of default `pytest` discovery per `pyproject.toml`)

## 2) Current State (Measured + Observed)

### Code size (approximate)

* `src/cerebro`: **509 Python files**, **~142k LOC**
* `src/cerebro_sdk`: **34 Python files**, **~7.3k LOC**
* `scripts`: **28 Python files**, **~6.2k LOC**
* `tests`: **157 Python files**, **~29k LOC**
* `infra`: **26 Python files**, **~6.6k LOC**

### Tooling and CI reality

* Python version pinned: `.python-version` = **3.11.8**; `pyproject.toml` requires **>=3.11**.
* Package manager: **uv** (`make install-dev`, `uv sync --extra dev`).
* Lint/format/type:
  * Repo config contains **Black + isort + flake8 + mypy + Ruff**.
  * Pre-commit currently runs **ruff** + **ruff-format** + **mypy**.
* GitHub Actions:
  * `tests.yml` runs ruff + mypy + pytest + e2e + TS SDK + Go agent + infra validation.
  * `lint.yml` runs Ruff/mypy, but only over **selected producer paths**, plus a small docstring check set.
  * `security-health.yml` runs pip-audit, Bandit, Trivy, Gitleaks, npm audit (mostly non-blocking).

### Architecture strengths (keep)

* Append-only audit model for compliance history
* CEL-based policy/rule approach
* Provider abstraction across cloud + SaaS
* Agent runtime with approvals + telemetry
* Dual SDK support (TypeScript + Python)

## 3) Shortcomings (Codebase Risks to Address)

This section is intentionally concrete and repo-specific.

### 3.1 Tooling inconsistencies (high impact)

**Symptom:** Pre-commit uses Ruff + Ruff formatter, while `Makefile` uses Black/isort/flake8; line-length settings differ (`black=88`, `ruff=140`).

**Impact:** format churn, inconsistent local vs CI output, time lost resolving style diffs.

**Evidence:**

* `pyproject.toml`: `[tool.black] line-length = 88`, `[tool.ruff] line-length = 140`
* `.pre-commit-config.yaml`: `ruff` + `ruff-format` hooks
* `Makefile`: `make format` runs `black` + `isort`, `make lint` runs `flake8` + `mypy`

### 3.2 CI test sharding appears misconfigured (high risk)

**Symptom:** `.github/workflows/tests.yml` runs pytest with `--shard=${{ matrix.shard }}/4`, but local pytest does not recognize `--shard`.

**Impact:** CI may be brittle/unreproducible; local reproduction of failures becomes harder; potential silent CI break if plugin availability changes.

**Action:** Standardize on an explicit, pinned sharding approach (e.g., `pytest-xdist`, `pytest-split`, or a small in-repo plugin) and ensure it’s installed via `dev` extras.

### 3.3 Import-time side effects + noisy initialization (medium/high)

**Symptom:** Importing certain modules triggers registrations and logs (providers/producers, Celery app config, rate limiting).

**Impact:** slower test collection, hard-to-control startup behavior, duplicated registrations, noisy logs.

**Evidence:**

* `cerebro.infrastructure.provider_registry` registers providers at import time.
* `cerebro.findings.producers.registry` auto-discovers producers by importing submodules.

### 3.4 Registry idempotency bugs (high)

**Symptom:** Producer registry warns about overrides, but still appends producers into per-provider/per-resource lists.

**Impact:** duplicate evaluations, duplicated findings, performance regressions, nondeterministic behavior.

**Evidence:** `ProducerRegistry.register()` in `src/cerebro/findings/producers/base.py` appends to index lists even when overriding.

### 3.5 Type checking strategy is not yet coherent (medium)

**Symptom:** Mypy is configured for strictness, but CI runs mypy with `--ignore-missing-imports` and/or on subsets; older modules likely lag.

**Impact:** type safety benefits are uneven; contributors don’t know what standards apply where.

### 3.6 Testing taxonomy and ownership unclear (medium)

**Symptom:** Multiple test directories (`tests/`, `tests/unit`, `tests_unit/`), plus CI selectively ignores some markers.

**Impact:** contributors can easily write tests that don’t run in CI, or rely on fixtures that make tests slow/flaky.

### 3.7 Security scanning mostly informational (medium)

**Symptom:** security workflows often use `|| true` / non-failing exit codes.

**Impact:** vulnerabilities can persist without forcing remediation decisions.

### 3.8 Operational readiness gaps (medium)

**Symptom:** Observability exists (Prometheus + some OTEL deps), but tracing and correlation is incomplete and not consistently enforced.

**Impact:** on-call/debug time increases as system grows.

## 4) Roadmap Overview (Phased Execution)

This roadmap is organized into **workstreams** that can run in parallel, with a recommended “stability-first” ordering.

### Phase A (0–2 weeks): Fix the foundations that block velocity

1. Toolchain alignment and CI reproducibility
2. Fix registry idempotency + import-time side effects
3. Test suite determinism and performance quick wins

### Phase B (2–6 weeks): Expand quality gates and reliability

1. Testing strategy: integration coverage for providers + contract tests
2. Type coverage expansion for public APIs and core domain
3. Standardized error model + consistent retries/backoff

### Phase C (6–12 weeks): Operational excellence + scale readiness

1. Structured logging + correlation IDs everywhere
2. OpenTelemetry tracing across API → tasks → providers
3. SLOs, burn-rate alerts, and load testing

### Phase D (ongoing): Product/platform expansion

Providers, frameworks, AI capabilities, and enterprise features continue, but must not regress quality gates.

## 5) Workstreams (Detailed Plan)

### Workstream 1: Tooling & CI Reliability

#### Goal

One canonical workflow for formatting/lint/type/test that is identical locally and in CI.

#### Deliverables

1. A single “golden” command set:
   * `make format` (or `uv run ...`) produces the final formatting state
   * `make lint` is the lint baseline used by CI
   * `make test` matches CI selection (markers + ignores)
2. CI that runs the same commands (no divergent flags).

#### Actions (prioritized)

1. **Choose the formatter and align line-length** (recommended: Ruff formatter everywhere).
   * Update `Makefile` to use `ruff format` and `ruff check`.
   * Remove or freeze Black/isort usage to avoid conflicts.
2. **Rationalize lint rules**:
   * Make CI run `ruff check` across `src/`, `tests/`, `scripts/` (not only selected producers).
   * Keep per-file ignores in `pyproject.toml` as needed.
3. **Fix test sharding**:
   * Option A: adopt `pytest-xdist` and shard via `-n` + `--dist=loadscope`.
   * Option B: adopt `pytest-split` (duration-based sharding) with explicit installation.
   * Remove `--shard` until it is supported and pinned.

#### Acceptance criteria

* A contributor can run the exact CI steps locally without custom plugins.
* No formatting ping-pong between tools.
* CI failures are actionable and reproducible.

---

### Workstream 2: Deterministic Initialization (No Side Effects)

#### Goal

Importing modules should not:

* register global state repeatedly
* emit info logs
* perform network calls
* trigger expensive autodiscovery

#### Actions

1. **Make registries idempotent**
   * Fix `ProducerRegistry.register()` to avoid duplicate entries when overriding.
   * Add regression tests ensuring repeated init does not duplicate producers.
2. **Move registration out of import time**
   * Providers: stop calling `provider_registry.register(...)` at module import; do it in an explicit `init_providers()`.
   * Producers: ensure autodiscovery is only run from a controlled entrypoint (API startup / worker startup / CLI command) and is cached.
3. **Reduce pytest startup cost**
   * Avoid importing `cerebro.api.main:app` in global `tests/conftest.py` if possible; use an app factory fixture.

#### Acceptance criteria

* `pytest --help` does not perform producer autodiscovery.
* Repeated initialization does not change registry contents (idempotent).
* Test collection time reduces measurably.

---

### Workstream 3: Testing Strategy & Coverage (Provider + API + Tasks)

#### Goal

Add confidence without slowing developers down.

#### Test taxonomy (enforce)

* **Unit**: pure logic, no DB/network; fast; default PR gate
* **Integration**: DB + internal services; deterministic; runs on PRs when relevant
* **E2E**: in-process ASGI, higher-level workflows; runs on main and targeted PRs
* **Contract**: OpenAPI/SDK generation, provider schema contracts

#### Actions

1. **Make the default unit suite fast**
   * Ensure unit tests don’t require provider autodiscovery.
   * Use `fakeredis` and in-memory SQLite where appropriate.
2. **Provider integration tests**
   * For AWS/GCP/GitHub/Okta/M365/Azure providers: add mock-based tests (moto/httpx mocking) for:
     * auth failures
     * pagination
     * rate limiting
     * partial failures
     * schema mapping correctness
3. **Contract tests**
   * Validate OpenAPI is stable and TS SDK types match.
   * Add snapshot-style checks for critical endpoints.

#### Acceptance criteria

* PRs run a fast suite (<10 minutes) that catches most regressions.
* Provider changes require tests in the matching provider package.
* OpenAPI/SDK drift is caught automatically.

---

### Workstream 4: Type Safety (Incremental, Enforced)

#### Goal

Strict typing for public APIs and high-risk modules, gradually expanding without blocking legacy code.

#### Strategy

1. Define “typed boundaries”:
   * `src/cerebro/core/`, `src/cerebro/api/`, `src/cerebro_sdk/` should be strict first.
2. Use mypy overrides to progressively tighten.
3. Add “new code must be typed” rule for touched modules.

#### Actions

* Create a mypy plan by package (baseline errors, target dates).
* Add type-focused unit tests where runtime types matter (Pydantic schemas, API responses).

#### Acceptance criteria

* Mypy passes on prioritized packages with strict settings.
* Type regressions are prevented by CI.

---

### Workstream 5: Security Hardening (Practical Gates)

#### Goal

Make security checks meaningful and prevent introducing new risks.

#### Actions

1. **Make “new vulnerabilities” fail CI**
   * Keep legacy findings visible, but block net-new criticals.
2. **Secrets handling**
   * Ensure `.env` patterns and fixture JSON exemptions remain safe.
   * Tighten Gitleaks configuration if necessary.
3. **Audit integrity**
   * Plan cryptographic chaining for append-only audit logs (design + threat model).

#### Acceptance criteria

* CI blocks introducing new CRITICAL vulnerabilities in container/deps.
* Secret leaks are prevented pre-merge.

---

### Workstream 6: Observability & Ops Readiness

#### Goal

Reduce time-to-debug and support scaling.

#### Actions

1. Structured logging conventions:
   * request IDs / trace IDs, org/account context, action IDs
2. OpenTelemetry:
   * traces across API requests and Celery tasks; exporter configuration for dev/prod
3. Health checks:
   * deep health endpoints (DB/Redis/Snowflake connectivity) with timeouts
4. SLOs:
   * define core SLIs (API latency, task backlog, provider collection freshness)

#### Acceptance criteria

* For any request, operators can find correlated logs/metrics/traces.
* Core services expose actionable health endpoints.

## 6) Platform Expansion Backlog (Keep Shipping, Without Regressions)

These are the high-level product expansions, but they must respect Workstreams 1–6 gates.

### 6.1 Provider ecosystem

Current providers appear present in `src/cerebro/providers/`: `aws`, `gcp`, `azure`, `github`, `kubernetes`, `m365`, `okta`, `workspace`.

Priority additions (suggested):

* Slack Enterprise (audit logs)
* CrowdStrike (EDR findings)
* Wiz (CSPM ingestion)
* Snyk (vuln findings)

For each provider:

* Define data model (tables/entities)
* Implement ingestion with retries/backoff
* Add producer mappings (findings)
* Add integration tests + contract tests
* Add rate-limit handling + observability

### 6.2 Compliance frameworks

Existing: SOC2, ISO27001, NIST CSF.

Next:

* NIST CSF 2.0 (if current is 1.x mapping)
* CIS Controls v8
* PCI DSS 4.0

For each framework:

* Control catalog
* Evidence mapping strategy
* Automated evidence collection coverage targets
* Reporting + export requirements

### 6.3 AI-powered security autonomy

The detailed autonomy roadmap lives in `docs/TODO.md`. The codebase plan here focuses on:

* Evaluation harnesses integrated into CI
* Telemetry schemas and storage
* Safe action adapters + rollback

## 7) Immediate Execution Plan (Next 14 Days)

### Week 1: Stop the bleeding

1. Decide formatter/linter single source of truth and align configs.
2. Fix producer registry idempotency and add regression tests.
3. Remove or implement pytest sharding so CI and local match.

### Week 2: Make it stick

1. Expand CI lint coverage beyond selected producers.
2. Add 2–3 provider integration test modules (start with AWS/GitHub) as templates.
3. Add a “quality gates” section to CI summaries (what ran, what was skipped).

## 8) Success Metrics (Engineering)

| Metric | Baseline | 30d Target | 90d Target |
| --- | ---:| ---:| ---: |
| Time to reproduce CI failure locally | High | Low | Very low |
| Median PR feedback loop (lint+unit) | TBD | <10 min | <7 min |
| Flaky test rate | TBD | <1% | <0.5% |
| Typed coverage of core/api/sdk | TBD | +20% | +50% |
| Duplicate producer registrations | Observed | 0 | 0 |

## 9) Owners and Operating Rhythm

Suggested ownership model:

* **Backend**: providers, compliance, findings, API correctness
* **Platform**: CI/tooling, deploy workflows, observability, performance
* **Security**: threat models, scanners, audit integrity, RBAC
* **AI/Agents**: evaluation harnesses, tool safety, autonomy controls

Operating rhythm:

* Weekly: reliability review (CI stability, flaky tests, perf regressions)
* Biweekly: roadmap checkpoint (workstream progress, scope adjustments)

## 10) Risk Register (Engineering)

| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| Toolchain conflicts cause constant formatting churn | High | High | Single formatter + aligned line-length |
| CI sharding mismatch blocks contributions | High | Medium | Pin plugin or remove flag |
| Import-time side effects create nondeterminism | High | Medium | App factories + explicit init |
| Provider API changes break ingestion | High | Medium | Contract tests + version pinning |
| Security scans become noise | Medium | High | Gate net-new criticals |

---

Last updated: 2026-01
Owner: Security Platform Team
