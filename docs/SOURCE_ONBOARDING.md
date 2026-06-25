# Cerebro Source Onboarding

This runbook is the canonical path for adding a new source runtime (Okta, GitHub, SentinelOne, S3, etc.) to a Cerebro deployment. It covers the Pulumi config surface, secret wiring, scheduling, and the validation steps required before a source can start advancing.

The goal is that onboarding a source becomes a single reviewed PR against this repository, not a multi-day integration. If a step in this runbook is missing or ambiguous, treat that as a defect and fix it in the same PR that surfaces it.

## Prerequisites

Before you start, confirm the following:

1. **The source has a runtime in the Cerebro image.** A `sourceId` (e.g. `okta`, `github`, `sentinelone`, `s3`) only works if the runtime registered with that id ships in the image referenced by `cerebro:imageTag`. If you are adding a brand-new `sourceId`, that runtime first needs to land in the upstream Cerebro repo and reach a tag that is deployed here.
2. **You know the target stack.** Source runtimes live in stack config:
   - `infra/aws/Pulumi.sec-dev.yaml` for the `sec-dev` stack.
   - `infra/aws/Pulumi.go-prod.yaml` for the `go-prod` stack.
3. **You have the credentials path planned.** Cerebro never reads plaintext secrets from stack config. Each secret must be reachable through one of the two supported paths in [Wire credentials](#wire-credentials).
4. **You have decided on a `runtime_id`.** Runtime ids are stable identifiers used by the orchestrator, the postgres cursor table, and downstream graph projections. Pick a slug you will not need to rename: `{tenant}-{source}-{family}` is the established pattern (`writer-okta-audit`, `writer-github-audit-writerinternal`, …). Renaming a runtime_id after it has advanced means rewinding the cursor and reingesting; do not do it casually.

## New source authoring

If the `sourceId` does not exist yet, start in the upstream `writer/cerebro` repo with the Source Runtime SDK generator instead of hand-writing the adapter surface:

```bash
./bin/cerebro source-runtime sdk new <source-id> \
  source_type=json_api \
  auth_model=bearer_token \
  asset_schemas=<schema[,schema]> \
  finding_schemas=<schema[,schema]> \
  freshness_expectation=24h \
  dry_run=true
```

The generator emits the source adapter, event contracts, deploy manifest, EvidenceCAS reference mapping, graph projection scaffolds, tests, `SOURCE_RUNTIME.md`, `PR_BODY.md`, and `source_health_receipt.json`. Treat those generated artifacts as upstream review evidence:

- `deploy.yaml` is the source-owned runtime contract that release tooling turns into `cerebro-runtime-contract.json`.
- `source_health_receipt.json` records generated freshness, failure-mode, and health-path expectations that this repo verifies when a stack declares the generated source runtime.
- `SOURCE_RUNTIME.md` and `PR_BODY.md` summarize the source authoring choices for upstream review and downstream release notes.

Do not add `cerebro:sourceRuntimes` or schedules here until a promoted `cerebro:imageTag` includes the generated source. Until then, this repo can only track the planned deployment and credentials path.

## Configuration surface

A source onboarding PR touches at most three keys in the stack file plus, optionally, one IAM scope key.

| Key | Required | Purpose |
| --- | --- | --- |
| `cerebro:sourceRuntimes` | Yes | Declarative runtime definitions bootstrapped into Cerebro before the API container starts. |
| `cerebro:sourceSecretKeys` | Only if the runtime references a secret not already imported | Additional ECS secret env vars sourced from `{externalSecretsPrefix}/<key>`. |
| `cerebro:orchestratorSchedules` | Yes (unless the default hourly schedule is acceptable) | Named EventBridge schedules with per-runtime commands. |
| `cerebro:s3Sources` | Only for S3-backed runtimes | Least-privilege S3 read scope granted to the runtime task role. |

The schema for these keys lives in `infra/aws/Pulumi.yaml`; treat that file as authoritative if it diverges from this runbook.

### `cerebro:sourceRuntimes` entry shape

Each entry is a single source instance. The orchestrator distinguishes instances by `id`, so you can run multiple instances of the same `sourceId` (e.g. one live tail and one historical backfill) by giving them different ids.

```yaml
cerebro:sourceRuntimes:
  - id: writer-okta-audit            # stable runtime_id; do not rename after first run
    sourceId: okta                   # registered runtime in the Cerebro image
    tenantId: writer                 # cerebro tenant the events belong to
    config:
      family: audit                  # source-specific config key
      domain: env:OKTA_DOMAIN        # env: refs are resolved from ECS secret env vars
      token: env:OKTA_API_TOKEN
      per_page: "200"
      since: "2026-05-01T00:00:00Z"  # optional historical bound
```

Rules:

- `id`, `sourceId`, and `tenantId` are required.
- `config` is a free-form object passed to the runtime. Every `env:<NAME>` reference must resolve to a secret env var on the task (see [Wire credentials](#wire-credentials)).
- Numeric and boolean config values should be quoted as strings if the runtime expects strings (e.g. `per_page: "100"`); follow what the existing entries for that `sourceId` already do.
- Use distinct ids for backfills (`writer-okta-audit-2026-q1`) so the live and historical cursors do not collide. Backfill ids typically pair with a time-bounded orchestrator schedule that is removed once the window completes.

### Wire credentials

The runtime resolves `env:<NAME>` references at runtime against the ECS task's environment. There are two supported ways to populate that environment, and both flow through `cerebro:externalSecretsPrefix`:

1. **Secret is already imported.** If the env var name (e.g. `GITHUB_TOKEN`, `OKTA_API_TOKEN`, `OKTA_DOMAIN`) already appears in the stack's `cerebro:sourceSecretKeys`, no further change is needed. The Pulumi program auto-detects `env:` references in `cerebro:sourceRuntimes` and refuses to deploy if the underlying secret key is not declared, so a missing import will fail preview, not production.
2. **New secret.** Add the secret value under `{externalSecretsPrefix}/<NAME>` in the approved secret system (Infisical for sec-dev, AWS Secrets Manager for go-prod), then add `<NAME>` to `cerebro:sourceSecretKeys`. The ECS task definition will then expose it as an env var, and the runtime config can reference it as `env:<NAME>`.

**Never inline a token, key, or password directly in `config:`.** Stack files are reviewed in plaintext. The only acceptable string values are non-secret config (domains, dates, page sizes, owners, etc.).

### Schedule the runtime

A runtime that exists in `cerebro:sourceRuntimes` is bootstrapped into Cerebro but does not run until something calls the orchestrator with its id. Add a named schedule:

```yaml
cerebro:orchestratorSchedules:
  - name: okta-audit-live
    scheduleExpression: rate(10 minutes)
    taskCount: 1
    command:
      - orchestrator
      - run
      - runtime_id=writer-okta-audit
      - page_limit=20
      - graph_page_limit=100
      - event_limit=1000
```

Guidelines:

- One schedule per runtime instance. Live tails typically run on `rate(5 minutes)` to `rate(15 minutes)`; backfills run faster (`rate(2 minutes)` to `rate(5 minutes)`) because they have a bounded amount of work.
- For time-bounded backfills, set `removeAfter: "YYYY-MM-DD"`. The schedule is deleted automatically after that date so backfill schedules do not linger past their useful life.
- `taskCount` should stay at `1` for any runtime whose cursor is not cross-task safe (this is the current default for all in-tree runtimes). Running two tasks against the same `runtime_id` will fight over the cursor.
- `page_limit`, `graph_page_limit`, and `event_limit` cap the amount of work a single orchestrator invocation will do. Tune them downward if a runtime is starving other tasks; tune them upward only after confirming the source's rate limits.

### S3-backed runtimes

If `sourceId: s3`, the runtime task role needs explicit `s3:GetObject` and `s3:ListBucket` on the source bucket. Add the scope under `cerebro:s3Sources`; do **not** widen the role with `s3:*`. Reuse an existing scope entry if the bucket is already listed.

### EvidenceCAS-backed evidence pointers

Some source runtimes may emit evidence that is stored in EvidenceCAS. This
repository does not implement an EvidenceCAS client; onboarding should preserve
EvidenceCAS references as pointer-only supporting evidence. The runtime payload
should include an `evidencecas://` URI plus digest, Merkle root, and commit id,
and should not inline the referenced bytes into claims or findings.

See [EvidenceCAS references](EVIDENCE_CAS_REFERENCES.md) for the required
reference shape, bucket/key conventions, auth expectations, and troubleshooting
guidance.

## Validation

Run these before requesting review. They are cheap and catch the most common mistakes.

1. **Python compile** (no cloud credentials required):
   ```bash
   python3 -m compileall -q infra/aws
   ```
2. **Pulumi preview** against the target stack:
   ```bash
   cd infra/aws
   uv run pulumi preview --stack sec-dev   # or go-prod
   ```
   The preview should show: a new/updated EventBridge schedule, no IAM diff outside `cerebro:s3Sources` (if you touched it), and no diff on RDS, NATS, Neo4j, or the ALB. If you see a diff on a resource you did not intend to change, stop and reconcile before opening the PR.
3. **Env-reference sanity:** confirm every `env:<NAME>` in your new runtime entry appears in `cerebro:sourceSecretKeys` (or is already in the existing list). The Pulumi program will fail preview if a reference is unresolved, but it is faster to check by eye first.
4. **Generated source receipt sanity:** for generated sources, confirm the stack runtime config preserves the generated `health_path`, `expected_cadence_seconds`, and `stale_after_seconds` values from `source_health_receipt.json` unless the upstream source PR intentionally changed them. Runtime contract verification fails if a stack-declared generated source drifts from the signed receipt.

## Rollout

1. Open the PR. The repo's PR workflow runs the AWS preview and mirrors the pinned image tag to sec-dev ECR, so reviewers see the preview output without running it locally.
2. After merge, the `sec-dev` schedule is deployed automatically by the infra deploy workflow. For `go-prod`, dispatch the deploy workflow explicitly per the deployment process in the repository README.
3. **Watch the first run.** Check the orchestrator task logs in CloudWatch and confirm the runtime is advancing its cursor in Cerebro. A new runtime that fails its first run will retry on its schedule and burn API quota until you stop it; do not walk away before the first successful tick.
4. **Confirm downstream propagation.** New events should land in the postgres append log, then the JetStream stream, then the Neo4j graph projection. If only the append log is advancing, something downstream is wedged; treat it as an incident, not a configuration question.

## Day-2 operations

- **Pausing a runtime:** remove its entry from `cerebro:orchestratorSchedules`. Leave the `cerebro:sourceRuntimes` entry in place so the cursor is preserved; deleting the runtime entry rewinds it.
- **Retiring a runtime permanently:** remove both the schedule and the `cerebro:sourceRuntimes` entry in the same PR, and call out in the PR description that the cursor will be discarded. Coordinate with the source's downstream consumers before merging.
- **Bumping the source image:** sources are part of the Cerebro runtime image and ship with `cerebro:imageTag` bumps; you do not pin a source version independently.
- **Renaming a runtime_id:** treat this as a full retire + reintroduce. Plan a backfill window if you need historical continuity.

### Recover missing graph ingest history

Graph-health follow-up issues report declared runtimes that have no current
graph ingest run history. Use the `Source Runtime Backfill` workflow to plan
and run bounded recovery:

1. Dispatch the workflow in `plan` mode with the reported runtime ids.
2. Copy the emitted `plan_hash` into a second dispatch using `run` mode and the
   same inputs.
3. For provider flakes, set `failed_run_retry_seconds` to a bounded window and
   keep `run_attempt_timeout_seconds` lower than the total wait window.
4. If the run still fails, inspect the `Plan and run backfill` log. Source sync
   failures include structured context plus recent raw task logs; bootstrap
   failures include both bootstrap structured logs and raw logs when available.

Deploy graph-health healing retries failed source-runtime attempts for 600
seconds by default. Use the manual backfill workflow when a follow-up issue
needs a narrower runtime list, a longer retry window, or a plan hash review
before running the recovery.

Do not quarantine a runtime only to make graph health pass. Quarantine is for a
known bad or intentionally paused runtime, and the same PR must remove the
active `cerebro:sourceRuntimes` and `cerebro:orchestratorSchedules` references
while adding `cerebro:temporarilyDisabledSourceRuntimes` metadata with an owner,
reason, disabled date, review deadline, and re-enable criteria.

## Adding a new `sourceId`

This runbook covers onboarding an *instance* of an existing source. If you need a new `sourceId` (a new kind of source the runtime does not yet know how to talk to):

1. Generate the upstream source scaffold with `source-runtime sdk new` and land the reviewed runtime implementation in `writer/cerebro`.
2. The upstream source reaches a tagged image with a signed runtime deploy contract.
3. That tag is promoted into `cerebro:imageTag` here, either as a normal bump or alongside the new `cerebro:sourceRuntimes` entry.
4. Then follow this runbook for the new instance.

Until those three steps are complete, the new `sourceId` will fail bootstrap and the orchestrator schedule will error every tick.
