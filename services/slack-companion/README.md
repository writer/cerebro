# Cerebro Slack Companion

Slack operator surface for Cerebro security work.

This service handles Slack commands, app mentions, alert triage, scheduled checks, goals, and operator approvals. Cerebro remains the source of truth for tenants, findings, evidence, graph context, source runtime state, and response-action audit. The companion owns Slack transport, operator workflows, local memory, and bounded orchestration around Cerebro APIs.

## Operator Workflows

| Workflow | Slack entrypoint | Result |
| --- | --- | --- |
| Runtime status | `/cerebro health [runtime-id]` | Source runtime health, sync state, ingest state, and finding evaluation state. |
| Findings review | `/cerebro findings [runtime-id]` | Open findings with Cerebro links and action buttons. |
| Evidence review | `/cerebro evidence <runtime-id> <finding-id>` | Evidence rows for a finding, plus EvidenceCAS refs when Cerebro exposes them. |
| Graph question | `/cerebro ask <question>` | Cerebro-backed answer with cited source context and remembered team context. |
| Reusable checks | `/cerebro skills` and `/cerebro skill <skill-id> [details]` | Available checks and an immediate run for a selected check. |
| Scheduled checks | `/cerebro schedule <plain language>` and `/cerebro schedules` | Durable checks that run on a cadence and post results back to Slack. |
| Durable goals | `/cerebro goal <objective>` and `/cerebro goals [status]` | Long-running work with checkpoints, leases, and approval gates. |
| Risk subject check | Ask Cerebro in a configured security thread | One bounded DM to the evidence-linked person, with the self-reported answer returned to the originating security thread. |
| Runtime writes | `/cerebro sync`, `/cerebro ingest`, `/cerebro evaluate` | Source runtime work submitted through Cerebro write APIs. |
| Operator status | `/cerebro operator whoami` and `/cerebro operator deploy` | Actor mapping, write access, deploy policy, and current deployment fence state. |
| Cerebro fleet | App Home and `/cerebro operator health` | Active, draining, and stopped Cerebros with label, role, commit, instance id, and heartbeat. |
| Cerebro ensemble | Human investigate and act requests | Active security peers challenge the answer read-only; an Opus chair returns one response. Peer timeout leaves the primary answer unchanged. |
| Distributed Cerebro work | Multi-source investigate and act requests | Opus chooses whether independent read-only checks should run on live peers. The primary imports their evidence receipts, completes any remaining checks, and remains the only writer and final responder. |

## Security Cases

Security cases give operators a durable view of GitHub security alerts and canonical Cerebro compliance work items without changing the existing commands, findings, goals, schedules, or evidence workflows. Cerebro owns the compliance work queue; the companion stores the Slack case and approval history.

An operator can ask Cerebro to handle an alert in a normal Slack thread. The assistant resolves the Cerebro runtime, finding, repository, and alert reference through the existing Pi work loop, then starts a case. The case records the current state, owner, next action, blockers, evidence-backed resources, pull request, approvals, and completion receipt.

The first supported journey is:

1. Investigate the current Cerebro finding and affected resources.
2. Attach a bounded code fix and open a draft pull request.
3. Keep checking after CI passes until the pull request merges.
4. Request reviewed approval for a fresh finding evaluation.
5. Read the finding again and close the case only when the current status is `resolved`.

For canonical compliance work, the assistant opens one case per Cerebro work-item ID, reads live state from Cerebro, and submits commands with the current item version. Each write becomes an approval-required durable goal step. Remediation records the change first; a separate `verify_assurance` command can resolve the item only after Cerebro accepts a fresh post-change assurance decision.

Case states use operator work language: `investigating`, `needs_evidence`, `needs_decision`, `ready_to_act`, `waiting_on_owner`, `verifying`, `closed`, and `blocked`. The agent tools preserve the GitHub alert journey and add canonical work-item open, list, status, command planning, approved execution, and independent verification. See [Canonical compliance work cases](docs/canonical-compliance-work-cases.md) for the data contract and rollout gates.

Unknown `/cerebro ...` text is treated as a graph-backed question.

## Slash Commands

| Command | Purpose |
| --- | --- |
| `/cerebro help` | Show available commands. |
| `/cerebro home` | Refresh the Slack app home tab. |
| `/cerebro health [runtime-id]` | Show source runtime health. |
| `/cerebro findings [runtime-id]` | List open findings by runtime. |
| `/cerebro ask <question>` | Ask a Cerebro question using graph, evidence, and memory context. |
| `/cerebro evidence <runtime-id> <finding-id>` | Show finding evidence rows. |
| `/cerebro skills` | List reusable security checks. |
| `/cerebro skill <skill-id> [details]` | Run a reusable security check now. |
| `/cerebro schedule <plain language>` | Create a scheduled check. |
| `/cerebro schedules` | List scheduled checks. |
| `/cerebro schedule run <schedule-id>` | Run a scheduled check now. |
| `/cerebro schedule pause <schedule-id>` | Pause a scheduled check. |
| `/cerebro schedule resume <schedule-id>` | Resume a scheduled check. |
| `/cerebro goal <objective>` | Create an autonomous goal. |
| `/cerebro goals [status]` | List goals by status. |
| `/cerebro goal show <goal-id>` | Show goal state and recent checkpoints. |
| `/cerebro goal pause <goal-id>` | Pause a goal. |
| `/cerebro goal resume <goal-id>` | Resume a paused goal. |
| `/cerebro goal cancel <goal-id>` | Cancel a goal. |
| `/cerebro goal complete <goal-id> [summary]` | Mark a goal complete. |
| `/cerebro operator [whoami\|deploy]` | Show operator identity or deploy policy. |
| `/cerebro sync <runtime-id>` | Start a source runtime sync. |
| `/cerebro ingest <runtime-id>` | Start graph ingest for a runtime. |
| `/cerebro evaluate <runtime-id>` | Start finding evaluation for a runtime. |

Aliases: `/cerebro finding`, `/cerebro runbooks`, `/cerebro runbook`, `/cerebro cron`, `/cerebro jobs`, and `/cerebro ops`.

## App Mentions And Triage

- `@Cerebro ...` app mentions run through the same answer pipeline as `/cerebro ask`.
- Triage channels are controlled by `SLACK_TRIAGE_CHANNEL_IDS`.
- Risk subject checks are controlled separately by `SLACK_RISK_ATTESTATION_CHANNEL_IDS`. Cerebro requires current risk evidence, a unique active human Slack identity, and an originating security thread. The answer never closes or changes the risk by itself.
- The triage loop dedupes Slack events, reviews security-relevant work messages and root app alerts, researches the local thread or channel context, and posts lifecycle notices when enabled.
- App mention failures are reported as failures. The service does not send a substitute answer after a failed app mention response.
- Research is bounded by `SLACK_RESEARCH_MAX_CHANNELS`, `SLACK_RESEARCH_HISTORY_LIMIT`, `CEREBRO_TRIAGE_MAX_RESEARCH_STEPS`, and `CEREBRO_TRIAGE_TIMEOUT_MS`.

## Memory And Learning

The companion uses memory to improve security answers, but recalled notes are context, not proof.

| Memory source | Configuration | Use |
| --- | --- | --- |
| Security learning table | `SECURITY_LEARNING_TABLE_NAME` | Prior investigations, recurring patterns, answer summaries, and team-specific context. |
| Security mission table | `CEREBRO_AUTONOMY_GOALS_TABLE_NAME` | Mission snapshots, immutable transitions, leases, revisioned work outbox records, and sharded operator indexes. |
| Security mission queue | `CEREBRO_AUTONOMY_QUEUE_URL` | FIFO delivery of bounded mission revisions, retry handling, and dead-letter isolation. |
| Joined Slack channels | `CEREBRO_SLACK_CHANNEL_LEARNING_*` | Model-curated reusable context from ordinary human messages in public and private channels where Cerebro is a member. |
| Company library | `SECURITY_LEARNING_TABLE_NAME` | Versioned operating dossiers and cross-domain theses derived from cited candidate memories. |
| Daily notes | `CEREBRO_DAILY_NOTES_*` | Consolidated work notes with retention controls. |
| Working memory files | `SECURITY_WORKING_MEMORY_DIR` | Compact non-secret notes loaded into prompts. |
| Learning docs | `SECURITY_LEARNING_DOCS_DIR` | Longer reference docs loaded under a character limit, including `SECURITY_KNOWLEDGE.md` for source-backed Infosec context. |
| Improvement artifacts | `CEREBRO_IMPROVEMENT_*` | Private redacted human-feedback cases, candidate receipts, held-out evaluation, shadow results, canary results, and promotion state. |

Passive channel learning is separate from reply and triage routing. It ignores DMs, bot posts, message edits, commands, and Cerebro mentions. Redacted batches stay in process until the configured size or flush interval; the configured orchestrator model curates one batch at a time, and durable memory receives only its compact result. Set `CEREBRO_SLACK_CHANNEL_LEARNING_EXCLUDED_CHANNEL_IDS` for channels that must not contribute context. Curation failure stores nothing.

Direct human Cerebro interactions follow a separate improvement path. Every delivered answer is written to the private interaction ledger. Answers with allowed live evidence create a redacted, subject-bound training case in the encrypted improvement bucket even when Slack presentation paraphrases the verified claim. Blocked, incomplete-delivery, and downvoted interactions become response-only failure replays with no facts or receipts; they teach Cerebro to answer the request without turning the failed response into evidence. Follow-ups link to the prior same-human interaction and carry the prior exchange as case context. Memory-only answers, Slack mentions, Slack message URLs, and secret values do not become training truth. The Opus hillclimb loads these cases for development when `CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET` or `--conversation-bucket` is set; live cases never enter held-out evaluation.

Historical channel learning runs as a one-off process from the deployed image. It lists only joined public and private channels, scans a fixed time window, expands thread replies, drops bot and app posts before curation, and checkpoints progress in the learning table. Batch markers make restarts idempotent, and run receipts contain coverage counts without message text. The default command scans 180 days:

```bash
npm run backfill:slack -- --days 180 --max-roots-per-channel 20000
```

Use an ECS one-off task with the service task definition so the process receives the same network, task role, runtime configuration, and mounted learning docs as the service. A completed checkpoint is skipped on rerun; a failed or capped checkpoint resumes from its last completed history page.

Company library compounding groups cited Slack memories into operating dossiers, recursively merges repeated domains, and forms cross-domain theses. Dossiers retain procedures, owners, decisions, exceptions, contradictions, open questions, dates, and source receipts. Theses state the repeated pattern, its limits, and what would disprove it. Every record remains a candidate with `until_reverified` freshness; current policy, access, ownership, product state, and deployment state still require a live source check.

The service checks for at least 12 new Slack memory records every six hours. A DynamoDB lease allows one writer, and source-batch fingerprints make retries idempotent. Each completed run writes one generation-specific snapshot, then atomically switches the active-generation pointer with the run receipt. Searches read only that active snapshot; incomplete runs cannot replace it, and prior snapshots remain available for audit. The librarian requires the configured Opus orchestrator model. Run compounding immediately from the deployed image with:

```bash
npm run compound:library -- --force --min-records 1
```

Use [docs/infosec-assistant-knowledge.md](docs/infosec-assistant-knowledge.md) when adding asset, owner, connector, detection, access, severity, exception, runbook, and investigation context. The Prisma Cloud connector source map lives in [docs/prisma-cloud-connector-sources.md](docs/prisma-cloud-connector-sources.md), and broader SDK/API connector sources live in [docs/security-connector-sdk-sources.md](docs/security-connector-sdk-sources.md). Do not store raw logs, transcripts, secret values, credentials, hidden reasoning, or personal data in memory files. Evidence and graph facts should come from Cerebro or linked source systems.

## Autonomy Boundaries

Durable goals let the service keep working across Slack turns and worker restarts. Each runnable mission transition writes a revisioned work-outbox record in the same DynamoDB transaction as the snapshot and ledger event. A publisher sends that revision to the FIFO mission queue. A worker claims the exact revision, advances one ready step, writes a checkpoint and consumption receipt, posts state back to Slack, and releases the claim. Delayed and duplicate messages cannot execute a newer revision. Transient failures retry through SQS and exhaust into the mission dead-letter queue.

`CEREBRO_AUTONOMY_QUEUE_ENABLED=false` keeps the prior due-index runner available for local development and rollback. Production enables the queue. A five-minute reconciliation pass repairs a missing outbox item for a due mission without becoming the primary execution scheduler.

Self-repair goals include a GitHub monitor step. When a goal includes a PR URL, PR number, branch, ref, or commit, the runner reads PR/check status through the bounded runtime-code GitHub client. Pending checks schedule another wake, passing checks move the goal to review/merge waiting, merged PRs complete the goal, and failed checks block the goal with the check result recorded.

Repeated human answer gaps, runtime failures, and needs-work ratings also enter the recursive-improvement control plane. Equivalent signals accumulate in one durable run. Before the author queue receives work, the control plane resolves the immutable repository base and source commits and signs an expiring delegation manifest with the exact run, generation, signal digests, repository boundary, draft-only authority, execution budgets, policy versions, and deterministic rollout cohort. The author workcell verifies that manifest before model or GitHub access. `disabled` and `shadow` jobs perform no model or GitHub work; `canary` runs only eligible signed cohorts; `active` runs every valid cohort. A separate verifier workcell has no model access and receives no GitHub write credential. Protected GitHub workflows sign exact repository, pull request, branch, base, candidate commit, and required-check receipts before the verifier accepts held-out, shadow, canary, or promotion work. Promotion requires a separate evaluator version and a separately signed reviewed decision. Machine handoffs do not create improvement runs.

Review-class executor steps create an approval record and move the goal to `approval_needed`. Slack users in `SLACK_AUTONOMY_APPROVAL_USER_IDS` can approve or reject the step from Slack. Destructive actions, exfiltration, credential exposure, and unsupported repositories stay blocked.

For the deeper autonomy plan, see [docs/autonomy-roadmap.md](docs/autonomy-roadmap.md).

## Cerebro Access

The companion talks to Cerebro through tenant-scoped credentials. Reads use the shared read key. Writes require both a route-specific Cerebro key and a Slack user allowlist.

| Area | Cerebro credential | Slack allowlist |
| --- | --- | --- |
| Reads | `CEREBRO_READ_API_KEY` | Slash command or app mention access. |
| Findings | `CEREBRO_FINDINGS_API_KEY` | `SLACK_FINDING_WRITE_USER_IDS` |
| Source runtimes | `CEREBRO_SOURCE_API_KEY` | `SLACK_SOURCE_WRITE_USER_IDS` |
| Runtime responses | `CEREBRO_RUNTIME_RESPONSE_API_KEY` | `SLACK_RESPONSE_WRITE_USER_IDS` |
| Graph actions | `CEREBRO_GRAPH_ACTION_API_KEY` | `SLACK_GRAPH_ACTION_USER_IDS` |
| Operator checks | Existing deploy metadata | `SLACK_OPERATOR_USER_IDS` |

Graph Cypher and graph mutations go through Cerebro. The companion does not connect directly to Neo4j.

## Runtime Tools

- EvidenceCAS is read-only and only resolves refs surfaced by Cerebro evidence.
- Infisical tooling exposes project metadata and fingerprints by default. Secret values stay disabled unless `INFISICAL_ALLOW_SECRET_VALUES=true`.
- Panther MCP tools are read-only by default. Set `PANTHER_MCP_ENABLED=true` and `PANTHER_MCP_URL` to a Streamable HTTP MCP endpoint, or enable the ECS sidecar with `pantherMcpSidecarEnabled`. The Panther MCP service owns `PANTHER_INSTANCE_URL` and `PANTHER_API_TOKEN`; the companion only needs `PANTHER_MCP_AUTH_TOKEN` when an external MCP endpoint requires bearer auth.
- Runtime code tools can read GitHub PR and check status for any repo. GitHub PR creation is restricted by `CEREBRO_CODE_WRITE_ALLOWED_ORGS`, file limits, shell limits, and GitHub credentials.
- Code Mode is model-selected for repeated calls, filtering, joins, pagination, or other bounded composition. Each execution runs in a fresh QuickJS child with no ambient environment, filesystem, network, module loader, or host objects; nested tools keep their normal Slack actor, intent, approval, target, budget, and evidence checks.
- A configured Slack operator can ask Cerebro to improve its own behavior. Cerebro can inspect runtime, skill, and workspace state in Code Mode and submit one draft-only companion PR through `cerebro_code_self_improvement_pr`. The host derives the candidate id from the Slack turn, binds the content digest and current base SHA, and blocks dependency, credential, policy, evaluator, release-gate, and Code Mode paths. Merge, deployment, and promotion remain separate reviewed actions.
- Compliance context is read-only and pulled from `CEREBRO_COMPLIANCE_CONTEXT_REPO` at `CEREBRO_COMPLIANCE_CONTEXT_REF`, defaulting to `writer/cerebro@main`. Set `CEREBRO_COMPLIANCE_CONTEXT_LOCAL_DIR` to use a mounted checkout; otherwise the companion fetches a curated bounded corpus from GitHub and caches it in memory.
- The default assistant runtime is Pi on Amazon Bedrock: `PI_PROVIDER=amazon-bedrock`, `PI_MODEL=us.anthropic.claude-opus-4-8`. Flue uses that model to orchestrate plans and final synthesis. Set `PI_EXECUTION_MODEL` and `PI_EXECUTION_THINKING_LEVEL` to run the bounded tool-execution stage on a faster model; when unset, execution uses the orchestrator model and thinking level.
- In ECS, Bedrock access should come from the task role, not long-lived keys.

## Local Development

Install dependencies:

```sh
npm ci
```

Create local configuration:

```sh
cp .env.example .env
```

Run in Socket Mode:

```sh
npm run dev
```

Socket Mode requires `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_SOCKET_MODE=true`, and Cerebro read configuration. HTTP mode requires `SLACK_SIGNING_SECRET` and the Express endpoint exposed to Slack.

Run checks:

```sh
npm run typecheck
npm run architecture:check
npm test
npm run build
npm run check
```

`npm run check` runs typecheck, architecture checks, and tests.

Update the vendored Cerebro SDK after backend contract changes:

```sh
npm run sync:cerebro-sdk
```

The generated SDK lives in [vendor/cerebro-sdk](vendor/cerebro-sdk).

## Configuration

Use [.env.example](.env.example) as the complete configuration index. Important groups:

- Slack transport, team allowlist, triage channels, lifecycle notices, research limits, and audit logs.
- Cerebro base URL, tenant, web URL, default runtimes, companion runtime id, read key, write keys, and Slack user mapping.
- EvidenceCAS read-only lookup settings.
- Infisical read-only metadata settings.
- Panther MCP endpoint, allowed tools, auth token, and timeout.
- Slack write allowlists for findings, sources, runtime responses, graph actions, autonomy approvals, and operator commands.
- Proactive triage and assistant runtime settings.
- Security learning, daily notes, working memory, and learning docs.
- Runtime code workspace, shell limits, GitHub write orgs, and GitHub PR credentials.
- Recursive-improvement table, private artifact bucket, queue, evaluator, worker, and promotion settings.
- Scheduled checks, durable goals, telemetry, HA event dedupe, and ECS deployment fence settings.

## Deploy

This repository owns the host source, tests, and container build inputs. The deployment repository owns environment configuration, cloud resources, promotion, release receipts, runtime checks, and rollback.

A deployment must consume an exact commit from this repository, verify its signed Cerebro product manifest, and record the deployed commit and image digest. A container start is not a healthy release: the deployment gate must also verify steady state, runtime configuration, Cerebro access, Slack delivery, and rollback state.

See [docs/monorepo-cutover.md](docs/monorepo-cutover.md) for the source and deployment ownership contract.

`/cerebro operator deploy` reports the deploy policy, actor access, and whether the ECS deployment fence is enabled for the running worker.

`/cerebro operator health` reports the same readiness snapshot as `/readyz`: config audit, deploy fence, Slack work queue, scheduled-check backlog, autonomy-goal backlog, and failing runtime checks.

## Repository Map

| Path | Owner |
| --- | --- |
| [src/index.ts](src/index.ts) | Process bootstrap and runtime wiring. |
| [src/agent/tools](src/agent/tools) | Agent tool registry, tool metadata, policy, and telemetry instrumentation. |
| [docs/operating-contracts.md](docs/operating-contracts.md) | Tool authority, runtime boundary, credential, and target-ownership rules. |
| [docs/security-mission-fabric.md](docs/security-mission-fabric.md) | Versioned AppSec, identity, and detection mission contracts, execution states, approvals, and completion rules. |
| [docs/infosec-assistant-knowledge.md](docs/infosec-assistant-knowledge.md) | Source intake and recall rules for Infosec assistant knowledge. |
| [docs/prisma-cloud-connector-sources.md](docs/prisma-cloud-connector-sources.md) | Prisma Cloud connector source map for recall-backed connector questions. |
| [docs/security-connector-sdk-sources.md](docs/security-connector-sdk-sources.md) | SDK and API source map for security connector implementation and recall. |
| [docs/testing-strategy.md](docs/testing-strategy.md) | Test layer selection and mocking rules. |
| [TELEMETRY.md](TELEMETRY.md) | Production telemetry pivots, query recipes, domains, and config switches. |
| [src/config](src/config) | Environment parsing and typed runtime configuration. |
| [src/runtime](src/runtime) | Config audit, readiness checks, and runtime health rendering. |
| [src/slack/commands](src/slack/commands) | Slash command handlers by domain. |
| [src/slack/actions](src/slack/actions) | Slack button and modal action handlers by domain. |
| [src/slack/events](src/slack/events) | App mentions, message events, and event-level coordination. |
| [src/slack/research](src/slack/research) | Read-only Slack research tools for assistant context. |
| [src/slack/coordination.ts](src/slack/coordination.ts) | Slack event dedupe, release receipt coordination, restart evidence, and ECS deployment fence checks. |
| [src/a2a/fleet.ts](src/a2a/fleet.ts) | A2A instance discovery, addressed messages, Agent Card, and acknowledged shutdown handoff. |
| [src/a2a/rate-limit.ts](src/a2a/rate-limit.ts) | Tenant-wide Dynamo leases and shared provider cooldowns for Cerebro model workflows and source calls. |
| [src/agent/cerebro-ensemble.ts](src/agent/cerebro-ensemble.ts) | Read-only peer review and Opus arbitration for difficult human requests. |
| [src/agent/distributed-work.ts](src/agent/distributed-work.ts) | Opus work decomposition, parallel read-only peer execution, progress messages, evidence receipts, and packet resumption. |
| [src/slack/release-receipt.ts](src/slack/release-receipt.ts) | Typed validation for durable deployment receipts and release checks. |
| [src/agent](src/agent) | Assistant runtime, tool registry, and Cerebro answer flow. |
| [src/cerebro](src/cerebro) | Cerebro API client and service modules. |
| [src/evidence-cas](src/evidence-cas) | EvidenceCAS read-only ref resolution. |
| [src/infisical](src/infisical) | Infisical metadata and fingerprint lookups. |
| [src/learning](src/learning) | Daily notes and learning document loading. |
| [src/learning/security-memory](src/learning/security-memory) | Durable security learning storage, scoring, and retrieval. |
| [src/improvement](src/improvement) | Recursive-improvement runs, artifacts, queues, evaluation, worker, and promotion gates. |
| [src/schedules](src/schedules) | Scheduled check storage, parsing, runner, and Slack output. |
| [src/autonomy](src/autonomy) | Goal storage, runner, approval flow, and checkpoints. |
| [src/skills](src/skills) | Reusable security check definitions. |
| [src/triage](src/triage) | Proactive alert triage pipeline. |
| [src/security](src/security) | Safety checks for destructive or unsafe requests. |
| [src/code](src/code) | Runtime code workspace, shell checks, and GitHub PR helpers. |
| [src/work](src/work) | In-process work queue and background work tracking. |
| [infra](infra) | Pulumi infrastructure for sec-dev. |
| [docs](docs) | Architecture notes, autonomy roadmap, and Slack app manifest. |

## References

- [Architecture](docs/architecture.md)
- [Autonomy roadmap](docs/autonomy-roadmap.md)
- [Security Mission Fabric](docs/security-mission-fabric.md)
- [Slack app manifest](docs/slack-app-manifest.yaml)
