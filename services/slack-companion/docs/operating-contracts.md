# Operating Contracts

These contracts keep the Slack companion predictable as the agent tool surface grows.

## Tool Authority

Agent tools live under `src/agent/tools`. `src/agent/tools/tool-metadata.ts` classifies each tool by:

- family
- authority
- target source
- credential scope
- side effect
- retry model

Update the metadata when adding a tool. The policy manifest and telemetry use this metadata so operators can tell whether a tool is read-only, memory-writing, workspace-writing, shell-backed, or GitHub-writing.

Do not create detached tool trees under `src/tools`. New tools should be registered through the existing `createSecurityAgentTools` composition path.

## Runtime Boundaries

When data crosses an external, async, durable, approval, scheduler, runtime-code, or Slack boundary, the receiving module owns validation.

Defaults:

- Parse external or durable data before using it for routing, credentials, locks, approvals, or side effects.
- Keep actor, destination, credential subject, runtime id, and idempotency key as explicit fields.
- Do not infer authority from nearby text or recovered metadata after a boundary crossing.
- Use model tool schemas for model input, but validate host-owned authority in runtime code.
- Repair legacy data only in named migration or backfill paths.

## Runtime Health

The companion exposes two local health routes:

- `/healthz` is liveness. It should stay shallow and return when the process can answer HTTP.
- `/readyz` is readiness. It reports typed config, dependency, deployment fence, queue, schedule, and autonomy states as line-oriented text.

Slack operator health uses the same readiness snapshot as `/readyz`. Do not add a separate operator-only health path for the same state. Add new checks to `src/runtime/health.ts`, then render them through both surfaces.

Readiness checks must not return secrets, raw Slack text, prompts, tool arguments, tokens, cookies, or credential values. Use explicit check ids, low-cardinality statuses, and concrete operator actions.

## Failure Budgets

Background work must stop retrying after a bounded number of repeated failures.

- Scheduled checks block after repeated failed runs. Operators can inspect the last summary and resume the schedule after the dependency, prompt, or channel target is fixed.
- Autonomy goals block after repeated runner failures. Operators can inspect the blocker and resume the goal after the dependency or stored state is fixed.
- Blocking a job or goal must record a structured telemetry event and preserve the last operator-facing error summary.

## Agent Control Plane

Cerebro owns the security-agent control plane. The companion may read it through the route-scoped read key, but it must parse the response into typed runtime fields before using it for goal creation, runner policy, approvals, or tool summaries.

Required fields for autonomy work:

- control-plane version
- selected profile id
- goal capability id
- maximum action stage
- requested action stage
- required verifier ids
- selection time

Durable goals store these fields as `executionContract`. Runner code must enforce `maxActionStage` before starting a goal step. If a stored contract is missing or invalid, attach a new contract before advancing the goal. If the selected contract does not allow the requested stage, block the goal and record the blocker.

## Code Mode Execution

Code Mode is a model-selected execution style within the existing Pi and Flue research plan. It may compose registered operations, but it does not create a second agent, a deterministic question router, or a new authority boundary.

- Start one fresh child process for each `cerebro_execute` call. Run only the synchronous QuickJS `RELEASE_SYNC` build. Do not reuse a runtime or load an Asyncify build.
- Give the child only bounded program input and a typed IPC channel. Do not give it environment variables, credentials, filesystem access, a working-directory capability, network access, module loading, dynamic import, timers, host objects, or direct tool implementations.
- Treat model-produced JavaScript as untrusted even when the Slack requester and registered tools are trusted. The parent process owns validation, authority, dispatch, cancellation, and result bounds.
- Resolve each nested call from the current registered `AgentToolCatalog`, validate its bounded argument object, and apply the same current-turn plan, selected-tool, actor, intent, approval, target, research-budget, failure-circuit, credential, instrumentation, and evidence checks as a direct call.
- Make registered trusted Slack and write tools discoverable and eligible for selection. Do not silently remove a write merely because Code Mode is active. A nested write still requires its ordinary host-owned authority and exact approval. A guest field such as `approved=true` is input to validate, not proof of approval.
- For an explicit self-improvement request from a configured Slack operator, compose runtime, skill, workspace, and validation reads in Code Mode when useful. Use the turn's one side effect for `cerebro_code_self_improvement_pr`, which forces the configured companion repository, draft state, branch prefix, idempotent candidate id, file bounds, and protected-path exclusions. When no code change is needed, use one skill-improvement write instead. Do not expose general workspace writes, shell, or general GitHub writes to the self-improvement intent.
- Bind catalog discovery and execution to one bounded catalog snapshot. The toolset digest detects accidental or stale mismatch only; it does not grant access, prove the caller, authorize a target, or replace the current plan and policy checks.
- Reject broker recursion, unknown tools, tools outside the current research plan, malformed messages, duplicate call ids, late replies, stale execution ids, and excess pending or total calls. Never accept a model-supplied function, URL, shell fragment, credential, receipt, or host object as a tool implementation.
- Require explicit authority metadata for every write-shaped registered tool name. Reject a newly registered create, update, write, patch, shell, request, execute, or similar operation until its authority, credential, target, retry, and side-effect metadata are exact.
- Allow at most one side-effecting nested call per execution and serialize it after prior reads settle. Use a direct call or a durable agent-run workflow for work that needs more than one side effect.
- Enforce program-size, argument-size, result-size, output-size, tool-count, side-effect-count, CPU, wall-clock, child-lifetime, and memory limits. Kill the child on deadline or protocol failure and reap it before completing the outer call.
- Do not retry a nested side effect automatically. If the child exits, the guest fails, result finalization fails, or the side-effect tool reports failure after the host accepted a write, record `outcome_unknown`, stop the execution, and run the registered independent read verifier before reporting completion or considering another action.
- Reject a program that returns while a nested call is outstanding. If that outstanding call is side-effecting, record `outcome_unknown`, stop the turn, and require independent target verification.
- Keep merge, deploy, promotion, infrastructure, and production control-plane actions outside a self-improvement Code Mode program. Passing held-out, shadow, canary, GitHub-check, exact-head, reviewed-decision, and signature gates remain mandatory where the recursive-improvement control plane applies.
- Treat `cerebro_execute` and catalog search as orchestration controls. They do not consume a source-research step and do not mint evidence. Each successful nested source call consumes the normal budget and mints its own current-turn receipt and subject-bound evidence envelope. Failed, blocked, fabricated, late, or duplicate calls mint nothing.
- Keep source code, source hashes, tool arguments, tool results, IPC payloads, child stdout and stderr, target identifiers, toolset digests, evidence receipts, Slack text, and credentials out of telemetry and logs. Emit fixed outcome classes, bounded counts, durations, limit classes, and child-exit classes only.

The child-process boundary removes ambient companion capabilities and gives the parent a kill boundary. It is not an operating-system sandbox. Production deployment must additionally bound the companion task or worker memory. If the shipped QuickJS WebAssembly module can grow beyond its configured runtime limit, use a fixed-memory module or a separately memory-limited worker before claiming memory-safe containment.

## Assistant Intelligence State

Research-plan, claim-ledger, world-state, hypothesis-ledger, decision-ledger, workflow-compile, action-simulation, and attention-decision tools store bounded state for the current assistant turn. They do not grant authority, call an external system, or perform a write. Observed facts and supported or contradicted claims must reference an evidence receipt issued by a successful source tool in that turn.

The assistant thread-state store persists the bounded result for follow-up continuity. Durable state is parsed and normalized when read. Treat it as context for entity resolution, prior reports, decisions, and resumable work. Reverify current findings, deployments, identities, tickets, alerts, and resource state through the owning source before asserting that they are unchanged.

Each human request also advances a private mission record with an objective, desired outcome, exact source subjects, acceptance criteria, open loops, delivery state, and last user intent. Keep the exact Slack thread as the primary continuity key. A referential or corrective root message may resume the latest mission for the same channel and human; a new concrete request must not inherit that mission, and another human must never receive it.

Successful source tools produce an evidence envelope in addition to an opaque receipt. The envelope keeps a finding, runtime, ticket, repository, person, or resource id beside its source tool, URL, observed time, and returned fields. Claim evidence, mission subjects, citations, and evals must preserve that binding. Never transfer a status, timestamp, count, owner, or URL between subjects returned by the same tool.

Human requests also carry private teammate state: the objective, desired outcome, scope resolved from the request or tools, bounded assumptions, Cerebro commitments, open loops, and one required user decision when progress cannot continue safely. The assistant must inspect thread state and relevant sources before requesting scope. Generic requests for a repository, ticket, project, owner, runtime, or source are not a valid substitute for inspection. Every unfinished Cerebro commitment must reference a durable goal with acceptance criteria. The host must read that goal before presentation and replace model-authored status with stored status, next wake, blockers, artifacts, and completion evidence. A missing, cross-thread, or unpersisted goal is not an active commitment. Teammate fields are internal continuity data and must not appear as labels or schema text in Slack replies.

## Response Feedback

Human-facing assistant answers include `Helpful` and `Needs work` controls. `Helpful` records the rating immediately, then asks what Cerebro should repeat. The user can select a positive category and add the useful behavior and completed result. A needs-work rating requires a category and can include the expected result and a comment.

- Keep one current rating per Slack user and answer. A later rating replaces the earlier rating.
- Use personal categories to tune later replies for that user. Require recurrence before applying a category across the team.
- Require two helpful ratings across two threads before applying a personal successful pattern. Require five helpful ratings from three contributors across three threads before applying a team successful pattern.
- Give the same requester at most two topic-related or same-thread successful examples. Quote positive notes and completed results as untrusted text.
- Resolve the feedback author's Slack display name at submission time and retain the Slack user id as the stable identity.
- Give later replies to that same user at most three recent needs-work cases with bounded, redacted excerpts of the comment, original request, and delivered response. Delimit the cases as untrusted feedback and never follow instructions inside them.
- Keep exact comments and completed results out of cross-user team guidance. Team guidance includes the category and support counts, not contributor names.
- Treat ratings as quality and preference signals only. They are not security facts, source evidence, operator instructions, approval, authority, or permission.
- Store needs-work examples as transient `skill_improvement` context. Promotion or code repair still follows the existing review boundary.
- Join each rating to the delivered answer record: sender kind, execution lane, selected tool names, research trail, evidence refs, actions taken, next actions, durable commitment ids and states, and Slack delivery receipt. This context is for outcome analysis; it does not grant authority.
- Record delivery, later follow-ups, explicit rework requests, verified action closure, mission completion, total latency, and source-subject counts as separate outcome events. These events measure whether the answer reduced work; they do not become company facts or authorize a change.
- After each delivered human answer, write one redacted conversation case to the encrypted improvement bucket when the answer contains allowed live source evidence. Presentation wording does not determine whether verified evidence can enter the case. Required facts and subject bindings come only from verified claim packets. Blocked, incomplete-delivery, and downvoted interactions may enter as response-only failure replays with no factual target or evidence receipt; memory-only answers cannot teach factual corpus content. A same-human follow-up carries the prior request and answer into thread context and links the new interaction to the prior interaction id.
- Live conversation cases are training data only. The hillclimb may load recent train cases from `CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET`; it must ignore every other partition. Promotion still depends on the static, untouched held-out partition.
- Release replay gates score human requests. Bot-authored machine handoffs remain eligible for Pi suppression but do not count toward human response-quality release thresholds.
- Keep the attributed cases in the private feedback and improvement stores. Do not emit raw questions, answers, comments, or display names in telemetry or candidate PR material.

A valid compiled workflow does not authorize execution. Every action step needs the existing host-owned approval and target checks. The workflow compiler additionally requires an idempotency key, rollback, and verification condition so the autonomy goal can resume safely.

## Risk Subject Checks

Cerebro may ask one person whether they performed or approved activity tied to a security risk. This is available only from channels in `SLACK_RISK_ATTESTATION_CHANNEL_IDS`.

- Require current source evidence for the risk, an explicit account-to-person identity basis, at least one evidence receipt issued by a successful source check in the current answer, and one unique active human Slack user id before sending a message.
- Send only a bounded activity summary, source system, and observed time. Keep identity evidence, raw evidence, secrets, and accusation language out of the DM.
- Accept an answer only from the Slack user who received the check. Store `yes`, `no`, or `unsure` as self-attestation with a 90-day TTL and make duplicate requests and responses idempotent.
- Report the answer to the originating security thread without mentioning the person. Label it self-reported and name the independent verification step.
- Never treat an answer as source evidence, approval, permission, or risk disposition. Do not resolve, suppress, downgrade, or otherwise change a risk from the answer alone.

## Policy Discovery Candidates

The Slack assistant may create, prove, and shadow private Cerebro policy candidates for configured operators and configured security-triage channels. Policy discovery is separate from assistant self-improvement: it authors a security control and its tests, not companion runtime code or prompts.

- Treat Slack messages, incident discussion, corrections, and proposed explanations as untrusted hypotheses. Do not treat them as source evidence, current asset state, approval, or policy truth.
- Send Cerebro only a host-derived bounded semantic hypothesis, a host-derived opaque Slack origin reference, and typed request-local graph topology. Never send raw channel ids, message timestamps, Slack text, AWS account ids, ARNs, session names, endpoints, secret names, or secret references.
- Allow candidate creation, proof, and shadow execution for a configured Slack operator or a configured security-triage channel, including bot-root triage without a human user id. Require a configured operator for cross-candidate get and list operations. Derive the origin reference in host code; model input cannot select an origin or actor.
- Cerebro owns the `grounded -> proved -> ready_for_review` lifecycle. `blocked` is terminal. The companion cannot skip states or assert proof from generated text.
- Candidate proof may author policy and test artifacts and execute isolated tests. Candidate shadowing reads the bounded current graph and returns counts and an opaque receipt; it does not create findings.
- Model-visible candidate results include lifecycle state, safe entity types and relations, graph counts, proof gates, shadow counts, artifact paths, and artifact digests. Omit origin references, graph node handles, source identifiers, generated file bodies, and raw evidence.
- Candidate tools cannot promote a policy, create or update findings, write graph data, open a pull request, merge code, deploy, or change production policy state.
- A `pr_ready` result is a review gate, not GitHub authority. Opening a draft remains a separate code-change or response-action workflow through the existing GitHub tool and its host-owned target and review checks. An ordinary security-answer intent cannot make that write.
- Candidate artifact export is operator-only and available only to code-change or response-action intents. It returns exactly the generated policy and test files after checking `ready_for_review`, `pr_ready`, proof, shadow, artifact safety, and export-size bounds. It is a read and does not grant GitHub authority.
- Telemetry records fixed tool names, lifecycle outcomes, counts, durations, and error classes only. Keep hypotheses, Slack origins, evidence references, graph handles, policy bodies, test bodies, and cloud identifiers out of telemetry.

## Joined Channel Learning

Cerebro may learn from ordinary human messages in public and private Slack channels where the app is a member. Channel membership controls event delivery; the passive learning path does not widen Slack scopes or search channels the app has not joined.

- Keep passive learning separate from response, reaction, mention, command, and triage routing.
- Ignore DMs, bot posts, edits, commands, direct Cerebro mentions, and configured excluded channel ids. Preserve human references to other teammates after redaction so ownership and handoffs remain learnable.
- Redact and bound message text before buffering it in process. Do not write the batch to DynamoDB, EFS, telemetry, logs, daily notes, improvement artifacts, or PR material.
- Require semantic curation before every durable write. If no curator is configured, curation fails, or the batch has no reusable value, store nothing.
- Store compact declarative context with a Slack source reference. Reject social chatter, one-off status, speculation, personal details, and unsupported claims.
- Process independent source batches with bounded concurrency. On incremental runs, re-merge only affected dossier domains and carry unaffected active dossiers into the new generation. Publish the active pointer only after every refreshed dossier and thesis is durable.
- Treat channel-derived memory as context that must be reverified before a current-state or security claim.
- Run historical learning from the deployed image as a one-off task. Fix the upper timestamp at run start, checkpoint each completed page, and keep idempotent batch markers so a retry does not relearn completed batches.
- Keep ordinary joined-channel learning continuous through Slack message events. Keep direct Cerebro interactions in the improvement ledger and conversation corpus even though mention messages are excluded from company-memory curation.
- Record only channel ids, timestamps, counts, status, and curator outcomes in backfill checkpoints and receipts. Do not store message text in backfill state or logs.

## Agent Run Execution

Non-trivial work that continues beyond one answer uses the durable agent-run record. The model may propose the objective, plan, resources, and acceptance criteria. The host owns execution.

- Resolve tools only from the registered `AgentToolCatalog`; never execute a model-supplied function, URL, or shell fragment as a tool name.
- Validate exact tool arguments before dispatch and keep each argument object bounded.
- Block agent-run tools from recursively creating or mutating another run.
- Limit workspace, shell, and GitHub writes to self-repair capability runs.
- Require reviewed approval for Cerebro writes, ticket writes, and any step that explicitly requests approval.
- Require an independent read-only verification tool for external writes.
- Require Cerebro writes to carry an idempotency key and rollback plan.
- Evaluate named acceptance criteria from execution or verification evidence. Manual criteria remain pending.
- Record artifacts only after they exist. Record completion only through a completion receipt.
- On operator correction, verify the replacement against the owning source and preserve the previous claim, replacement, reason, and source references.

Canonical resource references provide stable identity across Slack, Cerebro, GitHub, Jira, Linear, AWS, Panther, evidence, people, and services. Their freshness and confidence fields are evidence metadata, not authorization.

Slack delivery is complete only when every planned reply part is posted. Give each part a stable idempotency id and retry transient Slack failures three times without reposting earlier parts. Persist planned and posted counts in the answer mission. A partial post after retries is a failed delivery, not a completed answer.

## Goal Failure Recovery

The goal document boundary removes undefined values before DynamoDB marshalling. Runner infrastructure failures use capped exponential rescheduling. After three consecutive equivalent failures, move the goal to `blocked`, clear `nextWakeAt`, preserve the plan and audit log, and emit one terminal runner event. An operator may resume the same goal after the stored cause is fixed.

## Recursive Improvement

Human answer gaps, runtime failures, and structured needs-work ratings feed one recursive-improvement control plane. Machine handoffs do not create improvement runs.

- Store private redacted examples only in the encrypted, versioned improvement artifact bucket. Keep Slack questions, answers, and comments out of commits, PR bodies, telemetry, and queue metadata.
- Accumulate equivalent signals in one cooldown-window run. Queue candidate work only after the configured signal threshold.
- Persist each monotonic author generation, its exact signal artifact SHA set, and its repository target before queueing work. Reconcile an unconfirmed queue dispatch from that durable intent. Only one unexpired generation lease may write the candidate branch, and stale generations must not record a candidate.
- Open code candidates through the isolated improvement worker. The worker receives the GitHub App credential, improvement table, artifact bucket, and queue; it does not receive Slack tokens or Cerebro write keys.
- The platform team owns maintenance, security review, and version upgrades for `@aws-sdk/client-s3` and `@aws-sdk/client-sqs`. The improvement artifact and queue adapters are their only runtime call sites.
- Treat candidate creation, held-out evaluation, shadow traffic, canary traffic, promotion, rollback, and blocking as explicit durable states with immutable events.
- Require a held-out human-traffic corpus and different candidate and evaluator versions. A candidate cannot change its own evaluator and pass in the same version.
- Treat source-subject mismatch, latency-budget failure, and excess human follow-ups as promotion blockers alongside invented receipts and visible internal failures.
- Require passing held-out, shadow, and canary outcomes before promotion. Promotion requires a KMS-signed reviewed decision from the protected GitHub environment.
- Bind held-out evaluation, shadow, canary, and the signed promotion decision to the exact candidate commit. Discard superseded well-formed jobs without retargeting them to a newer candidate.
- Roll back on a failed shadow or canary outcome. Move stale queued or evaluating runs to `blocked` so dead work does not retry indefinitely.
- Keep feedback and traffic signals advisory. They do not grant source authority, approval, credentials, or permission for production writes.
- Security mission packs are versioned plans, not authority grants. A missing identity or detection action tool remains `needs_tool`; the runner does not substitute a generic connector or mark the step complete.

## Credential And Target Ownership

The model may request work, but runtime code owns credential use and target boundaries.

- Slack tokens stay in Slack transport and Slack research tools.
- Cerebro keys stay route-scoped.
- EvidenceCAS resolves only refs surfaced by Cerebro evidence.
- Compliance packet tools are read-only. They build review packets, evidence ledgers, policy-system maps, redacted audit-safe summaries, finding lifecycle plans, exception drafts, triage quality checks, approval-backed remediation plans, and scheduler-compatible monitor drafts from supplied refs and source context; they do not certify a control, create a schedule, write a finding, or write to a GRC system.
- Infisical tools return status, metadata, and fingerprints, not raw secret values.
- Panther MCP tools are read-only by default. The MCP endpoint owns the Panther API token. The companion may hold only an optional bearer token for the MCP endpoint, and mutating Panther tool names stay disabled until a reviewed approval path exists.
- Enabled mutating Panther tools are classified as `security_write`. Durable mission execution requires a per-step reviewed approval, idempotency key, rollback, and a separately registered read-only verification tool. A mission pack cannot turn a read tool into a write tool or grant Panther credentials.
- Runtime code tools stay inside the configured workspace. GitHub reads may inspect any repo; GitHub writes are limited to configured write orgs.
- Jira search tools read bounded issue summaries only. Jira and Linear draft tools produce bounded payloads only. Jira and Linear create tools may create one external issue after an explicit ticket request when credentials and target project or team are configured. Jira update may comment, add/remove labels, or transition one issue after an explicit ticket update request and an exact issue key.
- Cerebro source-run and finding-update tools must return a dry-run plan unless `execute=true` and reviewed approval are present. Resolve, suppress, assignment, due-date, ticket-link, note, sync, graph-ingest, and finding-evaluation writes use dedicated tools rather than ad hoc HTTP calls.

## Policy Checks

`npm run architecture:check` enforces repository-local contracts that are cheap to scan:

- no detached `src/tools` tree
- telemetry map shape stays incident-ready
- policy docs are linked from `AGENTS.md`

The script is intentionally narrow. Add rules only for contracts that are easy to explain and likely to regress.
