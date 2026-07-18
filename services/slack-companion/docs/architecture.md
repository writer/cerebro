# Architecture

```text
Slack App
  slash commands, App Home, Block Kit buttons, modals, mentions, alert messages
        |
        v
Cerebro Slack Companion
  Slack verification, user allowlists, Pi agents, security memory, Cerebro SDK wrapper, message rendering
        |---------------> Code Mode child process
        |                  fresh QuickJS RELEASE_SYNC runtime, bounded program, no ambient capabilities
        |                         |
        |                         v
        |                  parent-owned typed tool broker
        |---------------> Cerebro API
        |                  source runtime health, findings, evidence, graph reason, actions, workflow audit
        |
        |---------------> EvidenceCAS
        |                  read-only ref, manifest, and verify calls for specific evidencecas:// refs
        |
        v
DynamoDB / EFS
  durable security memory, event claims, scheduled checks, per-thread Slack session state, daily notes, bounded working-memory files, and curated learning docs
        |
        v
Improvement control plane
  DynamoDB runs and events, encrypted S3 artifacts, SQS and DLQ, isolated PR worker, held-out evaluation, shadow, canary, signed promotion
```

## Design Rules

- Cerebro is the source of truth.
- Slack user IDs are mapped to Cerebro actors for audit, not for tenant authorization.
- Cerebro API credentials are tenant-scoped and route-scoped.
- Mutating Slack actions require an allowlisted Slack user and the matching Cerebro write credential.
- Graph actions start as dry runs.
- Approved execution uses Cerebro's `approved=true` contract and idempotency key.
- Slack messages summarize facts; detailed evidence stays in Cerebro.
- EvidenceCAS is the content-addressed evidence plane. Use it only to resolve or verify specific refs surfaced by Cerebro evidence, not to search for findings.
- Proactive alert triage is read-only. It can research and recommend; it cannot mutate findings, runtimes, or response actions.
- Security memory stores only concise non-secret operational notes.
- Joined public and private Slack channels contribute bounded redacted batches to semantic curation. Passive learning never replies, and only the compact curator result can reach durable memory. A one-off historical worker can backfill a fixed window, expand human thread replies, resume from DynamoDB checkpoints, and report coverage without storing transcripts. A second-stage Opus librarian groups cited candidate memories into versioned dossiers, recursively consolidates repeated domains, and creates cross-domain theses without treating historical Slack as current authority. A completed run writes dossiers and theses to a generation-specific snapshot before atomically publishing its active pointer and run receipt. Reads use only the active generation, while older snapshots remain available for audit and a partial write cannot replace the current library.
- Per-thread Slack session state stores compact triage outcomes, context-fetch markers, and monitor suggestions. It does not store raw Slack transcripts.
- Session recall searches prior Cerebro Slack answers, triage outcomes, and notes. It is context for repeated work, not live proof of current graph state.
- Learning docs store reusable markdown knowledge: normal patterns, runbook notes, and investigation lessons. They are updated through tools, bounded, and sanitized.
- Scheduled checks are stored by tenant and run through the same Slack security assistant boundary as app mentions.
- Code Mode is a model-selected execution style inside the Pi assistant, not a second question router. Each execution gets a fresh child process running the synchronous QuickJS release with no ambient filesystem, environment, network, module, timer, or host-process access. The child can reach registered tools only through the parent-owned typed broker.
- Code Mode changes composition, not authority. Registered Slack and write tools remain eligible for the current plan, but every nested call keeps its normal actor, intent, approval, target, budget, retry, instrumentation, and evidence checks. One Code Mode execution may perform at most one serialized side effect.
- Long-horizon autonomy is run-based. Durable agent runs carry an objective, an executable dependency plan, canonical resources, acceptance criteria, artifacts, corrections, completion receipts, capability manifests, tool-run records, approval records, and worker leases. The runner advances one claimed step per wake and reports state changes in Slack. The autonomy roadmap lives in [autonomy-roadmap.md](autonomy-roadmap.md).
- Human answer records join the request lane, tool and evidence trail, actions, durable commitments, Slack delivery receipt, and later structured feedback. Bot-authored handoffs remain in the agent loop but are reported separately from human product traffic.
- Helpful ratings can name the behavior Cerebro should repeat and the result it helped complete. Repeated categories become personal or team successful patterns. Only the same requester can receive a related private positive note; team patterns contain the category and support counts.
- Every failed tool result counts toward a per-answer circuit that stops the third call to the same failing tool. Shared source health cools down repeated availability failures across answers without disabling a reachable source for one repository or permission mismatch. Slow successful sources remain available but are marked degraded so the agent can prefer a faster relevant source.
- Runner infrastructure failures back off and move a goal to `blocked` after three equivalent failures; the goal keeps its plan and audit trail for operator repair and resume.
- Recursive improvement uses human traffic only. Private examples stay in encrypted S3 artifacts; candidate PRs contain no Slack transcript. Candidate and evaluator versions must differ, promotion requires passing held-out, shadow, and canary evidence plus a signed reviewed decision, and failed outcomes roll back.

## Main Workflows

### Runtime Health

The companion calls `GET /source-runtimes/health` and renders the runtime id, source id, sync status, graph ingest status, and finding evaluation status.

### Findings

The companion calls `GET /source-runtimes/{runtimeID}/findings?status=open&order=priority` for configured runtimes. Finding cards expose evidence, graph context, note, assign, due date, resolve, and suppress actions.

### Ask

The companion first calls `POST /api/v1/agent-platform/evidence-packets`, then `POST /api/v1/agent-platform/graph/reason`. If either route reports stale or blocked context, the Slack reply names the blocker instead of filling gaps with guesses.

### Terminated-Identity Access Control

`cerebro_offboarding_snapshot` binds exact Okta, GitHub, and AWS runtime IDs to one source snapshot. It reads runtime health, source checkpoints, graph-ingest runs, finding-evaluation runs, exact subject claims, and the two cross-source offboarding finding families. The returned snapshot contains provider coverage, per-runtime revision digests, a subject revision, blockers, and a durable Cerebro decision-packet ID. Runtime configuration and raw provider payloads are not returned.

`cerebro_offboarding_refresh` is a reviewed Cerebro write. It synchronizes each named provider runtime, runs graph ingestion, evaluates the offboarding rules on the named Okta runtimes, then performs a new read. The refresh receipt is valid only when every stage succeeds, every runtime revision changes, and the new source snapshot is healthy and fresh.

`cerebro_offboarding_action` calls the existing finding-scoped graph-action route. It always performs a dry run first. Provider execution additionally requires `execute=true`, `approved=true`, an exact target, an idempotency key, and the stable digest from the reviewed dry run. A changed proposal blocks execution.

`operator_offboarding_control_start` persists the reviewed action as an agent run. The run waits separately for provider-action and post-action-recollection approvals. Closure then requires a new Okta, GitHub, and AWS snapshot, changed runtime and subject revisions, a successful action reference on the finding, no open exact finding, a durable decision packet, and an independent Cerebro close-loop verdict. A failed check leaves the run open or blocked with its receipts; it cannot produce a successful completion receipt.

### App Mentions

App mentions run through the Pi security assistant. The model selects an execution lane for each turn: `converse`, `continue`, `lookup`, `investigate`, or `act`. Conversation and thread-continuation turns can complete without evidence tools when no current state is claimed. Lookup, investigation, and action turns establish a claim plan and an explicit tool pack before evidence calls. The Pi path enforces that model-selected pack at the tool hook. The Flue path also removes unselected tool schemas from the research stage. Its planner may assign Librarian, Researcher, Analyst, Coordinator, Triage, QA, Developer, and Compliance work. The host preserves that bounded model-selected team and does not add roles from the lane, lenses, tools, claim count, or plan length. Each assignment asks for a structured completion or blocker receipt, but missing private work is recorded as aggregate incomplete coverage and cannot discard an otherwise grounded answer or surface as an internal Slack error. Evidence roles retain only exact receipts from successful source checks. Specialist work stays private and is synthesized into one teammate response. Flue can use a stronger orchestrator for the plan and any required final synthesis while a separate higher-throughput model executes the bounded tool plan. Both stages retain typed outputs; unset execution settings use the orchestrator model. The total timeout is split across planning, research, and final synthesis, and a schema-valid, protocol-clean research draft can be delivered when final synthesis fails. No keyword or synchronous pre-agent router selects the lane, source, or specialist team.

The same planner selects `execution_style=direct` for a small number of independent calls or `execution_style=code` when the answer needs bounded composition, filtering, joins, pagination, or repeated reads. In Code Mode the model first searches a compact typed catalog, then submits one bounded JavaScript program and the catalog snapshot digest to `cerebro_execute`. The digest detects a toolset change between discovery and execution; it is not a capability token, approval, evidence receipt, or grant of authority.

`cerebro_execute` starts one fresh child process and loads the QuickJS `RELEASE_SYNC` build. The child receives the program and bounded broker messages over its inherited IPC channel. It receives no companion environment, credentials, filesystem path, network client, module loader, dynamic import, timer, or host object. The parent validates every broker message, resolves only a tool registered in the current catalog and selected by the current research plan, validates arguments, runs the normal tool hooks, and returns a bounded result. The program, arguments, results, child output, toolset digest, targets, receipts, and credentials are not telemetry fields.

CPU, wall-clock, program-size, result-size, tool-call, side-effect, and child-lifetime limits bound one execution. A deadline or child failure terminates that child and leaves the Slack assistant process available for a later turn. A side effect starts only after prior reads complete, and no second side effect can be dispatched. If termination occurs after a write was accepted but before its result was received, the outcome is `unknown`: the host does not retry the write and requires the registered independent read verifier before reporting completion or attempting another action.

An explicit self-improvement request from a configured Slack operator can use this path to inspect runtime status, skills, and workspace files, run bounded validation, and submit one draft candidate through `cerebro_code_self_improvement_pr`. The host binds the request to the Slack actor, configured companion repository, draft state, branch prefix, idempotent candidate id, file bounds, and protected-path exclusions. The draft PR is the turn's single side effect and contains the implementation, durable procedural change, and regression test. Code Mode does not expose general workspace writes or shell to self-improvement, and it does not merge, deploy, promote, or bypass the recursive-improvement release gates. Repeated passive feedback still enters the separate improvement worker as a bounded review packet; automatic code authorship from those signals is outside this path.

The outer `cerebro_execute` call is an orchestration control and does not create source evidence. Each successful nested source call passes through the regular instrumentation path and receives its own current-turn evidence receipt and subject-bound envelope. Failed, blocked, fabricated, late, or duplicate broker messages do not receive evidence.

The assistant maintains per-thread operational state in the configured triage thread-state table. The record contains bounded entities, already-reported facts, observed and inferred world facts, competing hypotheses, decisions, workflow state, earned-attention state, and recent turn summaries. Follow-ups use this record to resolve references and avoid repeating reported facts. Drift-prone facts still require a live source check before a present-tense answer.

Investigation controls are local typed tools inside the existing agent loop. `operator_world_state` separates observed, inferred, expected, and desired facts. `operator_hypothesis_ledger` keeps competing explanations, counterevidence, falsifiers, and the next discriminating check. `operator_claim_ledger` records source scope, coverage, freshness, and what an empty result proves. Observed or supported state requires an evidence receipt issued by a successful source tool in the same turn. Comparisons use one claim and the narrowest supported source query per named subject so status, freshness, ownership, and counts remain attached to the record that supplied them. Named people are resolved through thread state and Slack user evidence before the assistant asks for an email or login.

When a person's answer would distinguish investigation hypotheses, the agent can use `slack_risk_attestation_request` from a configured security channel. The host validates the channel, unique active human target, risk reference, identity basis, and evidence references before opening a DM. The DM contains bounded activity, system, and time fields. The response is stored in the encrypted learning table with a 90-day TTL and posted back to the originating security thread as unverified self-attestation. It cannot authorize or perform a finding change. `slack_risk_attestation_status` reads that bounded state from the originating channel.

`operator_workflow_compile` builds a resumable observe-to-verify DAG. Executable steps carry an exact registered tool name and bounded JSON arguments. Action steps require approval, an idempotency key, rollback, an independent read-only verification tool, and post-action verification. `operator_action_simulation` records affected resources, owners, risks, evidence, rollback, and verification before a write recommendation; it does not execute or authorize the write.

`operator_goal_create` persists that DAG as an agent run when work must continue beyond the current answer. AppSec remediation, identity access risk, and detection response use the versioned [Security Mission Fabric](security-mission-fabric.md): the compiler stores a pack receipt and each step's action stage, input state, tool selector, approval, rollback, and verification boundary. The host-owned dispatcher resolves only registered tools, validates top-level arguments against the tool schema, enforces tool authority, and blocks recursive run writes. External writes require approval and independent verification. Cerebro and external security-platform writes also require an idempotency key and rollback. A run is complete only after its acceptance criteria pass and the host records a completion receipt.

Unfinished teammate commitments must reference an agent run created in the same turn or a previously verified run. Before Slack copy is written, the host reads the run and replaces model-authored status with the stored goal status, active step, next wake, blockers, acceptance criteria, artifacts, and completion receipt. One host-observed goal creation can repair one omitted model link. Missing, cross-thread, or unpersisted goals become blocked commitments and cannot satisfy the teammate-ownership quality gate. Later thread turns receive refreshed goal state instead of relying on the earlier promise.

Agent runs use typed canonical resource references such as Cerebro findings, GitHub pull requests, Slack threads, AWS resources, people, services, and evidence. References carry source, freshness, confidence, and typed links; they remain context until the owning source verifies current state. Files, reports, patches, commits, pull requests, tickets, evidence packets, and decisions are attached as task artifacts after they exist.

The registered tool catalog is searchable from the agent loop. Discovery returns tool family, authority, side effect, retry model, and required arguments; it does not grant authority. Verified operator corrections are stored as `operator_correction` memory and can be attached to the relevant run so superseded claims are not silently reused.

The assistant uses `operator_attention_decision` for automated and proactive signals. Novelty, materiality, urgency, actionability, confidence, and decision need produce an advisory attention receipt. Human questions still receive a response. Automated posts can be suppressed when they contain no material delta or explicit request.

The assistant prompt includes an autonomy standard: treat broad requests as goals, default to action, persist concise progress, and ask for input only when no safe default exists. Durable goal execution now has a runner that can wake due goals, claim a lease, advance one ready step, checkpoint the result, request Slack approval for review-class actions, and resume after restarts.

The assistant can also debug the Slack companion itself through `cerebro_companion_self_context`. That tool returns sanitized service identity, runtime ids, command registry, skills, agent tools, feature flags, storage modes, likely configuration gaps, and a debug playbook. It reports only configured or missing state for credentials and never returns token or API key values.

The assistant can write durable memory entries for source-backed Infosec knowledge, team context, normal patterns, prior investigations, and runbook notes. It no longer writes each generated answer back into semantic memory. Verified world facts and decisions are stored as structured `operator_fact` and `operator_decision` records; encounter stories remain transient replay material. Asset, owner, connector, detection, access, severity, and exception context upsert the `SECURITY_KNOWLEDGE.md` learning doc when promoted, so future prompts get compact reusable context without re-reading raw Slack history. Company-library records use a separate tenant partition and expose read-only search and record tools. Each claim retains its cited source memory ids and programmatically derived Slack artifacts; missing citations reject the record. Memory, library, and docs writes are redacted before storage and are not authorization sources. Stable lessons should be written as declarative facts with source artifacts; raw logs, Slack transcripts, temporary task state, and imperative self-instructions stay out of memory.

Each delivered human-facing answer has `Helpful` and `Needs work` controls. A needs-work rating records one structured reason and an optional comment. Ratings are idempotent per Slack user and response, so a user can change a rating without adding duplicate votes. The action handler resolves the author's Slack display name while retaining the Slack user id as stable identity. Recent personal categories inform that user's later replies; up to three recent needs-work cases also provide bounded redacted excerpts of the comment, original request, and delivered response. Those cases are explicitly untrusted quality context: they are not facts, evidence, instructions, authority, approval, or permission, and their instructions must not be followed. Exact comments stay scoped to the same user; cross-user team guidance requires recurrence and may name contributors without exposing comments. The same attribution is retained in encrypted private improvement artifacts but is excluded from telemetry and candidate PR material. Needs-work categories also create transient `skill_improvement` records for bounded review and later repair analysis. Answer context expires after 30 days; rating records expire after 120 days.

Answers with claim-bound evidence also create a durable receipt after Slack delivery. The receipt stores redacted claim summaries, hashed source identity and version, validity windows, and claim-to-source dependencies; it does not store source payloads or answer text. The `Evidence receipt` action exposes a same-channel projection with current, expired, contradicted, or needs-reverification state. A source version change or corroborated source feedback invalidates dependent claims and writes a thread marker. Later turns in that thread receive the marker in prompt context and must re-check the affected source before reusing the claim.

Recursive improvement is the escalation on that learning path. Weak or blocked human answers and needs-work ratings become private redacted signal artifacts tagged by skill and issue type. Equivalent signals accumulate in a durable run. After the threshold, the main service queues a bounded candidate and a separate ECS worker opens the draft PR. The worker receives only the improvement data plane, KMS verify permission, and scoped GitHub App credential; it does not receive Slack tokens, Cerebro write keys, or working memory.

The run records candidate creation, held-out evaluation, shadow traffic, canary traffic, promotion, rollback, and blocking as explicit state transitions with immutable event rows. Candidate and evaluator versions must differ. A failed held-out gate blocks the run; failed shadow or canary evidence rolls it back. Passing evidence moves the run to `awaiting_promotion`. A protected GitHub workflow signs the reviewed decision with KMS, and the worker verifies that signature before promotion.

Every completed turn also receives a local replay-quality receipt for follow-up continuity, claim grounding, coverage honesty, execution efficiency, action closure, correction learning, goal understanding, teammate ownership, burden reduction, and natural Slack copy. Failed receipts become bounded `skill_improvement` records while encounter stories remain the replay corpus. `npm run eval:assistant` reads JSONL replay turns from stdin and reports pass rate, average score, and blocker counts.

`npm run eval:traffic` reads redacted real-traffic replay cases from stdin. Each case can require an execution lane, source tool, evidence reference, response or suppression outcome, completed action receipt, verified correction, captured objective, resolved scope, recommendation, owned follow-up, and absence of an unnecessary user decision. The release report fails when the case count, pass rate, average score, correction closure, unsupported-negative, teammate-expectation, or candidate-regression gate fails. The replay file is not stored by this repository.

### Skills And Scheduled Checks

Security skills are built-in runbooks for common checks such as login posture, runtime health, high-risk findings, Slack app review, stale findings, and evidence integrity. `/cerebro skill <id>` runs one immediately through the Pi security assistant.

`/cerebro schedule <plain language>` creates a scheduled check from operator text. A Pi planner interprets the request and returns a structured plan with interval, daily, weekday, weekly, one-shot, runtime-health trigger, finding-count trigger, pre-run context provider, and DAG step fields. Deterministic code validates the returned plan, computes the next run, gathers any requested read-only context snapshots, and executes ready DAG steps. `then` creates step dependencies so broad checks can run as a DAG: independent first-stage checks run in parallel, and later steps wait for the named dependencies to complete.

The pre-run context layer collects bounded read-only context before scheduled work without arbitrary script execution. Supported providers collect runtime health, a bounded open-finding sample, or sanitized Slack companion self-context. The collected data is injected into the scheduled assistant prompt as read-only context to verify before reporting.

Scheduled check results are posted to the configured Slack channel and recorded as daily notes. They do not grant new write authority; scheduled steps use the same assistant read-side tool boundary and can recommend or dry-run safe paths but cannot resolve, suppress, assign, page, or mutate infrastructure.

### Proactive Slack Review

The companion listens for normal user messages in `SLACK_TRIAGE_CHANNEL_IDS`. It also reviews root app or bot posts when the text contains clear alert, finding, runtime, deploy, CI, policy, or security signal. It ignores message edits, unconfigured channels, threaded bot replies, and messages authored by the Cerebro bot user.

Each triage channel can set a posture with `SLACK_TRIAGE_CHANNEL_POLICIES`: `strict`, `quiet`, `watch`, or `eager`. Strict channels require a high-confidence security signal before Cerebro speaks. Quiet channels allow concrete alerts and short follow-ups but suppress weak operational chatter. Watch channels use the normal response gate. Eager channels fetch more context and lower the confidence threshold for useful first-line replies.

Short channel acknowledgements stay quiet. In an existing thread, short resolution updates such as "fixed", "done", "resolved", "shipped", and "merged" are still eligible for triage so Cerebro can verify whether evidence, ownership, or an open finding should change the team's next action. It still posts only when the response gate finds concrete value and a verified basis.

When a human reply is direct feedback about a prior Cerebro answer in the same thread, the companion can post a short correction or clarification. That path requires visible Slack thread context and does not turn the reply into a security report.

Accepted messages build a proactive context packet before the Pi call. The packet includes channel posture, durable thread state, bounded visible thread or message context when needed, bounded channel context for first-pass/eager review, and security memory matches. `CEREBRO_TRIAGE_THREAD_STATE_TABLE_NAME` stores this per-thread state; when it is unset, Cerebro uses the learning table, then the schedules table, then process memory for local runs.

Each accepted message runs through an `@earendil-works/pi-agent-core` agent. The default model is Bedrock `amazon-bedrock/us.anthropic.claude-opus-4-8`; ECS provides model auth through the task role. The agent can call only read-side Cerebro tools plus security memory, Slack research tools, and bounded EvidenceCAS ref resolution: graph reasoning, evidence packet creation, runtime health, open finding reads, finding evidence, entity neighborhoods, CAS manifest verification, memory search, session recall, memory write, curated learning-doc updates, Slack thread context, Slack message context, Slack channel context, Slack search, and Slack scope checks.

The Slack thread reply contains the classification, confidence, summary, evidence, next actions, and research trail. For actionable deploy, CI, runtime, or finding threads, the reply can include a pending monitor suggestion with `Start check` and `Dismiss` actions. Accepting a suggestion creates a scheduled check from the stored schedule text; it does not perform an irreversible production, graph, or finding write.

If Pi cannot run during passive alert triage, the service can record a bounded Cerebro graph fallback result. Assistant questions do not use deterministic pre-routing or direct fallback answers; Slack search, memory, self-context, graph, and EvidenceCAS checks are selected inside the Pi agent path. If Pi cannot run for an app mention, the background agent loop reports a blocked state instead of answering from substitute routes.

### Actions

Finding lifecycle writes call Cerebro finding routes. Provider actions use `POST /platform/graph/actions` with `dry_run=true` first. Slack approval modals pass a human reason and call Cerebro again with `approved=true`.

### Audit Claims

The companion can write a compact claim record to its SDK runtime for commands and approvals. These claims are operational breadcrumbs, not an authorization source.
