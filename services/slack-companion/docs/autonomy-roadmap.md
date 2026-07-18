# Autonomy Roadmap

This roadmap is for making Cerebro behave like an operator-grade long-horizon agent inside Slack.

The target is not a larger answer generator. The target is a system that can receive a broad goal, inspect its operating context, make and revise a plan, use tools for hours or days, recover from failures, report progress, and stop only when a real capability boundary is reached.

## Operating Contract

- Treat broad requests as goals, not single-turn prompts.
- Default to action: inspect context, plan, run tools, revise, and continue.
- Ask for input only when the answer materially changes the action and no safe default exists.
- Persist progress, blockers, assumptions, decisions, and artifacts so work can resume after process restarts.
- Prefer reviewable changes: branches, patches, tests, PRs, check watching, and explicit merge policy.
- Keep Slack updates short and stateful: current state, completed actions, blocker, next action.
- Keep hard blocks narrow: secret exfiltration, credential exposure, workspace escape, and disabling exfiltration or audit controls.
- Gate irreversible production, infrastructure, graph, and data changes through read-only impact checks, dry runs, backup/rollback planning, and a reviewed approval path.

## Current Foundation

- App mentions already enter one Pi assistant loop.
- The assistant has Cerebro graph, finding, runtime, EvidenceCAS, Slack research, memory, learning-doc, Infisical metadata, and runtime code tools.
- Runtime code tools can write bounded workspace files, run exfil-gated shell checks, open reviewable GitHub PRs in configured Writer orgs, and read PR/check status for any GitHub repo.
- Durable autonomy goals can be created, listed, shown, paused, resumed, cancelled, and completed from Slack.
- Capability manifests classify autonomy work by owner, data sources, allowed actions, blast radius, and approval requirements.
- The autonomy runner can wake due goals, claim a worker lease, execute one ready step, record tool runs, request approval, monitor GitHub PR checks for self-repair goals, post Slack progress, and release the lease.
- Durable agent runs now store canonical resources, concrete artifacts, acceptance criteria, verified corrections, exact tool execution fields, and completion receipts.
- Unfinished assistant commitments are linked to stored agent runs and refreshed from the goal store before a Slack answer is presented. Later thread turns receive current goal state and completion evidence.
- The runner dispatches registered tools with bounded arguments, durable retries, reviewed approval, independent read-only verification, and acceptance checks.
- The agent can search registered tool metadata, normalize resource references, inspect a run, attach artifacts, and store verified corrections.
- Redacted real-traffic replay cases enforce source, evidence, outcome, correction, and regression release gates through `npm run eval:traffic`.
- Repeated human answer gaps and needs-work ratings now create durable recursive-improvement runs. An isolated worker opens the draft candidate, held-out evaluation uses a separate evaluator version, shadow and canary outcomes are recorded, and KMS-signed reviewed decisions control promotion or rollback.
- Scheduled checks provide the first durable recurring-work surface.
- Proactive Slack review has channel postures, durable per-thread session state, bounded context packets, and monitor suggestions that create scheduled checks after a human accepts them.
- Daily notes, security memory, working memory, and learning docs provide compact persistent context.
- Slack event claims and deployment fencing prevent duplicate side effects across workers.

## Remaining Capability

### Goal-backed Commitments

Status: complete for the current assistant and runner boundary. `operator_goal_create` stores channel, thread, requester, objective, plan, active step, assumptions, blockers, artifacts, updates, next wake, completion, capability, tool runs, approvals, worker claim, canonical resources, acceptance criteria, corrections, and completion receipts. The assistant records the returned goal id in every unfinished commitment. The host can recover one omitted link from a goal creation observed in the same turn, rejects missing or cross-thread links, refreshes the stored goal before Slack presentation, and supplies current goal state to later thread turns.

### Planner And Executor

Continue building the autonomy runner above `SecurityAssistantService`.

The runner should:

- turn the request into a plan with ordered and parallelizable steps
- execute one or more steps per wake
- revise the plan after tool results
- checkpoint after every material action
- post progress when the state changes
- resume after process restart
- stop only on completion, hard block, repeated failure, or approval-needed state

Status: the runner exists and advances one stored step per wake through a worker lease. It executes exact registered tools, records bounded results, retries transient failures up to the stored limit, creates approval records for reviewed actions, resumes the same waiting step after approval, verifies external writes through an independent read-only tool, evaluates acceptance criteria, records a completion receipt, posts progress in Slack, and releases claims. Cerebro finding investigations still revise the next plan step from verifier verdicts and evidence gaps. Self-repair goals can monitor GitHub PR/check status and re-wake while checks are pending. CI failure log inspection and deployment monitors remain future tool work.

### Tool Expansion

The current runtime code tools are useful but still narrow. The autonomy runner needs tools for:

- GitHub issue, branch, PR, review, merge, and check watching
- CI log inspection and failure repair
- repo checkout or workspace sync inside an exfil-gated sandbox
- package install through allowlisted registries and lockfile review
- scheduled follow-up wakes
- artifact handoff for longer reports
- approval requests for irreversible actions

### Policy Layer

Use a small policy engine before tool calls and before committed side effects.

Policy should classify actions as:

- `allow`: read-only checks, bounded local code edits, tests, memory writes, notes, PR creation, status updates
- `review`: merge, deploy, production config changes, graph writes, finding lifecycle writes, paging, customer-visible Slack posts outside the working thread
- `block`: secret exfiltration, credential exposure, workspace escape, disabling exfiltration controls, disabling audit controls

The policy should return a reason, allowed next action, and any required approval record.

### Work Log

Every autonomous run should emit a compact work log.

Log entries should include:

- step started
- tool called
- artifact changed
- test/check result
- assumption made
- blocker found
- approval requested
- decision made
- step completed

This log is not hidden reasoning. It is an operator-facing audit trail.

### Slack UX

Slack should become the control surface for long work.

Required controls:

- start goal
- show goal state
- pause
- resume
- cancel
- approve reviewed action
- request status
- open artifact or PR

The bot should update the thread status while running and post only meaningful state changes.

Proactive review should use the same posture in passive channels: gather context, speak when there is a concrete next action, stay quiet when a message only needs observation, and offer a scheduled check when repeated follow-up would help.

## Implementation Phases

### Phase 1: Autonomy Contract

- Add a named autonomy prompt standard.
- Document the operating contract and policy model.
- Keep tests around the default-action and exfil-boundary language.

### Phase 2: Durable Goal Store

- Add `AutonomousGoalRecord`.
- Store goals in the schedules table or a dedicated DynamoDB table.
- Add local in-memory fallback for tests and dev.
- Add commands or app mentions for goal status, pause, resume, and cancel.

Status: the goal record, work-log shape, capability id, execution contract, tool-run records, approval records, worker claim, store interface, in-memory fallback, DynamoDB persistence, and Slack controls exist. Goals reuse the learning/schedules table under a separate partition when no dedicated autonomy table is configured. New goals store the selected agent profile, maximum action stage, requested action stage, required verifiers, and contract version.

### Phase 3: Runner

- Add `AutonomyRunner`.
- Execute one planned step at a time with checkpointing.
- Re-enter from stored state on wake.
- Record work-log entries and progress notes.

Status: `AutonomyRunner` is present. It polls due goals, claims a short lease, attaches a typed execution contract when a legacy goal is missing one, blocks steps above the contract action stage, advances one ready step, records tool runs, asks for approval when the manifest requires it, posts Slack progress, and releases the claim. For finding investigations with wired Cerebro dependencies, it uses the verifier result and evidence gaps to set the next investigation step.

### Phase 4: GitHub Operator Tools

- Add tools for PR lookup, check watching, CI log reading, commit push, merge, and branch cleanup.
- Keep merge behind explicit user request or configured merge policy.
- Make CI repair a resumable goal instead of a one-shot answer.

Status: repeated Slack answer gaps and needs-work ratings accumulate in a durable improvement run. Private redacted examples stay in encrypted versioned S3 artifacts, an SQS/DLQ worker opens the bounded draft candidate, held-out traffic evaluation requires a separate evaluator version, and explicit shadow, canary, promotion, rollback, and blocked states preserve the release record. The autonomy runner can still read PR state and current check runs/status contexts for self-repair goals. CI log repair and automatic code authorship remain future runner work.

### Phase 5: Sandbox And Package Work

- Add a controlled repo workspace.
- Allow package installs only through reviewed lockfile changes and bounded registry access.
- Keep environment scrubbed and block secret-like input and output.

### Phase 6: Approval Records

- Add approval requests for review-class actions.
- Store approver, action summary, risk, dry-run output, rollback path, and execution result.
- Tie approval records to Slack user ids and Cerebro actor ids.

Status: approval records exist on goals. Slack agent-run cards render pending approval actions, and only `SLACK_AUTONOMY_APPROVAL_USER_IDS` can approve or reject them. Executable steps preserve idempotency, rollback, verification, and result state. Provider-specific dry-run artifacts still depend on the selected write tool.

### Phase 7: Long-Running Monitors

- Let the agent create monitors for CI checks, deployment health, finding counts, runtime health, and follow-up reminders.
- Monitors should wake the goal runner with stored context.

Status: GitHub PR/check monitoring exists for self-repair goals. Proactive Slack triage can now suggest short-lived scheduled checks for actionable deploy, CI, runtime, and finding threads after a human accepts the suggestion. Deployment health, finding-count, runtime-health, and reminder monitors still need deeper runner integration.

## Non-Goals

- Do not add deterministic phrase routing for assistant questions.
- Do not give the agent raw secret values in Slack.
- Do not let shell commands read outside the workspace.
- Do not silently execute irreversible production or data changes.
- Do not store raw logs, Slack transcripts, credentials, or hidden reasoning as memory.

## First Useful Slice

The current slice adds proactive Slack context, durable thread session state, channel postures, and accepted monitor suggestions. The next useful slice should connect CI log inspection and repair planning to failed check states, then add merge/deploy monitors that wake the same durable goal without taking irreversible actions.
