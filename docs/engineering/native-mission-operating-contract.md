# Native Mission Operating Contract

## Decision

Cerebro will treat a mission as the durable unit of agent work. A mission records the condition Cerebro must change,
the current beliefs about that condition, the active plan, exact commitments, authority, verification requirements,
and the events that should resume work.

A finding, case, ticket, pull request, chat response, provider receipt, or completed job can contribute to a mission.
None of them closes it. Closure requires an independently verified desired condition.

## Customer Outcome

An operator can state a continuing objective once. Cerebro resumes when relevant facts change, performs work covered
by existing authority, requests only decisions it cannot make, verifies the result from a newer authoritative
observation, and reopens the mission if the condition later becomes false.

The operator should not have to reconstruct the objective, prior investigation, attempted actions, or remaining
decision every time they continue the conversation.

## Durable Records

The native control kernel owns six records:

1. **Mandate:** the desired condition, scope, maximum violation age, and lifecycle revision.
2. **Mission:** one concrete unresolved difference between observed state and the mandate.
3. **Belief:** a versioned statement with evidence, counterevidence, missing evidence, confidence, source revision,
   and explicit invalidation conditions.
4. **Plan revision:** an immutable hypothesis-bound set of ordered capability steps. A revision states why the plan
   changed and which steps it superseded.
5. **Commitment:** one actor's exact capability, target, expected effect, authority, execution state, rollback
   reference, and receipts.
6. **Wake condition:** a source revision, event, deadline, conversation sequence, or decision that should resume work.

Application records remain useful projections. Findings explain current risk. Controls and claims explain assurance.
Tickets and pull requests coordinate external work. Evidence packages support a recipient and period. They do not
become parallel mission stores.

## Belief Rules

- Every material belief has stable identity and optimistic revision checks.
- `supported` requires supporting evidence with no counterevidence or named missing evidence.
- `contradicted` requires counterevidence.
- Confidence is bounded data, not a substitute for evidence.
- Every belief names what would invalidate it.
- Source revisions remain opaque. A later observation is proven by a different committed revision, not by ordering
  arbitrary revision strings.
- Model text may propose a belief. Only a validated event records or revises it.

## Plan And Commitment Rules

- Plans are immutable revisions, not mutable model scratchpads.
- Every plan references the beliefs it is intended to test or change.
- Every step names a capability, stable subject, expected effect, dependencies, and whether a decision is required.
- A commitment binds one plan step to an actor and resource.
- Approval binds the exact commitment. A changed target or effect requires a new decision.
- Execution requires a current scoped grant.
- Provider acceptance moves a commitment to verification; it does not fulfill it.
- Fulfillment requires a receipt from the verification path.

## Wake Rules

Missions sleep durably. They do not poll through model calls.

Supported wake conditions are:

- a committed source revision changes;
- a typed event is observed for the exact subject;
- a deadline is reached;
- a bound conversation advances;
- an exact decision is recorded.

Wake conditions are armed, satisfied, or cancelled. Replay must derive the same status. A wake signal cannot widen
tenant, mission, subject, or decision scope.

## Conversation Resolution

Chat and agent protocols are command surfaces over missions, not mission storage.

An encounter resolves in this order:

1. Continue an explicitly referenced mission when it exists.
2. Continue the only open mission that overlaps the resolved subjects.
3. Ask the operator to choose when multiple open missions match.
4. Open a mission when no existing mission matches.

Subject extraction may use a model. The kernel receives typed subject identifiers and applies deterministic resolution.
The raw transcript is retained for traceability but does not replace mission state.

## Adaptive Execution Depth

The kernel routes each encounter to the least expensive sufficient path:

- **Read current state:** a follow-up can be answered from fresh durable mission state with no material evidence gap.
- **Targeted verification:** the answer needs a newer fact or one bounded capability call.
- **Deep investigation:** the operator explicitly requests it, or a consequential action has a material evidence gap.

This routing decision is recorded. A short follow-up must not launch a default research pipeline merely because a
model is available.

## Supervisor Directives

The supervisor emits one typed directive from replayed state:

- resolve scope;
- revise the plan;
- request one exact decision;
- execute one ready commitment;
- verify one executed commitment;
- wait on named wake conditions;
- replan from satisfied wake conditions;
- block with a stable code when the state has no executable commitment or valid wake condition;
- close a verified mission;
- take no action.

The supervisor does not generate prose, call providers, or advance state. Runtime adapters execute a directive and
append the resulting event or failure.

## Interruption Policy

Cerebro contacts an operator when:

- a decision is required for a named commitment;
- evidence invalidates the current plan;
- authority, time, or execution budget is exhausted;
- the mission is blocked with no valid wake condition;
- the desired condition is independently verified;
- a previously verified condition becomes false again.

Routine observations, plan updates, retries inside policy, and progress already visible in mission state do not need
separate notifications.

## First Complete Mandate

The first complete mandate remains: no terminated identity retains production access for more than 24 hours.

The acceptance trajectory is:

1. Resolve a termination and effective access observation to one mission.
2. Record the belief that access remains, including missing post-change evidence and an invalidation condition.
3. Record an immutable plan and exact removal commitment.
4. Request the minimum required decision.
5. Execute through a scoped identity capability grant.
6. Record provider acceptance as an execution receipt.
7. Arm a wake condition for a changed authoritative source revision.
8. Revise the belief from the newer observation.
9. Fulfill the commitment and verify the mission using a distinct verifier.
10. Close the mission, then reopen scope resolution when a later source event requires a new check.

The control-kernel integration test replays this trajectory twice and requires identical aggregates.

## Measures

Measure the operating result:

- time from mandate violation to verified condition;
- human decisions per verified mission;
- missions closed without an avoidable interruption;
- time waiting without a valid wake condition;
- verification failure and false-closure rate;
- reopened missions;
- receipts reused by findings, assurance, and disclosure projections;
- time to answer a follow-up from current mission state.

Do not use model calls, tool calls, plan steps, generated findings, or messages sent as outcome measures.

## Boundary

The kernel remains pure Rust domain code. JetStream is the event log, Postgres holds current projections and leases,
and Neo4j remains rebuildable. Runtime adapters own transport, storage, model calls, provider calls, and notifications.
No new database, graph write path, unmediated action surface, or generic workflow language is introduced.
