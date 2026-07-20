# Control kernel protocol

The control kernel accepts bounded commands from agents and operators. Every command carries a schema version, request ID, and tenant ID. The tenant ID in the envelope must match the command payload.

## Command contract

The first protocol revision supports these commands:

- `open_mission`: create a mission against an exact mandate revision.
- `advance_mission`: request one legal mission state transition using the current mission revision.
- `authorize`: test one actor, action, resource, and observation time against one capability grant.
- `record_decision`: bind an approval decision to the exact proposal digest that was evaluated.
- `record_verification`: record an independent observation after an action.

Agents do not receive general write access. A capability grant names the tenant, actor, allowed actions, resource prefixes, issue time, expiry time, and revocation time. Requests outside any of those bounds are denied.

## Mission replay

Mission events use a tenant-scoped, mission-scoped sequence beginning at one. Each envelope includes an observation time, actor, and idempotency key. Replay rejects:

- sequence gaps or reordering;
- duplicate idempotency keys;
- tenant or mission changes inside a stream;
- a second open event;
- transitions whose recorded source state differs from the aggregate;
- transitions that violate the mission state machine.

Given the same ordered event stream, replay produces the same mission state and revision.

## Action completion

An approval authorizes only the proposal digest recorded in its receipt. Any mutation to the proposal requires another decision.

A mission can reach `verified` only after the runtime accepts a verification receipt with all of these properties:

- the verifier differs from the executor;
- the observed source revision differs from the pre-action source revision;
- the expected effect is present;
- at least one evidence URN identifies the confirming observation.

The protocol types define this boundary. Storage, scheduling, transport, and source adapters remain outside the pure kernel crate.
