# Implementation Plan: Managed endpoint attestation

## Selected Design And Constraints

Keep native hooks and the per-user LaunchAgent. Add managed enrollment, signed heartbeats, monotonic chain-head checkpoints, and organization-issued investigation capabilities. Capture must remain local and bounded when offline; development builds cannot claim organization-managed status.

## Source Revision And Drift Check

The evidence collection digest is `bfa4bc59097fda4e450a4f9cb8a4b69b6ff46fa790d44eb10b29f11107889a6b` at revision `67ddd5ee4dcfa5580e81e3e03509473f4c45f371`. The LaunchAgent implementation was in the working tree, so refresh the digest and review transport, signing, and ledger drift before server contract implementation.

## Affected Components

- `plugins/cerebro-agent-receipts/Sources/CerebroShieldAgent/main.swift`
- `plugins/cerebro-agent-receipts/Sources/ReceiptCore/ReceiptStore.swift`
- `plugins/cerebro-agent-receipts/Sources/ReceiptCore/AdminCapability.swift`
- managed macOS configuration and signing pipeline
- Cerebro device enrollment, checkpoint, and incident APIs

## Ordered Work Packages

- Define versioned enrollment, heartbeat, checkpoint, acknowledgement, and key-rotation messages.
- Enroll only identified signed builds and bind organization, device key, hardware or MDM identity, and app signing identity.
- Persist one bounded checkpoint retry record and send asynchronously from the LaunchAgent.
- Reject replayed sequence numbers and conflicting chain heads server-side.
- Compute device states: enrolling, fresh, stale, rollback, conflict, retired, and signing drift.
- Issue investigation capabilities after enterprise authentication with explicit actions and a lifetime no longer than one hour.
- Add fleet coverage, stale-device, rollback, and capability-use audit views.

## Compatibility And Migration

Existing local ledgers remain readable. Development builds remain labeled Development trust and do not enroll. Managed rollout begins report-only; devices without enrollment are unknown rather than healthy. Key rotation accepts a bounded overlap signed by the prior device identity or a managed re-enrollment authority.

## Tactical Protections During Migration

Keep same-user admission checks, 0600 development key validation, root-owned managed configuration validation, bounded fallback capacity, exact-once drain, and explicit agent-supplied origin labels. Do not use CDHash or identity-provider group membership as an authorization result.

## Tests And Security Validation

- Enrollment rejects unsigned, wrong-organization, and wrong-device artifacts.
- Heartbeat rejects expired, replayed, malformed, and wrong-key messages.
- Checkpoint rejects sequence rollback and conflicting heads at one sequence.
- Offline queue converges once after 24 hours without blocking hook capture.
- Capability rejects wrong device, missing action, altered payload, future issue time, and lifetime over one hour.
- Device retirement blocks new checkpoints and capabilities while preserving audit history.

## Performance And Resource Benchmarks

Measure hook p95, agent CPU, agent RSS, checkpoint payload size, request rate, reconnect burst, and control-plane verification throughput. Compare against the current local-only build. Initial gates are under 5 ms hook p95 delta, under 1 percent average agent CPU, under 10 MiB steady-state RSS increase, and no unbounded reconnect queue.

## Rollout And Rollback

Pilot 20 managed Macs without paging, then enable ticket-only stale incidents, then operational alerts after the false-stale rate is accepted. Roll back by disabling checkpoint delivery and incident routing while retaining local collection and server history. Device retirement and key revocation remain available during rollback.

## Acceptance Criteria

- Every enrolled pilot device exposes a current chain head, last heartbeat, signing identity, adapter state, and binary drift state.
- Collector disablement creates a stale state within the policy window.
- Replayed and forked checkpoints create distinct rollback and conflict incidents.
- Status-app termination has no effect on freshness or capture.
- Investigation actions are accepted only with a valid device-bound capability and are audit logged by request ID.

## Open Decisions

- Enrollment authority and device posture source
- Freshness window and offline allowance
- Checkpoint retention and privacy policy
- Incident owner and escalation path
- Production key custody and rotation mechanism
