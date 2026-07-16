# Agent Receipt Canary

Date: 2026-07-16

## Fresh Codex session

A new Codex process started with an empty receipt directory and ran one `printf` shell action. The installed plugin used its bundled universal helper.

Observed hook states:

- Session start: completed
- Tool attempt: completed
- Tool result: completed

Verification result:

```json
{"actions":1,"candidateCorrelations":0,"completedActions":1,"integrityPassed":true,"localOnlyActions":1,"providerBound":0,"providerPolicyPassed":false,"receipts":3,"unmatchedProviderEvents":0,"validReceipts":3}
```

The ledger connected the action to one Codex session ID, turn ID, and tool-call ID. The attempt and completion produced two receipts but one action. The ledger stored command and result digests instead of raw command output.

## Background collector recovery

The registered LaunchAgent was tested independently of the status app with four local session receipts.

- Frozen collector: the hook returned successfully and queued one bounded fallback record.
- Collector resumed: the queue drained from one record to zero and produced exactly one receipt for the canary session.
- Status app terminated: the collector retained its PID and captured another session.
- Collector terminated: launchd restarted it under a new PID and the next session was captured.
- Final verification: 4 receipts, 4 valid signatures, integrity passed.

These results prove persistence and local recovery on this development Mac. They do not prove that a local user cannot disable the LaunchAgent or that a provider mutation was prevented.

The v3 login-item package was then rebuilt and registered in place with an unchanged collector binary. The second registration passed nested code-signature validation, launchd reported the collector running, and the XPC health probe succeeded. A new frozen-collector canary queued one record; after recovery the queue returned to zero and the session occurred exactly once in the ledger. Terminating collector PID `7275` caused launchd to start PID `12202`; the health probe recovered and the final collector ledger contained 5 receipts with 5 valid signatures.

This repeat-upgrade result is a development packaging check, not release-signing evidence. The release gate still requires a Developer ID or enterprise-signed, hardened, notarized universal app and an upgrade test from the prior shipped version.

## Authenticated provider lookup

The helper queried AWS CloudTrail through an authenticated CLI profile for a three-minute window containing the earlier `RegisterTaskDefinition` canary.

Observed provider data:

- Provider events: 1
- Provenance: `authenticated_aws_api`
- Completed local actions in this new ledger: 0
- Unmatched provider events: 1
- Strict verification exit: 1

This is the expected provider-gap result. CloudTrail identified an AWS CLI operation and its cloud principal, but it did not identify the Codex session or tool call that initiated the command. Retrospective provider data cannot reconstruct local evidence that was never captured.

## Investment gate

The current plugin proves two useful states:

1. A new Codex shell action produces verifiable local agent evidence.
2. An actual provider mutation without that evidence remains in the provider denominator as a gap.

The next investment should fund the credential broker and remote checkpoint described in the README. Do not call the control enforced until brokered mutations bind one-to-one and deliberate direct-role mutations remain provider gaps.
