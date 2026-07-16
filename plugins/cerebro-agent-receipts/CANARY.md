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
