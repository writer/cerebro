# Security Hardening Review: Cerebro Shield for macOS

## Evidence Basis

I inspected the endpoint collector, transport, signing, investigation-capability, and Service Management code and ran the recovery canaries recorded in `CANARY.md`. The evidence shows a useful local control: capture continues without the status app, queues during collector failure, recovers exactly once, and preserves a verifiable chain. It also shows the limit we must design around: the collector and its hook inputs remain inside the same user's authority.

## Constraints

We need native agent integrations and offline recovery without adding latency to every hook. We must not use an identity-provider group or a binary hash as a privilege grant, and we must keep the difference between post-capture integrity, complete capture, and provider enforcement explicit.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Move shield trust off the endpoint | LaunchAgent recovery canary, same-user XPC boundary, device-bound investigation capabilities | Managed remote attestation; brokered provider enforcement | Attest fleet coverage first; require the broker before claiming prevention | [Review](proposals/move-shield-trust-off-endpoint.md) |

## Recommendation Summary

I recommend managed remote attestation as the next funded vertical because it converts a local green state into an organization-measurable control: which devices are enrolled, fresh, current, and on an unbroken chain. The brokered option should win for any mutation where prevention is worth the availability and migration cost. We should not wait for that larger program to make endpoint disappearance visible, but we also should not describe remote freshness as mutation enforcement.

## Next Decisions

Security and infrastructure owners need to select the first protected provider action family, a heartbeat freshness window, offline policy, broker owner, and break-glass review path.
