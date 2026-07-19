---
name: agent-execution-receipts
description: Inspect signed Codex execution receipts, import provider audit events, and explain whether an action has local evidence, a candidate correlation, or a provider binding.
---

# Agent Execution Receipts

Use this skill when the user asks who or what ran a command, whether an agent action reached a provider, or which agent-originated changes lack provider attribution.

## Procedure

1. Open the Cerebro Agent Receipts app or read `receipts.ndjson` from the configured receipt directory.
2. Verify each receipt signature and the append-only digest chain before using it as evidence.
3. Import a CloudTrail `LookupEvents` response when provider observations are available.
4. Report one of three states without collapsing them:
   - `Local evidence only`: a signed local receipt exists.
   - `Candidate correlation`: one provider event has a one-to-one evidence match, but no trusted binding.
   - `Provider bound`: an authenticated provider event passes the configured account, dedicated role, action ID, action, and time checks.
5. Start from the provider-event population and identify every provider mutation without a completed one-to-one action match.

Never treat a process name, user agent, `startedBy` value, local transcript, session-wide identifier, or user-imported JSON as provider-bound attribution.
