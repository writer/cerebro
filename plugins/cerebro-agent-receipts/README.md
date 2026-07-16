# Cerebro Agent Receipts

This plugin records local evidence for Codex tool executions and compares completed actions with AWS CloudTrail events. It is designed to answer two separate questions without conflating them:

1. What action did Codex attempt and complete on this Mac?
2. Which in-scope provider events do not have a one-to-one action match?

## Evidence states

- **Local evidence only:** chained receipts exist and verify against the public-key pin stored with this Mac's receipt ledger.
- **Candidate correlation:** one provider event matches one completed action by time plus action or local-user claim. This is not a verified binding.
- **Provider bound:** an event fetched through an authenticated AWS API call matches the expected account, dedicated agent role, action ID, action name, and time window.
- **Provider gap:** an imported in-scope provider event was not allocated to a completed local action.

JSON selected through the file importer is always marked `user_imported_json` and can never produce a provider-bound result.

## Run

```bash
swift build
swift run ReceiptCoreChecks
./script/build_hook_release.sh
./script/build_and_run.sh --verify
```

The Codex plugin calls `scripts/run-hook.sh`, which verifies and runs the bundled ad-hoc-signed universal helper without compiling in the hook path. Set `CEREBRO_AGENT_RECEIPTS_BUILD_FROM_SOURCE=1` to rebuild into the plugin data directory for development. A managed deployment must replace the ad-hoc signature with an identified Developer ID or enterprise signature and verify the release artifact before enrollment.

See `CANARY.md` for the measured fresh-session and authenticated-provider results.

## Provider evidence

Import a CloudTrail export as untrusted comparison data:

```bash
swift run CerebroAgentReceiptHook import-cloudtrail lookup-events.json
```

Fetch an event family directly through the configured AWS CLI profile:

```bash
swift run CerebroAgentReceiptHook fetch-cloudtrail \
  <profile> RegisterTaskDefinition \
  2026-07-15T08:40:00Z 2026-07-15T08:43:00Z
```

Configure the provider-binding policy before verification:

```bash
export CEREBRO_EXPECTED_AWS_ACCOUNT_ID=<account-id>
export CEREBRO_EXPECTED_AWS_AGENT_ROLE=cerebro-agent-executor
swift run CerebroAgentReceiptHook verify --require-provider-bound
```

The strict verification command fails on empty local evidence, invalid local receipts, zero completed actions, incomplete action binding, or unmatched provider events.

## Security boundary

Codex hooks are evidence collection, not complete interception. They do not observe every possible tool path and plugin hooks can be disabled. The local username is labeled as a claim; it is not proof that a person authorized an action. A permission-request hook only proves that Codex reached an approval gate, not who decided or whether the decision was allowed.

The deployable role template in `assets/aws-canary-role.yaml` is limited to `/cerebro/canary/*`. Its trust principal must be a dedicated broker workload identity. Trusting an operator's normal SSO role would not prevent direct credential bypass.

The remaining production boundary is a signed desktop credential broker with a remotely enrolled device key and remote receipt-chain checkpoints. Until that boundary is deployed, this plugin provides local execution evidence and provider-first gap detection, not an enforcement claim.

## Canary acceptance test

The funded control should pass all of these cases in a sandbox account:

1. One brokered `PutParameter` produces one completed action and one provider binding.
2. A denied action produces zero provider mutations.
3. Two actions plus one provider event produce one match and one unmatched action.
4. A user-imported event carrying a forged action ID produces zero provider bindings.
5. A direct-admin `PutParameter` produces one provider gap.
6. Deleting a local receipt tail is detected by the remote chain checkpoint.

Success means 100% of brokered mutations bind one-to-one, all deliberate bypasses appear in the provider-event denominator, denied mutations remain zero, and spoofed imports never bind.
