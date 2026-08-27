# Cerebro Agent Receipts

This plugin records local evidence for coding-agent tool executions and compares completed actions with AWS CloudTrail events. It is designed to answer two separate questions without conflating them:

1. What action did a connected coding agent attempt and complete on this Mac?
2. Which in-scope provider events do not have a one-to-one action match?

## Agent connections

The macOS app manages local event adapters for these agent products:

| Agent | Local event source | Configuration |
| --- | --- | --- |
| Codex | Plugin lifecycle hooks | Installed with this plugin |
| Droid | Native command hooks | `~/.factory/settings.json` |
| Claude Code | Native command hooks | `~/.claude/settings.json` |
| OpenCode | Native plugin event bus | `~/.config/opencode/plugins/cerebro-agent-receipts.js` |
| Cursor | Native command hooks | `~/.cursor/hooks.json` |

The macOS app registers a per-user LaunchAgent that owns receipt signing, the ledger, adapter reconciliation, and recovery of a bounded fallback queue. The visible app is a menu-bar status and investigation surface; quitting it does not stop the collector. The collector discovers supported local executables and reconciles their managed adapters every 30 seconds. Invalid JSON and an unrelated OpenCode plugin at the managed path are left unchanged for an operator. Login-item registration remains subject to macOS approval.

Device status separates five facts that must not be collapsed into one green state: collector reachable, executable detected, adapter current, recent integrity-valid agent event, and executable identity. The integration counts are local detected-tool inventory, not a fleet, session, or action coverage denominator. Static code validation records the signing identifier, Team ID, CDHash, and content digest where available. Organization-managed state requires both the configured Team ID and configured signing identifier from a verified publisher signature. CDHash and content digest are drift evidence, not administrator authorization.

Organization investigation access is represented by a signed capability bound to the organization, collector device key, subject, role, canonical operation, canonical target, issue time, expiry, and grant ID. The organization verification key, expected Team ID, and expected signing identifier are accepted only from a root-owned, non-writable managed preferences file. There is no local administrator toggle. An enterprise identity provider can authorize server-side capability issuance, but a group claim alone does not grant local macOS privilege. Adapter mutations consume the grant ID in an atomic local ledger and reject another use. That ledger remains inside the same-user endpoint boundary; remote mutation authorization still requires an independent server-side use record. Executable CDHashes are recorded for drift analysis and never used as authorization.

Each receipt records the agent product, adapter, native event name, session, tool call, input digest, and lifecycle state through one normalized contract. The raw event remains an agent-supplied claim; disabled hooks and commands run outside a connected agent are outside this evidence boundary. Cursor user hooks cover local sessions. Cloud sessions require a project-level hook configuration.

## Cerebro delivery

Managed deployments can enable background receipt delivery with these root-owned preference values:

- `ReceiptUploadEnabled`: `true`
- `CerebroBaseURL`: the HTTPS Cerebro origin, with no credentials, query, fragment, or path
- `HardwareUUID`: the hardware identifier bound into the one-time enrollment credential

The status app accepts the one-time bootstrap token in a secure field and sends it directly to the collector over authenticated XPC. The app clears the field before the request and does not write the token to preferences or delivery state. The collector enrolls its existing receipt-signing key as the device key, stores only the rotating refresh credential in the device-only Keychain, and keeps access tokens in memory.

Before upload, the collector takes a locked ledger snapshot and verifies its signatures, sequence, and chain. It sends one bounded receipt claim at a time with a DPoP-bound access token and a deterministic idempotency key. The non-secret cursor advances only after Cerebro returns `202 accepted` for the enrolled device. Network and server failures leave the cursor unchanged; receipt, credential-binding, and idempotency conflicts block delivery for investigation.

The resulting graph record proves that an authenticated enrolled device submitted the bounded claim. Cerebro does not yet verify the complete endpoint receipt signature or a remote chain checkpoint, so this is not proof that the named agent or person executed the action.

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

The Codex plugin calls `scripts/run-hook.sh`, which verifies and runs the installed signed helper when one is available. A repository checkout without an installed helper builds the hook from source into the plugin data directory and reuses that generated executable. Other connected agents invoke the same helper through their native local hook or plugin interface. Set `CEREBRO_AGENT_RECEIPTS_BUILD_FROM_SOURCE=1` to force a source rebuild for development. A managed deployment must replace the ad-hoc signature with an identified Developer ID or enterprise signature and verify the release artifact before enrollment. The app labels an ad-hoc build as **Development trust** because that signature does not establish a durable publisher boundary.

The repository does not track compiled hook executables. The agent-receipt hook workflow builds the universal helper from `Package.swift` and `Sources/`, runs the package checks, records its checksum, and uploads the generated executable for the exact commit. The local development script builds the menu app and collector for the current Mac architecture; release packaging must archive universal binaries, apply the managed signing identity, enable hardened runtime, notarize the app, and exercise an in-place upgrade. Ad-hoc development rebuilds cannot prove the launch constraints used by a managed signature.

The runtime canary currently covers Codex end to end. Droid, Claude Code, OpenCode, and Cursor are covered by adapter contract checks and fixture validation; each still needs a fresh native session canary before release qualification.

The collector resumes its authenticated XPC listener before adapter maintenance starts. A managed hook never places an event into the user-writable development fallback: if the collector rejects or cannot accept an event, the hook returns a nonzero result for the invoking agent to report or enforce. Release qualification must verify that each supported agent treats that result as a stopped or visibly failed operation; a nonzero hook result alone does not prove the agent blocked the action.

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

Agent hooks are evidence collection, not complete interception. They do not observe every possible tool path and hooks can be disabled. The local username is labeled as a claim; it is not proof that a person authorized an action. A permission-request hook only proves that an agent reached an approval gate, not who decided or whether the decision was allowed.

The deployable role template in `assets/aws-canary-role.yaml` is limited to `/cerebro/canary/*`. Its trust principal must be a dedicated broker workload identity. Trusting an operator's normal SSO role would not prevent direct credential bypass.

The current collector is a separately registered per-user LaunchAgent and can still be disabled by that user. In a development build it stores its signing key in a user-owned 0600 file because ad-hoc rebuilds do not have a stable Keychain code requirement; a signed managed build uses Keychain custody. Device enrollment and authenticated delivery are implemented; signed remote heartbeats and server-verified chain checkpoints remain the next trust boundary. A later privileged broker and provider-side deny policy must own protected cloud mutations. Endpoint Security is reserved for a later system extension if protected local process interception is required. Until those boundaries are deployed, this plugin provides persistent local execution evidence, authenticated device-claim delivery, adapter drift recovery, executable identity inventory, and provider-first gap detection—not an enforcement or verified-execution claim.

## Canary acceptance test

The funded control should pass all of these cases in a sandbox account:

1. One brokered `PutParameter` produces one completed action and one provider binding.
2. A denied action produces zero provider mutations.
3. Two actions plus one provider event produce one match and one unmatched action.
4. A user-imported event carrying a forged action ID produces zero provider bindings.
5. A direct-admin `PutParameter` produces one provider gap.
6. Deleting a local receipt tail is detected by the remote chain checkpoint.

Success means 100% of brokered mutations bind one-to-one, all deliberate bypasses appear in the provider-event denominator, denied mutations remain zero, and spoofed imports never bind.
