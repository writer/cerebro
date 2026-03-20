# Agent SDK Package Auto-Generation

Generated from `docs/AGENT_SDK_CONTRACTS.json` via `go run ./scripts/generate_agent_sdk_packages/main.go`.

- Tool bindings: **30**
- Package paths:
  - `sdk/go/cerebro`
  - `sdk/python/cerebro_sdk`
  - `sdk/python/pyproject.toml`
  - `sdk/typescript`

## Convenience Methods

| Tool ID | Go | Python | TypeScript |
|---|---|---|---|
| `cerebro_access_review` | `AccessReview` | `access_review` | `accessReview` |
| `cerebro_actuate_recommendation` | `ActuateRecommendation` | `actuate_recommendation` | `actuateRecommendation` |
| `cerebro_annotate` | `Annotate` | `annotate` | `annotate` |
| `cerebro_autonomous_credential_response` | `AutonomousCredentialResponse` | `autonomous_credential_response` | `autonomousCredentialResponse` |
| `cerebro_autonomous_workflow_approve` | `AutonomousWorkflowApprove` | `autonomous_workflow_approve` | `autonomousWorkflowApprove` |
| `cerebro_autonomous_workflow_status` | `AutonomousWorkflowStatus` | `autonomous_workflow_status` | `autonomousWorkflowStatus` |
| `cerebro_blast_radius` | `BlastRadius` | `blast_radius` | `blastRadius` |
| `cerebro_check` | `Check` | `check` | `check` |
| `cerebro_claim` | `Claim` | `claim` | `claim` |
| `cerebro_context` | `Context` | `context` | `context` |
| `cerebro_correlate_events` | `CorrelateEvents` | `correlate_events` | `correlateEvents` |
| `cerebro_decide` | `Decide` | `decide` | `decide` |
| `cerebro_entity_history` | `EntityHistory` | `entity_history` | `entityHistory` |
| `cerebro_execution_status` | `ExecutionStatus` | `execution_status` | `executionStatus` |
| `cerebro_findings` | `Findings` | `findings` | `findings` |
| `cerebro_graph_changelog` | `GraphChangelog` | `graph_changelog` | `graphChangelog` |
| `cerebro_graph_query` | `GraphQuery` | `graph_query` | `graphQuery` |
| `cerebro_graph_simulate` | `GraphSimulate` | `graph_simulate` | `graphSimulate` |
| `cerebro_identity_calibration` | `IdentityCalibration` | `identity_calibration` | `identityCalibration` |
| `cerebro_identity_review` | `IdentityReview` | `identity_review` | `identityReview` |
| `cerebro_leverage` | `Leverage` | `leverage` | `leverage` |
| `cerebro_observe` | `Observe` | `observe` | `observe` |
| `cerebro_outcome` | `Outcome` | `outcome` | `outcome` |
| `cerebro_quality` | `Quality` | `quality` | `quality` |
| `cerebro_report` | `Report` | `report` | `report` |
| `cerebro_resolve_identity` | `ResolveIdentity` | `resolve_identity` | `resolveIdentity` |
| `cerebro_risk_score` | `RiskScore` | `risk_score` | `riskScore` |
| `cerebro_simulate` | `Simulate` | `simulate` | `simulate` |
| `cerebro_split_identity` | `SplitIdentity` | `split_identity` | `splitIdentity` |
| `cerebro_templates` | `Templates` | `templates` | `templates` |

## Notes

- The generated SDKs keep a single generic tool-call surface plus per-tool convenience methods.
- Report run streaming is exposed for both MCP and platform report SSE endpoints.
- Admin SDK credential lifecycle methods target the managed `/api/v1/admin/agent-sdk/credentials*` surface.
