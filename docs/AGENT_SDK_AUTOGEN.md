# Agent SDK Auto-Generated Contract Catalog

Generated from the shared `App.AgentSDKTools()` registry and `internal/agentsdk` contract metadata via `go run ./scripts/generate_agent_sdk_docs/main.go`.

- Catalog API version: **cerebro.agent-sdk.contracts/v1alpha1**
- Catalog kind: **AgentSDKCatalog**
- MCP protocol version: **2025-06-18**
- Tools: **27**
- Resources: **5**
- MCP methods + notifications: **7**

## Tools

| ID | Version | Internal Name | Method | Category | Execution | Async | Progress | Path | Permission |
|---|---|---|---|---|---|---|---|---|---|
| `cerebro_access_review` | `1.0.0` | `cerebro.access_review` | `access_review` | `query` | `direct_tool` | false | false | ` ` | `sdk.enforcement.run` |
| `cerebro_actuate_recommendation` | `1.0.0` | `cerebro.actuate_recommendation` | `actuate_recommendation` | `query` | `direct_tool` | false | false | ` ` | `sdk.worldmodel.write` |
| `cerebro_annotate` | `1.0.0` | `cerebro.annotate_entity` | `annotate` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/annotations` | `sdk.worldmodel.write` |
| `cerebro_blast_radius` | `1.0.0` | `cerebro.blast_radius` | `blast_radius` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_check` | `1.0.0` | `evaluate_policy` | `check` | `enforcement` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/check` | `sdk.enforcement.run` |
| `cerebro_claim` | `1.0.0` | `cerebro.write_claim` | `claim` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/claims` | `sdk.worldmodel.write` |
| `cerebro_context` | `1.0.0` | `insight_card` | `context` | `query` | `direct_tool` | false | false | `GET /api/v1/agent-sdk/context/{entity_id}` | `sdk.context.read` |
| `cerebro_correlate_events` | `1.0.0` | `cerebro.correlate_events` | `correlate_events` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_decide` | `1.0.0` | `cerebro.record_decision` | `decide` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/decisions` | `sdk.worldmodel.write` |
| `cerebro_entity_history` | `1.0.0` | `cerebro.entity_history` | `entity_history` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_execution_status` | `1.1.0` | `cerebro.execution_status` | `execution_status` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_findings` | `1.0.0` | `cerebro.findings` | `findings` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_graph_changelog` | `1.0.0` | `cerebro.graph_changelog` | `graph_changelog` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_graph_query` | `1.0.0` | `cerebro.graph_query` | `graph_query` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_graph_simulate` | `1.0.0` | `cerebro.simulate` | `graph_simulate` | `enforcement` | `direct_tool` | false | false | ` ` | `sdk.enforcement.run` |
| `cerebro_identity_calibration` | `1.0.0` | `cerebro.identity_calibration` | `identity_calibration` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_identity_review` | `1.0.0` | `cerebro.identity_review` | `identity_review` | `query` | `direct_tool` | false | false | ` ` | `sdk.worldmodel.write` |
| `cerebro_leverage` | `1.0.0` | `cerebro.graph_leverage_report` | `leverage` | `query` | `direct_tool` | false | false | `GET /api/v1/agent-sdk/leverage` | `sdk.context.read` |
| `cerebro_observe` | `1.0.0` | `cerebro.record_observation` | `observe` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/observations` | `sdk.worldmodel.write` |
| `cerebro_outcome` | `1.0.0` | `cerebro.record_outcome` | `outcome` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/outcomes` | `sdk.worldmodel.write` |
| `cerebro_quality` | `1.0.0` | `cerebro.graph_quality_report` | `quality` | `query` | `direct_tool` | false | false | `GET /api/v1/agent-sdk/quality` | `sdk.context.read` |
| `cerebro_report` | `2.0.0` | `cerebro.intelligence_report` | `report` | `intelligence` | `report_run` | true | true | `POST /api/v1/agent-sdk/report` | `sdk.context.read` |
| `cerebro_resolve_identity` | `1.0.0` | `cerebro.resolve_identity` | `resolve_identity` | `writeback` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/identity/resolve` | `sdk.worldmodel.write` |
| `cerebro_risk_score` | `1.0.0` | `cerebro.risk_score` | `risk_score` | `query` | `direct_tool` | false | false | ` ` | `sdk.context.read` |
| `cerebro_simulate` | `2.0.0` | `simulate` | `simulate` | `enforcement` | `direct_tool` | false | false | `POST /api/v1/agent-sdk/simulate` | `sdk.enforcement.run` |
| `cerebro_split_identity` | `1.0.0` | `cerebro.split_identity` | `split_identity` | `query` | `direct_tool` | false | false | ` ` | `sdk.worldmodel.write` |
| `cerebro_templates` | `1.0.0` | `cerebro.graph_query_templates` | `templates` | `query` | `direct_tool` | false | false | `GET /api/v1/agent-sdk/templates` | `sdk.context.read` |

## Resources

| URI | Version | Name | Permission |
|---|---|---|---|
| `cerebro://agent-sdk/catalog` | `1.0.0` | Agent SDK Contract Catalog | `sdk.schema.read` |
| `cerebro://reports/catalog` | `1.0.0` | Platform Report Catalog | `sdk.schema.read` |
| `cerebro://schema/edge-kinds` | `1.0.0` | Edge Kinds | `sdk.schema.read` |
| `cerebro://schema/node-kinds` | `1.0.0` | Node Kinds | `sdk.schema.read` |
| `cerebro://tools/catalog` | `1.0.0` | Agent Tool Catalog | `sdk.schema.read` |

## MCP Methods

| Name | Kind | Description |
|---|---|---|
| `initialize` | `request` | Initialize one MCP session over Streamable HTTP |
| `tools/list` | `request` | List visible Agent SDK tools |
| `tools/call` | `request` | Invoke one Agent SDK tool by public ID |
| `resources/list` | `request` | List readable Agent SDK resources |
| `resources/read` | `request` | Read one Agent SDK resource payload |
| `notifications/progress` | `notification` | Server-initiated progress notifications for long-running report executions |
| `notifications/report_section` | `notification` | Server-initiated section payload notifications for durable report executions |

## Example Inputs

### `cerebro_access_review`

```json
{
  "created_by": "created_by",
  "description": "description",
  "identity_id": "identity_id",
  "name": "name"
}
```

### `cerebro_actuate_recommendation`

```json
{
  "auto_generated": true,
  "confidence": 0.8,
  "decision_id": "decision:example",
  "id": "id",
  "insight_type": "insight_type",
  "metadata": {
    "example": true
  },
  "observed_at": "observed_at",
  "recommendation_id": "recommendation_id",
  "source_event_id": "source_event_id",
  "source_system": "agent",
  "summary": "summary",
  "target_ids": [],
  "title": "title",
  "valid_from": "valid_from",
  "valid_to": "valid_to"
}
```

### `cerebro_annotate`

```json
{
  "annotation": "Escalate for review",
  "confidence": 0.8,
  "entity_id": "service:payments",
  "metadata": {
    "example": true
  },
  "observed_at": "observed_at",
  "source_event_id": "source_event_id",
  "source_system": "agent",
  "tags": [],
  "valid_from": "valid_from",
  "valid_to": "valid_to"
}
```

### `cerebro_blast_radius`

```json
{
  "max_depth": 3,
  "principal_id": "service:payments"
}
```

### `cerebro_check`

```json
{
  "action": "refund.create",
  "context": {
    "example": true
  },
  "principal": {
    "example": true
  },
  "proposed_change": {
    "example": true
  },
  "resource": {
    "example": true
  },
  "trace_context": {
    "example": true
  }
}
```

### `cerebro_claim`

```json
{
  "claim_type": "claim_type",
  "confidence": 0.8,
  "evidence_ids": [],
  "id": "id",
  "metadata": {
    "example": true
  },
  "object_id": "object_id",
  "object_value": "object_value",
  "observed_at": "observed_at",
  "predicate": "healthy",
  "recorded_at": "recorded_at",
  "refuting_claim_ids": [],
  "reliability_score": 0.5,
  "source_event_id": "source_event_id",
  "source_id": "source_id",
  "source_name": "source_name",
  "source_system": "agent",
  "source_type": "source_type",
  "source_url": "source_url",
  "status": "status",
  "subject_id": "service:payments",
  "summary": "summary",
  "supersedes_claim_id": "supersedes_claim_id",
  "supporting_claim_ids": [],
  "transaction_from": "transaction_from",
  "transaction_to": "transaction_to",
  "trust_tier": "trust_tier",
  "valid_from": "valid_from",
  "valid_to": "valid_to"
}
```

### `cerebro_context`

```json
{
  "entity": "service:payments",
  "sections": [
    "sections"
  ]
}
```

### `cerebro_correlate_events`

```json
{
  "entity_id": "service:payments",
  "event_id": "event_id",
  "include_anomalies": false,
  "limit": 25,
  "pattern_id": "pattern_id"
}
```

### `cerebro_decide`

```json
{
  "action_ids": [],
  "confidence": 0.8,
  "decision_type": "prioritization",
  "evidence_ids": [],
  "id": "id",
  "made_by": "made_by",
  "metadata": {
    "example": true
  },
  "observed_at": "observed_at",
  "rationale": "rationale",
  "source_event_id": "source_event_id",
  "source_system": "agent",
  "status": "proposed",
  "target_ids": [],
  "valid_from": "valid_from",
  "valid_to": "valid_to"
}
```

### `cerebro_entity_history`

```json
{
  "entity_id": "service:payments",
  "from": "from",
  "recorded_at": "recorded_at",
  "timestamp": "timestamp",
  "to": "to"
}
```

### `cerebro_execution_status`

```json
{
  "limit": 20,
  "namespace": [
    "namespace"
  ],
  "offset": 0,
  "order": "updated",
  "report_id": "insights",
  "status": [
    "status"
  ]
}
```

### `cerebro_findings`

```json
{
  "domain": "domain",
  "limit": 50,
  "offset": 0,
  "policy_id": "policy_id",
  "query": "query",
  "severity": "severity",
  "signal_type": "signal_type",
  "status": "status"
}
```

### `cerebro_graph_changelog`

```json
{
  "account": "account",
  "diff_id": "diff_id",
  "kind": "kind",
  "last": "last",
  "limit": 20,
  "provider": "provider",
  "since": "since",
  "until": "until"
}
```

### `cerebro_graph_query`

```json
{
  "as_of": "as_of",
  "direction": "both",
  "from": "from",
  "k": 3,
  "limit": 25,
  "max_depth": 6,
  "mode": "neighbors",
  "node_id": "node_id",
  "target_id": "target_id",
  "to": "to"
}
```

### `cerebro_graph_simulate`

```json
{
  "edges": [],
  "mutations": [],
  "nodes": []
}
```

### `cerebro_identity_calibration`

```json
{
  "include_queue": true,
  "queue_limit": 25,
  "suggest_threshold": 0.55
}
```

### `cerebro_identity_review`

```json
{
  "alias_node_id": "alias_node_id",
  "canonical_node_id": "canonical_node_id",
  "confidence": 0.95,
  "observed_at": "observed_at",
  "reason": "reason",
  "reviewer": "reviewer",
  "source_event_id": "source_event_id",
  "source_system": "review",
  "verdict": "accepted"
}
```

### `cerebro_leverage`

```json
{
  "decision_sla_days": 14,
  "history_limit": 20,
  "identity_queue_limit": 25,
  "identity_suggest_threshold": 0.55,
  "recent_window_hours": 24,
  "since_version": 1,
  "stale_after_hours": 720
}
```

### `cerebro_observe`

```json
{
  "confidence": 0.8,
  "entity_id": "service:payments",
  "id": "id",
  "metadata": {
    "example": true
  },
  "observation": "manual_review_signal",
  "observed_at": "observed_at",
  "source_event_id": "source_event_id",
  "source_system": "agent",
  "summary": "summary",
  "valid_from": "valid_from",
  "valid_to": "valid_to"
}
```

### `cerebro_outcome`

```json
{
  "confidence": 0.8,
  "decision_id": "decision:example",
  "id": "id",
  "impact_score": 0.5,
  "metadata": {
    "example": true
  },
  "observed_at": "observed_at",
  "outcome_type": "impact_review",
  "source_event_id": "source_event_id",
  "source_system": "agent",
  "target_ids": [],
  "valid_from": "valid_from",
  "valid_to": "valid_to",
  "verdict": "confirmed"
}
```

### `cerebro_quality`

```json
{
  "history_limit": 20,
  "since_version": 1,
  "stale_after_hours": 720
}
```

### `cerebro_report`

```json
{
  "execution_mode": "sync",
  "materialize_result": true,
  "parameters": [
    {
      "boolean_value": true,
      "integer_value": 1,
      "name": "name",
      "number_value": 0.5,
      "string_value": "string_value",
      "timestamp_value": "2026-03-09T00:00:00Z"
    }
  ],
  "report_id": "insights",
  "retry_policy": {
    "base_backoff_ms": 5000,
    "max_attempts": 3,
    "max_backoff_ms": 60000
  }
}
```

### `cerebro_resolve_identity`

```json
{
  "alias_id": "alias_id",
  "alias_type": "alias_type",
  "auto_link_threshold": 0.5,
  "canonical_hint": "canonical_hint",
  "confidence": 0.5,
  "email": "email",
  "external_id": "external_id",
  "name": "name",
  "observed_at": "observed_at",
  "source_event_id": "source_event_id",
  "source_system": "source_system",
  "suggest_threshold": 0.5
}
```

### `cerebro_risk_score`

```json
{
  "entity_id": "service:payments",
  "include_overall": false
}
```

### `cerebro_simulate`

```json
{
  "context": "context",
  "parameters": {
    "example": true
  },
  "requester": "requester",
  "scenario": "customer_churn",
  "target": "service:payments"
}
```

### `cerebro_split_identity`

```json
{
  "alias_node_id": "alias_node_id",
  "canonical_node_id": "canonical_node_id",
  "observed_at": "observed_at",
  "reason": "reason",
  "source_event_id": "source_event_id",
  "source_system": "agent"
}
```

## Notes

- `docs/AGENT_SDK_CONTRACTS.json` is the machine-readable catalog for SDK generation, resource discovery, and compatibility checks.
- Public tool IDs are versioned independently from internal tool names so the SDK surface can stay stable while the substrate evolves.
- `cerebro_report` is execution-backed by durable `platform.report_run` resources and supports async execution plus MCP progress notifications.
