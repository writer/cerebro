# Graph Report Contract Catalog

Generated from the built-in report runtime registries via `go run ./scripts/generate_report_contract_docs/main.go`.

- Catalog API version: **cerebro.report.contracts/v1alpha1**
- Catalog kind: **ReportContractCatalog**
- Reports: **13**
- Measures: **66**
- Checks: **44**
- Section envelopes: **8**
- Section fragments: **3**
- Benchmark packs: **6**

## Reports

| ID | Version | Category | Result Schema | Run Path | Measure Count | Check Count | Section Count |
|---|---|---|---|---|---|---|---|
| `agent-action-effectiveness` | `1.0.0` | `decision_support` | `reports.AgentActionEffectivenessReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 6 | 3 | 5 |
| `playbook-effectiveness` | `1.0.0` | `decision_support` | `reports.PlaybookEffectivenessReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 7 | 3 | 7 |
| `unified-execution-timeline` | `1.0.0` | `knowledge` | `reports.UnifiedExecutionTimelineReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 5 | 3 | 2 |
| `insights` | `1.0.0` | `decision_support` | `reports.IntelligenceReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 4 | 3 | 4 |
| `quality` | `1.0.0` | `quality` | `reports.GraphQualityReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 6 | 4 | 7 |
| `ai-workloads` | `1.0.0` | `security_posture` | `reports.AIWorkloadInventoryReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 5 | 4 | 5 |
| `metadata-quality` | `1.0.0` | `quality` | `reports.GraphMetadataQualityReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 4 | 4 | 4 |
| `evaluation-temporal-analysis` | `1.0.0` | `knowledge` | `reports.EvaluationTemporalAnalysisReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 5 | 3 | 5 |
| `claim-conflicts` | `1.0.0` | `knowledge` | `graph.ClaimConflictReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 5 | 4 | 3 |
| `entity-summary` | `1.0.0` | `entity` | `reports.EntitySummaryReport` | `/api/v1/platform/intelligence/reports/entity-summary/runs` | 6 | 4 | 6 |
| `leverage` | `1.0.0` | `operating_model` | `reports.GraphLeverageReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 7 | 4 | 11 |
| `calibration-weekly` | `1.0.0` | `calibration` | `reports.WeeklyCalibrationReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 6 | 3 | 4 |
| `key-person-risk` | `1.0.0` | `business_context` | `reports.KeyPersonRiskReport` | `/api/v1/platform/intelligence/reports/{id}/runs` | 4 | 2 | 1 |

## Measures

| ID | Label | Value Type | Unit | Description |
|---|---|---|---|---|
| `actuation_coverage_percent` | `Actuation Coverage` | `number` | `percent` | Share of actions linked to targets, decisions, and outcomes. |
| `affected_arr` | `Affected ARR` | `number` | `currency` | ARR tied to customers that would lose a direct owner. |
| `average_quality_score` | `Average Quality Score` | `number` | `score` | Average conversation quality score from evaluation outcomes. |
| `canonical_kind_coverage_percent` | `Canonical Kind Coverage` | `number` | `percent` | Share of nodes using canonical ontology kinds. |
| `change_count` | `Tracked Changes` | `integer` | - | Number of graph changelog entries captured in the weekly window. |
| `closure_rate_percent` | `Closure Rate` | `number` | `percent` | Share of decisions linked to outcomes or evaluations. |
| `confidence` | `Confidence` | `number` | `percent` | Overall confidence after freshness, conformance, and evidence weighting. |
| `conflict_groups` | `Conflict Groups` | `integer` | - | Returned contradictory subject/predicate groups. |
| `conflicting_claims` | `Conflicting Claims` | `integer` | - | Returned conflicting claims across the result set. |
| `conformance_percent` | `Conformance` | `number` | `percent` | Schema conformance across graph writes. |
| `conversation_count` | `Conversations` | `integer` | - | Evaluation conversations included in the selected window. |
| `correctness_percent` | `Correctness` | `number` | `percent` | Share of evaluation conversations that ended in positive outcomes. |
| `cost_per_successful_conversation_usd` | `Cost Per Successful Conversation` | `number` | `usd` | Total evaluation cost divided by positive conversation outcomes. |
| `coverage` | `Coverage` | `number` | `percent` | How much of the selected scope is covered by the available graph evidence. |
| `coverage_percent` | `Coverage` | `number` | `percent` | Ontology coverage across node and edge kinds. |
| `customers_no_contact` | `Customers Without Contact` | `integer` | - | Customers that would lose a direct human contact. |
| `disputed_claims` | `Disputed Claims` | `integer` | - | Active posture claims with contradictory support. |
| `enum_validity_percent` | `Enum Validity` | `number` | `percent` | Share of enum-like values matching the allowed value set. |
| `evaluation_added_claim_count` | `Added Claims` | `integer` | - | Claims added between the pre-action and post-action world-state slices. |
| `evaluation_claim_count` | `Scoped Claims` | `integer` | - | Claims linked to the selected evaluation scope. |
| `evaluation_contradicted_claim_count` | `Contradicted Claims` | `integer` | - | Scoped claims contradicted by later world-model facts. |
| `evaluation_reversed_action_count` | `Reversed Actions` | `integer` | - | Evaluation actions explicitly reversed or rolled back. |
| `evaluation_superseded_claim_count` | `Superseded Claims` | `integer` | - | Scoped claims later superseded by newer claims. |
| `evidence_count` | `Evidence` | `integer` | - | Evidence artifacts attached to the entity support surface. |
| `facet_coverage_percent` | `Facet Coverage` | `number` | `percent` | Share of applicable built-in facets materialized on the entity. |
| `freshness_percent` | `Freshness` | `number` | `percent` | Recency-adjusted freshness for the selected scope. |
| `high_risk_workload_count` | `High-Risk AI Workloads` | `integer` | - | Detected AI workloads with critical or high risk posture. |
| `internet_exposed_workload_count` | `Internet-Exposed AI` | `integer` | - | Detected AI workloads reachable from the internet. |
| `leverage_score` | `Leverage Score` | `number` | `score` | Composite operating score for graph leverage. |
| `linkage_percent` | `Identity Linkage` | `number` | `percent` | Share of alias identities linked to canonical entities. |
| `maturity_score` | `Maturity Score` | `number` | `score` | Composite graph quality score. |
| `metadata_completeness_percent` | `Metadata Completeness` | `number` | `percent` | Coverage for required temporal metadata keys. |
| `outcome_count` | `Observed Outcomes` | `integer` | - | Number of outcomes in the calibration window. |
| `playbook_approval_bottleneck_count` | `Approval Bottlenecks` | `integer` | - | Approval-required stages that created friction or blocked progress. |
| `playbook_average_completion_minutes` | `Average Completion Time` | `number` | `minutes` | Average time between run start and terminal outcome. |
| `playbook_completion_rate_percent` | `Completion Rate` | `number` | `percent` | Share of playbook runs with terminal outcomes. |
| `playbook_repeat_execution_rate_percent` | `Repeat Execution Rate` | `number` | `percent` | Share of runs that repeated remediation on the same targets. |
| `playbook_rollback_rate_percent` | `Rollback Rate` | `number` | `percent` | Share of completed playbook runs ending in rollback or reversal signals. |
| `playbook_run_count` | `Runs` | `integer` | - | Playbook runs included in the selected window. |
| `playbook_success_rate_percent` | `Success Rate` | `number` | `percent` | Share of playbook runs ending in positive outcomes. |
| `precision_percent` | `Identity Precision` | `number` | `percent` | Accepted identity review precision over the selected calibration slice. |
| `profiled_kinds` | `Profiled Kinds` | `integer` | - | Number of kinds with explicit metadata profiles. |
| `readiness_score` | `Predictive Readiness` | `number` | `score` | Readiness for prediction and calibration based on evidence and labeled outcomes. |
| `required_key_coverage_percent` | `Required Key Coverage` | `number` | `percent` | Coverage for metadata keys marked required by ontology profiles. |
| `reversed_action_count` | `Reversed Actions` | `integer` | - | Actions explicitly reverted or later invalidated by negative outcomes. |
| `review_coverage_percent` | `Review Coverage` | `number` | `percent` | Share of aliases reviewed in the identity calibration slice. |
| `risk_score` | `Risk Score` | `number` | `score` | Top-line modeled risk score for the selected scope. |
| `rule_signal_count` | `Rule Signals` | `integer` | - | Number of rule signals available for backtesting. |
| `schema_valid_write_percent` | `Schema Valid Writes` | `number` | `percent` | Share of writes conforming to schema contracts. |
| `score` | `Risk Score` | `number` | `score` | Composite single-person-failure score. |
| `sensitive_data_workload_count` | `Sensitive Data Reach` | `integer` | - | Detected AI workloads with graph-visible access into sensitive data stores. |
| `shadow_ai_workload_count` | `Shadow AI` | `integer` | - | Self-hosted AI workloads outside the cloud-managed AI service footprint. |
| `sourceless_claims` | `Sourceless Claims` | `integer` | - | Active claims with no source attribution. |
| `stale_claims` | `Stale Claims` | `integer` | - | Claims beyond the requested staleness threshold. |
| `subresource_count` | `Subresources` | `integer` | - | Promoted subresources attached to the entity for explanation and provenance. |
| `successful_action_count` | `Successful Actions` | `integer` | - | Agent actions that aligned with positive conversation outcomes. |
| `supported_claims` | `Supported Claims` | `integer` | - | Active posture claims with evidence support. |
| `systems_bus_factor_0` | `Orphaned Systems` | `integer` | - | Systems that would drop to zero active owners. |
| `timeline_claim_count` | `Claims` | `integer` | - | Claim events represented in the returned timeline. |
| `timeline_evaluation_run_count` | `Evaluation Runs` | `integer` | - | Evaluation runs represented in the returned timeline. |
| `timeline_event_count` | `Timeline Events` | `integer` | - | Returned chronological events after scope and limit filters. |
| `timeline_evidence_count` | `Evidence` | `integer` | - | Direct evidence events represented in the returned timeline. |
| `timeline_playbook_run_count` | `Playbook Runs` | `integer` | - | Playbook runs represented in the returned timeline. |
| `timestamp_validity_percent` | `Timestamp Validity` | `number` | `percent` | Share of timestamp fields matching the expected timestamp type. |
| `unsupported_claims` | `Unsupported Claims` | `integer` | - | Active claims with no evidence support. |
| `workload_count` | `AI Workloads` | `integer` | - | Total detected AI workloads before filtering. |

## Checks

| ID | Title | Severity | Description |
|---|---|---|---|
| `action_reversals` | Action Reversals | `high` | Explicit reversals and negative post-action outcomes should remain low. |
| `actuation_closure` | Actuation Closure | `medium` | Actions should land with targets, decisions, and outcomes. |
| `agent_correctness` | Agent Correctness | `high` | Agent actions should consistently lead to positive conversation outcomes. |
| `canonical_identity` | Canonical Identity | `high` | Entity summaries should expose canonical refs plus source-native external refs. |
| `closed_loop` | Closed Loop | `medium` | Decisions without outcomes leave the intelligence loop incomplete. |
| `contradiction_density` | Contradiction Density | `medium` | Contradiction groups should remain bounded for key subject predicates. |
| `cost_efficiency` | Cost Efficiency | `medium` | Cost per successful conversation should remain within the expected operating envelope. |
| `counterfactual_readiness` | Counterfactual Readiness | `medium` | Counterfactual output depends on simulation-ready graph coverage. |
| `customer_exposure` | Customer Exposure | `high` | Person departures that strand customer ownership or ARR should be escalated. |
| `enum_validity` | Enum Validity | `medium` | Ontology-enumerated values should be normalized consistently. |
| `evaluation_contradictions` | Evaluation Contradictions | `high` | Evaluation-linked claims should not be contradicted by later world facts. |
| `evaluation_reversals` | Evaluation Reversals | `high` | Agent-driven actions should not require later reversal. |
| `evaluation_supersessions` | Evaluation Supersessions | `medium` | Earlier evaluation claims being superseded indicates the agent model drifted over time. |
| `facet_coverage` | Facet Coverage | `medium` | Applicable entity facets should materialize from the available source data. |
| `freshness` | Freshness | `high` | Insights depend on recent graph observations and outcome feedback. |
| `identity_linkage` | Identity Linkage | `high` | Unlinked aliases reduce graph trust and downstream personalization. |
| `identity_precision` | Identity Precision | `high` | Low-confidence identity linkage erodes cross-source graph trust. |
| `identity_review_coverage` | Identity Review Coverage | `medium` | Identity calibration requires regular reviewer decisions. |
| `internet_exposure` | Internet Exposure | `high` | AI-serving paths should not be exposed without strong ingress controls. |
| `metadata_profiles` | Metadata Profiles | `high` | Priority kinds should define required keys, timestamp keys, and enum constraints. |
| `ontology_conformance` | Ontology Conformance | `high` | Unknown or invalid kinds should fail the graph quality bar. |
| `ontology_trend` | Ontology Trend | `medium` | Weekly calibration should include a non-empty ontology trend slice. |
| `ontology_trust` | Ontology Trust | `high` | Canonical kind coverage and valid writes are prerequisite for reuse. |
| `outcome_backtest` | Outcome Backtest | `high` | Outcome coverage and signal backtesting must remain large enough for calibration. |
| `plaintext_provider_keys` | Provider Key Hygiene | `high` | AI provider credentials should not appear directly on workload metadata. |
| `playbook_approval_friction` | Playbook Approval Friction | `medium` | Approval-required stages should not become a systemic bottleneck. |
| `playbook_completion` | Playbook Completion | `high` | Playbook runs should reliably reach terminal outcomes. |
| `playbook_rollbacks` | Playbook Rollbacks | `high` | Completed playbooks should not frequently require rollback or reversal. |
| `posture_support` | Posture Support | `high` | Risk posture should be backed by evidence-linked claims rather than raw properties alone. |
| `required_keys` | Required Keys | `high` | Required metadata keys should be present across profiled writes. |
| `schema_conformance` | Schema Conformance | `high` | Confidence should be reduced when ontology writes are invalid or drifting. |
| `sensitive_data_scope` | Sensitive Data Scope | `medium` | AI workloads should be scoped away from unnecessary sensitive data stores. |
| `shadow_ai` | Shadow AI Detection | `medium` | Self-hosted AI indicators should be inventoried and owned. |
| `single_person_failure` | Single Person Failure | `high` | Critical systems and customer relationships should not hinge on one person. |
| `source_attribution` | Source Attribution | `high` | Claims should link back to first-class sources. |
| `source_coverage` | Source Coverage | `high` | Leverage weakens quickly when ingest breadth misses core operating systems. |
| `subresource_promotion` | Subresource Promotion | `medium` | Nested asset constructs that drive explanation or remediation should be promoted into durable subresources. |
| `supportability` | Supportability | `high` | Claims should be backed by evidence nodes or observations. |
| `temporal_metadata` | Temporal Metadata | `high` | Missing observed and valid timestamps weaken point-in-time reasoning. |
| `timeline_scope_isolation` | Timeline Scope Isolation | `high` | Tenant and workflow filters should isolate timeline output cleanly. |
| `timeline_stage_continuity` | Timeline Stage Continuity | `medium` | Missing stage identifiers should not drop workflow events from the timeline. |
| `timeline_support_coverage` | Timeline Support Coverage | `medium` | Workflow timelines should include directly supporting claims and evidence when available. |
| `timestamp_validity` | Timestamp Validity | `medium` | Timestamp fields should remain valid for bitemporal reasoning. |
| `truncation_transparency` | Truncation Transparency | `medium` | When contradiction output is truncated, total counts must remain explicit. |

## Section Envelopes

| ID | Version | Schema Name | Schema URL | Compatible Section Kinds |
|---|---|---|---|---|
| `distribution` | `1.0.0` | `PlatformDistributionEnvelope` | `urn:cerebro:report-envelope:distribution:v1` | `distribution`, `coverage_breakdown`, `health_breakdown`, `breakdown_table` |
| `evidence_list` | `1.0.0` | `PlatformEvidenceListEnvelope` | `urn:cerebro:report-envelope:evidence_list:v1` | `contradiction_groups`, `ranked_findings` |
| `narrative_block` | `1.0.0` | `PlatformNarrativeBlockEnvelope` | `urn:cerebro:report-envelope:narrative_block:v1` | `context`, `embedded_report` |
| `network_slice` | `1.0.0` | `PlatformNetworkSliceEnvelope` | `urn:cerebro:report-envelope:network_slice:v1` | `embedded_report` |
| `ranking` | `1.0.0` | `PlatformRankingEnvelope` | `urn:cerebro:report-envelope:ranking:v1` | `ranked_findings`, `ranked_backlog`, `action_list` |
| `recommendations` | `1.0.0` | `PlatformRecommendationsEnvelope` | `urn:cerebro:report-envelope:recommendations:v1` | `action_list` |
| `summary` | `1.0.0` | `PlatformSummaryEnvelope` | `urn:cerebro:report-envelope:summary:v1` | `context`, `scorecard`, `health_summary`, `calibration_summary`, `freshness_summary`, `readiness_summary`, `capability_summary`, `backtest_summary` |
| `timeseries` | `1.0.0` | `PlatformTimeseriesEnvelope` | `urn:cerebro:report-envelope:timeseries:v1` | `timeseries_summary` |

### Envelope Examples

#### `distribution`

```json
{
  "items": [
    {
      "dimension": "example",
      "measures": [
        {
          "id": "example",
          "label": "example",
          "value_type": "example"
        }
      ]
    }
  ]
}
```

#### `evidence_list`

```json
{
  "items": [
    {
      "evidence_id": "example",
      "source_system": "example"
    }
  ]
}
```

#### `narrative_block`

```json
{
  "body": "example"
}
```

#### `network_slice`

```json
{
  "edges": [
    {
      "kind": "example",
      "source": "example",
      "target": "example"
    }
  ],
  "nodes": [
    {
      "id": "example",
      "kind": "example"
    }
  ]
}
```

#### `ranking`

```json
{
  "items": [
    {
      "id": "example",
      "rank": 1,
      "title": "example"
    }
  ]
}
```

#### `recommendations`

```json
{
  "items": [
    {
      "id": "example",
      "priority": "example",
      "title": "example"
    }
  ]
}
```

#### `summary`

```json
{
  "headline": "example",
  "measures": [
    {
      "id": "example",
      "label": "example",
      "value_type": "example"
    }
  ]
}
```

#### `timeseries`

```json
{
  "points": [
    {
      "timestamp": "2026-03-10T00:00:00Z",
      "values": [
        {
          "id": "example",
          "label": "example",
          "value_type": "example"
        }
      ]
    }
  ]
}
```


## Section Fragments

| ID | Version | Schema Name | Schema URL | Description |
|---|---|---|---|---|
| `lineage` | `1.0.0` | `PlatformReportSectionLineage` | `urn:cerebro:report-section-fragment:lineage:v1` | Reusable lineage metadata embedded in report section summaries and emissions. |
| `materialization` | `1.0.0` | `PlatformReportSectionMaterialization` | `urn:cerebro:report-section-fragment:materialization:v1` | Reusable delivery and truncation metadata embedded in report section summaries and emissions. |
| `telemetry` | `1.0.0` | `PlatformReportSectionTelemetry` | `urn:cerebro:report-section-fragment:telemetry:v1` | Reusable execution telemetry embedded in report section summaries and emissions. |

## Benchmark Packs

| ID | Version | Scope | Schema Name | Schema URL | Bound Measures |
|---|---|---|---|---|---|
| `claim-conflicts.default` | `1.0.0` | `report` | `PlatformClaimConflictBenchmarkPack` | `urn:cerebro:benchmark-pack:claim-conflicts.default:v1` | `conflict_groups`, `unsupported_claims` |
| `decision-intelligence.default` | `1.0.0` | `report` | `PlatformDecisionIntelligenceBenchmarkPack` | `urn:cerebro:benchmark-pack:decision-intelligence.default:v1` | `risk_score`, `coverage`, `confidence` |
| `graph-leverage.default` | `1.0.0` | `report` | `PlatformGraphLeverageBenchmarkPack` | `urn:cerebro:benchmark-pack:graph-leverage.default:v1` | `leverage_score` |
| `graph-quality.default` | `1.0.0` | `report` | `PlatformGraphQualityBenchmarkPack` | `urn:cerebro:benchmark-pack:graph-quality.default:v1` | `maturity_score`, `coverage_percent`, `closure_rate_percent` |
| `metadata-quality.default` | `1.0.0` | `report` | `PlatformMetadataQualityBenchmarkPack` | `urn:cerebro:benchmark-pack:metadata-quality.default:v1` | `required_key_coverage_percent`, `timestamp_validity_percent` |
| `weekly-calibration.default` | `1.0.0` | `report` | `PlatformWeeklyCalibrationBenchmarkPack` | `urn:cerebro:benchmark-pack:weekly-calibration.default:v1` | `decision_accuracy_percent` |

## Notes

- `docs/GRAPH_REPORT_CONTRACTS.json` is the machine-readable catalog for compatibility checks and generated tooling.
- Section-envelope and benchmark-pack compatibility is version-governed; semantic changes require a version bump.
- Report runs, attempts, and events should bind to these contracts by stable IDs rather than handler-local assumptions.
