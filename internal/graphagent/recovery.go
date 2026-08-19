package graphagent

import (
	"context"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func (s *Service) recoverWeakRows(ctx context.Context, traceID string, started time.Time, timings StageTimings, conversion conversionResult, rows []map[string]any, params map[string]any, emit Emitter) ([]map[string]any, string, ValidatorResult, bool, bool, error) {
	if len(rows) > 0 {
		return nil, "", ValidatorResult{}, false, false, nil
	}
	recoveredConversion, recoveredParams, action, ok := recoveryConversion(conversion, params)
	if !ok {
		return nil, "", ValidatorResult{}, false, false, nil
	}
	if err := emit(Event{Name: EventRecovery, Data: RecoveryEvent{
		Attempt:    1,
		Reason:     "validated_query_returned_no_rows",
		Action:     action,
		Intent:     conversion.Plan.Intent,
		RowsBefore: len(rows),
	}}); err != nil {
		return nil, "", ValidatorResult{}, false, false, err
	}
	validation, rowLimit, err := s.validateConversion(ctx, recoveredConversion, recoveredConversion.Cypher, recoveredParams)
	if err != nil {
		return nil, "", ValidatorResult{}, false, false, err
	}
	if err := emit(Event{Name: EventCypher, Data: CypherEvent{Cypher: recoveredConversion.Cypher, Validator: validation}}); err != nil {
		return nil, "", ValidatorResult{}, false, false, err
	}
	if !validation.OK {
		return nil, "", validation, false, false, nil
	}
	recoveredRaw, err := s.rawCypher.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    recoveredConversion.Cypher,
		Params:   recoveredParams,
		RowLimit: rowLimit,
	})
	if err != nil {
		return nil, "", ValidatorResult{}, false, false, fmt.Errorf("%w: execute recovery cypher: %w", ErrRuntimeUnavailable, err)
	}
	if postProcessingCandidateLimitHit(recoveredConversion, recoveredRaw, rowLimit) {
		err := emitRefusal(emit, traceID, started, recoveredConversion.Cypher, "The deterministic Ask recovery query matched more graph rows than can be safely post-processed without risking an incomplete answer. Narrow the scope or ask for a more specific subset.", "post_processing_candidate_limit", timings)
		return nil, "", validation, false, true, err
	}
	recoveredRows := cypherRowsToMaps(recoveredRaw)
	recoveredRows = postProcessAskRows(recoveredConversion, recoveredRows)
	sanitizeInternalRowFields(recoveredRows)
	if err := emit(Event{Name: EventRecovery, Data: RecoveryEvent{
		Attempt:    1,
		Reason:     "validated_query_returned_no_rows",
		Action:     action,
		Intent:     conversion.Plan.Intent,
		RowsBefore: len(rows),
		RowsAfter:  len(recoveredRows),
	}}); err != nil {
		return nil, "", ValidatorResult{}, false, false, err
	}
	if len(recoveredRows) == 0 {
		return nil, "", validation, false, false, nil
	}
	return recoveredRows, recoveredConversion.Cypher, validation, true, false, nil
}

func recoveryConversion(conversion conversionResult, params map[string]any) (conversionResult, map[string]any, string, bool) {
	recovered := conversion
	recovered.Source = "deterministic_recovery"
	recovered.Corrected = true
	recoveredParams := cloneParams(params)
	switch conversion.Plan.Intent {
	case IntentIdentityBridge:
		recovered.Cypher = renderIdentityBridgeWithoutRecency(conversion.Plan.Limit)
		recovered.Diagnostics = append(recovered.Diagnostics, ConversionDiagnostic{
			Level:   "info",
			Code:    "recovery_identity_bridge_without_recency",
			Message: "Retried identity bridge query without the recency predicate after the canonical query returned no rows.",
		})
		return recovered, recoveredParams, "retry_identity_bridge_without_recency", true
	case IntentConnectorHealth:
		if recoveredParams["scope_urn"] == "" {
			return conversionResult{}, nil, "", false
		}
		recoveredParams["scope_urn"] = ""
		recovered.Diagnostics = append(recovered.Diagnostics, ConversionDiagnostic{
			Level:   "info",
			Code:    "recovery_connector_health_all_sources",
			Message: "Retried connector health across all sources after the scoped source query returned no rows.",
		})
		return recovered, recoveredParams, "retry_connector_health_all_sources", true
	case IntentTopRiskFindings:
		if len(conversion.Plan.Filters) == 0 {
			return conversionResult{}, nil, "", false
		}
		recovered.Plan.Filters = map[string]string{}
		cypher, ok := renderDeterministicPlan(recovered.Plan, defaultMaxRows)
		if !ok {
			return conversionResult{}, nil, "", false
		}
		recovered.Cypher = cypher
		recovered.Diagnostics = append(recovered.Diagnostics, ConversionDiagnostic{
			Level:   "info",
			Code:    "recovery_top_risk_without_filters",
			Message: "Retried top-risk findings without optional filters after the filtered query returned no rows.",
		})
		return recovered, recoveredParams, "retry_top_risk_without_filters", true
	default:
		return conversionResult{}, nil, "", false
	}
}

func cloneParams(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}

func renderIdentityBridgeWithoutRecency(limit int) string {
	return fmt.Sprintf(`MATCH (left:Entity {tenant_id: $tenant_id})-[leftRel:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})
MATCH (right:Entity {tenant_id: $tenant_id})-[rightRel:RELATION {relation: 'represents_identity'}]->(identity2:Entity {tenant_id: $tenant_id})
WHERE left.urn < right.urn
  AND identity2.urn = identity.urn
  AND left.entity_type <> right.entity_type
  AND CASE
        WHEN $scope_urn = '' THEN true
        WHEN left.urn = $scope_urn THEN true
        WHEN right.urn = $scope_urn THEN true
        WHEN identity.urn = $scope_urn THEN true
        ELSE false
      END
  AND NOT left.entity_type STARTS WITH 'identity'
  AND NOT right.entity_type STARTS WITH 'identity'
  AND NOT left.entity_type STARTS WITH 'identifier'
  AND NOT right.entity_type STARTS WITH 'identifier'
RETURN left.urn AS left_urn,
       coalesce(left.label, left.urn) AS left_label,
       left.entity_type AS left_type,
       right.urn AS right_urn,
       coalesce(right.label, right.urn) AS right_label,
       right.entity_type AS right_type,
       identity.urn AS identity_urn,
       coalesce(identity.label, identity.urn) AS identity_label,
       coalesce(%s, '') AS left_seen_at,
       coalesce(%s, '') AS right_seen_at
ORDER BY identity_label, left_urn, right_urn
LIMIT %d`, cypherJSONStringAttributes("leftRel.attributes_json", "at"), cypherJSONStringAttributes("rightRel.attributes_json", "at"), boundedLimit(limit, defaultMaxRows))
}
