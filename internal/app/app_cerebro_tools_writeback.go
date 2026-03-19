package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graph/knowledge"
)

func (a *App) toolCerebroRecordObservation(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		ID            string         `json:"id"`
		EntityID      string         `json:"entity_id"`
		Observation   string         `json:"observation"`
		Summary       string         `json:"summary"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.EntityID = strings.TrimSpace(req.EntityID)
	req.Observation = strings.TrimSpace(req.Observation)
	req.Summary = strings.TrimSpace(req.Summary)
	if req.EntityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}
	if req.Observation == "" {
		return "", fmt.Errorf("observation is required")
	}
	var result knowledge.ObservationWriteResult
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		if _, ok := g.GetNode(req.EntityID); !ok {
			return fmt.Errorf("entity not found: %s", req.EntityID)
		}
		var writeErr error
		result, writeErr = knowledge.WriteObservation(g, knowledge.ObservationWriteRequest{
			ID:              req.ID,
			SubjectID:       req.EntityID,
			ObservationType: req.Observation,
			Summary:         req.Summary,
			SourceSystem:    firstNonEmpty(req.SourceSystem, "agent"),
			SourceEventID:   req.SourceEventID,
			ObservedAt:      req.ObservedAt,
			ValidFrom:       req.ValidFrom,
			ValidTo:         req.ValidTo,
			Confidence:      req.Confidence,
			Metadata:        cloneToolJSONMap(req.Metadata),
		})
		return writeErr
	})
	if err != nil {
		return "", err
	}

	return marshalToolResponse(map[string]any{
		"observation_id": result.ObservationID,
		"entity_id":      req.EntityID,
		"subject_id":     result.SubjectID,
		"observed_at":    result.ObservedAt,
		"recorded_at":    result.RecordedAt,
	})
}

func (a *App) toolCerebroWriteClaim(ctx context.Context, args json.RawMessage) (string, error) {
	var req knowledge.ClaimWriteRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	var result knowledge.ClaimWriteResult
	mutatedGraph, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		var writeErr error
		result, writeErr = knowledge.WriteClaim(g, req)
		return writeErr
	})
	if err != nil {
		return "", err
	}

	conflictReport := knowledge.BuildClaimConflictReport(mutatedGraph, knowledge.ClaimConflictReportOptions{
		ValidAt:      result.ObservedAt,
		RecordedAt:   result.RecordedAt,
		MaxConflicts: 25,
	})
	conflicts := make([]map[string]any, 0, len(conflictReport.Conflicts))
	for _, conflict := range conflictReport.Conflicts {
		if conflict.SubjectID != strings.TrimSpace(req.SubjectID) || conflict.Predicate != strings.TrimSpace(req.Predicate) {
			continue
		}
		conflicts = append(conflicts, map[string]any{
			"key":                conflict.Key,
			"claim_ids":          append([]string(nil), conflict.ClaimIDs...),
			"values":             append([]string(nil), conflict.Values...),
			"source_ids":         append([]string(nil), conflict.SourceIDs...),
			"statuses":           append([]string(nil), conflict.Statuses...),
			"highest_confidence": conflict.HighestConfidence,
			"latest_observed_at": conflict.LatestObservedAt,
		})
	}

	return marshalToolResponse(map[string]any{
		"claim_id":                  result.ClaimID,
		"source_id":                 result.SourceID,
		"evidence_linked":           result.EvidenceLinked,
		"supporting_claims_linked":  result.SupportingClaimsLinked,
		"refuting_claims_linked":    result.RefutingClaimsLinked,
		"supersedes_linked":         result.SupersedesLinked,
		"observed_at":               result.ObservedAt,
		"recorded_at":               result.RecordedAt,
		"conflicts_detected":        conflicts,
		"conflict_groups_returned":  len(conflicts),
		"conflict_groups_truncated": conflictReport.Summary.ConflictsTruncated,
	})
}

func (a *App) toolCerebroAnnotateEntity(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		EntityID      string         `json:"entity_id"`
		Annotation    string         `json:"annotation"`
		Tags          []string       `json:"tags"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.EntityID = strings.TrimSpace(req.EntityID)
	req.Annotation = strings.TrimSpace(req.Annotation)
	if req.EntityID == "" {
		return "", fmt.Errorf("entity_id is required")
	}
	if req.Annotation == "" {
		return "", fmt.Errorf("annotation is required")
	}

	var (
		annotationID string
		count        int
	)
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		entity, ok := g.GetNode(req.EntityID)
		if !ok || entity == nil {
			return fmt.Errorf("entity not found: %s", req.EntityID)
		}

		metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
			SourceSystem:      "agent",
			SourceEventPrefix: "tool",
			DefaultConfidence: 0.80,
		})

		annotationID = fmt.Sprintf("annotation:%s:%d", req.EntityID, metadata.ObservedAt.UnixNano())
		properties := cloneToolJSONMap(entity.Properties)
		existing := toolAnnotationsFromValue(properties["annotations"])
		entry := map[string]any{
			"id":              annotationID,
			"annotation":      req.Annotation,
			"tags":            normalizeToolStringSlice(req.Tags),
			"source_system":   metadata.SourceSystem,
			"source_event_id": metadata.SourceEventID,
			"observed_at":     metadata.ObservedAt.Format(time.RFC3339),
			"valid_from":      metadata.ValidFrom.Format(time.RFC3339),
			"confidence":      metadata.Confidence,
		}
		if metadata.ValidTo != nil {
			entry["valid_to"] = metadata.ValidTo.Format(time.RFC3339)
		}
		if len(req.Metadata) > 0 {
			entry["metadata"] = cloneToolJSONMap(req.Metadata)
		}
		existing = append(existing, entry)
		properties["annotations"] = existing
		metadata.ApplyTo(properties)

		entity.Properties = properties
		g.AddNode(entity)
		count = len(existing)
		return nil
	})
	if err != nil {
		return "", err
	}

	return marshalToolResponse(map[string]any{
		"annotation_id": annotationID,
		"entity_id":     req.EntityID,
		"count":         count,
	})
}

func (a *App) toolCerebroRecordDecision(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		ID            string         `json:"id"`
		DecisionType  string         `json:"decision_type"`
		Status        string         `json:"status"`
		MadeBy        string         `json:"made_by"`
		Rationale     string         `json:"rationale"`
		TargetIDs     []string       `json:"target_ids"`
		EvidenceIDs   []string       `json:"evidence_ids"`
		ActionIDs     []string       `json:"action_ids"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.DecisionType = strings.TrimSpace(req.DecisionType)
	req.Status = strings.TrimSpace(req.Status)
	req.MadeBy = strings.TrimSpace(req.MadeBy)
	req.Rationale = strings.TrimSpace(req.Rationale)
	if req.DecisionType == "" {
		return "", fmt.Errorf("decision_type is required")
	}

	targetIDs := uniqueToolNormalizedIDs(req.TargetIDs)
	if len(targetIDs) == 0 {
		return "", fmt.Errorf("target_ids requires at least one target")
	}
	var decisionID string
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		for _, targetID := range targetIDs {
			if _, ok := g.GetNode(targetID); !ok {
				return fmt.Errorf("target not found: %s", targetID)
			}
		}

		metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
			SourceSystem:      "agent",
			SourceEventPrefix: "tool",
			DefaultConfidence: 0.80,
		})

		decisionID = strings.TrimSpace(req.ID)
		if decisionID == "" {
			decisionID = fmt.Sprintf("decision:%d", metadata.ObservedAt.UnixNano())
		}

		properties := cloneToolJSONMap(req.Metadata)
		properties["decision_type"] = req.DecisionType
		properties["status"] = firstNonEmpty(req.Status, "proposed")
		properties["made_at"] = metadata.ObservedAt.Format(time.RFC3339)
		properties["made_by"] = req.MadeBy
		properties["rationale"] = req.Rationale
		metadata.ApplyTo(properties)

		g.AddNode(&graph.Node{
			ID:         decisionID,
			Kind:       graph.NodeKindDecision,
			Name:       firstNonEmpty(req.DecisionType, decisionID),
			Provider:   metadata.SourceSystem,
			Properties: properties,
			Risk:       graph.RiskNone,
		})

		for _, targetID := range targetIDs {
			edgeProperties := metadata.PropertyMap()
			g.AddEdge(&graph.Edge{
				ID:         fmt.Sprintf("%s->%s:%s", decisionID, targetID, graph.EdgeKindTargets),
				Source:     decisionID,
				Target:     targetID,
				Kind:       graph.EdgeKindTargets,
				Effect:     graph.EdgeEffectAllow,
				Properties: edgeProperties,
			})
		}
		for _, evidenceID := range uniqueToolNormalizedIDs(req.EvidenceIDs) {
			if _, ok := g.GetNode(evidenceID); !ok {
				continue
			}
			edgeProperties := metadata.PropertyMap()
			g.AddEdge(&graph.Edge{
				ID:         fmt.Sprintf("%s->%s:%s", decisionID, evidenceID, graph.EdgeKindBasedOn),
				Source:     decisionID,
				Target:     evidenceID,
				Kind:       graph.EdgeKindBasedOn,
				Effect:     graph.EdgeEffectAllow,
				Properties: edgeProperties,
			})
		}
		for _, actionID := range uniqueToolNormalizedIDs(req.ActionIDs) {
			if _, ok := g.GetNode(actionID); !ok {
				continue
			}
			edgeProperties := metadata.PropertyMap()
			g.AddEdge(&graph.Edge{
				ID:         fmt.Sprintf("%s->%s:%s", decisionID, actionID, graph.EdgeKindExecutedBy),
				Source:     decisionID,
				Target:     actionID,
				Kind:       graph.EdgeKindExecutedBy,
				Effect:     graph.EdgeEffectAllow,
				Properties: edgeProperties,
			})
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return marshalToolResponse(map[string]any{
		"decision_id":  decisionID,
		"target_count": len(targetIDs),
	})
}

func (a *App) toolCerebroRecordOutcome(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		ID            string         `json:"id"`
		DecisionID    string         `json:"decision_id"`
		OutcomeType   string         `json:"outcome_type"`
		Verdict       string         `json:"verdict"`
		ImpactScore   float64        `json:"impact_score"`
		TargetIDs     []string       `json:"target_ids"`
		SourceSystem  string         `json:"source_system"`
		SourceEventID string         `json:"source_event_id"`
		ObservedAt    time.Time      `json:"observed_at"`
		ValidFrom     time.Time      `json:"valid_from"`
		ValidTo       *time.Time     `json:"valid_to"`
		Confidence    float64        `json:"confidence"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	req.DecisionID = strings.TrimSpace(req.DecisionID)
	req.OutcomeType = strings.TrimSpace(req.OutcomeType)
	req.Verdict = strings.TrimSpace(req.Verdict)
	if req.DecisionID == "" {
		return "", fmt.Errorf("decision_id is required")
	}
	if req.OutcomeType == "" || req.Verdict == "" {
		return "", fmt.Errorf("outcome_type and verdict are required")
	}
	var outcomeID string
	targetIDs := uniqueToolNormalizedIDs(req.TargetIDs)
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		if _, ok := g.GetNode(req.DecisionID); !ok {
			return fmt.Errorf("decision not found: %s", req.DecisionID)
		}

		metadata := graph.NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, graph.WriteMetadataDefaults{
			SourceSystem:      "agent",
			SourceEventPrefix: "tool",
			DefaultConfidence: 0.80,
		})

		outcomeID = strings.TrimSpace(req.ID)
		if outcomeID == "" {
			outcomeID = fmt.Sprintf("outcome:%d", metadata.ObservedAt.UnixNano())
		}

		properties := cloneToolJSONMap(req.Metadata)
		properties["outcome_type"] = req.OutcomeType
		properties["verdict"] = req.Verdict
		properties["impact_score"] = req.ImpactScore
		metadata.ApplyTo(properties)

		g.AddNode(&graph.Node{
			ID:         outcomeID,
			Kind:       graph.NodeKindOutcome,
			Name:       firstNonEmpty(req.OutcomeType, outcomeID),
			Provider:   metadata.SourceSystem,
			Properties: properties,
			Risk:       graph.RiskNone,
		})
		evaluatesEdgeProperties := metadata.PropertyMap()
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", outcomeID, req.DecisionID, graph.EdgeKindEvaluates),
			Source:     outcomeID,
			Target:     req.DecisionID,
			Kind:       graph.EdgeKindEvaluates,
			Effect:     graph.EdgeEffectAllow,
			Properties: evaluatesEdgeProperties,
		})

		for _, targetID := range targetIDs {
			if _, ok := g.GetNode(targetID); !ok {
				continue
			}
			edgeProperties := metadata.PropertyMap()
			g.AddEdge(&graph.Edge{
				ID:         fmt.Sprintf("%s->%s:%s", outcomeID, targetID, graph.EdgeKindTargets),
				Source:     outcomeID,
				Target:     targetID,
				Kind:       graph.EdgeKindTargets,
				Effect:     graph.EdgeEffectAllow,
				Properties: edgeProperties,
			})
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return marshalToolResponse(map[string]any{
		"outcome_id":   outcomeID,
		"decision_id":  req.DecisionID,
		"target_count": len(targetIDs),
	})
}

func (a *App) toolCerebroResolveIdentity(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		AliasID           string    `json:"alias_id"`
		SourceSystem      string    `json:"source_system"`
		SourceEventID     string    `json:"source_event_id"`
		ExternalID        string    `json:"external_id"`
		AliasType         string    `json:"alias_type"`
		CanonicalHint     string    `json:"canonical_hint"`
		Email             string    `json:"email"`
		Name              string    `json:"name"`
		ObservedAt        time.Time `json:"observed_at"`
		Confidence        float64   `json:"confidence"`
		AutoLinkThreshold float64   `json:"auto_link_threshold"`
		SuggestThreshold  float64   `json:"suggest_threshold"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	var result graph.IdentityResolutionResult
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		var resolveErr error
		result, resolveErr = graph.ResolveIdentityAlias(g, graph.IdentityAliasAssertion{
			AliasID:       strings.TrimSpace(req.AliasID),
			SourceSystem:  strings.TrimSpace(req.SourceSystem),
			SourceEventID: strings.TrimSpace(req.SourceEventID),
			ExternalID:    strings.TrimSpace(req.ExternalID),
			AliasType:     strings.TrimSpace(req.AliasType),
			CanonicalHint: strings.TrimSpace(req.CanonicalHint),
			Email:         strings.TrimSpace(req.Email),
			Name:          strings.TrimSpace(req.Name),
			ObservedAt:    req.ObservedAt,
			Confidence:    req.Confidence,
		}, graph.IdentityResolutionOptions{
			AutoLinkThreshold: req.AutoLinkThreshold,
			SuggestThreshold:  req.SuggestThreshold,
		})
		return resolveErr
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(result)
}

func (a *App) toolCerebroSplitIdentity(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		AliasNodeID     string    `json:"alias_node_id"`
		CanonicalNodeID string    `json:"canonical_node_id"`
		Reason          string    `json:"reason"`
		SourceSystem    string    `json:"source_system"`
		SourceEventID   string    `json:"source_event_id"`
		ObservedAt      time.Time `json:"observed_at"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	var removed bool
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		var splitErr error
		removed, splitErr = graph.SplitIdentityAlias(
			g,
			strings.TrimSpace(req.AliasNodeID),
			strings.TrimSpace(req.CanonicalNodeID),
			strings.TrimSpace(req.Reason),
			strings.TrimSpace(req.SourceSystem),
			strings.TrimSpace(req.SourceEventID),
			req.ObservedAt,
		)
		return splitErr
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(map[string]any{
		"removed":           removed,
		"alias_node_id":     strings.TrimSpace(req.AliasNodeID),
		"canonical_node_id": strings.TrimSpace(req.CanonicalNodeID),
	})
}

func (a *App) toolCerebroIdentityReview(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		AliasNodeID     string    `json:"alias_node_id"`
		CanonicalNodeID string    `json:"canonical_node_id"`
		Verdict         string    `json:"verdict"`
		Reviewer        string    `json:"reviewer"`
		Reason          string    `json:"reason"`
		SourceSystem    string    `json:"source_system"`
		SourceEventID   string    `json:"source_event_id"`
		ObservedAt      time.Time `json:"observed_at"`
		Confidence      float64   `json:"confidence"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	var record graph.IdentityReviewRecord
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		var reviewErr error
		record, reviewErr = graph.ReviewIdentityAlias(g, graph.IdentityReviewDecision{
			AliasNodeID:     strings.TrimSpace(req.AliasNodeID),
			CanonicalNodeID: strings.TrimSpace(req.CanonicalNodeID),
			Verdict:         strings.TrimSpace(req.Verdict),
			Reviewer:        strings.TrimSpace(req.Reviewer),
			Reason:          strings.TrimSpace(req.Reason),
			SourceSystem:    strings.TrimSpace(req.SourceSystem),
			SourceEventID:   strings.TrimSpace(req.SourceEventID),
			ObservedAt:      req.ObservedAt,
			Confidence:      req.Confidence,
		})
		return reviewErr
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(record)
}

func (a *App) toolCerebroIdentityCalibration(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		SuggestThreshold float64 `json:"suggest_threshold"`
		QueueLimit       int     `json:"queue_limit"`
		IncludeQueue     *bool   `json:"include_queue"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	if req.SuggestThreshold < 0 || req.SuggestThreshold > 1 {
		return "", fmt.Errorf("suggest_threshold must be between 0 and 1")
	}

	includeQueue := true
	if req.IncludeQueue != nil {
		includeQueue = *req.IncludeQueue
	}
	queueLimit := clampInt(req.QueueLimit, 25, 1, 200)
	suggestThreshold := req.SuggestThreshold
	if suggestThreshold == 0 {
		suggestThreshold = 0.55
	}

	report := graph.BuildIdentityCalibrationReport(g, graph.IdentityCalibrationOptions{
		SuggestThreshold: suggestThreshold,
		QueueLimit:       queueLimit,
		IncludeQueue:     includeQueue,
	})
	return marshalToolResponse(report)
}

func (a *App) toolCerebroActuateRecommendation(ctx context.Context, args json.RawMessage) (string, error) {
	var req struct {
		ID               string         `json:"id"`
		RecommendationID string         `json:"recommendation_id"`
		InsightType      string         `json:"insight_type"`
		Title            string         `json:"title"`
		Summary          string         `json:"summary"`
		DecisionID       string         `json:"decision_id"`
		TargetIDs        []string       `json:"target_ids"`
		SourceSystem     string         `json:"source_system"`
		SourceEventID    string         `json:"source_event_id"`
		ObservedAt       time.Time      `json:"observed_at"`
		ValidFrom        time.Time      `json:"valid_from"`
		ValidTo          *time.Time     `json:"valid_to"`
		Confidence       float64        `json:"confidence"`
		AutoGenerated    bool           `json:"auto_generated"`
		Metadata         map[string]any `json:"metadata"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	var result graph.RecommendationActuationResult
	_, err := a.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		var actuationErr error
		result, actuationErr = graph.ActuateRecommendation(g, graph.RecommendationActuationRequest{
			ID:               strings.TrimSpace(req.ID),
			RecommendationID: strings.TrimSpace(req.RecommendationID),
			InsightType:      strings.TrimSpace(req.InsightType),
			Title:            strings.TrimSpace(req.Title),
			Summary:          strings.TrimSpace(req.Summary),
			DecisionID:       strings.TrimSpace(req.DecisionID),
			TargetIDs:        req.TargetIDs,
			SourceSystem:     strings.TrimSpace(req.SourceSystem),
			SourceEventID:    strings.TrimSpace(req.SourceEventID),
			ObservedAt:       req.ObservedAt,
			ValidFrom:        req.ValidFrom,
			ValidTo:          req.ValidTo,
			Confidence:       req.Confidence,
			AutoGenerated:    req.AutoGenerated,
			Metadata:         req.Metadata,
		})
		return actuationErr
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(result)
}

func cloneToolJSONMap(value map[string]any) map[string]any {
	if len(value) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func uniqueToolNormalizedIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeToolStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func toolAnnotationsFromValue(raw any) []map[string]any {
	switch typed := raw.(type) {
	case []map[string]any:
		return append([]map[string]any(nil), typed...)
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, m)
		}
		return out
	default:
		return []map[string]any{}
	}
}
