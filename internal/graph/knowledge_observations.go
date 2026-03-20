package graph

import (
	"fmt"
	"strings"
	"time"
)

// ObservationWriteRequest records one first-class observation targeting a graph entity.
type ObservationWriteRequest struct {
	ID              string         `json:"id,omitempty"`
	SubjectID       string         `json:"subject_id"`
	ObservationType string         `json:"observation_type"`
	Summary         string         `json:"summary,omitempty"`
	SourceSystem    string         `json:"source_system,omitempty"`
	SourceEventID   string         `json:"source_event_id,omitempty"`
	ObservedAt      time.Time      `json:"observed_at,omitempty"`
	ValidFrom       time.Time      `json:"valid_from,omitempty"`
	ValidTo         *time.Time     `json:"valid_to,omitempty"`
	RecordedAt      time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom time.Time      `json:"transaction_from,omitempty"`
	TransactionTo   *time.Time     `json:"transaction_to,omitempty"`
	Confidence      float64        `json:"confidence,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// ObservationWriteResult summarizes one observation write.
type ObservationWriteResult struct {
	ObservationID string    `json:"observation_id"`
	SubjectID     string    `json:"subject_id"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
	RecordedAt    time.Time `json:"recorded_at,omitempty"`
}

// WriteObservation records one first-class observation and links it to the target entity.
func WriteObservation(g *Graph, req ObservationWriteRequest) (ObservationWriteResult, error) {
	if g == nil {
		return ObservationWriteResult{}, fmt.Errorf("graph is required")
	}

	request, err := normalizeObservationWriteRequest(req)
	if err != nil {
		return ObservationWriteResult{}, err
	}
	if _, ok := g.GetNode(request.SubjectID); !ok {
		return ObservationWriteResult{}, fmt.Errorf("subject not found: %s", request.SubjectID)
	}

	metadata := NormalizeWriteMetadata(request.ObservedAt, request.ValidFrom, request.ValidTo, request.SourceSystem, request.SourceEventID, request.Confidence, WriteMetadataDefaults{
		SourceSystem:      "api",
		SourceEventPrefix: "observation",
		DefaultConfidence: 0.80,
		RecordedAt:        request.RecordedAt,
		TransactionFrom:   request.TransactionFrom,
		TransactionTo:     request.TransactionTo,
	})

	observationID := request.ID
	if observationID == "" {
		observationID = fmt.Sprintf("observation:%d", metadata.ObservedAt.UnixNano())
	}
	properties := cloneAnyMap(request.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	g.AddNode(&Node{
		ID:         observationID,
		Kind:       NodeKindObservation,
		Name:       firstNonEmpty(request.ObservationType, request.Summary, observationID),
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
		observationProps: ptrObservationProperties(ObservationProperties{
			ObservationType: request.ObservationType,
			SubjectID:       request.SubjectID,
			Detail:          firstNonEmpty(request.Summary, request.ObservationType),
			SourceSystem:    metadata.SourceSystem,
			SourceEventID:   metadata.SourceEventID,
			Confidence:      metadata.Confidence,
			ObservedAt:      metadata.ObservedAt,
			ValidFrom:       metadata.ValidFrom,
			ValidTo:         metadata.ValidTo,
			RecordedAt:      metadata.RecordedAt,
			TransactionFrom: metadata.TransactionFrom,
			TransactionTo:   metadata.TransactionTo,
			present: observationPropertyObservationType |
				observationPropertySubjectID |
				observationPropertyDetail |
				observationPropertySourceSystem |
				observationPropertySourceEventID |
				observationPropertyConfidence |
				observationPropertyObservedAt |
				observationPropertyValidFrom |
				observationPropertyRecordedAt |
				observationPropertyTransactionFrom |
				func() observationPropertyPresence {
					mask := observationPropertyPresence(0)
					if metadata.ValidTo != nil {
						mask |= observationPropertyValidTo
					}
					if metadata.TransactionTo != nil {
						mask |= observationPropertyTransactionTo
					}
					return mask
				}(),
		}),
	})

	edgeProperties := metadata.PropertyMap()
	g.AddEdge(&Edge{
		ID:         fmt.Sprintf("%s->%s:%s", observationID, request.SubjectID, EdgeKindTargets),
		Source:     observationID,
		Target:     request.SubjectID,
		Kind:       EdgeKindTargets,
		Effect:     EdgeEffectAllow,
		Properties: edgeProperties,
	})

	return ObservationWriteResult{
		ObservationID: observationID,
		SubjectID:     request.SubjectID,
		ObservedAt:    metadata.ObservedAt,
		RecordedAt:    metadata.RecordedAt,
	}, nil
}

func normalizeObservationWriteRequest(req ObservationWriteRequest) (ObservationWriteRequest, error) {
	out := req
	out.ID = strings.TrimSpace(req.ID)
	out.SubjectID = strings.TrimSpace(req.SubjectID)
	out.ObservationType = strings.TrimSpace(req.ObservationType)
	out.Summary = strings.TrimSpace(req.Summary)
	out.SourceSystem = strings.TrimSpace(req.SourceSystem)
	out.SourceEventID = strings.TrimSpace(req.SourceEventID)
	if out.SubjectID == "" {
		return ObservationWriteRequest{}, fmt.Errorf("subject_id is required")
	}
	if out.ObservationType == "" {
		return ObservationWriteRequest{}, fmt.Errorf("observation_type is required")
	}
	out.Confidence = clampUnit(req.Confidence)
	return out, nil
}
