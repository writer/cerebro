package graph

import (
	"fmt"
	"strings"
	"time"
)

// WriteMetadata captures normalized temporal and provenance fields for graph writes.
type WriteMetadata struct {
	ObservedAt      time.Time  `json:"observed_at"`
	ValidFrom       time.Time  `json:"valid_from"`
	ValidTo         *time.Time `json:"valid_to,omitempty"`
	RecordedAt      time.Time  `json:"recorded_at"`
	TransactionFrom time.Time  `json:"transaction_from"`
	TransactionTo   *time.Time `json:"transaction_to,omitempty"`
	SourceSystem    string     `json:"source_system"`
	SourceEventID   string     `json:"source_event_id"`
	Confidence      float64    `json:"confidence"`
}

// WriteMetadataDefaults controls fallback behavior during metadata normalization.
type WriteMetadataDefaults struct {
	Now               time.Time  `json:"now,omitempty"`
	RecordedAt        time.Time  `json:"recorded_at,omitempty"`
	TransactionFrom   time.Time  `json:"transaction_from,omitempty"`
	TransactionTo     *time.Time `json:"transaction_to,omitempty"`
	SourceSystem      string     `json:"source_system,omitempty"`
	SourceEventID     string     `json:"source_event_id,omitempty"`
	SourceEventPrefix string     `json:"source_event_prefix,omitempty"`
	DefaultConfidence float64    `json:"default_confidence,omitempty"`
}

// NormalizeWriteMetadata enforces consistent temporal/provenance defaults for graph writes.
func NormalizeWriteMetadata(observedAt, validFrom time.Time, validTo *time.Time, sourceSystem, sourceEventID string, confidence float64, defaults WriteMetadataDefaults) WriteMetadata {
	now := defaults.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if observedAt.IsZero() {
		observedAt = now
	}
	observedAt = observedAt.UTC()

	if validFrom.IsZero() {
		validFrom = observedAt
	}
	validFrom = validFrom.UTC()

	var normalizedValidTo *time.Time
	if validTo != nil && !validTo.IsZero() {
		copy := validTo.UTC()
		normalizedValidTo = &copy
	}

	recordedAt := defaults.RecordedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = now
	}
	if recordedAt.IsZero() {
		recordedAt = observedAt
	}

	transactionFrom := defaults.TransactionFrom.UTC()
	if transactionFrom.IsZero() {
		transactionFrom = recordedAt
	}

	var transactionTo *time.Time
	if defaults.TransactionTo != nil && !defaults.TransactionTo.IsZero() {
		copy := defaults.TransactionTo.UTC()
		if !copy.Before(transactionFrom) {
			transactionTo = &copy
		}
	}

	sourceSystem = strings.ToLower(strings.TrimSpace(sourceSystem))
	if sourceSystem == "" {
		sourceSystem = strings.ToLower(strings.TrimSpace(defaults.SourceSystem))
	}
	if sourceSystem == "" {
		sourceSystem = "unknown"
	}

	sourceEventID = strings.TrimSpace(sourceEventID)
	if sourceEventID == "" {
		sourceEventID = strings.TrimSpace(defaults.SourceEventID)
	}
	if sourceEventID == "" {
		prefix := strings.TrimSpace(defaults.SourceEventPrefix)
		if prefix == "" {
			prefix = "event"
		}
		sourceEventID = fmt.Sprintf("%s:%d", prefix, observedAt.UnixNano())
	}

	defaultConfidence := defaults.DefaultConfidence
	if defaultConfidence <= 0 {
		defaultConfidence = 0.80
	}
	confidence = clampUnit(confidence)
	if confidence <= 0 {
		confidence = clampUnit(defaultConfidence)
	}

	return WriteMetadata{
		ObservedAt:      observedAt,
		ValidFrom:       validFrom,
		ValidTo:         normalizedValidTo,
		RecordedAt:      recordedAt,
		TransactionFrom: transactionFrom,
		TransactionTo:   transactionTo,
		SourceSystem:    sourceSystem,
		SourceEventID:   sourceEventID,
		Confidence:      confidence,
	}
}

// PropertyMap returns metadata as normalized graph property key/value pairs.
func (m WriteMetadata) PropertyMap() map[string]any {
	properties := map[string]any{
		"source_system":    m.SourceSystem,
		"source_event_id":  m.SourceEventID,
		"observed_at":      m.ObservedAt.UTC().Format(time.RFC3339),
		"valid_from":       m.ValidFrom.UTC().Format(time.RFC3339),
		"recorded_at":      m.RecordedAt.UTC().Format(time.RFC3339),
		"transaction_from": m.TransactionFrom.UTC().Format(time.RFC3339),
		"confidence":       m.Confidence,
	}
	if m.ValidTo != nil && !m.ValidTo.IsZero() {
		properties["valid_to"] = m.ValidTo.UTC().Format(time.RFC3339)
	}
	if m.TransactionTo != nil && !m.TransactionTo.IsZero() {
		properties["transaction_to"] = m.TransactionTo.UTC().Format(time.RFC3339)
	}
	return properties
}

// ApplyTo merges metadata fields into an existing property map.
func (m WriteMetadata) ApplyTo(properties map[string]any) {
	if properties == nil {
		return
	}
	for key, value := range m.PropertyMap() {
		properties[key] = value
	}
}
