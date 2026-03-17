package graph

import (
	"strings"
	"time"
)

// ObservationProperties captures the stable high-frequency observation fields
// that currently dominate artifact and runtime query paths.
type ObservationProperties struct {
	ObservationType string
	SubjectID       string
	Detail          string
	SourceSystem    string
	SourceEventID   string
	Confidence      float64
	ObservedAt      time.Time
	ValidFrom       time.Time
	ValidTo         *time.Time
	RecordedAt      time.Time
	TransactionFrom time.Time
	TransactionTo   *time.Time
}

// ObservationProperties returns the typed observation property view when this
// node is an observation. It falls back to parsing the generic property map so
// restored snapshots continue to work before the wider typed-property migration
// is complete.
func (n *Node) ObservationProperties() (ObservationProperties, bool) {
	if n == nil || n.Kind != NodeKindObservation {
		return ObservationProperties{}, false
	}
	if n.observationProps != nil {
		return cloneObservationProperties(*n.observationProps), true
	}
	return observationPropertiesFromMap(n.Properties)
}

func hydrateNodeTypedProperties(node *Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case NodeKindObservation:
		props, ok := observationPropertiesFromMap(node.Properties)
		if !ok {
			node.observationProps = nil
			return
		}
		node.observationProps = ptrObservationProperties(props)
	default:
		node.observationProps = nil
	}
}

func cloneObservationProperties(props ObservationProperties) ObservationProperties {
	cloned := props
	if props.ValidTo != nil {
		validTo := props.ValidTo.UTC()
		cloned.ValidTo = &validTo
	}
	if props.TransactionTo != nil {
		transactionTo := props.TransactionTo.UTC()
		cloned.TransactionTo = &transactionTo
	}
	return cloned
}

func ptrObservationProperties(props ObservationProperties) *ObservationProperties {
	cloned := cloneObservationProperties(props)
	return &cloned
}

func observationPropertiesFromMap(properties map[string]any) (ObservationProperties, bool) {
	if len(properties) == 0 {
		return ObservationProperties{}, false
	}

	props := ObservationProperties{
		ObservationType: strings.TrimSpace(readString(properties, "observation_type")),
		SubjectID:       strings.TrimSpace(readString(properties, "subject_id")),
		Detail:          strings.TrimSpace(readString(properties, "detail")),
		SourceSystem:    strings.TrimSpace(readString(properties, "source_system")),
		SourceEventID:   strings.TrimSpace(readString(properties, "source_event_id")),
		Confidence:      readFloat(properties, "confidence"),
	}
	if ts, ok := temporalPropertyTime(properties, "observed_at"); ok {
		props.ObservedAt = ts
	}
	if ts, ok := temporalPropertyTime(properties, "valid_from"); ok {
		props.ValidFrom = ts
	}
	if ts, ok := temporalPropertyTime(properties, "valid_to"); ok {
		props.ValidTo = &ts
	}
	if ts, ok := temporalPropertyTime(properties, "recorded_at"); ok {
		props.RecordedAt = ts
	}
	if ts, ok := temporalPropertyTime(properties, "transaction_from"); ok {
		props.TransactionFrom = ts
	}
	if ts, ok := temporalPropertyTime(properties, "transaction_to"); ok {
		props.TransactionTo = &ts
	}

	if props.ObservationType == "" &&
		props.SubjectID == "" &&
		props.Detail == "" &&
		props.SourceSystem == "" &&
		props.SourceEventID == "" &&
		props.Confidence == 0 &&
		props.ObservedAt.IsZero() &&
		props.ValidFrom.IsZero() &&
		props.ValidTo == nil &&
		props.RecordedAt.IsZero() &&
		props.TransactionFrom.IsZero() &&
		props.TransactionTo == nil {
		return ObservationProperties{}, false
	}
	return props, true
}
