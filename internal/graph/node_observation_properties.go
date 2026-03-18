package graph

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type observationPropertyPresence uint16

const (
	observationPropertyObservationType observationPropertyPresence = 1 << iota
	observationPropertySubjectID
	observationPropertyDetail
	observationPropertySourceSystem
	observationPropertySourceEventID
	observationPropertyConfidence
	observationPropertyObservedAt
	observationPropertyValidFrom
	observationPropertyValidTo
	observationPropertyRecordedAt
	observationPropertyTransactionFrom
	observationPropertyTransactionTo
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
	present         observationPropertyPresence
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

// PropertyValue returns one normalized node property value, materializing
// typed observation fields on demand while preserving compact internal storage.
func (n *Node) PropertyValue(key string) (any, bool) {
	if n == nil {
		return nil, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}
	if props, ok := n.ObservationProperties(); ok {
		if value, ok := observationPropertyValue(props, key); ok {
			return value, true
		}
	}
	if n.Properties == nil {
		return nil, false
	}
	value, ok := n.Properties[key]
	if !ok {
		return nil, false
	}
	return cloneAny(value), true
}

// PropertyMap returns a cloned property map that includes compactly stored
// observation fields for export, snapshots, and API responses.
func (n *Node) PropertyMap() map[string]any {
	return cloneNodeProperties(n)
}

func hydrateNodeTypedProperties(node *Node) {
	if node == nil {
		return
	}
	switch node.Kind {
	case NodeKindObservation:
		props, ok := observationPropertiesFromMap(node.Properties)
		if !ok {
			if node.observationProps != nil {
				props = cloneObservationProperties(*node.observationProps)
				ok = props.present != 0
			}
		}
		if ok {
			node.observationProps = ptrObservationProperties(props)
		} else {
			node.observationProps = nil
		}
		stripObservationPropertyKeys(node.Properties)
		if len(node.Properties) == 0 {
			node.Properties = nil
		}
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

	var props ObservationProperties
	if value, ok := properties["observation_type"]; ok && value != nil {
		props.ObservationType = strings.TrimSpace(observationStringValue(value))
		props.present |= observationPropertyObservationType
	}
	if value, ok := properties["subject_id"]; ok && value != nil {
		props.SubjectID = strings.TrimSpace(observationStringValue(value))
		props.present |= observationPropertySubjectID
	}
	if value, ok := properties["detail"]; ok && value != nil {
		props.Detail = strings.TrimSpace(observationStringValue(value))
		props.present |= observationPropertyDetail
	}
	if value, ok := properties["source_system"]; ok && value != nil {
		props.SourceSystem = strings.TrimSpace(observationStringValue(value))
		props.present |= observationPropertySourceSystem
	}
	if value, ok := properties["source_event_id"]; ok && value != nil {
		props.SourceEventID = strings.TrimSpace(observationStringValue(value))
		props.present |= observationPropertySourceEventID
	}
	if value, ok := properties["confidence"]; ok && value != nil {
		if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= observationPropertyConfidence
		}
	}
	if ts, ok := temporalPropertyTime(properties, "observed_at"); ok {
		props.ObservedAt = ts
		props.present |= observationPropertyObservedAt
	}
	if ts, ok := temporalPropertyTime(properties, "valid_from"); ok {
		props.ValidFrom = ts
		props.present |= observationPropertyValidFrom
	}
	if ts, ok := temporalPropertyTime(properties, "valid_to"); ok {
		props.ValidTo = &ts
		props.present |= observationPropertyValidTo
	}
	if ts, ok := temporalPropertyTime(properties, "recorded_at"); ok {
		props.RecordedAt = ts
		props.present |= observationPropertyRecordedAt
	}
	if ts, ok := temporalPropertyTime(properties, "transaction_from"); ok {
		props.TransactionFrom = ts
		props.present |= observationPropertyTransactionFrom
	}
	if ts, ok := temporalPropertyTime(properties, "transaction_to"); ok {
		props.TransactionTo = &ts
		props.present |= observationPropertyTransactionTo
	}

	if props.present == 0 {
		return ObservationProperties{}, false
	}
	return props, true
}

func cloneNodeProperties(node *Node) map[string]any {
	if node == nil {
		return nil
	}
	properties := cloneAnyMap(node.Properties)
	if props, ok := node.ObservationProperties(); ok {
		if properties == nil {
			properties = make(map[string]any, 12)
		}
		materializeObservationProperties(properties, props)
	}
	if len(properties) == 0 {
		return nil
	}
	return properties
}

func materializeObservationProperties(dst map[string]any, props ObservationProperties) {
	if dst == nil {
		return
	}
	if props.present&observationPropertyObservationType != 0 {
		dst["observation_type"] = props.ObservationType
	}
	if props.present&observationPropertySubjectID != 0 {
		dst["subject_id"] = props.SubjectID
	}
	if props.present&observationPropertyDetail != 0 {
		dst["detail"] = props.Detail
	}
	if props.present&observationPropertySourceSystem != 0 {
		dst["source_system"] = props.SourceSystem
	}
	if props.present&observationPropertySourceEventID != 0 {
		dst["source_event_id"] = props.SourceEventID
	}
	if props.present&observationPropertyConfidence != 0 {
		dst["confidence"] = props.Confidence
	}
	if props.present&observationPropertyObservedAt != 0 {
		dst["observed_at"] = props.ObservedAt.UTC().Format(time.RFC3339)
	}
	if props.present&observationPropertyValidFrom != 0 {
		dst["valid_from"] = props.ValidFrom.UTC().Format(time.RFC3339)
	}
	if props.present&observationPropertyValidTo != 0 && props.ValidTo != nil {
		dst["valid_to"] = props.ValidTo.UTC().Format(time.RFC3339)
	}
	if props.present&observationPropertyRecordedAt != 0 {
		dst["recorded_at"] = props.RecordedAt.UTC().Format(time.RFC3339)
	}
	if props.present&observationPropertyTransactionFrom != 0 {
		dst["transaction_from"] = props.TransactionFrom.UTC().Format(time.RFC3339)
	}
	if props.present&observationPropertyTransactionTo != 0 && props.TransactionTo != nil {
		dst["transaction_to"] = props.TransactionTo.UTC().Format(time.RFC3339)
	}
}

func stripObservationPropertyKeys(properties map[string]any) {
	if len(properties) == 0 {
		return
	}
	for _, key := range []string{
		"observation_type",
		"subject_id",
		"detail",
		"source_system",
		"source_event_id",
		"confidence",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"transaction_to",
	} {
		delete(properties, key)
	}
}

func isObservationPropertyKey(key string) bool {
	switch strings.TrimSpace(key) {
	case "observation_type",
		"subject_id",
		"detail",
		"source_system",
		"source_event_id",
		"confidence",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"transaction_to":
		return true
	default:
		return false
	}
}

func observationPropertyValue(props ObservationProperties, key string) (any, bool) {
	switch strings.TrimSpace(key) {
	case "observation_type":
		if props.present&observationPropertyObservationType != 0 {
			return props.ObservationType, true
		}
	case "subject_id":
		if props.present&observationPropertySubjectID != 0 {
			return props.SubjectID, true
		}
	case "detail":
		if props.present&observationPropertyDetail != 0 {
			return props.Detail, true
		}
	case "source_system":
		if props.present&observationPropertySourceSystem != 0 {
			return props.SourceSystem, true
		}
	case "source_event_id":
		if props.present&observationPropertySourceEventID != 0 {
			return props.SourceEventID, true
		}
	case "confidence":
		if props.present&observationPropertyConfidence != 0 {
			return props.Confidence, true
		}
	case "observed_at":
		if props.present&observationPropertyObservedAt != 0 {
			return props.ObservedAt.UTC().Format(time.RFC3339), true
		}
	case "valid_from":
		if props.present&observationPropertyValidFrom != 0 {
			return props.ValidFrom.UTC().Format(time.RFC3339), true
		}
	case "valid_to":
		if props.present&observationPropertyValidTo != 0 && props.ValidTo != nil {
			return props.ValidTo.UTC().Format(time.RFC3339), true
		}
	case "recorded_at":
		if props.present&observationPropertyRecordedAt != 0 {
			return props.RecordedAt.UTC().Format(time.RFC3339), true
		}
	case "transaction_from":
		if props.present&observationPropertyTransactionFrom != 0 {
			return props.TransactionFrom.UTC().Format(time.RFC3339), true
		}
	case "transaction_to":
		if props.present&observationPropertyTransactionTo != 0 && props.TransactionTo != nil {
			return props.TransactionTo.UTC().Format(time.RFC3339), true
		}
	}
	return nil, false
}

func setObservationPropertyValue(node *Node, key string, value any) bool {
	if node == nil || node.Kind != NodeKindObservation {
		return false
	}
	props, _ := node.ObservationProperties()
	key = strings.TrimSpace(key)
	switch key {
	case "observation_type":
		if value == nil {
			props.ObservationType = ""
			props.present &^= observationPropertyObservationType
		} else {
			props.ObservationType = strings.TrimSpace(observationStringValue(value))
			props.present |= observationPropertyObservationType
		}
	case "subject_id":
		if value == nil {
			props.SubjectID = ""
			props.present &^= observationPropertySubjectID
		} else {
			props.SubjectID = strings.TrimSpace(observationStringValue(value))
			props.present |= observationPropertySubjectID
		}
	case "detail":
		if value == nil {
			props.Detail = ""
			props.present &^= observationPropertyDetail
		} else {
			props.Detail = strings.TrimSpace(observationStringValue(value))
			props.present |= observationPropertyDetail
		}
	case "source_system":
		if value == nil {
			props.SourceSystem = ""
			props.present &^= observationPropertySourceSystem
		} else {
			props.SourceSystem = strings.TrimSpace(observationStringValue(value))
			props.present |= observationPropertySourceSystem
		}
	case "source_event_id":
		if value == nil {
			props.SourceEventID = ""
			props.present &^= observationPropertySourceEventID
		} else {
			props.SourceEventID = strings.TrimSpace(observationStringValue(value))
			props.present |= observationPropertySourceEventID
		}
	case "confidence":
		if value == nil {
			props.Confidence = 0
			props.present &^= observationPropertyConfidence
		} else if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= observationPropertyConfidence
		} else {
			return false
		}
	case "observed_at":
		if value == nil {
			props.ObservedAt = time.Time{}
			props.present &^= observationPropertyObservedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.ObservedAt = ts
			props.present |= observationPropertyObservedAt
		} else {
			return false
		}
	case "valid_from":
		if value == nil {
			props.ValidFrom = time.Time{}
			props.present &^= observationPropertyValidFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidFrom = ts
			props.present |= observationPropertyValidFrom
		} else {
			return false
		}
	case "valid_to":
		if value == nil {
			props.ValidTo = nil
			props.present &^= observationPropertyValidTo
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidTo = &ts
			props.present |= observationPropertyValidTo
		} else {
			return false
		}
	case "recorded_at":
		if value == nil {
			props.RecordedAt = time.Time{}
			props.present &^= observationPropertyRecordedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.RecordedAt = ts
			props.present |= observationPropertyRecordedAt
		} else {
			return false
		}
	case "transaction_from":
		if value == nil {
			props.TransactionFrom = time.Time{}
			props.present &^= observationPropertyTransactionFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.TransactionFrom = ts
			props.present |= observationPropertyTransactionFrom
		} else {
			return false
		}
	case "transaction_to":
		if value == nil {
			props.TransactionTo = nil
			props.present &^= observationPropertyTransactionTo
		} else if ts, ok := temporalValueTime(value); ok {
			props.TransactionTo = &ts
			props.present |= observationPropertyTransactionTo
		} else {
			return false
		}
	default:
		return false
	}
	applyObservationPropertiesToNode(node, props)
	return true
}

func applyObservationPropertiesToNode(node *Node, props ObservationProperties) {
	if node == nil {
		return
	}
	if props.present == 0 {
		node.observationProps = nil
	} else {
		node.observationProps = ptrObservationProperties(props)
	}
	if node.Properties != nil {
		stripObservationPropertyKeys(node.Properties)
		if len(node.Properties) == 0 {
			node.Properties = nil
		}
	}
}

func observationStringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func observationFloatValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}
