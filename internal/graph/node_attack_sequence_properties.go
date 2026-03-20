package graph

import (
	"strconv"
	"strings"
	"time"
)

type attackSequencePropertyPresence uint32

const (
	attackSequencePropertySequenceType attackSequencePropertyPresence = 1 << iota
	attackSequencePropertyWorkloadRef
	attackSequencePropertyDetail
	attackSequencePropertySeverity
	attackSequencePropertyObservationCount
	attackSequencePropertySequenceStart
	attackSequencePropertySequenceEnd
	attackSequencePropertyWindowSeconds
	attackSequencePropertyObservationTypes
	attackSequencePropertyOrderedObservationIDs
	attackSequencePropertyMITREAttack
	attackSequencePropertySourceSystem
	attackSequencePropertySourceEventID
	attackSequencePropertyObservedAt
	attackSequencePropertyValidFrom
	attackSequencePropertyValidTo
	attackSequencePropertyRecordedAt
	attackSequencePropertyTransactionFrom
	attackSequencePropertyConfidence
)

// AttackSequenceProperties captures the stable attack_sequence fields that
// dominate runtime sequence projection and temporal reads.
type AttackSequenceProperties struct {
	SequenceType          string
	WorkloadRef           string
	Detail                string
	Severity              string
	ObservationCount      int
	SequenceStart         time.Time
	SequenceEnd           time.Time
	WindowSeconds         int64
	ObservationTypes      []string
	OrderedObservationIDs []string
	MITREAttack           []string
	SourceSystem          string
	SourceEventID         string
	ObservedAt            time.Time
	ValidFrom             time.Time
	ValidTo               *time.Time
	RecordedAt            time.Time
	TransactionFrom       time.Time
	Confidence            float64
	present               attackSequencePropertyPresence
}

// AttackSequenceProperties returns the typed attack sequence view when this
// node is an attack_sequence. It falls back to parsing the generic property map
// so restored snapshots continue to work during the wider typed-property
// migration.
func (n *Node) AttackSequenceProperties() (AttackSequenceProperties, bool) {
	if n == nil || n.Kind != NodeKindAttackSequence {
		return AttackSequenceProperties{}, false
	}
	if n.propertyColumns != nil && n.ordinal != InvalidNodeOrdinal {
		if props, ok := n.propertyColumns.AttackSequenceProperties(n.ordinal); ok {
			return props, true
		}
	}
	if n.attackSequenceProps != nil {
		return cloneAttackSequenceProperties(*n.attackSequenceProps), true
	}
	return attackSequencePropertiesFromMap(n.Properties)
}

func cloneAttackSequenceProperties(props AttackSequenceProperties) AttackSequenceProperties {
	cloned := props
	cloned.ObservationTypes = append([]string(nil), props.ObservationTypes...)
	cloned.OrderedObservationIDs = append([]string(nil), props.OrderedObservationIDs...)
	cloned.MITREAttack = append([]string(nil), props.MITREAttack...)
	if props.ValidTo != nil {
		validTo := props.ValidTo.UTC()
		cloned.ValidTo = &validTo
	}
	return cloned
}

func ptrAttackSequenceProperties(props AttackSequenceProperties) *AttackSequenceProperties {
	cloned := cloneAttackSequenceProperties(props)
	return &cloned
}

func attackSequencePropertiesFromMap(properties map[string]any) (AttackSequenceProperties, bool) {
	if len(properties) == 0 {
		return AttackSequenceProperties{}, false
	}

	var props AttackSequenceProperties
	if value, ok := properties["sequence_type"]; ok && value != nil {
		props.SequenceType = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertySequenceType
	}
	if value, ok := properties["workload_ref"]; ok && value != nil {
		props.WorkloadRef = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertyWorkloadRef
	}
	if value, ok := properties["detail"]; ok && value != nil {
		props.Detail = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertyDetail
	}
	if value, ok := properties["severity"]; ok && value != nil {
		props.Severity = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertySeverity
	}
	if value, ok := properties["observation_count"]; ok && value != nil {
		if count, ok := attackSequenceIntValue(value); ok {
			props.ObservationCount = count
			props.present |= attackSequencePropertyObservationCount
		}
	}
	if ts, ok := temporalPropertyTime(properties, "sequence_start"); ok {
		props.SequenceStart = ts
		props.present |= attackSequencePropertySequenceStart
	}
	if ts, ok := temporalPropertyTime(properties, "sequence_end"); ok {
		props.SequenceEnd = ts
		props.present |= attackSequencePropertySequenceEnd
	}
	if value, ok := properties["window_seconds"]; ok && value != nil {
		if seconds, ok := attackSequenceInt64Value(value); ok {
			props.WindowSeconds = seconds
			props.present |= attackSequencePropertyWindowSeconds
		}
	}
	if values := normalizedStringSlice(valueOrNil(properties, "observation_types")); len(values) > 0 {
		props.ObservationTypes = values
		props.present |= attackSequencePropertyObservationTypes
	}
	if values := normalizedStringSlice(valueOrNil(properties, "ordered_observation_ids")); len(values) > 0 {
		props.OrderedObservationIDs = values
		props.present |= attackSequencePropertyOrderedObservationIDs
	}
	if values := normalizedStringSlice(valueOrNil(properties, "mitre_attack")); len(values) > 0 {
		props.MITREAttack = values
		props.present |= attackSequencePropertyMITREAttack
	}
	if value, ok := properties["source_system"]; ok && value != nil {
		props.SourceSystem = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertySourceSystem
	}
	if value, ok := properties["source_event_id"]; ok && value != nil {
		props.SourceEventID = strings.TrimSpace(observationStringValue(value))
		props.present |= attackSequencePropertySourceEventID
	}
	if ts, ok := temporalPropertyTime(properties, "observed_at"); ok {
		props.ObservedAt = ts
		props.present |= attackSequencePropertyObservedAt
	}
	if ts, ok := temporalPropertyTime(properties, "valid_from"); ok {
		props.ValidFrom = ts
		props.present |= attackSequencePropertyValidFrom
	}
	if ts, ok := temporalPropertyTime(properties, "valid_to"); ok {
		props.ValidTo = &ts
		props.present |= attackSequencePropertyValidTo
	}
	if ts, ok := temporalPropertyTime(properties, "recorded_at"); ok {
		props.RecordedAt = ts
		props.present |= attackSequencePropertyRecordedAt
	}
	if ts, ok := temporalPropertyTime(properties, "transaction_from"); ok {
		props.TransactionFrom = ts
		props.present |= attackSequencePropertyTransactionFrom
	}
	if value, ok := properties["confidence"]; ok && value != nil {
		if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= attackSequencePropertyConfidence
		}
	}

	if props.present == 0 {
		return AttackSequenceProperties{}, false
	}
	return props, true
}

func materializeAttackSequenceProperties(dst map[string]any, props AttackSequenceProperties) {
	if dst == nil {
		return
	}
	if props.present&attackSequencePropertySequenceType != 0 {
		dst["sequence_type"] = props.SequenceType
	}
	if props.present&attackSequencePropertyWorkloadRef != 0 {
		dst["workload_ref"] = props.WorkloadRef
	}
	if props.present&attackSequencePropertyDetail != 0 {
		dst["detail"] = props.Detail
	}
	if props.present&attackSequencePropertySeverity != 0 {
		dst["severity"] = props.Severity
	}
	if props.present&attackSequencePropertyObservationCount != 0 {
		dst["observation_count"] = props.ObservationCount
	}
	if props.present&attackSequencePropertySequenceStart != 0 {
		dst["sequence_start"] = props.SequenceStart.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertySequenceEnd != 0 {
		dst["sequence_end"] = props.SequenceEnd.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyWindowSeconds != 0 {
		dst["window_seconds"] = props.WindowSeconds
	}
	if props.present&attackSequencePropertyObservationTypes != 0 {
		dst["observation_types"] = append([]string(nil), props.ObservationTypes...)
	}
	if props.present&attackSequencePropertyOrderedObservationIDs != 0 {
		dst["ordered_observation_ids"] = append([]string(nil), props.OrderedObservationIDs...)
	}
	if props.present&attackSequencePropertyMITREAttack != 0 {
		dst["mitre_attack"] = append([]string(nil), props.MITREAttack...)
	}
	if props.present&attackSequencePropertySourceSystem != 0 {
		dst["source_system"] = props.SourceSystem
	}
	if props.present&attackSequencePropertySourceEventID != 0 {
		dst["source_event_id"] = props.SourceEventID
	}
	if props.present&attackSequencePropertyObservedAt != 0 {
		dst["observed_at"] = props.ObservedAt.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyValidFrom != 0 {
		dst["valid_from"] = props.ValidFrom.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyValidTo != 0 && props.ValidTo != nil {
		dst["valid_to"] = props.ValidTo.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyRecordedAt != 0 {
		dst["recorded_at"] = props.RecordedAt.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyTransactionFrom != 0 {
		dst["transaction_from"] = props.TransactionFrom.UTC().Format(time.RFC3339)
	}
	if props.present&attackSequencePropertyConfidence != 0 {
		dst["confidence"] = props.Confidence
	}
}

func stripAttackSequencePropertyKeys(properties map[string]any) {
	if len(properties) == 0 {
		return
	}
	for _, key := range []string{
		"sequence_type",
		"workload_ref",
		"detail",
		"severity",
		"observation_count",
		"sequence_start",
		"sequence_end",
		"window_seconds",
		"observation_types",
		"ordered_observation_ids",
		"mitre_attack",
		"source_system",
		"source_event_id",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"confidence",
	} {
		delete(properties, key)
	}
}

func isAttackSequencePropertyKey(key string) bool {
	switch strings.TrimSpace(key) {
	case "sequence_type",
		"workload_ref",
		"detail",
		"severity",
		"observation_count",
		"sequence_start",
		"sequence_end",
		"window_seconds",
		"observation_types",
		"ordered_observation_ids",
		"mitre_attack",
		"source_system",
		"source_event_id",
		"observed_at",
		"valid_from",
		"valid_to",
		"recorded_at",
		"transaction_from",
		"confidence":
		return true
	default:
		return false
	}
}

func attackSequencePropertyValue(props AttackSequenceProperties, key string) (any, bool) {
	switch strings.TrimSpace(key) {
	case "sequence_type":
		if props.present&attackSequencePropertySequenceType != 0 {
			return props.SequenceType, true
		}
	case "workload_ref":
		if props.present&attackSequencePropertyWorkloadRef != 0 {
			return props.WorkloadRef, true
		}
	case "detail":
		if props.present&attackSequencePropertyDetail != 0 {
			return props.Detail, true
		}
	case "severity":
		if props.present&attackSequencePropertySeverity != 0 {
			return props.Severity, true
		}
	case "observation_count":
		if props.present&attackSequencePropertyObservationCount != 0 {
			return props.ObservationCount, true
		}
	case "sequence_start":
		if props.present&attackSequencePropertySequenceStart != 0 {
			return props.SequenceStart.UTC().Format(time.RFC3339), true
		}
	case "sequence_end":
		if props.present&attackSequencePropertySequenceEnd != 0 {
			return props.SequenceEnd.UTC().Format(time.RFC3339), true
		}
	case "window_seconds":
		if props.present&attackSequencePropertyWindowSeconds != 0 {
			return props.WindowSeconds, true
		}
	case "observation_types":
		if props.present&attackSequencePropertyObservationTypes != 0 {
			return append([]string(nil), props.ObservationTypes...), true
		}
	case "ordered_observation_ids":
		if props.present&attackSequencePropertyOrderedObservationIDs != 0 {
			return append([]string(nil), props.OrderedObservationIDs...), true
		}
	case "mitre_attack":
		if props.present&attackSequencePropertyMITREAttack != 0 {
			return append([]string(nil), props.MITREAttack...), true
		}
	case "source_system":
		if props.present&attackSequencePropertySourceSystem != 0 {
			return props.SourceSystem, true
		}
	case "source_event_id":
		if props.present&attackSequencePropertySourceEventID != 0 {
			return props.SourceEventID, true
		}
	case "observed_at":
		if props.present&attackSequencePropertyObservedAt != 0 {
			return props.ObservedAt.UTC().Format(time.RFC3339), true
		}
	case "valid_from":
		if props.present&attackSequencePropertyValidFrom != 0 {
			return props.ValidFrom.UTC().Format(time.RFC3339), true
		}
	case "valid_to":
		if props.present&attackSequencePropertyValidTo != 0 && props.ValidTo != nil {
			return props.ValidTo.UTC().Format(time.RFC3339), true
		}
	case "recorded_at":
		if props.present&attackSequencePropertyRecordedAt != 0 {
			return props.RecordedAt.UTC().Format(time.RFC3339), true
		}
	case "transaction_from":
		if props.present&attackSequencePropertyTransactionFrom != 0 {
			return props.TransactionFrom.UTC().Format(time.RFC3339), true
		}
	case "confidence":
		if props.present&attackSequencePropertyConfidence != 0 {
			return props.Confidence, true
		}
	}
	return nil, false
}

func setAttackSequencePropertyValue(node *Node, key string, value any) bool {
	if node == nil || node.Kind != NodeKindAttackSequence {
		return false
	}
	props, _ := node.AttackSequenceProperties()
	key = strings.TrimSpace(key)
	switch key {
	case "sequence_type":
		if value == nil {
			props.SequenceType = ""
			props.present &^= attackSequencePropertySequenceType
		} else {
			props.SequenceType = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertySequenceType
		}
	case "workload_ref":
		if value == nil {
			props.WorkloadRef = ""
			props.present &^= attackSequencePropertyWorkloadRef
		} else {
			props.WorkloadRef = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertyWorkloadRef
		}
	case "detail":
		if value == nil {
			props.Detail = ""
			props.present &^= attackSequencePropertyDetail
		} else {
			props.Detail = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertyDetail
		}
	case "severity":
		if value == nil {
			props.Severity = ""
			props.present &^= attackSequencePropertySeverity
		} else {
			props.Severity = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertySeverity
		}
	case "observation_count":
		if value == nil {
			props.ObservationCount = 0
			props.present &^= attackSequencePropertyObservationCount
		} else if count, ok := attackSequenceIntValue(value); ok {
			props.ObservationCount = count
			props.present |= attackSequencePropertyObservationCount
		} else {
			return false
		}
	case "sequence_start":
		if value == nil {
			props.SequenceStart = time.Time{}
			props.present &^= attackSequencePropertySequenceStart
		} else if ts, ok := temporalValueTime(value); ok {
			props.SequenceStart = ts
			props.present |= attackSequencePropertySequenceStart
		} else {
			return false
		}
	case "sequence_end":
		if value == nil {
			props.SequenceEnd = time.Time{}
			props.present &^= attackSequencePropertySequenceEnd
		} else if ts, ok := temporalValueTime(value); ok {
			props.SequenceEnd = ts
			props.present |= attackSequencePropertySequenceEnd
		} else {
			return false
		}
	case "window_seconds":
		if value == nil {
			props.WindowSeconds = 0
			props.present &^= attackSequencePropertyWindowSeconds
		} else if seconds, ok := attackSequenceInt64Value(value); ok {
			props.WindowSeconds = seconds
			props.present |= attackSequencePropertyWindowSeconds
		} else {
			return false
		}
	case "observation_types":
		if value == nil {
			props.ObservationTypes = nil
			props.present &^= attackSequencePropertyObservationTypes
		} else {
			props.ObservationTypes = normalizedStringSlice(value)
			if len(props.ObservationTypes) == 0 {
				props.present &^= attackSequencePropertyObservationTypes
			} else {
				props.present |= attackSequencePropertyObservationTypes
			}
		}
	case "ordered_observation_ids":
		if value == nil {
			props.OrderedObservationIDs = nil
			props.present &^= attackSequencePropertyOrderedObservationIDs
		} else {
			props.OrderedObservationIDs = normalizedStringSlice(value)
			if len(props.OrderedObservationIDs) == 0 {
				props.present &^= attackSequencePropertyOrderedObservationIDs
			} else {
				props.present |= attackSequencePropertyOrderedObservationIDs
			}
		}
	case "mitre_attack":
		if value == nil {
			props.MITREAttack = nil
			props.present &^= attackSequencePropertyMITREAttack
		} else {
			props.MITREAttack = normalizedStringSlice(value)
			if len(props.MITREAttack) == 0 {
				props.present &^= attackSequencePropertyMITREAttack
			} else {
				props.present |= attackSequencePropertyMITREAttack
			}
		}
	case "source_system":
		if value == nil {
			props.SourceSystem = ""
			props.present &^= attackSequencePropertySourceSystem
		} else {
			props.SourceSystem = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertySourceSystem
		}
	case "source_event_id":
		if value == nil {
			props.SourceEventID = ""
			props.present &^= attackSequencePropertySourceEventID
		} else {
			props.SourceEventID = strings.TrimSpace(observationStringValue(value))
			props.present |= attackSequencePropertySourceEventID
		}
	case "observed_at":
		if value == nil {
			props.ObservedAt = time.Time{}
			props.present &^= attackSequencePropertyObservedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.ObservedAt = ts
			props.present |= attackSequencePropertyObservedAt
		} else {
			return false
		}
	case "valid_from":
		if value == nil {
			props.ValidFrom = time.Time{}
			props.present &^= attackSequencePropertyValidFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidFrom = ts
			props.present |= attackSequencePropertyValidFrom
		} else {
			return false
		}
	case "valid_to":
		if value == nil {
			props.ValidTo = nil
			props.present &^= attackSequencePropertyValidTo
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidTo = &ts
			props.present |= attackSequencePropertyValidTo
		} else {
			return false
		}
	case "recorded_at":
		if value == nil {
			props.RecordedAt = time.Time{}
			props.present &^= attackSequencePropertyRecordedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.RecordedAt = ts
			props.present |= attackSequencePropertyRecordedAt
		} else {
			return false
		}
	case "transaction_from":
		if value == nil {
			props.TransactionFrom = time.Time{}
			props.present &^= attackSequencePropertyTransactionFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.TransactionFrom = ts
			props.present |= attackSequencePropertyTransactionFrom
		} else {
			return false
		}
	case "confidence":
		if value == nil {
			props.Confidence = 0
			props.present &^= attackSequencePropertyConfidence
		} else if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= attackSequencePropertyConfidence
		} else {
			return false
		}
	default:
		return false
	}
	applyAttackSequencePropertiesToNode(node, props)
	return true
}

func applyAttackSequencePropertiesToNode(node *Node, props AttackSequenceProperties) {
	if node == nil {
		return
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		node.propertyColumns.ClearAttackSequenceProperties(node.ordinal)
		if props.present != 0 {
			node.propertyColumns.SetAttackSequenceProperties(node.ordinal, props)
		}
		node.attackSequenceProps = nil
	} else {
		if props.present == 0 {
			node.attackSequenceProps = nil
		} else {
			node.attackSequenceProps = ptrAttackSequenceProperties(props)
		}
	}
	if node.Properties != nil {
		stripAttackSequencePropertyKeys(node.Properties)
		if len(node.Properties) == 0 {
			node.Properties = nil
		}
	}
}

func attackSequenceIntValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func attackSequenceInt64Value(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case float32:
		return int64(typed), true
	case float64:
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func normalizedStringSlice(value any) []string {
	items := stringSliceFromValue(value)
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func valueOrNil(properties map[string]any, key string) any {
	if properties == nil {
		return nil
	}
	return properties[key]
}
