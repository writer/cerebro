package graph

import (
	"strings"
	"time"
)

const (
	metadataPropertyKeySourceSystem    = "source_system"
	metadataPropertyKeySourceEventID   = "source_event_id"
	metadataPropertyKeyConfidence      = "confidence"
	metadataPropertyKeyObservedAt      = "observed_at"
	metadataPropertyKeyValidFrom       = "valid_from"
	metadataPropertyKeyValidTo         = "valid_to"
	metadataPropertyKeyRecordedAt      = "recorded_at"
	metadataPropertyKeyTransactionFrom = "transaction_from"
	metadataPropertyKeyTransactionTo   = "transaction_to"
)

type metadataPropertyPresence uint16

const (
	metadataPropertySourceSystem metadataPropertyPresence = 1 << iota
	metadataPropertySourceEventID
	metadataPropertyConfidence
	metadataPropertyObservedAt
	metadataPropertyValidFrom
	metadataPropertyValidTo
	metadataPropertyRecordedAt
	metadataPropertyTransactionFrom
	metadataPropertyTransactionTo
)

// NodeMetadataProperties captures common temporal/provenance metadata that is
// shared across many node kinds and promoted out of per-node property maps.
type NodeMetadataProperties struct {
	SourceSystem    string
	SourceEventID   string
	Confidence      float64
	ObservedAt      time.Time
	ValidFrom       time.Time
	ValidTo         *time.Time
	RecordedAt      time.Time
	TransactionFrom time.Time
	TransactionTo   *time.Time
	present         metadataPropertyPresence
}

// MetadataProperties returns the typed metadata view for this node. Observation
// and attack-sequence nodes derive their shared metadata from their specialized
// typed property sets so callers can use one accessor across node kinds.
func (n *Node) MetadataProperties() (NodeMetadataProperties, bool) {
	if n == nil {
		return NodeMetadataProperties{}, false
	}
	if props, ok := metadataPropertiesFromSpecializedNode(n); ok {
		return props, true
	}
	if n.propertyColumns != nil && n.ordinal != InvalidNodeOrdinal {
		if props, ok := n.propertyColumns.MetadataProperties(n.ordinal); ok {
			return props, true
		}
	}
	if n.metadataProps != nil {
		return cloneNodeMetadataProperties(*n.metadataProps), true
	}
	return nodeMetadataPropertiesFromMap(n.Properties)
}

func metadataPropertiesFromSpecializedNode(node *Node) (NodeMetadataProperties, bool) {
	if node == nil {
		return NodeMetadataProperties{}, false
	}
	if props, ok := node.ObservationProperties(); ok {
		var metadata NodeMetadataProperties
		if props.present&observationPropertySourceSystem != 0 {
			metadata.SourceSystem = props.SourceSystem
			metadata.present |= metadataPropertySourceSystem
		}
		if props.present&observationPropertySourceEventID != 0 {
			metadata.SourceEventID = props.SourceEventID
			metadata.present |= metadataPropertySourceEventID
		}
		if props.present&observationPropertyConfidence != 0 {
			metadata.Confidence = props.Confidence
			metadata.present |= metadataPropertyConfidence
		}
		if props.present&observationPropertyObservedAt != 0 {
			metadata.ObservedAt = props.ObservedAt
			metadata.present |= metadataPropertyObservedAt
		}
		if props.present&observationPropertyValidFrom != 0 {
			metadata.ValidFrom = props.ValidFrom
			metadata.present |= metadataPropertyValidFrom
		}
		if props.present&observationPropertyValidTo != 0 && props.ValidTo != nil {
			validTo := props.ValidTo.UTC()
			metadata.ValidTo = &validTo
			metadata.present |= metadataPropertyValidTo
		}
		if props.present&observationPropertyRecordedAt != 0 {
			metadata.RecordedAt = props.RecordedAt
			metadata.present |= metadataPropertyRecordedAt
		}
		if props.present&observationPropertyTransactionFrom != 0 {
			metadata.TransactionFrom = props.TransactionFrom
			metadata.present |= metadataPropertyTransactionFrom
		}
		if props.present&observationPropertyTransactionTo != 0 && props.TransactionTo != nil {
			transactionTo := props.TransactionTo.UTC()
			metadata.TransactionTo = &transactionTo
			metadata.present |= metadataPropertyTransactionTo
		}
		if metadata.present != 0 {
			return metadata, true
		}
	}
	if props, ok := node.AttackSequenceProperties(); ok {
		var metadata NodeMetadataProperties
		if props.present&attackSequencePropertySourceSystem != 0 {
			metadata.SourceSystem = props.SourceSystem
			metadata.present |= metadataPropertySourceSystem
		}
		if props.present&attackSequencePropertySourceEventID != 0 {
			metadata.SourceEventID = props.SourceEventID
			metadata.present |= metadataPropertySourceEventID
		}
		if props.present&attackSequencePropertyConfidence != 0 {
			metadata.Confidence = props.Confidence
			metadata.present |= metadataPropertyConfidence
		}
		if props.present&attackSequencePropertyObservedAt != 0 {
			metadata.ObservedAt = props.ObservedAt
			metadata.present |= metadataPropertyObservedAt
		}
		if props.present&attackSequencePropertyValidFrom != 0 {
			metadata.ValidFrom = props.ValidFrom
			metadata.present |= metadataPropertyValidFrom
		}
		if props.present&attackSequencePropertyValidTo != 0 && props.ValidTo != nil {
			validTo := props.ValidTo.UTC()
			metadata.ValidTo = &validTo
			metadata.present |= metadataPropertyValidTo
		}
		if props.present&attackSequencePropertyRecordedAt != 0 {
			metadata.RecordedAt = props.RecordedAt
			metadata.present |= metadataPropertyRecordedAt
		}
		if props.present&attackSequencePropertyTransactionFrom != 0 {
			metadata.TransactionFrom = props.TransactionFrom
			metadata.present |= metadataPropertyTransactionFrom
		}
		if metadata.present != 0 {
			return metadata, true
		}
	}
	return NodeMetadataProperties{}, false
}

func cloneNodeMetadataProperties(props NodeMetadataProperties) NodeMetadataProperties {
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

func ptrNodeMetadataProperties(props NodeMetadataProperties) *NodeMetadataProperties {
	cloned := cloneNodeMetadataProperties(props)
	return &cloned
}

func nodeMetadataPropertiesFromMap(properties map[string]any) (NodeMetadataProperties, bool) {
	if len(properties) == 0 {
		return NodeMetadataProperties{}, false
	}
	var props NodeMetadataProperties
	if value, ok := properties[metadataPropertyKeySourceSystem]; ok && value != nil {
		props.SourceSystem = strings.TrimSpace(observationStringValue(value))
		props.present |= metadataPropertySourceSystem
	}
	if value, ok := properties[metadataPropertyKeySourceEventID]; ok && value != nil {
		props.SourceEventID = strings.TrimSpace(observationStringValue(value))
		props.present |= metadataPropertySourceEventID
	}
	if value, ok := properties[metadataPropertyKeyConfidence]; ok && value != nil {
		if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= metadataPropertyConfidence
		}
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyObservedAt); ok {
		props.ObservedAt = ts
		props.present |= metadataPropertyObservedAt
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyValidFrom); ok {
		props.ValidFrom = ts
		props.present |= metadataPropertyValidFrom
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyValidTo); ok {
		props.ValidTo = &ts
		props.present |= metadataPropertyValidTo
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyRecordedAt); ok {
		props.RecordedAt = ts
		props.present |= metadataPropertyRecordedAt
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyTransactionFrom); ok {
		props.TransactionFrom = ts
		props.present |= metadataPropertyTransactionFrom
	}
	if ts, ok := temporalPropertyTime(properties, metadataPropertyKeyTransactionTo); ok {
		props.TransactionTo = &ts
		props.present |= metadataPropertyTransactionTo
	}
	if props.present == 0 {
		return NodeMetadataProperties{}, false
	}
	return props, true
}

func materializeNodeMetadataProperties(dst map[string]any, props NodeMetadataProperties) {
	if dst == nil {
		return
	}
	if props.present&metadataPropertySourceSystem != 0 {
		dst[metadataPropertyKeySourceSystem] = props.SourceSystem
	}
	if props.present&metadataPropertySourceEventID != 0 {
		dst[metadataPropertyKeySourceEventID] = props.SourceEventID
	}
	if props.present&metadataPropertyConfidence != 0 {
		dst[metadataPropertyKeyConfidence] = props.Confidence
	}
	if props.present&metadataPropertyObservedAt != 0 {
		dst[metadataPropertyKeyObservedAt] = props.ObservedAt.UTC().Format(time.RFC3339)
	}
	if props.present&metadataPropertyValidFrom != 0 {
		dst[metadataPropertyKeyValidFrom] = props.ValidFrom.UTC().Format(time.RFC3339)
	}
	if props.present&metadataPropertyValidTo != 0 && props.ValidTo != nil {
		dst[metadataPropertyKeyValidTo] = props.ValidTo.UTC().Format(time.RFC3339)
	}
	if props.present&metadataPropertyRecordedAt != 0 {
		dst[metadataPropertyKeyRecordedAt] = props.RecordedAt.UTC().Format(time.RFC3339)
	}
	if props.present&metadataPropertyTransactionFrom != 0 {
		dst[metadataPropertyKeyTransactionFrom] = props.TransactionFrom.UTC().Format(time.RFC3339)
	}
	if props.present&metadataPropertyTransactionTo != 0 && props.TransactionTo != nil {
		dst[metadataPropertyKeyTransactionTo] = props.TransactionTo.UTC().Format(time.RFC3339)
	}
}

func stripPromotedMetadataPropertyKeys(properties map[string]any, props NodeMetadataProperties) {
	if len(properties) == 0 || props.present == 0 {
		return
	}
	if props.present&metadataPropertySourceSystem != 0 {
		delete(properties, metadataPropertyKeySourceSystem)
	}
	if props.present&metadataPropertySourceEventID != 0 {
		delete(properties, metadataPropertyKeySourceEventID)
	}
	if props.present&metadataPropertyConfidence != 0 {
		delete(properties, metadataPropertyKeyConfidence)
	}
	if props.present&metadataPropertyObservedAt != 0 {
		delete(properties, metadataPropertyKeyObservedAt)
	}
	if props.present&metadataPropertyValidFrom != 0 {
		delete(properties, metadataPropertyKeyValidFrom)
	}
	if props.present&metadataPropertyValidTo != 0 {
		delete(properties, metadataPropertyKeyValidTo)
	}
	if props.present&metadataPropertyRecordedAt != 0 {
		delete(properties, metadataPropertyKeyRecordedAt)
	}
	if props.present&metadataPropertyTransactionFrom != 0 {
		delete(properties, metadataPropertyKeyTransactionFrom)
	}
	if props.present&metadataPropertyTransactionTo != 0 {
		delete(properties, metadataPropertyKeyTransactionTo)
	}
}

func metadataPropertyValue(props NodeMetadataProperties, key string) (any, bool) {
	switch strings.TrimSpace(key) {
	case metadataPropertyKeySourceSystem:
		if props.present&metadataPropertySourceSystem != 0 {
			return props.SourceSystem, true
		}
	case metadataPropertyKeySourceEventID:
		if props.present&metadataPropertySourceEventID != 0 {
			return props.SourceEventID, true
		}
	case metadataPropertyKeyConfidence:
		if props.present&metadataPropertyConfidence != 0 {
			return props.Confidence, true
		}
	case metadataPropertyKeyObservedAt:
		if props.present&metadataPropertyObservedAt != 0 {
			return props.ObservedAt.UTC().Format(time.RFC3339), true
		}
	case metadataPropertyKeyValidFrom:
		if props.present&metadataPropertyValidFrom != 0 {
			return props.ValidFrom.UTC().Format(time.RFC3339), true
		}
	case metadataPropertyKeyValidTo:
		if props.present&metadataPropertyValidTo != 0 && props.ValidTo != nil {
			return props.ValidTo.UTC().Format(time.RFC3339), true
		}
	case metadataPropertyKeyRecordedAt:
		if props.present&metadataPropertyRecordedAt != 0 {
			return props.RecordedAt.UTC().Format(time.RFC3339), true
		}
	case metadataPropertyKeyTransactionFrom:
		if props.present&metadataPropertyTransactionFrom != 0 {
			return props.TransactionFrom.UTC().Format(time.RFC3339), true
		}
	case metadataPropertyKeyTransactionTo:
		if props.present&metadataPropertyTransactionTo != 0 && props.TransactionTo != nil {
			return props.TransactionTo.UTC().Format(time.RFC3339), true
		}
	}
	return nil, false
}

func metadataPropertyTime(props NodeMetadataProperties, key string) (time.Time, bool) {
	switch strings.TrimSpace(key) {
	case metadataPropertyKeyObservedAt:
		if props.present&metadataPropertyObservedAt != 0 {
			return props.ObservedAt.UTC(), true
		}
	case metadataPropertyKeyValidFrom:
		if props.present&metadataPropertyValidFrom != 0 {
			return props.ValidFrom.UTC(), true
		}
	case metadataPropertyKeyValidTo:
		if props.present&metadataPropertyValidTo != 0 && props.ValidTo != nil {
			return props.ValidTo.UTC(), true
		}
	case metadataPropertyKeyRecordedAt:
		if props.present&metadataPropertyRecordedAt != 0 {
			return props.RecordedAt.UTC(), true
		}
	case metadataPropertyKeyTransactionFrom:
		if props.present&metadataPropertyTransactionFrom != 0 {
			return props.TransactionFrom.UTC(), true
		}
	case metadataPropertyKeyTransactionTo:
		if props.present&metadataPropertyTransactionTo != 0 && props.TransactionTo != nil {
			return props.TransactionTo.UTC(), true
		}
	}
	return time.Time{}, false
}

func setNodeMetadataPropertyValue(node *Node, key string, value any) bool {
	if node == nil || node.Kind == NodeKindObservation || node.Kind == NodeKindAttackSequence {
		return false
	}
	props, _ := node.MetadataProperties()
	switch strings.TrimSpace(key) {
	case metadataPropertyKeySourceSystem:
		if value == nil {
			props.SourceSystem = ""
			props.present &^= metadataPropertySourceSystem
		} else {
			props.SourceSystem = strings.TrimSpace(observationStringValue(value))
			props.present |= metadataPropertySourceSystem
		}
	case metadataPropertyKeySourceEventID:
		if value == nil {
			props.SourceEventID = ""
			props.present &^= metadataPropertySourceEventID
		} else {
			props.SourceEventID = strings.TrimSpace(observationStringValue(value))
			props.present |= metadataPropertySourceEventID
		}
	case metadataPropertyKeyConfidence:
		if value == nil {
			props.Confidence = 0
			props.present &^= metadataPropertyConfidence
		} else if confidence, ok := observationFloatValue(value); ok {
			props.Confidence = confidence
			props.present |= metadataPropertyConfidence
		} else {
			return false
		}
	case metadataPropertyKeyObservedAt:
		if value == nil {
			props.ObservedAt = time.Time{}
			props.present &^= metadataPropertyObservedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.ObservedAt = ts
			props.present |= metadataPropertyObservedAt
		} else {
			return false
		}
	case metadataPropertyKeyValidFrom:
		if value == nil {
			props.ValidFrom = time.Time{}
			props.present &^= metadataPropertyValidFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidFrom = ts
			props.present |= metadataPropertyValidFrom
		} else {
			return false
		}
	case metadataPropertyKeyValidTo:
		if value == nil {
			props.ValidTo = nil
			props.present &^= metadataPropertyValidTo
		} else if ts, ok := temporalValueTime(value); ok {
			props.ValidTo = &ts
			props.present |= metadataPropertyValidTo
		} else {
			return false
		}
	case metadataPropertyKeyRecordedAt:
		if value == nil {
			props.RecordedAt = time.Time{}
			props.present &^= metadataPropertyRecordedAt
		} else if ts, ok := temporalValueTime(value); ok {
			props.RecordedAt = ts
			props.present |= metadataPropertyRecordedAt
		} else {
			return false
		}
	case metadataPropertyKeyTransactionFrom:
		if value == nil {
			props.TransactionFrom = time.Time{}
			props.present &^= metadataPropertyTransactionFrom
		} else if ts, ok := temporalValueTime(value); ok {
			props.TransactionFrom = ts
			props.present |= metadataPropertyTransactionFrom
		} else {
			return false
		}
	case metadataPropertyKeyTransactionTo:
		if value == nil {
			props.TransactionTo = nil
			props.present &^= metadataPropertyTransactionTo
		} else if ts, ok := temporalValueTime(value); ok {
			props.TransactionTo = &ts
			props.present |= metadataPropertyTransactionTo
		} else {
			return false
		}
	default:
		return false
	}
	applyNodeMetadataPropertiesToNode(node, props)
	return true
}

func applyNodeMetadataPropertiesToNode(node *Node, props NodeMetadataProperties) {
	if node == nil {
		return
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		node.propertyColumns.ClearMetadataProperties(node.ordinal)
		if props.present != 0 {
			node.propertyColumns.SetMetadataProperties(node.ordinal, props)
		}
		node.metadataProps = nil
	} else {
		if props.present == 0 {
			node.metadataProps = nil
		} else {
			node.metadataProps = ptrNodeMetadataProperties(props)
		}
	}
	if node.Properties != nil {
		stripPromotedMetadataPropertyKeys(node.Properties, props)
		if len(node.Properties) == 0 {
			node.Properties = nil
		}
	}
}

func bindableNodeMetadataProperties(node *Node) (NodeMetadataProperties, bool) {
	if node == nil || node.Kind == NodeKindObservation || node.Kind == NodeKindAttackSequence {
		return NodeMetadataProperties{}, false
	}
	if node.metadataProps != nil {
		return cloneNodeMetadataProperties(*node.metadataProps), true
	}
	if props, ok := nodeMetadataPropertiesFromMap(node.Properties); ok {
		return props, true
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		if props, ok := node.propertyColumns.MetadataProperties(node.ordinal); ok {
			return props, true
		}
	}
	return NodeMetadataProperties{}, false
}

func nodePropertyFloat(node *Node, keys ...string) float64 {
	if node == nil {
		return 0
	}
	for _, key := range keys {
		if value, ok := node.PropertyValue(key); ok {
			if number, ok := observationFloatValue(value); ok {
				return number
			}
		}
	}
	return 0
}
