package graph

import "time"

const (
	observationPropertyKeyObservationType = "observation_type"
	observationPropertyKeySubjectID       = "subject_id"
	observationPropertyKeyDetail          = "detail"
	observationPropertyKeySourceSystem    = "source_system"
	observationPropertyKeySourceEventID   = "source_event_id"
	observationPropertyKeyConfidence      = "confidence"
	observationPropertyKeyObservedAt      = "observed_at"
	observationPropertyKeyValidFrom       = "valid_from"
	observationPropertyKeyValidTo         = "valid_to"
	observationPropertyKeyRecordedAt      = "recorded_at"
	observationPropertyKeyTransactionFrom = "transaction_from"
	observationPropertyKeyTransactionTo   = "transaction_to"
)

const (
	attackSequencePropertyKeySequenceType          = "sequence_type"
	attackSequencePropertyKeyWorkloadRef           = "workload_ref"
	attackSequencePropertyKeyDetail                = "detail"
	attackSequencePropertyKeySeverity              = "severity"
	attackSequencePropertyKeyObservationCount      = "observation_count"
	attackSequencePropertyKeySequenceStart         = "sequence_start"
	attackSequencePropertyKeySequenceEnd           = "sequence_end"
	attackSequencePropertyKeyWindowSeconds         = "window_seconds"
	attackSequencePropertyKeyObservationTypes      = "observation_types"
	attackSequencePropertyKeyOrderedObservationIDs = "ordered_observation_ids"
	attackSequencePropertyKeyMITREAttack           = "mitre_attack"
	attackSequencePropertyKeySourceSystem          = "source_system"
	attackSequencePropertyKeySourceEventID         = "source_event_id"
	attackSequencePropertyKeyObservedAt            = "observed_at"
	attackSequencePropertyKeyValidFrom             = "valid_from"
	attackSequencePropertyKeyValidTo               = "valid_to"
	attackSequencePropertyKeyRecordedAt            = "recorded_at"
	attackSequencePropertyKeyTransactionFrom       = "transaction_from"
	attackSequencePropertyKeyConfidence            = "confidence"
)

// PropertyColumns keeps promoted observation and attack-sequence properties in
// graph-owned typed columns keyed by node ordinal.
type PropertyColumns struct {
	observations    *ColumnStore
	attackSequences *ColumnStore
}

func NewPropertyColumns() *PropertyColumns {
	return &PropertyColumns{
		observations:    NewColumnStore(),
		attackSequences: NewColumnStore(),
	}
}

func (c *PropertyColumns) Clone() *PropertyColumns {
	if c == nil {
		return nil
	}
	return &PropertyColumns{
		observations:    c.observations.Clone(),
		attackSequences: c.attackSequences.Clone(),
	}
}

func (c *PropertyColumns) ClearOrdinal(ordinal NodeOrdinal) {
	if c == nil {
		return
	}
	c.ClearObservationProperties(ordinal)
	c.ClearAttackSequenceProperties(ordinal)
}

func (c *PropertyColumns) ObservationProperties(ordinal NodeOrdinal) (ObservationProperties, bool) {
	if c == nil || c.observations == nil || ordinal == InvalidNodeOrdinal {
		return ObservationProperties{}, false
	}
	var props ObservationProperties
	if value, ok := c.observations.String(observationPropertyKeyObservationType, ordinal); ok {
		props.ObservationType = value
		props.present |= observationPropertyObservationType
	}
	if value, ok := c.observations.String(observationPropertyKeySubjectID, ordinal); ok {
		props.SubjectID = value
		props.present |= observationPropertySubjectID
	}
	if value, ok := c.observations.String(observationPropertyKeyDetail, ordinal); ok {
		props.Detail = value
		props.present |= observationPropertyDetail
	}
	if value, ok := c.observations.String(observationPropertyKeySourceSystem, ordinal); ok {
		props.SourceSystem = value
		props.present |= observationPropertySourceSystem
	}
	if value, ok := c.observations.String(observationPropertyKeySourceEventID, ordinal); ok {
		props.SourceEventID = value
		props.present |= observationPropertySourceEventID
	}
	if value, ok := c.observations.Float64(observationPropertyKeyConfidence, ordinal); ok {
		props.Confidence = value
		props.present |= observationPropertyConfidence
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyObservedAt, ordinal); ok {
		props.ObservedAt = ts
		props.present |= observationPropertyObservedAt
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyValidFrom, ordinal); ok {
		props.ValidFrom = ts
		props.present |= observationPropertyValidFrom
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyValidTo, ordinal); ok {
		props.ValidTo = &ts
		props.present |= observationPropertyValidTo
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyRecordedAt, ordinal); ok {
		props.RecordedAt = ts
		props.present |= observationPropertyRecordedAt
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyTransactionFrom, ordinal); ok {
		props.TransactionFrom = ts
		props.present |= observationPropertyTransactionFrom
	}
	if ts, ok := propertyColumnTime(c.observations, observationPropertyKeyTransactionTo, ordinal); ok {
		props.TransactionTo = &ts
		props.present |= observationPropertyTransactionTo
	}
	if props.present == 0 {
		return ObservationProperties{}, false
	}
	return props, true
}

func (c *PropertyColumns) SetObservationProperties(ordinal NodeOrdinal, props ObservationProperties) {
	if c == nil || c.observations == nil || ordinal == InvalidNodeOrdinal {
		return
	}
	c.ClearObservationProperties(ordinal)
	if props.present == 0 {
		return
	}
	if props.present&observationPropertyObservationType != 0 {
		c.observations.SetString(observationPropertyKeyObservationType, ordinal, props.ObservationType)
	}
	if props.present&observationPropertySubjectID != 0 {
		c.observations.SetString(observationPropertyKeySubjectID, ordinal, props.SubjectID)
	}
	if props.present&observationPropertyDetail != 0 {
		c.observations.SetString(observationPropertyKeyDetail, ordinal, props.Detail)
	}
	if props.present&observationPropertySourceSystem != 0 {
		c.observations.SetString(observationPropertyKeySourceSystem, ordinal, props.SourceSystem)
	}
	if props.present&observationPropertySourceEventID != 0 {
		c.observations.SetString(observationPropertyKeySourceEventID, ordinal, props.SourceEventID)
	}
	if props.present&observationPropertyConfidence != 0 {
		c.observations.SetFloat64(observationPropertyKeyConfidence, ordinal, props.Confidence)
	}
	if props.present&observationPropertyObservedAt != 0 {
		setPropertyColumnTime(c.observations, observationPropertyKeyObservedAt, ordinal, props.ObservedAt)
	}
	if props.present&observationPropertyValidFrom != 0 {
		setPropertyColumnTime(c.observations, observationPropertyKeyValidFrom, ordinal, props.ValidFrom)
	}
	if props.present&observationPropertyValidTo != 0 && props.ValidTo != nil {
		setPropertyColumnTime(c.observations, observationPropertyKeyValidTo, ordinal, *props.ValidTo)
	}
	if props.present&observationPropertyRecordedAt != 0 {
		setPropertyColumnTime(c.observations, observationPropertyKeyRecordedAt, ordinal, props.RecordedAt)
	}
	if props.present&observationPropertyTransactionFrom != 0 {
		setPropertyColumnTime(c.observations, observationPropertyKeyTransactionFrom, ordinal, props.TransactionFrom)
	}
	if props.present&observationPropertyTransactionTo != 0 && props.TransactionTo != nil {
		setPropertyColumnTime(c.observations, observationPropertyKeyTransactionTo, ordinal, *props.TransactionTo)
	}
}

func (c *PropertyColumns) ClearObservationProperties(ordinal NodeOrdinal) {
	if c == nil || c.observations == nil {
		return
	}
	c.observations.ClearString(observationPropertyKeyObservationType, ordinal)
	c.observations.ClearString(observationPropertyKeySubjectID, ordinal)
	c.observations.ClearString(observationPropertyKeyDetail, ordinal)
	c.observations.ClearString(observationPropertyKeySourceSystem, ordinal)
	c.observations.ClearString(observationPropertyKeySourceEventID, ordinal)
	c.observations.ClearFloat64(observationPropertyKeyConfidence, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyObservedAt, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyValidFrom, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyValidTo, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyRecordedAt, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyTransactionFrom, ordinal)
	clearPropertyColumnTime(c.observations, observationPropertyKeyTransactionTo, ordinal)
}

func (c *PropertyColumns) AttackSequenceProperties(ordinal NodeOrdinal) (AttackSequenceProperties, bool) {
	if c == nil || c.attackSequences == nil || ordinal == InvalidNodeOrdinal {
		return AttackSequenceProperties{}, false
	}
	var props AttackSequenceProperties
	if value, ok := c.attackSequences.String(attackSequencePropertyKeySequenceType, ordinal); ok {
		props.SequenceType = value
		props.present |= attackSequencePropertySequenceType
	}
	if value, ok := c.attackSequences.String(attackSequencePropertyKeyWorkloadRef, ordinal); ok {
		props.WorkloadRef = value
		props.present |= attackSequencePropertyWorkloadRef
	}
	if value, ok := c.attackSequences.String(attackSequencePropertyKeyDetail, ordinal); ok {
		props.Detail = value
		props.present |= attackSequencePropertyDetail
	}
	if value, ok := c.attackSequences.String(attackSequencePropertyKeySeverity, ordinal); ok {
		props.Severity = value
		props.present |= attackSequencePropertySeverity
	}
	if value, ok := c.attackSequences.Int64(attackSequencePropertyKeyObservationCount, ordinal); ok {
		props.ObservationCount = int(value)
		props.present |= attackSequencePropertyObservationCount
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceStart, ordinal); ok {
		props.SequenceStart = ts
		props.present |= attackSequencePropertySequenceStart
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceEnd, ordinal); ok {
		props.SequenceEnd = ts
		props.present |= attackSequencePropertySequenceEnd
	}
	if value, ok := c.attackSequences.Int64(attackSequencePropertyKeyWindowSeconds, ordinal); ok {
		props.WindowSeconds = value
		props.present |= attackSequencePropertyWindowSeconds
	}
	if value, ok := c.attackSequences.StringSlice(attackSequencePropertyKeyObservationTypes, ordinal); ok {
		props.ObservationTypes = value
		props.present |= attackSequencePropertyObservationTypes
	}
	if value, ok := c.attackSequences.StringSlice(attackSequencePropertyKeyOrderedObservationIDs, ordinal); ok {
		props.OrderedObservationIDs = value
		props.present |= attackSequencePropertyOrderedObservationIDs
	}
	if value, ok := c.attackSequences.StringSlice(attackSequencePropertyKeyMITREAttack, ordinal); ok {
		props.MITREAttack = value
		props.present |= attackSequencePropertyMITREAttack
	}
	if value, ok := c.attackSequences.String(attackSequencePropertyKeySourceSystem, ordinal); ok {
		props.SourceSystem = value
		props.present |= attackSequencePropertySourceSystem
	}
	if value, ok := c.attackSequences.String(attackSequencePropertyKeySourceEventID, ordinal); ok {
		props.SourceEventID = value
		props.present |= attackSequencePropertySourceEventID
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeyObservedAt, ordinal); ok {
		props.ObservedAt = ts
		props.present |= attackSequencePropertyObservedAt
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidFrom, ordinal); ok {
		props.ValidFrom = ts
		props.present |= attackSequencePropertyValidFrom
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidTo, ordinal); ok {
		props.ValidTo = &ts
		props.present |= attackSequencePropertyValidTo
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeyRecordedAt, ordinal); ok {
		props.RecordedAt = ts
		props.present |= attackSequencePropertyRecordedAt
	}
	if ts, ok := propertyColumnTime(c.attackSequences, attackSequencePropertyKeyTransactionFrom, ordinal); ok {
		props.TransactionFrom = ts
		props.present |= attackSequencePropertyTransactionFrom
	}
	if value, ok := c.attackSequences.Float64(attackSequencePropertyKeyConfidence, ordinal); ok {
		props.Confidence = value
		props.present |= attackSequencePropertyConfidence
	}
	if props.present == 0 {
		return AttackSequenceProperties{}, false
	}
	return props, true
}

func (c *PropertyColumns) SetAttackSequenceProperties(ordinal NodeOrdinal, props AttackSequenceProperties) {
	if c == nil || c.attackSequences == nil || ordinal == InvalidNodeOrdinal {
		return
	}
	c.ClearAttackSequenceProperties(ordinal)
	if props.present == 0 {
		return
	}
	if props.present&attackSequencePropertySequenceType != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeySequenceType, ordinal, props.SequenceType)
	}
	if props.present&attackSequencePropertyWorkloadRef != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeyWorkloadRef, ordinal, props.WorkloadRef)
	}
	if props.present&attackSequencePropertyDetail != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeyDetail, ordinal, props.Detail)
	}
	if props.present&attackSequencePropertySeverity != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeySeverity, ordinal, props.Severity)
	}
	if props.present&attackSequencePropertyObservationCount != 0 {
		c.attackSequences.SetInt64(attackSequencePropertyKeyObservationCount, ordinal, int64(props.ObservationCount))
	}
	if props.present&attackSequencePropertySequenceStart != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceStart, ordinal, props.SequenceStart)
	}
	if props.present&attackSequencePropertySequenceEnd != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceEnd, ordinal, props.SequenceEnd)
	}
	if props.present&attackSequencePropertyWindowSeconds != 0 {
		c.attackSequences.SetInt64(attackSequencePropertyKeyWindowSeconds, ordinal, props.WindowSeconds)
	}
	if props.present&attackSequencePropertyObservationTypes != 0 {
		c.attackSequences.SetStringSlice(attackSequencePropertyKeyObservationTypes, ordinal, props.ObservationTypes)
	}
	if props.present&attackSequencePropertyOrderedObservationIDs != 0 {
		c.attackSequences.SetStringSlice(attackSequencePropertyKeyOrderedObservationIDs, ordinal, props.OrderedObservationIDs)
	}
	if props.present&attackSequencePropertyMITREAttack != 0 {
		c.attackSequences.SetStringSlice(attackSequencePropertyKeyMITREAttack, ordinal, props.MITREAttack)
	}
	if props.present&attackSequencePropertySourceSystem != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeySourceSystem, ordinal, props.SourceSystem)
	}
	if props.present&attackSequencePropertySourceEventID != 0 {
		c.attackSequences.SetString(attackSequencePropertyKeySourceEventID, ordinal, props.SourceEventID)
	}
	if props.present&attackSequencePropertyObservedAt != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyObservedAt, ordinal, props.ObservedAt)
	}
	if props.present&attackSequencePropertyValidFrom != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidFrom, ordinal, props.ValidFrom)
	}
	if props.present&attackSequencePropertyValidTo != 0 && props.ValidTo != nil {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidTo, ordinal, *props.ValidTo)
	}
	if props.present&attackSequencePropertyRecordedAt != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyRecordedAt, ordinal, props.RecordedAt)
	}
	if props.present&attackSequencePropertyTransactionFrom != 0 {
		setPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyTransactionFrom, ordinal, props.TransactionFrom)
	}
	if props.present&attackSequencePropertyConfidence != 0 {
		c.attackSequences.SetFloat64(attackSequencePropertyKeyConfidence, ordinal, props.Confidence)
	}
}

func (c *PropertyColumns) ClearAttackSequenceProperties(ordinal NodeOrdinal) {
	if c == nil || c.attackSequences == nil {
		return
	}
	c.attackSequences.ClearString(attackSequencePropertyKeySequenceType, ordinal)
	c.attackSequences.ClearString(attackSequencePropertyKeyWorkloadRef, ordinal)
	c.attackSequences.ClearString(attackSequencePropertyKeyDetail, ordinal)
	c.attackSequences.ClearString(attackSequencePropertyKeySeverity, ordinal)
	c.attackSequences.ClearInt64(attackSequencePropertyKeyObservationCount, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceStart, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeySequenceEnd, ordinal)
	c.attackSequences.ClearInt64(attackSequencePropertyKeyWindowSeconds, ordinal)
	c.attackSequences.ClearStringSlice(attackSequencePropertyKeyObservationTypes, ordinal)
	c.attackSequences.ClearStringSlice(attackSequencePropertyKeyOrderedObservationIDs, ordinal)
	c.attackSequences.ClearStringSlice(attackSequencePropertyKeyMITREAttack, ordinal)
	c.attackSequences.ClearString(attackSequencePropertyKeySourceSystem, ordinal)
	c.attackSequences.ClearString(attackSequencePropertyKeySourceEventID, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyObservedAt, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidFrom, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyValidTo, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyRecordedAt, ordinal)
	clearPropertyColumnTime(c.attackSequences, attackSequencePropertyKeyTransactionFrom, ordinal)
	c.attackSequences.ClearFloat64(attackSequencePropertyKeyConfidence, ordinal)
}

func propertyColumnTime(store *ColumnStore, key string, ordinal NodeOrdinal) (time.Time, bool) {
	if store == nil {
		return time.Time{}, false
	}
	if zero, ok := store.Bool(propertyColumnZeroTimeKey(key), ordinal); ok && zero {
		return time.Time{}, true
	}
	value, ok := store.Int64(key, ordinal)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(0, value).UTC(), true
}

func setPropertyColumnTime(store *ColumnStore, key string, ordinal NodeOrdinal, value time.Time) {
	if store == nil {
		return
	}
	if value.IsZero() {
		store.ClearInt64(key, ordinal)
		store.SetBool(propertyColumnZeroTimeKey(key), ordinal, true)
		return
	}
	store.ClearBool(propertyColumnZeroTimeKey(key), ordinal)
	store.SetInt64(key, ordinal, value.UTC().UnixNano())
}

func clearPropertyColumnTime(store *ColumnStore, key string, ordinal NodeOrdinal) {
	if store == nil {
		return
	}
	store.ClearInt64(key, ordinal)
	store.ClearBool(propertyColumnZeroTimeKey(key), ordinal)
}

func propertyColumnZeroTimeKey(key string) string {
	return key + "__zero_time"
}

func (g *Graph) bindNodePropertyColumnsLocked(node *Node) {
	if g == nil || node == nil {
		return
	}
	var (
		observationProps    ObservationProperties
		hasObservationProps bool
		attackSequenceProps AttackSequenceProperties
		hasAttackProps      bool
	)
	if node.Kind == NodeKindObservation {
		observationProps, hasObservationProps = bindableObservationProperties(node)
	}
	if node.Kind == NodeKindAttackSequence {
		attackSequenceProps, hasAttackProps = bindableAttackSequenceProperties(node)
	}

	node.propertyColumns = g.propertyColumns
	if g.propertyColumns == nil || node.ordinal == InvalidNodeOrdinal {
		if hasObservationProps {
			node.observationProps = ptrObservationProperties(observationProps)
		} else {
			node.observationProps = nil
		}
		if hasAttackProps {
			node.attackSequenceProps = ptrAttackSequenceProperties(attackSequenceProps)
		} else {
			node.attackSequenceProps = nil
		}
		return
	}

	g.propertyColumns.ClearOrdinal(node.ordinal)
	if hasObservationProps {
		g.propertyColumns.SetObservationProperties(node.ordinal, observationProps)
	}
	if hasAttackProps {
		g.propertyColumns.SetAttackSequenceProperties(node.ordinal, attackSequenceProps)
	}
	node.observationProps = nil
	node.attackSequenceProps = nil
}

func bindableObservationProperties(node *Node) (ObservationProperties, bool) {
	if node == nil || node.Kind != NodeKindObservation {
		return ObservationProperties{}, false
	}
	if node.observationProps != nil {
		return cloneObservationProperties(*node.observationProps), true
	}
	if props, ok := observationPropertiesFromMap(node.Properties); ok {
		return props, true
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		if props, ok := node.propertyColumns.ObservationProperties(node.ordinal); ok {
			return props, true
		}
	}
	return ObservationProperties{}, false
}

func bindableAttackSequenceProperties(node *Node) (AttackSequenceProperties, bool) {
	if node == nil || node.Kind != NodeKindAttackSequence {
		return AttackSequenceProperties{}, false
	}
	if node.attackSequenceProps != nil {
		return cloneAttackSequenceProperties(*node.attackSequenceProps), true
	}
	if props, ok := attackSequencePropertiesFromMap(node.Properties); ok {
		return props, true
	}
	if node.propertyColumns != nil && node.ordinal != InvalidNodeOrdinal {
		if props, ok := node.propertyColumns.AttackSequenceProperties(node.ordinal); ok {
			return props, true
		}
	}
	return AttackSequenceProperties{}, false
}
