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

// PropertyColumns keeps promoted metadata, common scalar, observation, and attack-sequence properties in
// graph-owned typed columns keyed by node ordinal.
type PropertyColumns struct {
	metadata        *ColumnStore
	common          *ColumnStore
	observations    *ColumnStore
	attackSequences *ColumnStore
}

func NewPropertyColumns() *PropertyColumns {
	return &PropertyColumns{
		metadata:        NewColumnStore(),
		common:          NewColumnStore(),
		observations:    NewColumnStore(),
		attackSequences: NewColumnStore(),
	}
}

func (c *PropertyColumns) Clone() *PropertyColumns {
	if c == nil {
		return nil
	}
	return &PropertyColumns{
		metadata:        c.metadata.Clone(),
		common:          c.common.Clone(),
		observations:    c.observations.Clone(),
		attackSequences: c.attackSequences.Clone(),
	}
}

func (c *PropertyColumns) ClearOrdinal(ordinal NodeOrdinal) {
	if c == nil {
		return
	}
	c.ClearMetadataProperties(ordinal)
	c.ClearCommonProperties(ordinal)
	c.ClearObservationProperties(ordinal)
	c.ClearAttackSequenceProperties(ordinal)
}

func (c *PropertyColumns) MetadataProperties(ordinal NodeOrdinal) (NodeMetadataProperties, bool) {
	if c == nil || c.metadata == nil || ordinal == InvalidNodeOrdinal {
		return NodeMetadataProperties{}, false
	}
	var props NodeMetadataProperties
	if value, ok := c.metadata.String(metadataPropertyKeySourceSystem, ordinal); ok {
		props.SourceSystem = value
		props.present |= metadataPropertySourceSystem
	}
	if value, ok := c.metadata.String(metadataPropertyKeySourceEventID, ordinal); ok {
		props.SourceEventID = value
		props.present |= metadataPropertySourceEventID
	}
	if value, ok := c.metadata.Float64(metadataPropertyKeyConfidence, ordinal); ok {
		props.Confidence = value
		props.present |= metadataPropertyConfidence
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyObservedAt, ordinal); ok {
		props.ObservedAt = ts
		props.present |= metadataPropertyObservedAt
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyValidFrom, ordinal); ok {
		props.ValidFrom = ts
		props.present |= metadataPropertyValidFrom
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyValidTo, ordinal); ok {
		props.ValidTo = &ts
		props.present |= metadataPropertyValidTo
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyRecordedAt, ordinal); ok {
		props.RecordedAt = ts
		props.present |= metadataPropertyRecordedAt
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyTransactionFrom, ordinal); ok {
		props.TransactionFrom = ts
		props.present |= metadataPropertyTransactionFrom
	}
	if ts, ok := propertyColumnTime(c.metadata, metadataPropertyKeyTransactionTo, ordinal); ok {
		props.TransactionTo = &ts
		props.present |= metadataPropertyTransactionTo
	}
	if props.present == 0 {
		return NodeMetadataProperties{}, false
	}
	return props, true
}

func (c *PropertyColumns) SetMetadataProperties(ordinal NodeOrdinal, props NodeMetadataProperties) {
	if c == nil || c.metadata == nil || ordinal == InvalidNodeOrdinal {
		return
	}
	c.ClearMetadataProperties(ordinal)
	if props.present == 0 {
		return
	}
	if props.present&metadataPropertySourceSystem != 0 {
		c.metadata.SetString(metadataPropertyKeySourceSystem, ordinal, props.SourceSystem)
	}
	if props.present&metadataPropertySourceEventID != 0 {
		c.metadata.SetString(metadataPropertyKeySourceEventID, ordinal, props.SourceEventID)
	}
	if props.present&metadataPropertyConfidence != 0 {
		c.metadata.SetFloat64(metadataPropertyKeyConfidence, ordinal, props.Confidence)
	}
	if props.present&metadataPropertyObservedAt != 0 {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyObservedAt, ordinal, props.ObservedAt)
	}
	if props.present&metadataPropertyValidFrom != 0 {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyValidFrom, ordinal, props.ValidFrom)
	}
	if props.present&metadataPropertyValidTo != 0 && props.ValidTo != nil {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyValidTo, ordinal, *props.ValidTo)
	}
	if props.present&metadataPropertyRecordedAt != 0 {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyRecordedAt, ordinal, props.RecordedAt)
	}
	if props.present&metadataPropertyTransactionFrom != 0 {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyTransactionFrom, ordinal, props.TransactionFrom)
	}
	if props.present&metadataPropertyTransactionTo != 0 && props.TransactionTo != nil {
		setPropertyColumnTime(c.metadata, metadataPropertyKeyTransactionTo, ordinal, *props.TransactionTo)
	}
}

func (c *PropertyColumns) ClearMetadataProperties(ordinal NodeOrdinal) {
	if c == nil || c.metadata == nil {
		return
	}
	c.metadata.ClearString(metadataPropertyKeySourceSystem, ordinal)
	c.metadata.ClearString(metadataPropertyKeySourceEventID, ordinal)
	c.metadata.ClearFloat64(metadataPropertyKeyConfidence, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyObservedAt, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyValidFrom, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyValidTo, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyRecordedAt, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyTransactionFrom, ordinal)
	clearPropertyColumnTime(c.metadata, metadataPropertyKeyTransactionTo, ordinal)
}

func (c *PropertyColumns) CommonProperties(ordinal NodeOrdinal) (NodeCommonProperties, bool) {
	if c == nil || c.common == nil || ordinal == InvalidNodeOrdinal {
		return NodeCommonProperties{}, false
	}
	var props NodeCommonProperties
	if value, ok := c.common.String(commonPropertyKeyServiceID, ordinal); ok {
		props.ServiceID = value
		props.present |= commonPropertyServiceID
	}
	if value, ok := c.common.String(commonPropertyKeyPublicIP, ordinal); ok {
		props.PublicIP = value
		props.present |= commonPropertyPublicIP
	}
	if value, ok := c.common.String(commonPropertyKeyDataClassification, ordinal); ok {
		props.DataClassification = value
		props.present |= commonPropertyDataClassification
	}
	if value, ok := c.common.String(commonPropertyKeyIdentityType, ordinal); ok {
		props.IdentityType = value
		props.present |= commonPropertyIdentityType
	}
	if value, ok := c.common.Bool(commonPropertyKeyInternetExposed, ordinal); ok {
		props.InternetExposed = value
		props.present |= commonPropertyInternetExposed
	}
	if value, ok := c.common.Bool(commonPropertyKeyMFAEnabled, ordinal); ok {
		props.MFAEnabled = value
		props.present |= commonPropertyMFAEnabled
	}
	if value, ok := c.common.Bool(commonPropertyKeyContainsPII, ordinal); ok {
		props.ContainsPII = value
		props.present |= commonPropertyContainsPII
	}
	if value, ok := c.common.Bool(commonPropertyKeyContainsPHI, ordinal); ok {
		props.ContainsPHI = value
		props.present |= commonPropertyContainsPHI
	}
	if value, ok := c.common.Bool(commonPropertyKeyContainsPCI, ordinal); ok {
		props.ContainsPCI = value
		props.present |= commonPropertyContainsPCI
	}
	if value, ok := c.common.Bool(commonPropertyKeyContainsSecrets, ordinal); ok {
		props.ContainsSecrets = value
		props.present |= commonPropertyContainsSecrets
	}
	if props.present == 0 {
		return NodeCommonProperties{}, false
	}
	return props, true
}

func (c *PropertyColumns) SetCommonProperties(ordinal NodeOrdinal, props NodeCommonProperties) {
	if c == nil || c.common == nil || ordinal == InvalidNodeOrdinal {
		return
	}
	c.ClearCommonProperties(ordinal)
	if props.present == 0 {
		return
	}
	if props.present&commonPropertyServiceID != 0 {
		c.common.SetString(commonPropertyKeyServiceID, ordinal, props.ServiceID)
	}
	if props.present&commonPropertyPublicIP != 0 {
		c.common.SetString(commonPropertyKeyPublicIP, ordinal, props.PublicIP)
	}
	if props.present&commonPropertyDataClassification != 0 {
		c.common.SetString(commonPropertyKeyDataClassification, ordinal, props.DataClassification)
	}
	if props.present&commonPropertyIdentityType != 0 {
		c.common.SetString(commonPropertyKeyIdentityType, ordinal, props.IdentityType)
	}
	if props.present&commonPropertyInternetExposed != 0 {
		c.common.SetBool(commonPropertyKeyInternetExposed, ordinal, props.InternetExposed)
	}
	if props.present&commonPropertyMFAEnabled != 0 {
		c.common.SetBool(commonPropertyKeyMFAEnabled, ordinal, props.MFAEnabled)
	}
	if props.present&commonPropertyContainsPII != 0 {
		c.common.SetBool(commonPropertyKeyContainsPII, ordinal, props.ContainsPII)
	}
	if props.present&commonPropertyContainsPHI != 0 {
		c.common.SetBool(commonPropertyKeyContainsPHI, ordinal, props.ContainsPHI)
	}
	if props.present&commonPropertyContainsPCI != 0 {
		c.common.SetBool(commonPropertyKeyContainsPCI, ordinal, props.ContainsPCI)
	}
	if props.present&commonPropertyContainsSecrets != 0 {
		c.common.SetBool(commonPropertyKeyContainsSecrets, ordinal, props.ContainsSecrets)
	}
}

func (c *PropertyColumns) ClearCommonProperties(ordinal NodeOrdinal) {
	if c == nil || c.common == nil {
		return
	}
	c.common.ClearString(commonPropertyKeyServiceID, ordinal)
	c.common.ClearString(commonPropertyKeyPublicIP, ordinal)
	c.common.ClearString(commonPropertyKeyDataClassification, ordinal)
	c.common.ClearString(commonPropertyKeyIdentityType, ordinal)
	c.common.ClearBool(commonPropertyKeyInternetExposed, ordinal)
	c.common.ClearBool(commonPropertyKeyMFAEnabled, ordinal)
	c.common.ClearBool(commonPropertyKeyContainsPII, ordinal)
	c.common.ClearBool(commonPropertyKeyContainsPHI, ordinal)
	c.common.ClearBool(commonPropertyKeyContainsPCI, ordinal)
	c.common.ClearBool(commonPropertyKeyContainsSecrets, ordinal)
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
		metadataProps       NodeMetadataProperties
		hasMetadataProps    bool
		commonProps         NodeCommonProperties
		hasCommonProps      bool
		observationProps    ObservationProperties
		hasObservationProps bool
		attackSequenceProps AttackSequenceProperties
		hasAttackProps      bool
	)
	metadataProps, hasMetadataProps = bindableNodeMetadataProperties(node)
	commonProps, hasCommonProps = bindableNodeCommonProperties(node)
	if node.Kind == NodeKindObservation {
		observationProps, hasObservationProps = bindableObservationProperties(node)
	}
	if node.Kind == NodeKindAttackSequence {
		attackSequenceProps, hasAttackProps = bindableAttackSequenceProperties(node)
	}

	node.propertyColumns = g.propertyColumns
	if g.propertyColumns == nil || node.ordinal == InvalidNodeOrdinal {
		if hasMetadataProps {
			node.metadataProps = ptrNodeMetadataProperties(metadataProps)
		} else {
			node.metadataProps = nil
		}
		if hasCommonProps {
			node.commonProps = ptrNodeCommonProperties(commonProps)
		} else {
			node.commonProps = nil
		}
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
	if hasMetadataProps {
		g.propertyColumns.SetMetadataProperties(node.ordinal, metadataProps)
	}
	if hasCommonProps {
		g.propertyColumns.SetCommonProperties(node.ordinal, commonProps)
	}
	if hasObservationProps {
		g.propertyColumns.SetObservationProperties(node.ordinal, observationProps)
	}
	if hasAttackProps {
		g.propertyColumns.SetAttackSequenceProperties(node.ordinal, attackSequenceProps)
	}
	node.metadataProps = nil
	node.commonProps = nil
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
