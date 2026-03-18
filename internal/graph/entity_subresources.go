package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	entityAssetNormalizerSourceSystem = "platform.normalizer"
	entityAssetNormalizerSourceName   = "entity_asset_normalizer"
	entityAssetNormalizerSourceType   = "pipeline"
)

var bucketConfiguredSubresourceKinds = []NodeKind{
	NodeKindBucketPolicyStatement,
	NodeKindBucketPublicAccessBlock,
	NodeKindBucketEncryptionConfig,
	NodeKindBucketLoggingConfig,
	NodeKindBucketVersioningConfig,
}

// EntitySubresourceRecord captures one promoted subresource attached to an entity.
type EntitySubresourceRecord struct {
	ID               string                        `json:"id"`
	Kind             NodeKind                      `json:"kind"`
	Name             string                        `json:"name,omitempty"`
	Assessment       string                        `json:"assessment,omitempty"`
	Summary          string                        `json:"summary,omitempty"`
	Knowledge        EntityKnowledgeSupportSummary `json:"knowledge"`
	RelatedEntityIDs []string                      `json:"related_entity_ids,omitempty"`
	Fields           map[string]any                `json:"fields,omitempty"`
}

// EntityAssetNormalizationResult summarizes one normalization pass over entity support modules.
type EntityAssetNormalizationResult struct {
	NormalizedAt        time.Time `json:"normalized_at"`
	BucketsProcessed    int       `json:"buckets_processed"`
	SubresourcesCreated int       `json:"subresources_created"`
	ObservationsCreated int       `json:"observations_created"`
	ClaimsCreated       int       `json:"claims_created"`
}

type entityNormalizationContext struct {
	metadata        WriteMetadata
	observedAt      time.Time
	validFrom       time.Time
	validTo         *time.Time
	recordedAt      time.Time
	transactionFrom time.Time
	transactionTo   *time.Time
}

func NormalizeEntityAssetSupport(g *Graph, now time.Time) EntityAssetNormalizationResult {
	result := EntityAssetNormalizationResult{}
	if g == nil {
		return result
	}
	if now.IsZero() {
		now = temporalNowUTC()
	} else {
		now = now.UTC()
	}
	result.NormalizedAt = now
	for _, bucket := range g.GetNodesByKind(NodeKindBucket) {
		if bucket == nil || bucket.DeletedAt != nil {
			continue
		}
		result.BucketsProcessed++
		normalizeBucketEntitySupport(g, bucket, now, &result)
	}
	return result
}

func buildEntitySubresourceRecords(g *Graph, entityID string, validAt, recordedAt time.Time) []EntitySubresourceRecord {
	if g == nil {
		return nil
	}
	records := make([]EntitySubresourceRecord, 0)
	seen := make(map[string]struct{})
	for _, edge := range g.GetInEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindConfigures {
			continue
		}
		node, ok := g.GetNode(edge.Source)
		if !ok || node == nil || !entityConfiguredSubresourceKind(node.Kind) {
			continue
		}
		if _, exists := seen[node.ID]; exists {
			continue
		}
		seen[node.ID] = struct{}{}
		records = append(records, buildEntitySubresourceRecord(g, node, validAt, recordedAt))
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Assessment != records[j].Assessment {
			return entityFacetAssessmentOrder(records[i].Assessment) < entityFacetAssessmentOrder(records[j].Assessment)
		}
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].ID < records[j].ID
	})
	return records
}

func buildEntitySubresourceRecord(g *Graph, node *Node, validAt, recordedAt time.Time) EntitySubresourceRecord {
	knowledge := buildEntityKnowledgeSupportSummary(g, node.ID, validAt, recordedAt)
	claims := collectClaimRecords(g, ClaimQueryOptions{
		SubjectID:  node.ID,
		ValidAt:    validAt,
		RecordedAt: recordedAt,
		Limit:      maxClaimQueryLimit,
	})
	assessment := strings.TrimSpace(readString(node.Properties, "assessment"))
	if assessment == "" {
		if posture := buildEntityPostureSummary(claims, validAt); posture != nil && len(posture.Claims) > 0 {
			assessment = posture.Claims[0].Assessment
		}
	}
	if assessment == "" {
		assessment = "info"
	}
	related := configuredSubresourceTargets(g, node.ID, validAt, recordedAt)
	return EntitySubresourceRecord{
		ID:               node.ID,
		Kind:             node.Kind,
		Name:             strings.TrimSpace(node.Name),
		Assessment:       assessment,
		Summary:          firstNonEmpty(strings.TrimSpace(readString(node.Properties, "summary")), strings.TrimSpace(node.Name)),
		Knowledge:        knowledge,
		RelatedEntityIDs: related,
		Fields:           entitySubresourceFields(node.Properties),
	}
}

func entityConfiguredSubresourceKind(kind NodeKind) bool {
	for _, candidate := range bucketConfiguredSubresourceKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func configuredSubresourceTargets(g *Graph, subresourceID string, validAt, recordedAt time.Time) []string {
	if g == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var ids []string
	for _, edge := range g.GetOutEdgesBitemporal(subresourceID, validAt, recordedAt) {
		if edge == nil {
			continue
		}
		if edge.Kind != EdgeKindTargets && edge.Kind != EdgeKindRefers {
			continue
		}
		if _, ok := seen[edge.Target]; ok {
			continue
		}
		seen[edge.Target] = struct{}{}
		ids = append(ids, edge.Target)
	}
	sort.Strings(ids)
	return ids
}

func entitySubresourceFields(properties map[string]any) map[string]any {
	fields := cloneAnyMap(properties)
	for _, key := range []string{
		"source_system", "source_event_id", "observed_at", "valid_from", "valid_to",
		"recorded_at", "transaction_from", "transaction_to", "confidence", "summary",
	} {
		delete(fields, key)
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func propertyHasAnyKey(properties map[string]any, keys ...string) bool {
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := properties[key]; ok {
			return true
		}
	}
	return false
}

func relatedBucketSubresourceNode(g *Graph, bucketID string, kind NodeKind, validAt, recordedAt time.Time) (*Node, bool) {
	if g == nil {
		return nil, false
	}
	for _, edge := range g.GetInEdgesBitemporal(bucketID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindConfigures {
			continue
		}
		node, ok := g.GetNode(edge.Source)
		if !ok || node == nil || node.Kind != kind {
			continue
		}
		return node, true
	}
	return nil, false
}

func normalizeBucketEntitySupport(g *Graph, bucket *Node, now time.Time, result *EntityAssetNormalizationResult) {
	meta := entityNormalizationContextFor(bucket, now)
	publicSupportClaims := make([]string, 0, 4)
	publicTrueSignals := 0

	if claimIDs, createdSubresources, createdObservations, createdClaims := ensureBucketPolicyStatementSupport(g, bucket, meta); len(claimIDs) > 0 {
		result.SubresourcesCreated += createdSubresources
		result.ObservationsCreated += createdObservations
		result.ClaimsCreated += createdClaims
		publicSupportClaims = append(publicSupportClaims, claimIDs...)
		publicTrueSignals += len(claimIDs)
	}
	if claimID, createdSubresource, createdObservation, createdClaim, blocked, known := ensureBucketPublicAccessBlockSupport(g, bucket, meta); claimID != "" {
		if createdSubresource {
			result.SubresourcesCreated++
		}
		if createdObservation {
			result.ObservationsCreated++
		}
		if createdClaim {
			result.ClaimsCreated++
		}
		publicSupportClaims = append(publicSupportClaims, claimID)
		if known && !blocked {
			publicTrueSignals++
		}
	}
	if claimID, createdSubresource, createdObservation, createdClaim := ensureBucketEncryptionSupport(g, bucket, meta); claimID != "" {
		if createdSubresource {
			result.SubresourcesCreated++
		}
		if createdObservation {
			result.ObservationsCreated++
		}
		if createdClaim {
			result.ClaimsCreated++
		}
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "encrypted", claimBoolObjectValue(g, claimID, meta, true), supportIDs(claimID), "Bucket encryption posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "default_encryption_enabled", claimBoolObjectValue(g, claimID, meta, true), supportIDs(claimID), "Bucket default encryption posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
	}
	if claimID, createdSubresource, createdObservation, createdClaim := ensureBucketLoggingSupport(g, bucket, meta); claimID != "" {
		if createdSubresource {
			result.SubresourcesCreated++
		}
		if createdObservation {
			result.ObservationsCreated++
		}
		if createdClaim {
			result.ClaimsCreated++
		}
		value := claimBoolObjectValue(g, claimID, meta, readBool(bucket.Properties, "logging_enabled", "access_logging_enabled"))
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "access_logging_enabled", value, supportIDs(claimID), "Bucket access logging posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
	}
	if claimID, createdSubresource, createdObservation, createdClaim := ensureBucketVersioningSupport(g, bucket, meta); claimID != "" {
		if createdSubresource {
			result.SubresourcesCreated++
		}
		if createdObservation {
			result.ObservationsCreated++
		}
		if createdClaim {
			result.ClaimsCreated++
		}
		value := claimBoolObjectValue(g, claimID, meta, bucketVersioningEnabled(bucket.Properties))
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "versioning_enabled", value, supportIDs(claimID), "Bucket versioning posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
	}

	publicValue := bucketPublicAccessValue(bucket, publicTrueSignals)
	if len(publicSupportClaims) > 0 {
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "public_access", publicValue, publicSupportClaims, "Bucket public-access posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
		if _, created, err := ensureNormalizedBucketClaim(g, bucket, meta, "internet_exposed", publicValue, publicSupportClaims, "Bucket internet-exposure posture normalized from configuration support"); err == nil && created {
			result.ClaimsCreated++
		}
	}
}

func entityNormalizationContextFor(node *Node, fallback time.Time) entityNormalizationContext {
	observedAt, ok := graphObservedAt(node)
	if !ok || observedAt.IsZero() {
		observedAt = fallback
	}
	validFrom, ok := nodePropertyTime(node, "valid_from")
	if !ok || validFrom.IsZero() {
		validFrom = observedAt
	}
	validTo, ok := nodePropertyTime(node, "valid_to")
	var validToPtr *time.Time
	if ok {
		validToPtr = &validTo
	}
	recordedAt, ok := nodePropertyTime(node, "recorded_at")
	if !ok || recordedAt.IsZero() {
		recordedAt = observedAt
	}
	transactionFrom, ok := nodePropertyTime(node, "transaction_from")
	if !ok || transactionFrom.IsZero() {
		transactionFrom = recordedAt
	}
	transactionTo, ok := nodePropertyTime(node, "transaction_to")
	var transactionToPtr *time.Time
	if ok {
		transactionToPtr = &transactionTo
	}
	metadata := NormalizeWriteMetadata(observedAt, validFrom, validToPtr, entityAssetNormalizerSourceSystem, fmt.Sprintf("entity-asset-normalizer:%s", slugifyKnowledgeKey(node.ID)), 0.85, WriteMetadataDefaults{
		SourceSystem:      entityAssetNormalizerSourceSystem,
		SourceEventPrefix: "entity-asset-normalizer",
		DefaultConfidence: 0.85,
		RecordedAt:        recordedAt,
		TransactionFrom:   transactionFrom,
		TransactionTo:     transactionToPtr,
	})
	return entityNormalizationContext{
		metadata:        metadata,
		observedAt:      metadata.ObservedAt,
		validFrom:       metadata.ValidFrom,
		validTo:         metadata.ValidTo,
		recordedAt:      metadata.RecordedAt,
		transactionFrom: metadata.TransactionFrom,
		transactionTo:   metadata.TransactionTo,
	}
}

func ensureBucketPublicAccessBlockSupport(g *Graph, bucket *Node, meta entityNormalizationContext) (string, bool, bool, bool, bool, bool) {
	fields := map[string]any{
		"block_public_acls":        readBool(bucket.Properties, "block_public_acls"),
		"ignore_public_acls":       readBool(bucket.Properties, "ignore_public_acls"),
		"block_public_policy":      readBool(bucket.Properties, "block_public_policy"),
		"restrict_public_buckets":  readBool(bucket.Properties, "restrict_public_buckets"),
		"public_access_prevention": strings.TrimSpace(readString(bucket.Properties, "public_access_prevention")),
	}
	known := propertyHasAnyKey(bucket.Properties, "block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets", "public_access_prevention")
	if !known {
		return "", false, false, false, false, false
	}
	blocked := fields["block_public_acls"].(bool) && fields["block_public_policy"].(bool)
	if value := strings.ToLower(fields["public_access_prevention"].(string)); value == "enforced" || value == "enabled" {
		blocked = true
	}
	summary := "Bucket public-access block configuration normalized"
	fields["bucket_id"] = bucket.ID
	fields["public_access_block_id"] = fmt.Sprintf("public_access_block:%s", slugifyKnowledgeKey(bucket.ID))
	fields["assessment"] = boolAssessment(blocked, "pass", "fail")
	fields["summary"] = summary
	subresourceID, createdSubresource := ensureConfiguredSubresourceNode(g, bucket, NodeKindBucketPublicAccessBlock, fmt.Sprintf("bucket_public_access_block:%s", slugifyKnowledgeKey(bucket.ID)), "Bucket Public Access Block", fields, meta)
	observationID, createdObservation, _ := ensureConfiguredObservation(g, fmt.Sprintf("observation:%s:bucket_public_access_block", slugifyKnowledgeKey(bucket.ID)), subresourceID, "bucket_public_access_block_config", summary, fields, meta)
	claimID, createdClaim, _ := ensureConfiguredClaim(g, ClaimWriteRequest{
		ID:              fmt.Sprintf("claim:%s:bucket_public_access_block_enabled:normalized", slugifyKnowledgeKey(bucket.ID)),
		ClaimType:       "asset_subresource_posture",
		SubjectID:       subresourceID,
		Predicate:       "public_access_block_enabled",
		ObjectValue:     formatBool(blocked),
		Summary:         boolSummary(blocked, "Public-access block is enabled", "Public-access block is incomplete or disabled"),
		EvidenceIDs:     supportIDs(observationID),
		SourceSystem:    entityAssetNormalizerSourceSystem,
		SourceName:      entityAssetNormalizerSourceName,
		SourceType:      entityAssetNormalizerSourceType,
		ObservedAt:      meta.observedAt,
		ValidFrom:       meta.validFrom,
		ValidTo:         meta.validTo,
		RecordedAt:      meta.recordedAt,
		TransactionFrom: meta.transactionFrom,
		TransactionTo:   meta.transactionTo,
		Confidence:      0.85,
		Metadata:        map[string]any{"normalized": true, "subresource_kind": string(NodeKindBucketPublicAccessBlock)},
	})
	return claimID, createdSubresource, createdObservation, createdClaim, blocked, true
}

func ensureBucketPolicyStatementSupport(g *Graph, bucket *Node, meta entityNormalizationContext) ([]string, int, int, int) {
	candidates := []struct {
		field         string
		actionsField  string
		principal     string
		principalType string
		suffix        string
	}{
		{field: "anonymous_access", actionsField: "anonymous_actions", principal: "anonymous", principalType: "anonymous", suffix: "anonymous"},
		{field: "all_users_access", actionsField: "all_users_actions", principal: "allUsers", principalType: "all_users", suffix: "all-users"},
		{field: "all_authenticated_users_access", actionsField: "all_authenticated_users_actions", principal: "allAuthenticatedUsers", principalType: "all_authenticated_users", suffix: "all-authenticated-users"},
	}
	claimIDs := make([]string, 0, len(candidates))
	createdSubresources := 0
	createdObservations := 0
	createdClaims := 0
	for _, candidate := range candidates {
		if !readBool(bucket.Properties, candidate.field) {
			continue
		}
		fields := map[string]any{
			"bucket_id":      bucket.ID,
			"statement_id":   candidate.suffix,
			"effect":         "allow",
			"principal":      candidate.principal,
			"principal_type": candidate.principalType,
			"public_access":  true,
			"action_count":   len(stringSliceFromValue(bucket.Properties[candidate.actionsField])),
			"assessment":     "fail",
			"summary":        fmt.Sprintf("Bucket policy statement grants access to %s", candidate.principal),
		}
		subresourceID, createdSubresource := ensureConfiguredSubresourceNode(g, bucket, NodeKindBucketPolicyStatement, fmt.Sprintf("bucket_policy_statement:%s:%s", slugifyKnowledgeKey(bucket.ID), candidate.suffix), "Bucket Policy Statement", fields, meta)
		observationID, createdObservation, _ := ensureConfiguredObservation(g, fmt.Sprintf("observation:%s:bucket_policy_statement:%s", slugifyKnowledgeKey(bucket.ID), candidate.suffix), subresourceID, "bucket_policy_statement", fields["summary"].(string), fields, meta)
		claimID, createdClaim, _ := ensureConfiguredClaim(g, ClaimWriteRequest{
			ID:              fmt.Sprintf("claim:%s:bucket_policy_statement_public_access:%s", slugifyKnowledgeKey(bucket.ID), candidate.suffix),
			ClaimType:       "asset_subresource_posture",
			SubjectID:       subresourceID,
			Predicate:       "public_access",
			ObjectValue:     "true",
			Summary:         fmt.Sprintf("Policy statement %s exposes the bucket publicly", candidate.suffix),
			EvidenceIDs:     supportIDs(observationID),
			SourceSystem:    entityAssetNormalizerSourceSystem,
			SourceName:      entityAssetNormalizerSourceName,
			SourceType:      entityAssetNormalizerSourceType,
			ObservedAt:      meta.observedAt,
			ValidFrom:       meta.validFrom,
			ValidTo:         meta.validTo,
			RecordedAt:      meta.recordedAt,
			TransactionFrom: meta.transactionFrom,
			TransactionTo:   meta.transactionTo,
			Confidence:      0.90,
			Metadata:        map[string]any{"normalized": true, "subresource_kind": string(NodeKindBucketPolicyStatement)},
		})
		if claimID != "" {
			claimIDs = append(claimIDs, claimID)
		}
		if createdSubresource {
			createdSubresources++
		}
		if createdObservation {
			createdObservations++
		}
		if createdClaim {
			createdClaims++
		}
	}
	return claimIDs, createdSubresources, createdObservations, createdClaims
}

func ensureBucketEncryptionSupport(g *Graph, bucket *Node, meta entityNormalizationContext) (string, bool, bool, bool) {
	encrypted := readBool(bucket.Properties, "encrypted", "default_encryption", "default_encryption_enabled", "kms_encrypted")
	algorithm := strings.TrimSpace(readString(bucket.Properties, "encryption_algorithm"))
	keyID := strings.TrimSpace(readString(bucket.Properties, "encryption_key_id"))
	bucketKeyEnabled := readBool(bucket.Properties, "bucket_key_enabled")
	known := propertyHasAnyKey(bucket.Properties, "encrypted", "default_encryption", "default_encryption_enabled", "kms_encrypted", "encryption_algorithm", "encryption_key_id", "bucket_key_enabled")
	if !known {
		return "", false, false, false
	}
	fields := map[string]any{
		"bucket_id":            bucket.ID,
		"encryption_config_id": fmt.Sprintf("encryption:%s", slugifyKnowledgeKey(bucket.ID)),
		"encrypted":            encrypted,
		"encryption_algorithm": algorithm,
		"encryption_key_id":    keyID,
		"bucket_key_enabled":   bucketKeyEnabled,
		"assessment":           boolAssessment(encrypted, "pass", "fail"),
		"summary":              boolSummary(encrypted, "Bucket encryption configuration is enabled", "Bucket encryption configuration is disabled or incomplete"),
	}
	subresourceID, createdSubresource := ensureConfiguredSubresourceNode(g, bucket, NodeKindBucketEncryptionConfig, fmt.Sprintf("bucket_encryption_config:%s", slugifyKnowledgeKey(bucket.ID)), "Bucket Encryption Configuration", fields, meta)
	observationID, createdObservation, _ := ensureConfiguredObservation(g, fmt.Sprintf("observation:%s:bucket_encryption_config", slugifyKnowledgeKey(bucket.ID)), subresourceID, "bucket_encryption_config", fields["summary"].(string), fields, meta)
	claimID, createdClaim, _ := ensureConfiguredClaim(g, ClaimWriteRequest{
		ID:              fmt.Sprintf("claim:%s:bucket_encryption_config:normalized", slugifyKnowledgeKey(bucket.ID)),
		ClaimType:       "asset_subresource_posture",
		SubjectID:       subresourceID,
		Predicate:       "default_encryption_enabled",
		ObjectValue:     formatBool(encrypted),
		Summary:         fields["summary"].(string),
		EvidenceIDs:     supportIDs(observationID),
		SourceSystem:    entityAssetNormalizerSourceSystem,
		SourceName:      entityAssetNormalizerSourceName,
		SourceType:      entityAssetNormalizerSourceType,
		ObservedAt:      meta.observedAt,
		ValidFrom:       meta.validFrom,
		ValidTo:         meta.validTo,
		RecordedAt:      meta.recordedAt,
		TransactionFrom: meta.transactionFrom,
		TransactionTo:   meta.transactionTo,
		Confidence:      0.85,
		Metadata:        map[string]any{"normalized": true, "subresource_kind": string(NodeKindBucketEncryptionConfig)},
	})
	return claimID, createdSubresource, createdObservation, createdClaim
}

func ensureBucketLoggingSupport(g *Graph, bucket *Node, meta entityNormalizationContext) (string, bool, bool, bool) {
	enabled := readBool(bucket.Properties, "logging_enabled", "access_logging_enabled")
	targetBucket := strings.TrimSpace(readString(bucket.Properties, "logging_target_bucket"))
	targetPrefix := strings.TrimSpace(readString(bucket.Properties, "logging_target_prefix", "target_prefix"))
	known := propertyHasAnyKey(bucket.Properties, "logging_enabled", "access_logging_enabled", "logging_target_bucket", "logging_target_prefix", "target_prefix")
	if !known {
		return "", false, false, false
	}
	fields := map[string]any{
		"bucket_id":             bucket.ID,
		"logging_config_id":     fmt.Sprintf("logging:%s", slugifyKnowledgeKey(bucket.ID)),
		"logging_enabled":       enabled,
		"logging_target_bucket": targetBucket,
		"target_prefix":         targetPrefix,
		"assessment":            boolAssessment(enabled, "pass", "warn"),
		"summary":               boolSummary(enabled, "Bucket access logging is enabled", "Bucket access logging is not enabled"),
	}
	subresourceID, createdSubresource := ensureConfiguredSubresourceNode(g, bucket, NodeKindBucketLoggingConfig, fmt.Sprintf("bucket_logging_config:%s", slugifyKnowledgeKey(bucket.ID)), "Bucket Logging Configuration", fields, meta)
	if targetBucket != "" {
		if target, ok := lookupBucketByNameOrID(g, targetBucket); ok {
			addGraphEdgeIfMissing(g, &Edge{ID: fmt.Sprintf("%s->%s:%s", subresourceID, target.ID, EdgeKindTargets), Source: subresourceID, Target: target.ID, Kind: EdgeKindTargets, Effect: EdgeEffectAllow, Properties: cloneAnyMap(meta.metadata.PropertyMap())})
		}
	}
	observationID, createdObservation, _ := ensureConfiguredObservation(g, fmt.Sprintf("observation:%s:bucket_logging_config", slugifyKnowledgeKey(bucket.ID)), subresourceID, "bucket_logging_config", fields["summary"].(string), fields, meta)
	claimID, createdClaim, _ := ensureConfiguredClaim(g, ClaimWriteRequest{
		ID:              fmt.Sprintf("claim:%s:bucket_logging_config:normalized", slugifyKnowledgeKey(bucket.ID)),
		ClaimType:       "asset_subresource_posture",
		SubjectID:       subresourceID,
		Predicate:       "access_logging_enabled",
		ObjectValue:     formatBool(enabled),
		Summary:         fields["summary"].(string),
		EvidenceIDs:     supportIDs(observationID),
		SourceSystem:    entityAssetNormalizerSourceSystem,
		SourceName:      entityAssetNormalizerSourceName,
		SourceType:      entityAssetNormalizerSourceType,
		ObservedAt:      meta.observedAt,
		ValidFrom:       meta.validFrom,
		ValidTo:         meta.validTo,
		RecordedAt:      meta.recordedAt,
		TransactionFrom: meta.transactionFrom,
		TransactionTo:   meta.transactionTo,
		Confidence:      0.85,
		Metadata:        map[string]any{"normalized": true, "subresource_kind": string(NodeKindBucketLoggingConfig)},
	})
	return claimID, createdSubresource, createdObservation, createdClaim
}

func ensureBucketVersioningSupport(g *Graph, bucket *Node, meta entityNormalizationContext) (string, bool, bool, bool) {
	status := strings.ToLower(strings.TrimSpace(readString(bucket.Properties, "versioning_status", "versioning")))
	mfaDelete := readBool(bucket.Properties, "mfa_delete")
	known := propertyHasAnyKey(bucket.Properties, "versioning_status", "versioning", "mfa_delete")
	if !known {
		return "", false, false, false
	}
	enabled := status == "enabled" || status == "on"
	fields := map[string]any{
		"bucket_id":            bucket.ID,
		"versioning_config_id": fmt.Sprintf("versioning:%s", slugifyKnowledgeKey(bucket.ID)),
		"versioning_status":    firstNonEmpty(status, "disabled"),
		"mfa_delete":           mfaDelete,
		"assessment":           boolAssessment(enabled, "pass", "warn"),
		"summary":              boolSummary(enabled, "Bucket versioning is enabled", "Bucket versioning is not enabled"),
	}
	subresourceID, createdSubresource := ensureConfiguredSubresourceNode(g, bucket, NodeKindBucketVersioningConfig, fmt.Sprintf("bucket_versioning_config:%s", slugifyKnowledgeKey(bucket.ID)), "Bucket Versioning Configuration", fields, meta)
	observationID, createdObservation, _ := ensureConfiguredObservation(g, fmt.Sprintf("observation:%s:bucket_versioning_config", slugifyKnowledgeKey(bucket.ID)), subresourceID, "bucket_versioning_config", fields["summary"].(string), fields, meta)
	claimID, createdClaim, _ := ensureConfiguredClaim(g, ClaimWriteRequest{
		ID:              fmt.Sprintf("claim:%s:bucket_versioning_config:normalized", slugifyKnowledgeKey(bucket.ID)),
		ClaimType:       "asset_subresource_posture",
		SubjectID:       subresourceID,
		Predicate:       "versioning_enabled",
		ObjectValue:     formatBool(enabled),
		Summary:         fields["summary"].(string),
		EvidenceIDs:     supportIDs(observationID),
		SourceSystem:    entityAssetNormalizerSourceSystem,
		SourceName:      entityAssetNormalizerSourceName,
		SourceType:      entityAssetNormalizerSourceType,
		ObservedAt:      meta.observedAt,
		ValidFrom:       meta.validFrom,
		ValidTo:         meta.validTo,
		RecordedAt:      meta.recordedAt,
		TransactionFrom: meta.transactionFrom,
		TransactionTo:   meta.transactionTo,
		Confidence:      0.85,
		Metadata:        map[string]any{"normalized": true, "subresource_kind": string(NodeKindBucketVersioningConfig)},
	})
	return claimID, createdSubresource, createdObservation, createdClaim
}

func bucketVersioningEnabled(properties map[string]any) bool {
	status := strings.ToLower(strings.TrimSpace(readString(properties, "versioning_status", "versioning")))
	if status != "" {
		return status == "enabled" || status == "on"
	}
	return readBool(properties, "versioning_enabled")
}

func ensureConfiguredSubresourceNode(g *Graph, bucket *Node, kind NodeKind, id, name string, fields map[string]any, meta entityNormalizationContext) (string, bool) {
	if _, ok := g.GetNode(id); ok {
		return id, false
	}
	properties := cloneAnyMap(fields)
	if properties == nil {
		properties = make(map[string]any)
	}
	meta.metadata.ApplyTo(properties)
	g.AddNode(&Node{
		ID:         id,
		Kind:       kind,
		Name:       name,
		Provider:   bucket.Provider,
		Account:    bucket.Account,
		Region:     bucket.Region,
		Properties: properties,
		Risk:       bucket.Risk,
	})
	addGraphEdgeIfMissing(g, &Edge{
		ID:         fmt.Sprintf("%s->%s:%s", id, bucket.ID, EdgeKindConfigures),
		Source:     id,
		Target:     bucket.ID,
		Kind:       EdgeKindConfigures,
		Effect:     EdgeEffectAllow,
		Properties: cloneAnyMap(meta.metadata.PropertyMap()),
	})
	return id, true
}

func ensureConfiguredObservation(g *Graph, id, subjectID, observationType, summary string, fields map[string]any, meta entityNormalizationContext) (string, bool, error) {
	if subjectID == "" {
		return "", false, fmt.Errorf("subject_id is required")
	}
	if _, ok := g.GetNode(id); ok {
		return id, false, nil
	}
	metadata := cloneAnyMap(fields)
	delete(metadata, "assessment")
	delete(metadata, "summary")
	_, err := WriteObservation(g, ObservationWriteRequest{
		ID:              id,
		SubjectID:       subjectID,
		ObservationType: observationType,
		Summary:         summary,
		SourceSystem:    entityAssetNormalizerSourceSystem,
		SourceEventID:   fmt.Sprintf("entity-asset-normalizer:%s", slugifyKnowledgeKey(subjectID)),
		ObservedAt:      meta.observedAt,
		ValidFrom:       meta.validFrom,
		ValidTo:         meta.validTo,
		RecordedAt:      meta.recordedAt,
		TransactionFrom: meta.transactionFrom,
		TransactionTo:   meta.transactionTo,
		Confidence:      0.80,
		Metadata:        metadata,
	})
	return id, err == nil, err
}

func ensureConfiguredClaim(g *Graph, req ClaimWriteRequest) (string, bool, error) {
	if strings.TrimSpace(req.ID) == "" {
		return "", false, fmt.Errorf("claim id is required")
	}
	if _, ok := g.GetNode(req.ID); ok {
		return req.ID, false, nil
	}
	_, err := WriteClaim(g, req)
	return req.ID, err == nil, err
}

func ensureNormalizedBucketClaim(g *Graph, bucket *Node, meta entityNormalizationContext, predicate, objectValue string, supportingClaimIDs []string, summary string) (string, bool, error) {
	id := fmt.Sprintf("claim:%s:%s:normalized", slugifyKnowledgeKey(bucket.ID), slugifyKnowledgeKey(predicate))
	return ensureConfiguredClaim(g, ClaimWriteRequest{
		ID:                 id,
		ClaimType:          "entity_posture",
		SubjectID:          bucket.ID,
		Predicate:          predicate,
		ObjectValue:        objectValue,
		Summary:            summary,
		SupportingClaimIDs: supportingClaimIDs,
		SourceSystem:       entityAssetNormalizerSourceSystem,
		SourceName:         entityAssetNormalizerSourceName,
		SourceType:         entityAssetNormalizerSourceType,
		ObservedAt:         meta.observedAt,
		ValidFrom:          meta.validFrom,
		ValidTo:            meta.validTo,
		RecordedAt:         meta.recordedAt,
		TransactionFrom:    meta.transactionFrom,
		TransactionTo:      meta.transactionTo,
		Confidence:         0.85,
		Metadata: map[string]any{
			"normalized":       true,
			"entity_kind":      string(bucket.Kind),
			"normalizer_scope": "entity_support",
		},
	})
}

func claimBoolObjectValue(g *Graph, claimID string, meta entityNormalizationContext, fallback bool) string {
	if record, ok := GetClaimRecord(g, claimID, meta.validFrom, meta.recordedAt); ok {
		value := strings.ToLower(strings.TrimSpace(record.ObjectValue))
		switch value {
		case "true", "enabled", "on", "public":
			return "true"
		case "false", "disabled", "off", "private":
			return "false"
		}
	}
	return formatBool(fallback)
}

func bucketPublicAccessValue(bucket *Node, publicTrueSignals int) string {
	if publicTrueSignals > 0 {
		return "true"
	}
	if readBool(bucket.Properties, "public", "public_access", "all_users_access", "all_authenticated_users_access", "anonymous_access") {
		return "true"
	}
	return "false"
}

func lookupBucketByNameOrID(g *Graph, ref string) (*Node, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || g == nil {
		return nil, false
	}
	if node, ok := g.GetNode(ref); ok && node != nil && node.Kind == NodeKindBucket {
		return node, true
	}
	for _, bucket := range g.GetNodesByKind(NodeKindBucket) {
		if bucket == nil {
			continue
		}
		if bucket.ID == ref || strings.EqualFold(bucket.Name, ref) || strings.EqualFold(strings.TrimSpace(readString(bucket.Properties, "bucket_name")), ref) {
			return bucket, true
		}
	}
	return nil, false
}

func addGraphEdgeIfMissing(g *Graph, edge *Edge) {
	if g == nil || edge == nil {
		return
	}
	for _, existing := range g.GetOutEdges(edge.Source) {
		if existing == nil {
			continue
		}
		if existing.Target == edge.Target && existing.Kind == edge.Kind {
			return
		}
	}
	g.AddEdge(edge)
}

func boolAssessment(value bool, trueValue, falseValue string) string {
	if value {
		return trueValue
	}
	return falseValue
}

func boolSummary(value bool, trueValue, falseValue string) string {
	if value {
		return trueValue
	}
	return falseValue
}

func formatBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func supportIDs(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
