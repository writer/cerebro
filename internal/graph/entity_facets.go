package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const entityPostureStaleAfter = 30 * 24 * time.Hour

// EntityCanonicalRef exposes the stable platform-native identity of an entity.
type EntityCanonicalRef struct {
	ID        string   `json:"id"`
	Kind      NodeKind `json:"kind"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	Provider  string   `json:"provider,omitempty"`
	Account   string   `json:"account,omitempty"`
	Region    string   `json:"region,omitempty"`
}

// EntityExternalRef exposes source-native identifiers without making them the primary platform identity.
type EntityExternalRef struct {
	System  string `json:"system,omitempty"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	URL     string `json:"url,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// EntityAliasRecord captures one alternate alias attached to a canonical entity.
type EntityAliasRecord struct {
	ID           string   `json:"id,omitempty"`
	Kind         NodeKind `json:"kind,omitempty"`
	Name         string   `json:"name,omitempty"`
	AliasType    string   `json:"alias_type,omitempty"`
	SourceSystem string   `json:"source_system,omitempty"`
}

// EntityFacetFieldDefinition describes one typed field inside a facet contract.
type EntityFacetFieldDefinition struct {
	Key         string `json:"key"`
	ValueType   string `json:"value_type"`
	Description string `json:"description,omitempty"`
}

// EntityFacetDefinition describes one built-in entity facet contract.
type EntityFacetDefinition struct {
	ID              string                       `json:"id"`
	Version         string                       `json:"version"`
	Title           string                       `json:"title"`
	Description     string                       `json:"description,omitempty"`
	SchemaName      string                       `json:"schema_name"`
	SchemaURL       string                       `json:"schema_url"`
	ApplicableKinds []NodeKind                   `json:"applicable_kinds,omitempty"`
	SourceKeys      []string                     `json:"source_keys,omitempty"`
	ClaimPredicates []string                     `json:"claim_predicates,omitempty"`
	Fields          []EntityFacetFieldDefinition `json:"fields,omitempty"`
}

// EntityFacetRecord is one materialized facet attached to an entity detail view.
type EntityFacetRecord struct {
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	SchemaName      string         `json:"schema_name"`
	SchemaURL       string         `json:"schema_url"`
	Status          string         `json:"status"`
	Assessment      string         `json:"assessment"`
	Summary         string         `json:"summary,omitempty"`
	SourceKeys      []string       `json:"source_keys,omitempty"`
	ClaimPredicates []string       `json:"claim_predicates,omitempty"`
	Fields          map[string]any `json:"fields,omitempty"`
}

// EntityPostureClaimRecord captures one normalized posture/support claim on an entity.
type EntityPostureClaimRecord struct {
	ClaimID       string    `json:"claim_id"`
	Predicate     string    `json:"predicate"`
	ObjectID      string    `json:"object_id,omitempty"`
	ObjectValue   string    `json:"object_value,omitempty"`
	Status        string    `json:"status"`
	Assessment    string    `json:"assessment"`
	Summary       string    `json:"summary,omitempty"`
	Confidence    float64   `json:"confidence,omitempty"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
	Supported     bool      `json:"supported"`
	Conflicted    bool      `json:"conflicted"`
	Stale         bool      `json:"stale"`
	EvidenceCount int       `json:"evidence_count"`
	SourceCount   int       `json:"source_count"`
}

// EntityPostureSummary captures the current posture/support state attached to an entity.
type EntityPostureSummary struct {
	ActiveClaimCount    int                        `json:"active_claim_count"`
	SupportedClaimCount int                        `json:"supported_claim_count"`
	DisputedClaimCount  int                        `json:"disputed_claim_count"`
	StaleClaimCount     int                        `json:"stale_claim_count"`
	Claims              []EntityPostureClaimRecord `json:"claims,omitempty"`
}

var defaultEntityFacetDefinitions = []EntityFacetDefinition{
	{
		ID:              "ownership",
		Version:         "1.0.0",
		Title:           "Ownership",
		Description:     "Typed owner and manager context derived from relations and ownership claims.",
		SchemaName:      "PlatformEntityOwnershipFacet",
		SchemaURL:       "urn:cerebro:entity-facet:ownership:v1",
		ClaimPredicates: []string{"owner", "managed_by"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "owner_ids", ValueType: "array[string]"},
			{Key: "manager_ids", ValueType: "array[string]"},
		},
	},
	{
		ID:          "exposure",
		Version:     "1.0.0",
		Title:       "Exposure",
		Description: "Internet/public-access posture derived from graph edges, raw properties, and exposure claims.",
		SchemaName:  "PlatformEntityExposureFacet",
		SchemaURL:   "urn:cerebro:entity-facet:exposure:v1",
		ApplicableKinds: []NodeKind{
			NodeKindBucket, NodeKindDatabase, NodeKindFunction, NodeKindInstance, NodeKindNetwork, NodeKindService,
		},
		SourceKeys:      []string{"public", "public_access", "internet_accessible", "publicly_accessible"},
		ClaimPredicates: []string{"public_access", "internet_exposed"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "internet_exposed", ValueType: "boolean"},
			{Key: "public_access", ValueType: "boolean"},
		},
	},
	{
		ID:          "data_sensitivity",
		Version:     "1.0.0",
		Title:       "Data Sensitivity",
		Description: "Sensitivity signals derived from tags, raw properties, and normalized sensitivity claims.",
		SchemaName:  "PlatformEntityDataSensitivityFacet",
		SchemaURL:   "urn:cerebro:entity-facet:data-sensitivity:v1",
		ApplicableKinds: []NodeKind{
			NodeKindBucket, NodeKindDatabase, NodeKindSecret, NodeKindService,
		},
		SourceKeys:      []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets", "data_classification"},
		ClaimPredicates: []string{"contains_sensitive_data", "data_classification"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "contains_pii", ValueType: "boolean"},
			{Key: "contains_phi", ValueType: "boolean"},
			{Key: "contains_pci", ValueType: "boolean"},
			{Key: "contains_secrets", ValueType: "boolean"},
			{Key: "classification", ValueType: "string"},
		},
	},
	{
		ID:          "workload_security",
		Version:     "1.0.0",
		Title:       "Workload Security",
		Description: "Latest workload scan posture with vulnerability depth and attack-path context.",
		SchemaName:  "PlatformWorkloadSecurityFacet",
		SchemaURL:   "urn:cerebro:entity-facet:workload-security:v1",
		ApplicableKinds: []NodeKind{
			NodeKindInstance, NodeKindFunction, NodeKindWorkload,
		},
		Fields: []EntityFacetFieldDefinition{
			{Key: "last_scan_id", ValueType: "string"},
			{Key: "last_scanned_at", ValueType: "string"},
			{Key: "stale", ValueType: "boolean"},
			{Key: "os_name", ValueType: "string"},
			{Key: "os_version", ValueType: "string"},
			{Key: "os_architecture", ValueType: "string"},
			{Key: "package_count", ValueType: "integer"},
			{Key: "vulnerability_count", ValueType: "integer"},
			{Key: "critical_vulnerability_count", ValueType: "integer"},
			{Key: "high_vulnerability_count", ValueType: "integer"},
			{Key: "known_exploited_count", ValueType: "integer"},
			{Key: "fixable_vulnerability_count", ValueType: "integer"},
			{Key: "internet_exposed", ValueType: "boolean"},
			{Key: "admin_reachable_count", ValueType: "integer"},
			{Key: "sensitive_data_path_count", ValueType: "integer"},
			{Key: "cross_account_risk", ValueType: "boolean"},
			{Key: "prioritized_risk", ValueType: "string"},
		},
	},
	{
		ID:              "bucket_public_access",
		Version:         "1.0.0",
		Title:           "Bucket Public Access",
		Description:     "Bucket public exposure and public-access-block configuration.",
		SchemaName:      "PlatformBucketPublicAccessFacet",
		SchemaURL:       "urn:cerebro:entity-facet:bucket-public-access:v1",
		ApplicableKinds: []NodeKind{NodeKindBucket},
		SourceKeys:      []string{"public", "public_access", "block_public_acls", "block_public_policy", "restrict_public_buckets", "public_access_prevention", "all_users_access", "all_authenticated_users_access", "anonymous_access"},
		ClaimPredicates: []string{"public_access", "internet_exposed"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "public_access", ValueType: "boolean"},
			{Key: "block_public_acls", ValueType: "boolean"},
			{Key: "block_public_policy", ValueType: "boolean"},
			{Key: "restrict_public_buckets", ValueType: "boolean"},
			{Key: "all_users_access", ValueType: "boolean"},
			{Key: "all_authenticated_users_access", ValueType: "boolean"},
		},
	},
	{
		ID:              "bucket_encryption",
		Version:         "1.0.0",
		Title:           "Bucket Encryption",
		Description:     "Bucket encryption posture and key configuration.",
		SchemaName:      "PlatformBucketEncryptionFacet",
		SchemaURL:       "urn:cerebro:entity-facet:bucket-encryption:v1",
		ApplicableKinds: []NodeKind{NodeKindBucket},
		SourceKeys:      []string{"encrypted", "default_encryption", "default_encryption_enabled", "kms_encrypted", "encryption_algorithm", "encryption_key_id", "bucket_key_enabled"},
		ClaimPredicates: []string{"encrypted", "default_encryption_enabled"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "encrypted", ValueType: "boolean"},
			{Key: "encryption_algorithm", ValueType: "string"},
			{Key: "encryption_key_id", ValueType: "string"},
			{Key: "bucket_key_enabled", ValueType: "boolean"},
		},
	},
	{
		ID:              "bucket_logging",
		Version:         "1.0.0",
		Title:           "Bucket Logging",
		Description:     "Bucket access logging configuration and target.",
		SchemaName:      "PlatformBucketLoggingFacet",
		SchemaURL:       "urn:cerebro:entity-facet:bucket-logging:v1",
		ApplicableKinds: []NodeKind{NodeKindBucket},
		SourceKeys:      []string{"logging_enabled", "access_logging_enabled", "logging_target_bucket"},
		ClaimPredicates: []string{"access_logging_enabled"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "logging_enabled", ValueType: "boolean"},
			{Key: "logging_target_bucket", ValueType: "string"},
		},
	},
	{
		ID:              "bucket_versioning",
		Version:         "1.0.0",
		Title:           "Bucket Versioning",
		Description:     "Bucket versioning and MFA delete posture.",
		SchemaName:      "PlatformBucketVersioningFacet",
		SchemaURL:       "urn:cerebro:entity-facet:bucket-versioning:v1",
		ApplicableKinds: []NodeKind{NodeKindBucket},
		SourceKeys:      []string{"versioning", "versioning_status", "mfa_delete"},
		ClaimPredicates: []string{"versioning_enabled"},
		Fields: []EntityFacetFieldDefinition{
			{Key: "versioning_status", ValueType: "string"},
			{Key: "mfa_delete", ValueType: "boolean"},
		},
	},
}

// ListEntityFacetDefinitions returns the built-in entity facet definitions.
func ListEntityFacetDefinitions() []EntityFacetDefinition {
	out := append([]EntityFacetDefinition(nil), defaultEntityFacetDefinitions...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	for i := range out {
		out[i] = cloneEntityFacetDefinition(out[i])
	}
	return out
}

// GetEntityFacetDefinition returns one built-in facet definition by ID.
func GetEntityFacetDefinition(id string) (EntityFacetDefinition, bool) {
	id = strings.TrimSpace(id)
	for _, def := range defaultEntityFacetDefinitions {
		if def.ID == id {
			return cloneEntityFacetDefinition(def), true
		}
	}
	return EntityFacetDefinition{}, false
}

func cloneEntityFacetDefinition(def EntityFacetDefinition) EntityFacetDefinition {
	def.ApplicableKinds = append([]NodeKind(nil), def.ApplicableKinds...)
	def.SourceKeys = append([]string(nil), def.SourceKeys...)
	def.ClaimPredicates = append([]string(nil), def.ClaimPredicates...)
	def.Fields = append([]EntityFacetFieldDefinition(nil), def.Fields...)
	return def
}

func buildEntityCanonicalRef(node *Node) EntityCanonicalRef {
	ref := EntityCanonicalRef{
		ID:       strings.TrimSpace(node.ID),
		Kind:     node.Kind,
		Name:     entityCanonicalName(node),
		Provider: strings.TrimSpace(node.Provider),
		Account:  strings.TrimSpace(node.Account),
		Region:   strings.TrimSpace(node.Region),
	}
	ref.Namespace = entityCanonicalNamespace(node)
	return ref
}

func entityCanonicalNamespace(node *Node) string {
	parts := make([]string, 0, 3)
	if provider := strings.TrimSpace(node.Provider); provider != "" {
		parts = append(parts, provider)
	}
	if account := strings.TrimSpace(node.Account); account != "" {
		parts = append(parts, account)
	}
	if region := strings.TrimSpace(node.Region); region != "" {
		parts = append(parts, region)
	}
	if len(parts) > 0 {
		return strings.Join(parts, "/")
	}
	if idx := strings.Index(node.ID, ":"); idx > 0 {
		return node.ID[:idx]
	}
	return ""
}

func entityCanonicalName(node *Node) string {
	if name := strings.TrimSpace(node.Name); name != "" {
		return name
	}
	if arn, err := ParseARN(strings.TrimSpace(node.ID)); err == nil {
		resource := strings.TrimSpace(arn.Resource)
		if resource == "" {
			return strings.TrimSpace(node.ID)
		}
		resource = strings.TrimPrefix(resource, "bucket/")
		if idx := strings.LastIndexAny(resource, "/:"); idx >= 0 && idx+1 < len(resource) {
			return resource[idx+1:]
		}
		return resource
	}
	value := firstNonEmpty(
		readString(node.Properties, "bucket_name", "bucket_id", "service_id", "workload_id", "database_id", "db_instance_identifier", "instance_id", "resource_id", "external_id"),
		strings.TrimSpace(node.ID),
	)
	if idx := strings.LastIndexAny(value, "/:"); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	return value
}

func buildEntityExternalRefs(node *Node) []EntityExternalRef {
	var refs []EntityExternalRef
	seen := make(map[string]struct{})
	appendRef := func(ref EntityExternalRef) {
		ref.Type = strings.TrimSpace(ref.Type)
		ref.Value = strings.TrimSpace(ref.Value)
		ref.System = strings.TrimSpace(ref.System)
		ref.URL = strings.TrimSpace(ref.URL)
		if ref.Type == "" || ref.Value == "" {
			return
		}
		key := ref.System + "|" + ref.Type + "|" + ref.Value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}

	id := strings.TrimSpace(node.ID)
	if id != "" {
		switch {
		case strings.HasPrefix(id, "arn:"):
			appendRef(EntityExternalRef{System: firstNonEmpty(node.Provider, "aws"), Type: "arn", Value: id, Primary: true})
		case strings.HasPrefix(strings.ToLower(id), "/subscriptions/"):
			appendRef(EntityExternalRef{System: firstNonEmpty(node.Provider, "azure"), Type: "resource_id", Value: id, Primary: true})
		default:
			appendRef(EntityExternalRef{System: strings.TrimSpace(node.Provider), Type: "provider_id", Value: id, Primary: true})
		}
	}
	propertyRefs := []struct {
		key string
		typ string
	}{
		{key: "arn", typ: "arn"},
		{key: "resource_id", typ: "resource_id"},
		{key: "external_id", typ: "external_id"},
		{key: "service_id", typ: "service_id"},
		{key: "workload_id", typ: "workload_id"},
		{key: "database_id", typ: "database_id"},
		{key: "db_instance_identifier", typ: "database_id"},
		{key: "instance_id", typ: "instance_id"},
		{key: "bucket_id", typ: "bucket_id"},
		{key: "bucket_name", typ: "bucket_name"},
		{key: "project_id", typ: "project_id"},
		{key: "subscription_id", typ: "subscription_id"},
		{key: "url", typ: "url"},
	}
	for _, candidate := range propertyRefs {
		value := strings.TrimSpace(readString(node.Properties, candidate.key))
		if value == "" {
			continue
		}
		ref := EntityExternalRef{
			System: strings.TrimSpace(node.Provider),
			Type:   candidate.typ,
			Value:  value,
		}
		if candidate.typ == "url" {
			ref.URL = value
		}
		appendRef(ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Primary != refs[j].Primary {
			return refs[i].Primary
		}
		if refs[i].Type != refs[j].Type {
			return refs[i].Type < refs[j].Type
		}
		if refs[i].System != refs[j].System {
			return refs[i].System < refs[j].System
		}
		return refs[i].Value < refs[j].Value
	})
	return refs
}

func buildEntityAliasRecords(g *Graph, node *Node, validAt, recordedAt time.Time) []EntityAliasRecord {
	if g == nil || node == nil {
		return nil
	}
	var aliases []EntityAliasRecord
	seen := make(map[string]struct{})
	for _, edge := range g.GetInEdgesBitemporal(node.ID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindAliasOf {
			continue
		}
		aliasNode, ok := g.GetNode(edge.Source)
		if !ok || aliasNode == nil {
			continue
		}
		key := strings.TrimSpace(aliasNode.ID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		aliases = append(aliases, EntityAliasRecord{
			ID:           key,
			Kind:         aliasNode.Kind,
			Name:         strings.TrimSpace(aliasNode.Name),
			AliasType:    strings.TrimSpace(readString(aliasNode.Properties, "alias_type")),
			SourceSystem: firstNonEmpty(strings.TrimSpace(readString(aliasNode.Properties, "source_system")), strings.TrimSpace(aliasNode.Provider)),
		})
	}
	for _, value := range stringSliceFromValue(node.Properties["aliases"]) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := "property|" + value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		aliases = append(aliases, EntityAliasRecord{
			Name: value,
		})
	}
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].Kind != aliases[j].Kind {
			return aliases[i].Kind < aliases[j].Kind
		}
		if aliases[i].AliasType != aliases[j].AliasType {
			return aliases[i].AliasType < aliases[j].AliasType
		}
		if aliases[i].Name != aliases[j].Name {
			return aliases[i].Name < aliases[j].Name
		}
		return aliases[i].ID < aliases[j].ID
	})
	return aliases
}

func buildEntityFacetRecords(g *Graph, node *Node, validAt, recordedAt time.Time, claims []ClaimRecord) []EntityFacetRecord {
	if node == nil {
		return nil
	}
	claimIndex := indexClaimRecordsByPredicate(claims)
	records := make([]EntityFacetRecord, 0, len(defaultEntityFacetDefinitions))
	for _, def := range defaultEntityFacetDefinitions {
		if !entityFacetAppliesToNode(def, node.Kind) {
			continue
		}
		record, ok := materializeEntityFacet(g, node, validAt, recordedAt, def, claimIndex)
		if !ok {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Assessment != records[j].Assessment {
			return entityFacetAssessmentOrder(records[i].Assessment) < entityFacetAssessmentOrder(records[j].Assessment)
		}
		return records[i].ID < records[j].ID
	})
	return records
}

func entityFacetAppliesToNode(def EntityFacetDefinition, kind NodeKind) bool {
	if len(def.ApplicableKinds) == 0 {
		return true
	}
	for _, candidate := range def.ApplicableKinds {
		if candidate == kind {
			return true
		}
	}
	return false
}

func materializeEntityFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	switch def.ID {
	case "ownership":
		return materializeOwnershipFacet(g, node, validAt, recordedAt, def, claimIndex)
	case "exposure":
		return materializeExposureFacet(g, node, validAt, recordedAt, def, claimIndex)
	case "data_sensitivity":
		return materializeDataSensitivityFacet(node, def, claimIndex)
	case "workload_security":
		return materializeWorkloadSecurityFacet(g, node, validAt, recordedAt, def)
	case "bucket_public_access":
		return materializeBucketPublicAccessFacet(g, node, validAt, recordedAt, def, claimIndex)
	case "bucket_encryption":
		return materializeBucketEncryptionFacet(g, node, validAt, recordedAt, def, claimIndex)
	case "bucket_logging":
		return materializeBucketLoggingFacet(g, node, validAt, recordedAt, def, claimIndex)
	case "bucket_versioning":
		return materializeBucketVersioningFacet(g, node, validAt, recordedAt, def, claimIndex)
	default:
		return EntityFacetRecord{}, false
	}
}

func materializeOwnershipFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	owners := make([]string, 0)
	managers := make([]string, 0)
	appendUnique := func(values *[]string, candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		for _, existing := range *values {
			if existing == candidate {
				return
			}
		}
		*values = append(*values, candidate)
	}
	for _, record := range claimIndex["owner"] {
		appendUnique(&owners, firstNonEmpty(record.ObjectID, record.ObjectValue))
	}
	for _, record := range claimIndex["managed_by"] {
		appendUnique(&managers, firstNonEmpty(record.ObjectID, record.ObjectValue))
	}
	if g != nil {
		for _, edge := range g.GetInEdgesBitemporal(node.ID, validAt, recordedAt) {
			if edge == nil {
				continue
			}
			switch edge.Kind {
			case EdgeKindOwns:
				appendUnique(&owners, edge.Source)
			}
		}
		for _, edge := range g.GetOutEdgesBitemporal(node.ID, validAt, recordedAt) {
			if edge == nil {
				continue
			}
			if edge.Kind == EdgeKindManagedBy {
				appendUnique(&managers, edge.Target)
			}
		}
	}
	sort.Strings(owners)
	sort.Strings(managers)
	if len(owners) == 0 && len(managers) == 0 {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "warn",
			Summary:         "No typed owner or manager context attached",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	summary := fmt.Sprintf("%d owner(s), %d manager(s)", len(owners), len(managers))
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      "info",
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields: map[string]any{
			"owner_ids":   owners,
			"manager_ids": managers,
		},
	}, true
}

func materializeExposureFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	internetExposed := false
	if g != nil {
		for _, edge := range g.GetInEdgesBitemporal(node.ID, validAt, recordedAt) {
			if edge != nil && edge.Kind == EdgeKindExposedTo && (edge.Source == string(NodeKindInternet) || edge.Source == "internet") {
				internetExposed = true
				break
			}
		}
	}
	publicAccess, publicKnown := entityPropertyOrClaimBool(node, claimIndex, []string{"public", "public_access", "internet_accessible", "publicly_accessible"}, []string{"public_access", "internet_exposed"})
	if !publicKnown && internetExposed {
		publicAccess = true
		publicKnown = true
	}
	if !publicKnown && !internetExposed {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No exposure signals available",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	assessment := "pass"
	if publicAccess || internetExposed {
		assessment = "fail"
	}
	summary := "No public exposure detected"
	if publicAccess || internetExposed {
		summary = "Entity is publicly reachable or internet exposed"
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      assessment,
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields: map[string]any{
			"internet_exposed": internetExposed,
			"public_access":    publicAccess,
		},
	}, true
}

func materializeDataSensitivityFacet(node *Node, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	classification := firstNonEmpty(
		strings.TrimSpace(node.Tags["data_classification"]),
		strings.TrimSpace(readString(node.Properties, "data_classification", "classification")),
		latestClaimScalarValue(claimIndex["data_classification"]),
	)
	fields := map[string]any{
		"contains_pii":     readBool(node.Properties, "contains_pii"),
		"contains_phi":     readBool(node.Properties, "contains_phi"),
		"contains_pci":     readBool(node.Properties, "contains_pci"),
		"contains_secrets": readBool(node.Properties, "contains_secrets"),
	}
	if classification != "" {
		fields["classification"] = classification
	}
	sensitive := fields["contains_pii"].(bool) || fields["contains_phi"].(bool) || fields["contains_pci"].(bool) || fields["contains_secrets"].(bool) || classification != ""
	if !sensitive {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No typed sensitivity markers attached",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	summary := "Typed sensitivity markers attached"
	if classification != "" {
		summary = fmt.Sprintf("Classification %s with typed sensitivity markers", classification)
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      "info",
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields:          fields,
	}, true
}

func materializeWorkloadSecurityFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition) (EntityFacetRecord, bool) {
	if g == nil || node == nil {
		return EntityFacetRecord{}, false
	}

	scanNode, ok := latestWorkloadScanNodeAt(g, node.ID, validAt, recordedAt)
	if !ok || scanNode == nil {
		return EntityFacetRecord{
			ID:         def.ID,
			Title:      def.Title,
			SchemaName: def.SchemaName,
			SchemaURL:  def.SchemaURL,
			Status:     "missing",
			Assessment: "warn",
			Summary:    "No workload scan recorded for this entity",
		}, true
	}

	lastScannedAt, _ := temporalPropertyTime(scanNode.Properties, "completed_at")
	if lastScannedAt.IsZero() {
		lastScannedAt, _ = temporalPropertyTime(scanNode.Properties, "observed_at")
	}

	view := g.SubgraphBitemporal(validAt, recordedAt)
	if view == nil {
		view = g
	}
	blast := BlastRadius(view, node.ID, 3)
	cascade := CascadingBlastRadius(view, node.ID, 4)
	internetExposed := entityHasInternetExposureAt(view, node.ID, validAt, recordedAt)
	adminReachable := 0
	for _, reachable := range blast.ReachableNodes {
		if reachable == nil {
			continue
		}
		if reachable.EdgeKind == EdgeKindCanAdmin {
			adminReachable++
			continue
		}
		for _, action := range reachable.Actions {
			if action == "*" || strings.Contains(strings.ToLower(strings.TrimSpace(action)), "admin") {
				adminReachable++
				break
			}
		}
	}

	fields := map[string]any{
		"last_scan_id":                 scanNode.ID,
		"last_scanned_at":              formatWorkloadSecurityFacetTime(lastScannedAt),
		"stale":                        workloadSecurityFacetStale(lastScannedAt, validAt),
		"os_name":                      readString(scanNode.Properties, "os_name"),
		"os_version":                   readString(scanNode.Properties, "os_version"),
		"os_architecture":              readString(scanNode.Properties, "os_architecture"),
		"package_count":                readInt(scanNode.Properties, "package_count"),
		"vulnerability_count":          readInt(scanNode.Properties, "vulnerability_count"),
		"critical_vulnerability_count": readInt(scanNode.Properties, "critical_vulnerability_count"),
		"high_vulnerability_count":     readInt(scanNode.Properties, "high_vulnerability_count"),
		"known_exploited_count":        readInt(scanNode.Properties, "known_exploited_count"),
		"fixable_vulnerability_count":  readInt(scanNode.Properties, "fixable_vulnerability_count"),
		"internet_exposed":             internetExposed,
		"admin_reachable_count":        adminReachable,
		"sensitive_data_path_count":    len(cascade.SensitiveDataHits),
		"cross_account_risk":           blast.CrossAccountRisk,
		"prioritized_risk":             string(workloadSecurityPrioritizedRisk(scanNode, internetExposed, adminReachable, len(cascade.SensitiveDataHits), blast.CrossAccountRisk)),
	}

	assessment := "pass"
	summary := "Recent workload scan shows low attack-path context"
	if fields["stale"].(bool) {
		assessment = "warn"
		summary = "Workload scan data is stale"
	}
	if prioritized := workloadSecurityPrioritizedRisk(scanNode, internetExposed, adminReachable, len(cascade.SensitiveDataHits), blast.CrossAccountRisk); prioritized == RiskCritical {
		assessment = "fail"
		summary = "Critical workload vulnerabilities combine with reachable attack-path context"
	} else if prioritized == RiskHigh && assessment != "warn" {
		assessment = "warn"
		summary = "Workload scan shows exploitable vulnerability depth with meaningful blast radius"
	}
	if readInt(scanNode.Properties, "vulnerability_count") == 0 && !fields["stale"].(bool) {
		assessment = "pass"
		summary = "Latest workload scan found no tracked package vulnerabilities"
	}

	return EntityFacetRecord{
		ID:         def.ID,
		Title:      def.Title,
		SchemaName: def.SchemaName,
		SchemaURL:  def.SchemaURL,
		Status:     "present",
		Assessment: assessment,
		Summary:    summary,
		Fields:     fields,
	}, true
}

func latestWorkloadScanNodeAt(g *Graph, entityID string, validAt, recordedAt time.Time) (*Node, bool) {
	var latest *Node
	var latestAt time.Time
	for _, edge := range g.GetOutEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindHasScan {
			continue
		}
		node, ok := g.GetNode(edge.Target)
		if !ok || node == nil || node.Kind != NodeKindWorkloadScan {
			continue
		}
		candidateAt, _ := temporalPropertyTime(node.Properties, "completed_at")
		if candidateAt.IsZero() {
			candidateAt, _ = temporalPropertyTime(node.Properties, "observed_at")
		}
		if latest == nil || candidateAt.After(latestAt) {
			latest = node
			latestAt = candidateAt
		}
	}
	return latest, latest != nil
}

func entityHasInternetExposureAt(g *Graph, entityID string, validAt, recordedAt time.Time) bool {
	for _, edge := range g.GetInEdgesBitemporal(entityID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindExposedTo {
			continue
		}
		if edge.Source == string(NodeKindInternet) || edge.Source == "internet" {
			return true
		}
	}
	return false
}

func workloadSecurityFacetStale(lastScannedAt, validAt time.Time) bool {
	if lastScannedAt.IsZero() {
		return true
	}
	reference := validAt.UTC()
	if reference.IsZero() {
		reference = time.Now().UTC()
	}
	return reference.Sub(lastScannedAt.UTC()) > 24*time.Hour
}

func formatWorkloadSecurityFacetTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func workloadSecurityPrioritizedRisk(scanNode *Node, internetExposed bool, adminReachable, sensitiveDataPaths int, crossAccountRisk bool) RiskLevel {
	if scanNode == nil {
		return RiskNone
	}
	criticalCount := readInt(scanNode.Properties, "critical_vulnerability_count")
	highCount := readInt(scanNode.Properties, "high_vulnerability_count")
	kevCount := readInt(scanNode.Properties, "known_exploited_count")
	if kevCount > 0 && (internetExposed || adminReachable > 0 || sensitiveDataPaths > 0) {
		return RiskCritical
	}
	if criticalCount > 0 && (internetExposed || adminReachable > 0 || sensitiveDataPaths > 0 || crossAccountRisk) {
		return RiskCritical
	}
	if criticalCount > 0 || (highCount > 0 && (internetExposed || adminReachable > 0 || sensitiveDataPaths > 0)) {
		return RiskHigh
	}
	if highCount > 0 || readInt(scanNode.Properties, "vulnerability_count") > 0 {
		return RiskMedium
	}
	return RiskLow
}

func materializeBucketPublicAccessFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	properties := node.Properties
	if subresource, ok := relatedBucketSubresourceNode(g, node.ID, NodeKindBucketPublicAccessBlock, validAt, recordedAt); ok && subresource != nil {
		properties = subresource.Properties
	}
	publicAccess, publicAccessKnown := entityPropertyOrClaimBool(&Node{Properties: node.Properties}, claimIndex, []string{"public", "public_access"}, []string{"public_access"})
	fields := map[string]any{
		"public_access":                  publicAccess,
		"block_public_acls":              readBool(properties, "block_public_acls"),
		"block_public_policy":            readBool(properties, "block_public_policy"),
		"restrict_public_buckets":        readBool(properties, "restrict_public_buckets"),
		"all_users_access":               readBool(node.Properties, "all_users_access"),
		"all_authenticated_users_access": readBool(node.Properties, "all_authenticated_users_access"),
	}
	known := publicAccessKnown ||
		propertyHasAnyKey(properties, "block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets", "public_access_prevention") ||
		propertyHasAnyKey(node.Properties, "public", "public_access", "all_users_access", "all_authenticated_users_access", "anonymous_access")
	if !known {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No bucket public-access configuration available",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	publicAccess = publicAccess || fields["all_users_access"].(bool) || fields["all_authenticated_users_access"].(bool)
	fields["public_access"] = publicAccess
	blocked := fields["block_public_acls"].(bool) && fields["block_public_policy"].(bool)
	assessment := "pass"
	summary := "Public-access controls are configured"
	if publicAccess || !blocked {
		assessment = "fail"
		summary = "Bucket exposure or public-access-block settings indicate public risk"
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      assessment,
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields:          fields,
	}, true
}

func materializeBucketEncryptionFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	properties := node.Properties
	if subresource, ok := relatedBucketSubresourceNode(g, node.ID, NodeKindBucketEncryptionConfig, validAt, recordedAt); ok && subresource != nil {
		properties = subresource.Properties
	}
	encrypted, known := entityPropertyOrClaimBool(node, claimIndex, []string{"encrypted", "default_encryption", "default_encryption_enabled", "kms_encrypted"}, []string{"encrypted", "default_encryption_enabled"})
	if !known {
		encrypted, known = entityPropertyOrClaimBool(&Node{Properties: properties}, nil, []string{"encrypted", "default_encryption", "default_encryption_enabled", "kms_encrypted"}, nil)
	}
	fields := map[string]any{
		"encrypted":            encrypted,
		"encryption_algorithm": strings.TrimSpace(readString(properties, "encryption_algorithm")),
		"encryption_key_id":    strings.TrimSpace(readString(properties, "encryption_key_id")),
		"bucket_key_enabled":   readBool(properties, "bucket_key_enabled"),
	}
	if !known && fields["encryption_algorithm"] == "" && fields["encryption_key_id"] == "" && !fields["bucket_key_enabled"].(bool) {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No bucket encryption configuration available",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	assessment := "fail"
	summary := "Bucket encryption is disabled or unknown"
	if encrypted {
		assessment = "pass"
		summary = "Bucket encryption is enabled"
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      assessment,
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields:          fields,
	}, true
}

func materializeBucketLoggingFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	properties := node.Properties
	if subresource, ok := relatedBucketSubresourceNode(g, node.ID, NodeKindBucketLoggingConfig, validAt, recordedAt); ok && subresource != nil {
		properties = subresource.Properties
	}
	enabled, known := entityPropertyOrClaimBool(node, claimIndex, []string{"logging_enabled", "access_logging_enabled"}, []string{"access_logging_enabled"})
	if !known {
		enabled, known = entityPropertyOrClaimBool(&Node{Properties: properties}, nil, []string{"logging_enabled", "access_logging_enabled"}, nil)
	}
	targetBucket := strings.TrimSpace(readString(properties, "logging_target_bucket"))
	if !known && targetBucket == "" {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No bucket logging configuration available",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	assessment := "warn"
	summary := "Bucket access logging is not enabled"
	if enabled {
		assessment = "pass"
		summary = "Bucket access logging is enabled"
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      assessment,
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields: map[string]any{
			"logging_enabled":       enabled,
			"logging_target_bucket": targetBucket,
		},
	}, true
}

func materializeBucketVersioningFacet(g *Graph, node *Node, validAt, recordedAt time.Time, def EntityFacetDefinition, claimIndex map[string][]ClaimRecord) (EntityFacetRecord, bool) {
	properties := node.Properties
	if subresource, ok := relatedBucketSubresourceNode(g, node.ID, NodeKindBucketVersioningConfig, validAt, recordedAt); ok && subresource != nil {
		properties = subresource.Properties
	}
	status := strings.ToLower(strings.TrimSpace(readString(node.Properties, "versioning", "versioning_status")))
	known := propertyHasAnyKey(node.Properties, "versioning_status", "versioning", "mfa_delete")
	if status == "" {
		if value, ok := claimBoolValue(claimIndex["versioning_enabled"]); ok {
			known = true
			if value {
				status = "enabled"
			} else {
				status = "disabled"
			}
		}
	}
	if !known {
		status = strings.ToLower(strings.TrimSpace(readString(properties, "versioning", "versioning_status")))
		known = propertyHasAnyKey(properties, "versioning_status", "versioning", "mfa_delete")
	}
	mfaDelete := readBool(properties, "mfa_delete")
	if !known {
		return EntityFacetRecord{
			ID:              def.ID,
			Title:           def.Title,
			SchemaName:      def.SchemaName,
			SchemaURL:       def.SchemaURL,
			Status:          "missing",
			Assessment:      "unknown",
			Summary:         "No bucket versioning configuration available",
			SourceKeys:      append([]string(nil), def.SourceKeys...),
			ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		}, true
	}
	status = firstNonEmpty(status, "disabled")
	assessment := "warn"
	summary := "Bucket versioning is not enabled"
	if status == "enabled" || status == "on" {
		assessment = "pass"
		summary = "Bucket versioning is enabled"
	}
	return EntityFacetRecord{
		ID:              def.ID,
		Title:           def.Title,
		SchemaName:      def.SchemaName,
		SchemaURL:       def.SchemaURL,
		Status:          "present",
		Assessment:      assessment,
		Summary:         summary,
		SourceKeys:      append([]string(nil), def.SourceKeys...),
		ClaimPredicates: append([]string(nil), def.ClaimPredicates...),
		Fields: map[string]any{
			"versioning_status": status,
			"mfa_delete":        mfaDelete,
		},
	}, true
}

func buildEntityPostureSummary(claims []ClaimRecord, referenceTime time.Time) *EntityPostureSummary {
	postureClaims := make([]EntityPostureClaimRecord, 0)
	for _, record := range claims {
		if !isEntityPosturePredicate(record.Predicate) {
			continue
		}
		posture := EntityPostureClaimRecord{
			ClaimID:       record.ID,
			Predicate:     record.Predicate,
			ObjectID:      record.ObjectID,
			ObjectValue:   record.ObjectValue,
			Status:        record.Status,
			Assessment:    postureClaimAssessment(record),
			Summary:       firstNonEmpty(strings.TrimSpace(record.Summary), entityPostureClaimSummary(record)),
			Confidence:    record.Confidence,
			ObservedAt:    record.ObservedAt,
			Supported:     record.Derived.Supported,
			Conflicted:    record.Derived.Conflicted,
			EvidenceCount: record.Derived.EvidenceCount,
			SourceCount:   record.Derived.SourceCount,
		}
		if !referenceTime.IsZero() && !record.ObservedAt.IsZero() && referenceTime.Sub(record.ObservedAt) > entityPostureStaleAfter {
			posture.Stale = true
		}
		postureClaims = append(postureClaims, posture)
	}
	if len(postureClaims) == 0 {
		return nil
	}
	sort.Slice(postureClaims, func(i, j int) bool {
		if postureClaims[i].Assessment != postureClaims[j].Assessment {
			return entityFacetAssessmentOrder(postureClaims[i].Assessment) < entityFacetAssessmentOrder(postureClaims[j].Assessment)
		}
		if postureClaims[i].Supported != postureClaims[j].Supported {
			return postureClaims[i].Supported
		}
		if !postureClaims[i].ObservedAt.Equal(postureClaims[j].ObservedAt) {
			return postureClaims[i].ObservedAt.After(postureClaims[j].ObservedAt)
		}
		return postureClaims[i].ClaimID < postureClaims[j].ClaimID
	})
	summary := &EntityPostureSummary{
		Claims: postureClaims,
	}
	for _, claim := range postureClaims {
		summary.ActiveClaimCount++
		if claim.Supported {
			summary.SupportedClaimCount++
		}
		if claim.Conflicted {
			summary.DisputedClaimCount++
		}
		if claim.Stale {
			summary.StaleClaimCount++
		}
	}
	return summary
}

func isEntityPosturePredicate(predicate string) bool {
	switch strings.TrimSpace(predicate) {
	case "public_access", "internet_exposed", "encrypted", "default_encryption_enabled", "access_logging_enabled", "versioning_enabled", "backup_enabled", "contains_sensitive_data", "data_classification":
		return true
	default:
		return false
	}
}

func postureClaimAssessment(record ClaimRecord) string {
	value := strings.ToLower(strings.TrimSpace(firstNonEmpty(record.ObjectValue, record.ObjectID)))
	switch strings.TrimSpace(record.Predicate) {
	case "public_access", "internet_exposed":
		if value == "true" || value == "public" || value == "enabled" {
			return "fail"
		}
		return "pass"
	case "encrypted", "default_encryption_enabled", "access_logging_enabled", "versioning_enabled", "backup_enabled":
		if value == "false" || value == "disabled" || value == "off" {
			return "fail"
		}
		if value == "true" || value == "enabled" || value == "on" {
			return "pass"
		}
	case "contains_sensitive_data", "data_classification":
		return "info"
	}
	if record.Derived.Conflicted {
		return "warn"
	}
	return "info"
}

func entityPostureClaimSummary(record ClaimRecord) string {
	value := strings.TrimSpace(firstNonEmpty(record.ObjectValue, record.ObjectID))
	if value == "" {
		return record.Predicate
	}
	return fmt.Sprintf("%s = %s", record.Predicate, value)
}

func indexClaimRecordsByPredicate(claims []ClaimRecord) map[string][]ClaimRecord {
	index := make(map[string][]ClaimRecord)
	for _, record := range claims {
		predicate := strings.TrimSpace(record.Predicate)
		if predicate == "" {
			continue
		}
		index[predicate] = append(index[predicate], record)
	}
	for key := range index {
		sort.Slice(index[key], func(i, j int) bool {
			if !index[key][i].ObservedAt.Equal(index[key][j].ObservedAt) {
				return index[key][i].ObservedAt.After(index[key][j].ObservedAt)
			}
			return index[key][i].ID < index[key][j].ID
		})
	}
	return index
}

func latestClaimScalarValue(claims []ClaimRecord) string {
	for _, record := range claims {
		value := strings.TrimSpace(firstNonEmpty(record.ObjectValue, record.ObjectID))
		if value != "" {
			return value
		}
	}
	return ""
}

func claimBoolValue(claims []ClaimRecord) (bool, bool) {
	for _, record := range claims {
		value := strings.ToLower(strings.TrimSpace(firstNonEmpty(record.ObjectValue, record.ObjectID)))
		switch value {
		case "true", "enabled", "on", "public", "internet":
			return true, true
		case "false", "disabled", "off", "private", "internal":
			return false, true
		}
	}
	return false, false
}

func entityPropertyOrClaimBool(node *Node, claimIndex map[string][]ClaimRecord, propertyKeys, predicateKeys []string) (bool, bool) {
	for _, key := range propertyKeys {
		if _, ok := node.Properties[key]; ok {
			return readBool(node.Properties, key), true
		}
	}
	for _, key := range predicateKeys {
		if value, ok := claimBoolValue(claimIndex[key]); ok {
			return value, true
		}
	}
	return false, false
}

func entityFacetAssessmentOrder(value string) int {
	switch value {
	case "fail":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	case "pass":
		return 3
	default:
		return 4
	}
}
