package attestedcompute

import (
	"encoding/json"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type GraphDelta struct {
	Attestation Attestation `json:"attestation"`
	Entities    []Entity    `json:"entities"`
	Links       []Link      `json:"links"`
}

type Attestation struct {
	Format      string `json:"format"`
	Measurement string `json:"measurement"`
	KeyID       string `json:"key_id"`
	ImageDigest string `json:"image_digest"`
}

type Entity struct {
	URN        string            `json:"urn"`
	EntityType string            `json:"entity_type"`
	Label      string            `json:"label,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Link struct {
	FromURN    string            `json:"from_urn"`
	ToURN      string            `json:"to_urn"`
	Relation   string            `json:"relation"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func ProjectEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("attested compute event is required")
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	if tenantID == "" {
		return nil, nil, fmt.Errorf("attested compute tenant_id is required")
	}
	if strings.TrimSpace(event.GetKind()) != EventKindGraphDelta {
		return nil, nil, fmt.Errorf("attested compute event kind %q is unsupported", event.GetKind())
	}
	var delta GraphDelta
	if err := json.Unmarshal(event.GetPayload(), &delta); err != nil {
		return nil, nil, fmt.Errorf("decode attested compute graph delta: %w", err)
	}
	if len(delta.Entities) == 0 && len(delta.Links) == 0 {
		return nil, nil, nil
	}
	if err := validateAttestation(delta.Attestation); err != nil {
		return nil, nil, err
	}
	sourceID := strings.TrimSpace(event.GetSourceId())
	entities := make([]*ports.ProjectedEntity, 0, len(delta.Entities))
	for _, entity := range delta.Entities {
		projected, err := projectEntity(tenantID, sourceID, delta.Attestation, entity)
		if err != nil {
			return nil, nil, err
		}
		entities = append(entities, projected)
	}
	links := make([]*ports.ProjectedLink, 0, len(delta.Links))
	for _, link := range delta.Links {
		projected, err := projectLink(tenantID, sourceID, delta.Attestation, link)
		if err != nil {
			return nil, nil, err
		}
		links = append(links, projected)
	}
	return entities, links, nil
}

func projectEntity(tenantID string, sourceID string, attestation Attestation, entity Entity) (*ports.ProjectedEntity, error) {
	urn := strings.TrimSpace(entity.URN)
	entityType := strings.TrimSpace(entity.EntityType)
	if urn == "" || entityType == "" {
		return nil, fmt.Errorf("attested compute entity urn and entity_type are required")
	}
	if !tenantScopedURN(tenantID, urn) {
		return nil, fmt.Errorf("attested compute entity urn %q is outside tenant scope", urn)
	}
	if sensitiveEntityType(entityType) && !attestedURN(tenantID, urn) {
		return nil, fmt.Errorf("attested compute sensitive entity %q must use an attested token urn", entityType)
	}
	label := strings.TrimSpace(entity.Label)
	if sensitiveEntityType(entityType) && label != "" && !TokenLike(label) {
		return nil, fmt.Errorf("attested compute sensitive entity %q label must be tokenized", entityType)
	}
	attributes, err := sanitizeAttributes(tenantID, entity.Attributes)
	if err != nil {
		return nil, fmt.Errorf("attested compute entity %q attributes: %w", urn, err)
	}
	stampAttestation(attributes, attestation)
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      label,
		Attributes: attributes,
	}, nil
}

func projectLink(tenantID string, sourceID string, attestation Attestation, link Link) (*ports.ProjectedLink, error) {
	fromURN := strings.TrimSpace(link.FromURN)
	toURN := strings.TrimSpace(link.ToURN)
	relation := strings.TrimSpace(link.Relation)
	if fromURN == "" || toURN == "" || relation == "" {
		return nil, fmt.Errorf("attested compute link from_urn, to_urn, and relation are required")
	}
	if !tenantScopedURN(tenantID, fromURN) || !tenantScopedURN(tenantID, toURN) {
		return nil, fmt.Errorf("attested compute link endpoints must stay inside tenant scope")
	}
	if !allowedRelation(relation) {
		return nil, fmt.Errorf("attested compute relation %q is not allowed", relation)
	}
	attributes, err := sanitizeAttributes(tenantID, link.Attributes)
	if err != nil {
		return nil, fmt.Errorf("attested compute link %q attributes: %w", relation, err)
	}
	stampAttestation(attributes, attestation)
	return &ports.ProjectedLink{
		TenantID:   tenantID,
		SourceID:   sourceID,
		FromURN:    fromURN,
		ToURN:      toURN,
		Relation:   relation,
		Attributes: attributes,
	}, nil
}

func validateAttestation(attestation Attestation) error {
	if strings.TrimSpace(attestation.Format) == "" {
		return fmt.Errorf("attested compute attestation format is required")
	}
	if strings.TrimSpace(attestation.Measurement) == "" && strings.TrimSpace(attestation.ImageDigest) == "" {
		return fmt.Errorf("attested compute attestation measurement or image_digest is required")
	}
	return nil
}

func sanitizeAttributes(tenantID string, input map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(input)+4)
	for rawKey, rawValue := range input {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" || value == "" {
			continue
		}
		if sensitiveAttributeKey(key) && !blindedValue(tenantID, value) {
			return nil, fmt.Errorf("%s must be tokenized or tenant-scoped attested urn", key)
		}
		out[key] = value
	}
	return out, nil
}

func stampAttestation(attributes map[string]string, attestation Attestation) {
	if attributes == nil {
		return
	}
	addAttribute(attributes, "attested_compute_format", attestation.Format)
	addAttribute(attributes, "attested_compute_measurement", attestation.Measurement)
	addAttribute(attributes, "attested_compute_key_id", attestation.KeyID)
	addAttribute(attributes, "attested_compute_image_digest", attestation.ImageDigest)
}

func addAttribute(attributes map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		attributes[key] = value
	}
}

func tenantScopedURN(tenantID string, urn string) bool {
	tenantID = strings.TrimSpace(tenantID)
	urn = strings.TrimSpace(urn)
	return tenantID != "" && strings.HasPrefix(urn, "urn:cerebro:"+tenantID+":")
}

func attestedURN(tenantID string, urn string) bool {
	tenantID = strings.TrimSpace(tenantID)
	urn = strings.TrimSpace(urn)
	return tenantID != "" && strings.HasPrefix(urn, "urn:cerebro:"+tenantID+":attested:")
}

func blindedValue(tenantID string, value string) bool {
	value = strings.TrimSpace(value)
	return TokenLike(value) || attestedURN(tenantID, value)
}

func sensitiveEntityType(entityType string) bool {
	entityType = strings.TrimSpace(entityType)
	if entityType == "" {
		return false
	}
	if entityType == "asset.tag" || entityType == "data.classification" {
		return false
	}
	switch {
	case strings.HasPrefix(entityType, "aws."):
		return true
	case strings.HasPrefix(entityType, "azure."):
		return true
	case strings.HasPrefix(entityType, "gcp."):
		return true
	case strings.HasPrefix(entityType, "google_workspace."):
		return true
	case strings.HasPrefix(entityType, "okta."):
		return true
	case strings.Contains(entityType, "user"):
		return true
	case strings.Contains(entityType, "identity"):
		return true
	case strings.Contains(entityType, "principal"):
		return true
	default:
		return false
	}
}

func sensitiveAttributeKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	if strings.HasPrefix(normalized, "risk_") ||
		strings.HasPrefix(normalized, "posture_") ||
		strings.HasPrefix(normalized, "control_") ||
		strings.HasPrefix(normalized, "classification_") ||
		strings.HasPrefix(normalized, "attested_compute_") {
		return false
	}
	switch normalized {
	case "is_admin", "is_delegated_admin", "is_public", "mfa_enrolled", "mfa_enforced", "status", "severity", "confidence", "observed_at", "at", "last_observed_at", "sensitivity_label":
		return false
	}
	for _, marker := range []string{"arn", "email", "hostname", "ip", "label", "name", "principal", "resource_id", "resource_urn", "user", "urn"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func allowedRelation(relation string) bool {
	switch strings.TrimSpace(relation) {
	case "acted_on",
		"affected_by",
		"affects",
		"assigned_to",
		"associated_with",
		"attached_to",
		"belongs_to",
		"can_admin",
		"can_assume",
		"can_impersonate",
		"can_perform",
		"can_reach",
		"contains",
		"has_classification",
		"has_evidence",
		"has_identifier",
		"member_of",
		"observed_on",
		"owned_by",
		"represents_identity",
		"runs_as",
		"same_actor",
		"tagged_as":
		return true
	default:
		return false
	}
}
