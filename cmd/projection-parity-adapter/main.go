// projection-parity-adapter is a temporary migration boundary. It runs the
// current Go projector and emits only the semantic facts governed by the
// catalog projection contract. Rust owns comparison, persistence, and cutover.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const adapterRevision = "go-sourceprojection-semantic-v2"

type runEnvelope struct {
	TenantID               string            `json:"tenant_id"`
	SourceRuntimeID        string            `json:"source_runtime_id"`
	SourceID               string            `json:"source_id"`
	FamilyID               string            `json:"family_id"`
	CollectionID           string            `json:"collection_id"`
	Complete               bool              `json:"complete"`
	ObservedAtUnixMS       int64             `json:"observed_at_unix_ms"`
	ComparedAtUnixMS       int64             `json:"compared_at_unix_ms"`
	ProjectionLag          uint64            `json:"projection_lag"`
	InputDigest            string            `json:"input_digest"`
	LegacyProjectorVersion string            `json:"legacy_projector_revision"`
	RustProjectorVersion   string            `json:"rust_projector_revision"`
	RuntimeVersions        map[string]string `json:"runtime_versions"`
	Records                []recordWire      `json:"records"`
	LegacyFacts            []factWire        `json:"legacy_facts,omitempty"`
}

type recordWire struct {
	ObservationID   string            `json:"observation_id"`
	Family          string            `json:"family"`
	ProviderKind    string            `json:"provider_kind"`
	ProviderID      string            `json:"provider_id"`
	Fields          map[string]string `json:"fields"`
	Payload         any               `json:"payload"`
	EventKind       string            `json:"event_kind"`
	EventAttributes map[string]string `json:"event_attributes"`
}

type factWire struct {
	Kind  string   `json:"kind"`
	Parts []string `json:"parts"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	var input runEnvelope
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("decode parity run: %w", err)
	}
	if err := validateEnvelope(&input); err != nil {
		return err
	}
	family, err := catalogFamily(input.SourceID, input.FamilyID)
	if err != nil {
		return err
	}
	facts := make([]factWire, 0, len(input.Records)*3)
	for _, record := range input.Records {
		recordFacts, err := projectRecord(input, family, record)
		if err != nil {
			return err
		}
		facts = append(facts, recordFacts...)
	}
	sort.Slice(facts, func(i, j int) bool {
		return canonicalFact(facts[i]) < canonicalFact(facts[j])
	})
	input.LegacyFacts = deduplicateFacts(facts)
	input.LegacyProjectorVersion = adapterRevision
	input.RuntimeVersions["go"] = strings.TrimSpace(os.Getenv("CEREBRO_PARITY_GO_VERSION"))
	if input.RuntimeVersions["go"] == "" {
		input.RuntimeVersions["go"] = "go-runtime"
	}
	encodedRecords, err := json.Marshal(input.Records)
	if err != nil {
		return fmt.Errorf("encode parity records: %w", err)
	}
	sum := sha256.Sum256(encodedRecords)
	input.InputDigest = "sha256:" + hex.EncodeToString(sum[:])
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(input); err != nil {
		return fmt.Errorf("encode parity run: %w", err)
	}
	return nil
}

func validateEnvelope(input *runEnvelope) error {
	for field, value := range map[string]string{
		"tenant_id":         input.TenantID,
		"source_runtime_id": input.SourceRuntimeID,
		"source_id":         input.SourceID,
		"family_id":         input.FamilyID,
		"collection_id":     input.CollectionID,
	} {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s is required", field)
		}
	}
	if input.ObservedAtUnixMS <= 0 || input.ComparedAtUnixMS <= 0 {
		return errors.New("observed_at_unix_ms and compared_at_unix_ms must be positive")
	}
	if len(input.Records) == 0 {
		return errors.New("records are required")
	}
	if input.RuntimeVersions == nil {
		input.RuntimeVersions = map[string]string{}
	}
	return nil
}

func catalogFamily(sourceID, familyID string) (connectordefinitions.ResourceFamily, error) {
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil {
		return connectordefinitions.ResourceFamily{}, fmt.Errorf("load source catalog: %w", err)
	}
	if !ok {
		return connectordefinitions.ResourceFamily{}, fmt.Errorf("source %q is not in the catalog", sourceID)
	}
	for _, family := range entry.Definition.ResourceFamilies {
		if family.ID == familyID {
			return family, nil
		}
	}
	return connectordefinitions.ResourceFamily{}, fmt.Errorf(
		"family %q is not in source %q",
		familyID,
		sourceID,
	)
}

func projectRecord(
	run runEnvelope,
	family connectordefinitions.ResourceFamily,
	record recordWire,
) ([]factWire, error) {
	if record.Family != run.FamilyID {
		return nil, fmt.Errorf(
			"observation %q belongs to family %q, not %q",
			record.ObservationID,
			record.Family,
			run.FamilyID,
		)
	}
	attributes := cloneMap(record.EventAttributes)
	attributes[ports.EventAttributeSourceRuntimeID] = run.SourceRuntimeID
	eventKind := strings.TrimSpace(record.EventKind)
	if eventKind == "" {
		eventKind = run.SourceID + "." + run.FamilyID
	}
	payload, err := json.Marshal(record.Payload)
	if err != nil {
		return nil, fmt.Errorf("encode observation %q payload: %w", record.ObservationID, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         record.ObservationID,
		TenantId:   run.TenantID,
		SourceId:   run.SourceID,
		Kind:       eventKind,
		Payload:    payload,
		Attributes: attributes,
	}
	entities, links, err := projectCompatibilityEvent(event)
	if err != nil {
		return nil, fmt.Errorf("project observation %q: %w", record.ObservationID, err)
	}
	template := ""
	if family.Projection != nil {
		template = strings.TrimSpace(family.Projection.Template)
	}
	switch template {
	case "identity_user":
		return identityUserFacts(run, record, attributes, entities)
	case "identity_group":
		return identityGroupFacts(run, record, attributes, entities)
	case "group_membership":
		return membershipFacts(run, record, attributes, entities, links)
	case "audit_event":
		if run.SourceID == "doppler" {
			return dopplerAuditFacts(run, record, attributes, entities, links)
		}
		fallthrough
	default:
		return entityFacts(run, record, family, template, attributes, entities, links)
	}
}

// projectCompatibilityEvent keeps the retired Doppler projector's bounded
// semantic oracle inside this migration CLI. It is not registered with product
// projection and cannot become a production writer.
func projectCompatibilityEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event.GetSourceId() == "doppler" {
		return compatibilityOnlyDopplerProjection(event)
	}
	return sourceprojection.ProjectEvent(event)
}

func compatibilityOnlyDopplerProjection(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	attributes := event.GetAttributes()
	entity := func(kind, id, label string, values map[string]string) *ports.ProjectedEntity {
		return &ports.ProjectedEntity{
			URN:        compatibilityURN(kind, id),
			TenantID:   event.GetTenantId(),
			SourceID:   "doppler",
			EntityType: kind,
			Label:      label,
			Attributes: values,
		}
	}
	link := func(from, relation, to string) *ports.ProjectedLink {
		return &ports.ProjectedLink{
			TenantID: event.GetTenantId(),
			SourceID: "doppler",
			FromURN:  from,
			ToURN:    to,
			Relation: relation,
		}
	}

	switch event.GetKind() {
	case "doppler.secrets":
		secretID := first(attributes, "secret_id")
		if secretID == "" {
			secretID = event.GetId()
		}
		secretLabel := first(attributes, "secret_name")
		if secretLabel == "" {
			secretLabel = secretID
		}
		secret := entity("secret", secretID, secretLabel, map[string]string{"secret_id": secretID})
		entities := []*ports.ProjectedEntity{secret}
		var links []*ports.ProjectedLink
		if projectID := first(attributes, "project_id"); projectID != "" {
			project := entity("doppler.project", projectID, projectID, map[string]string{"project_id": projectID})
			entities = append(entities, project)
			links = append(links, link(secret.URN, "belongs_to", project.URN))
		}
		if evidenceID := first(attributes, "evidence_id"); evidenceID != "" {
			evidence := entity("runtime_evidence", evidenceID, evidenceID, map[string]string{"evidence_id": evidenceID})
			entities = append(entities, evidence)
			links = append(links, link(secret.URN, "has_evidence", evidence.URN))
		}
		return entities, links, nil
	case "doppler.projects":
		projectID := first(attributes, "resource_id", "external_id")
		if projectID == "" {
			projectID = event.GetId()
		}
		projectLabel := first(attributes, "resource_name")
		if projectLabel == "" {
			projectLabel = projectID
		}
		project := entity("doppler.project", projectID, projectLabel, map[string]string{"resource_id": projectID})
		entities := []*ports.ProjectedEntity{project}
		var links []*ports.ProjectedLink
		if evidenceID := first(attributes, "evidence_id"); evidenceID != "" {
			evidence := entity("runtime.evidence", evidenceID, evidenceID, map[string]string{"evidence_id": evidenceID})
			entities = append(entities, evidence)
			links = append(links, link(project.URN, "has_evidence", evidence.URN))
		}
		return entities, links, nil
	case "doppler.audit_events":
		actorID := first(attributes, "actor_id", "actor_email")
		resourceID := first(attributes, "resource_id", "target_id", "app_id", "group_id", "role_id")
		resourceType := first(attributes, "resource_type", "target_type")
		if resourceType == "" {
			resourceType = "resource"
		}
		var entities []*ports.ProjectedEntity
		var links []*ports.ProjectedLink
		var actor *ports.ProjectedEntity
		if actorID != "" {
			actorLabel := first(attributes, "actor_name", "actor_email", "actor_alternate_id", "actor_id")
			actor = entity("doppler.user", actorID, actorLabel, map[string]string{"actor_id": first(attributes, "actor_id")})
			entities = append(entities, actor)
		}
		if resourceID != "" {
			resourceLabel := first(attributes, "resource_name", "target_name", "resource_email")
			if resourceLabel == "" {
				resourceLabel = resourceID
			}
			resource := entity("doppler."+resourceType, resourceID, resourceLabel, map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
			})
			entities = append(entities, resource)
			if actor != nil {
				links = append(links, link(actor.URN, "acted_on", resource.URN))
			}
		}
		return entities, links, nil
	default:
		return nil, nil, fmt.Errorf("unsupported compatibility-only Doppler kind %q", event.GetKind())
	}
}

func compatibilityURN(kind, id string) string {
	return "compatibility:doppler:" + kind + ":" + lengthPrefixedID(id)
}

func identityUserFacts(
	run runEnvelope,
	record recordWire,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
) ([]factWire, error) {
	id := first(attributes, "user_id", "identity_id", "email")
	if id == "" {
		id = record.ProviderID
	}
	label := first(attributes, "display_name", "email", "user_id")
	if label == "" {
		label = record.ProviderID
	}
	if !containsEntity(entities, label) {
		return nil, fmt.Errorf("legacy projector did not emit identity %q", id)
	}
	key := providerKey(run.SourceRuntimeID, run.SourceID+".identity_user", id)
	return []factWire{{Kind: "provider_identity", Parts: []string{key, "identity", label}}}, nil
}

func identityGroupFacts(
	run runEnvelope,
	record recordWire,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
) ([]factWire, error) {
	id := first(attributes, "group_id", "group_email")
	if id == "" {
		id = record.ProviderID
	}
	label := first(attributes, "group_name", "group_email", "group_id")
	if label == "" {
		label = record.ProviderID
	}
	if !containsEntity(entities, label) {
		return nil, fmt.Errorf("legacy projector did not emit group %q", id)
	}
	key := providerKey(run.SourceRuntimeID, run.SourceID+".identity_group", id)
	return []factWire{{Kind: "entity", Parts: []string{key, "group", label}}}, nil
}

func membershipFacts(
	run runEnvelope,
	record recordWire,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
	links []*ports.ProjectedLink,
) ([]factWire, error) {
	groupID := first(attributes, "group_id")
	memberID := first(attributes, "member_id", "member_user_id", "user_id", "member_email")
	if groupID == "" || memberID == "" {
		return nil, fmt.Errorf("membership observation %q is missing endpoints", record.ObservationID)
	}
	groupLabel := first(attributes, "group_name", "group_email")
	if groupLabel == "" {
		groupLabel = groupID
	}
	memberLabel := first(attributes, "member_name", "member_email")
	if memberLabel == "" {
		memberLabel = memberID
	}
	if !containsEntity(entities, groupLabel) || !containsEntity(entities, memberLabel) {
		return nil, fmt.Errorf("legacy projector did not emit both membership endpoints")
	}
	if !containsRelation(links, "member_of") {
		return nil, fmt.Errorf("legacy projector did not emit member_of")
	}
	memberKey := providerKey(run.SourceRuntimeID, run.SourceID+".identity_user", memberID)
	groupKey := providerKey(run.SourceRuntimeID, run.SourceID+".identity_group", groupID)
	relationKey := "relationship:" + memberKey + ":member_of:" + groupKey
	return []factWire{
		{Kind: "provider_identity", Parts: []string{memberKey, "identity", memberLabel}},
		{Kind: "entity", Parts: []string{groupKey, "group", groupLabel}},
		{Kind: "relationship", Parts: []string{memberKey, "member_of", groupKey}},
		{Kind: "provenance", Parts: []string{relationKey, record.ObservationID}},
	}, nil
}

func entityFacts(
	run runEnvelope,
	record recordWire,
	family connectordefinitions.ResourceFamily,
	template string,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
	links []*ports.ProjectedLink,
) ([]factWire, error) {
	primary, err := primarySemanticEntity(run, record, family, template, attributes, entities)
	if err != nil {
		return nil, err
	}
	facts := []factWire{primary.fact()}
	if family.Projection != nil {
		relationshipFacts, err := declaredRelationshipFacts(
			run,
			record,
			family,
			attributes,
			entities,
			links,
			primary,
		)
		if err != nil {
			return nil, err
		}
		facts = append(facts, relationshipFacts...)
	}
	facts = append(facts, evidenceFacts(run, record, attributes, entities, links, primary)...)
	return facts, nil
}

type semanticEntity struct {
	factKind string
	key      string
	kind     string
	label    string
	urn      string
}

func (entity semanticEntity) fact() factWire {
	return factWire{Kind: entity.factKind, Parts: []string{entity.key, entity.kind, entity.label}}
}

func primarySemanticEntity(
	run runEnvelope,
	record recordWire,
	family connectordefinitions.ResourceFamily,
	template string,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
) (semanticEntity, error) {
	if family.Projection != nil && family.Projection.Entity != nil {
		entity, err := semanticEntityFromSpec(run, family.ID, attributes, *family.Projection.Entity, entities)
		if err != nil {
			return semanticEntity{}, err
		}
		if entity == nil {
			return semanticEntity{}, fmt.Errorf(
				"legacy projector did not emit catalog entity for %s.%s",
				run.SourceID,
				family.ID,
			)
		}
		return *entity, nil
	}

	id := projectedID(template, attributes)
	if id == "" {
		id = record.ProviderID
	}
	label := projectedLabel(template, attributes)
	if label == "" {
		label = record.ProviderID
	}
	projected := findEntity(entities, func(entity *ports.ProjectedEntity) bool {
		return entity.Label == label
	})
	if projected == nil {
		return semanticEntity{}, fmt.Errorf("legacy projector did not emit %s %q", template, id)
	}
	return semanticEntity{
		factKind: "entity",
		key:      providerKey(run.SourceRuntimeID, run.SourceID+"."+template, id),
		kind:     entityKind(template),
		label:    label,
		urn:      projected.URN,
	}, nil
}

func semanticEntityFromSpec(
	run runEnvelope,
	familyID string,
	attributes map[string]string,
	spec connectordefinitions.ProjectionEntitySpec,
	entities []*ports.ProjectedEntity,
) (*semanticEntity, error) {
	entityType, err := projectionEntityType(spec, attributes)
	if err != nil {
		return nil, fmt.Errorf("catalog entity type for %s.%s: %w", run.SourceID, familyID, err)
	}
	providerID, err := projectionEntityID(spec, attributes)
	if err != nil {
		return nil, fmt.Errorf("catalog entity id for %s.%s: %w", run.SourceID, familyID, err)
	}
	providerKind := entityType
	if !strings.Contains(providerKind, ".") {
		providerKind = run.SourceID + "." + providerKind
	}
	label := strings.TrimSpace(attributes[spec.LabelAttribute])
	if label == "" {
		label = providerID
	}
	projected := findEntity(entities, func(entity *ports.ProjectedEntity) bool {
		if strings.TrimSpace(entity.EntityType) != entityType || entity.Label != label {
			return false
		}
		for _, attribute := range spec.IDAttributes {
			if strings.TrimSpace(entity.Attributes[attribute]) != strings.TrimSpace(attributes[attribute]) {
				return false
			}
		}
		return true
	})
	if projected == nil {
		return nil, nil
	}
	kind := projectionEntityKind(entityType, providerKind)
	factKind := "entity"
	if kind == "identity" {
		factKind = "provider_identity"
	}
	return &semanticEntity{
		factKind: factKind,
		key:      providerKey(run.SourceRuntimeID, providerKind, providerID),
		kind:     kind,
		label:    label,
		urn:      projected.URN,
	}, nil
}

func projectionEntityType(
	spec connectordefinitions.ProjectionEntitySpec,
	attributes map[string]string,
) (string, error) {
	entityType := strings.TrimSpace(spec.EntityType)
	if strings.Contains(entityType, "|") {
		entityType = ""
		for _, attribute := range strings.Split(spec.EntityType, "|") {
			if value := strings.TrimSpace(attributes[strings.TrimSpace(attribute)]); value != "" {
				entityType = value
				break
			}
		}
	}
	if entityType == "" {
		return "", errors.New("entity_type is required")
	}
	return entityType, nil
}

func projectionEntityID(
	spec connectordefinitions.ProjectionEntitySpec,
	attributes map[string]string,
) (string, error) {
	values := make([]string, 0, len(spec.IDAttributes))
	for _, attribute := range spec.IDAttributes {
		value := strings.TrimSpace(attributes[attribute])
		if value == "" {
			return "", fmt.Errorf("%s is required", attribute)
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return "", errors.New("id_attributes are required")
	}
	if len(values) == 1 {
		return values[0], nil
	}
	var id strings.Builder
	for _, value := range values {
		fmt.Fprintf(&id, "%d:%s", len(value), value)
	}
	return id.String(), nil
}

func projectionEntityKind(entityType, providerKind string) string {
	switch entityType {
	case "identity_user":
		return "identity"
	case "identity_group":
		return "group"
	case "repository":
		return "repository"
	case "deployment":
		return "environment"
	case "policy":
		return "policy"
	case "finding", "vulnerability", "alert":
		return "finding"
	case "identity_application":
		return "application"
	case "cloud_resource", "asset", "secret", "endpoint_device", "identity_credential", "audit_event", "evidence_cas_reference":
		return "resource"
	default:
		return "provider:" + providerKind
	}
}

func declaredRelationshipFacts(
	run runEnvelope,
	record recordWire,
	family connectordefinitions.ResourceFamily,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
	links []*ports.ProjectedLink,
	primary semanticEntity,
) ([]factWire, error) {
	var facts []factWire
	for _, relationship := range family.Projection.Relationships {
		if !relationshipAttributesPresent(attributes, relationship) {
			continue
		}
		from := &primary
		if relationship.From != nil {
			projected, err := semanticEntityFromSpec(run, family.ID, attributes, *relationship.From, entities)
			if err != nil {
				return nil, err
			}
			if projected == nil {
				continue
			}
			from = projected
			facts = append(facts, from.fact())
		}
		to, err := semanticEntityFromSpec(run, family.ID, attributes, relationship.To, entities)
		if err != nil {
			return nil, err
		}
		if to == nil {
			continue
		}
		facts = append(facts, to.fact())
		relation := strings.TrimSpace(relationship.Relation)
		if containsProjectedLink(links, from.urn, relation, to.urn) {
			facts = append(facts, relationshipFact(*from, relation, *to, record.ObservationID)...)
		}
	}
	return facts, nil
}

func relationshipAttributesPresent(
	attributes map[string]string,
	relationship connectordefinitions.ProjectionRelationshipSpec,
) bool {
	required := append([]string(nil), relationship.RequiredAttributes...)
	if len(required) == 0 {
		if relationship.From != nil {
			required = append(required, relationship.From.IDAttributes...)
		}
		required = append(required, relationship.To.IDAttributes...)
	}
	for _, attribute := range required {
		if strings.TrimSpace(attributes[attribute]) == "" {
			return false
		}
	}
	return true
}

func evidenceFacts(
	run runEnvelope,
	record recordWire,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
	links []*ports.ProjectedLink,
	primary semanticEntity,
) []factWire {
	evidenceID := strings.TrimSpace(attributes["evidence_id"])
	if evidenceID == "" {
		return nil
	}
	evidenceProjection := findEntity(entities, func(entity *ports.ProjectedEntity) bool {
		entityType := strings.TrimSpace(entity.EntityType)
		return (entityType == "runtime.evidence" || entityType == "runtime_evidence") &&
			(entity.Label == evidenceID || strings.TrimSpace(entity.Attributes["evidence_id"]) == evidenceID)
	})
	if evidenceProjection == nil {
		return nil
	}
	evidence := semanticEntity{
		factKind: "entity",
		key:      providerKey(run.SourceRuntimeID, run.SourceID+".runtime_evidence", evidenceID),
		kind:     "evidence",
		label:    evidenceID,
		urn:      evidenceProjection.URN,
	}
	facts := []factWire{evidence.fact()}
	if containsProjectedLink(links, primary.urn, "has_evidence", evidence.urn) {
		facts = append(facts, relationshipFact(primary, "has_evidence", evidence, record.ObservationID)...)
	}
	return facts
}

func dopplerAuditFacts(
	run runEnvelope,
	record recordWire,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
	links []*ports.ProjectedLink,
) ([]factWire, error) {
	resourceID := first(attributes, "resource_id", "target_id")
	if resourceID == "" {
		resourceID = record.ProviderID
	}
	resourceType := first(attributes, "resource_type", "target_type")
	if resourceType == "" {
		resourceType = "resource"
	}
	resourceLabel := first(attributes, "resource_name", "target_name", "resource_email")
	if resourceLabel == "" {
		resourceLabel = resourceID
	}
	resourceProjection := findEntity(entities, func(entity *ports.ProjectedEntity) bool {
		return entity.Label == resourceLabel &&
			strings.TrimSpace(entity.Attributes["resource_id"]) == resourceID
	})
	if resourceProjection == nil {
		return nil, fmt.Errorf("legacy projector did not emit Doppler audit resource %q", resourceID)
	}
	resourceProviderID := lengthPrefixedID(resourceType, resourceID)
	resource := semanticEntity{
		factKind: "entity",
		key:      providerKey(run.SourceRuntimeID, "doppler.audit_resource", resourceProviderID),
		kind:     "resource",
		label:    resourceLabel,
		urn:      resourceProjection.URN,
	}
	facts := []factWire{resource.fact()}

	actorID := first(attributes, "actor_id", "actor_email")
	if actorID != "" {
		actorLabel := first(attributes, "actor_name", "actor_email")
		if actorLabel == "" {
			actorLabel = actorID
		}
		actorProjection := findEntity(entities, func(entity *ports.ProjectedEntity) bool {
			return strings.TrimSpace(entity.EntityType) == "doppler.user" && entity.Label == actorLabel
		})
		if actorProjection != nil {
			actor := semanticEntity{
				factKind: "provider_identity",
				key:      providerKey(run.SourceRuntimeID, "doppler.identity_user", actorID),
				kind:     "identity",
				label:    actorLabel,
				urn:      actorProjection.URN,
			}
			facts = append(facts, actor.fact())
			if containsProjectedLink(links, actor.urn, "acted_on", resource.urn) {
				facts = append(facts, relationshipFact(actor, "acted_on", resource, record.ObservationID)...)
			}
		}
	}
	facts = append(facts, evidenceFacts(run, record, attributes, entities, links, resource)...)
	return facts, nil
}

func lengthPrefixedID(values ...string) string {
	var id strings.Builder
	for _, value := range values {
		fmt.Fprintf(&id, "%d:%s", len(value), value)
	}
	return id.String()
}

func relationshipFact(from semanticEntity, relation string, to semanticEntity, observationID string) []factWire {
	relationKey := "relationship:" + from.key + ":" + relation + ":" + to.key
	return []factWire{
		{Kind: "relationship", Parts: []string{from.key, relation, to.key}},
		{Kind: "provenance", Parts: []string{relationKey, observationID}},
	}
}

func findEntity(
	entities []*ports.ProjectedEntity,
	matches func(*ports.ProjectedEntity) bool,
) *ports.ProjectedEntity {
	for _, entity := range entities {
		if entity != nil && matches(entity) {
			return entity
		}
	}
	return nil
}

func containsProjectedLink(links []*ports.ProjectedLink, fromURN, relation, toURN string) bool {
	for _, link := range links {
		if link != nil && link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

func providerKey(runtimeID, providerKind, providerID string) string {
	return "provider:" + runtimeID + ":" + providerKind + ":" + providerID
}

func projectedID(template string, values map[string]string) string {
	switch template {
	case "repository":
		return first(values, "repository_id", "repo_id", "resource_id", "id")
	case "deployment":
		return first(values, "deployment_id", "resource_id", "id")
	case "policy":
		return first(values, "policy_id", "resource_id", "id")
	case "finding", "vulnerability":
		return first(values, "finding_id", "vulnerability_id", "id")
	case "alert":
		return first(values, "alert_id", "finding_id", "id")
	case "secret":
		return first(values, "secret_id", "resource_id", "id")
	case "identity_application":
		return first(values, "app_id", "application_id", "id")
	default:
		return first(values, "resource_id", "id")
	}
}

func projectedLabel(template string, values map[string]string) string {
	switch template {
	case "repository":
		return first(values, "repository_name", "resource_name", "name")
	case "deployment":
		return first(values, "deployment_name", "resource_name", "name")
	case "policy":
		return first(values, "policy_name", "resource_name", "name")
	case "finding", "vulnerability":
		return first(values, "title", "finding_id", "id")
	case "alert":
		return first(values, "alert_name", "title", "alert_id")
	case "secret":
		return first(values, "secret_name", "resource_name", "name")
	default:
		return first(values, "resource_name", "name", "display_name")
	}
}

func entityKind(template string) string {
	switch template {
	case "identity_group":
		return "group"
	case "repository":
		return "repository"
	case "deployment":
		return "environment"
	case "policy":
		return "policy"
	case "finding", "vulnerability", "alert":
		return "finding"
	case "identity_application":
		return "application"
	default:
		return "resource"
	}
}

func first(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func containsEntity(entities []*ports.ProjectedEntity, label string) bool {
	for _, entity := range entities {
		if entity != nil && entity.Label == label {
			return true
		}
	}
	return false
}

func containsRelation(links []*ports.ProjectedLink, relation string) bool {
	for _, link := range links {
		if link != nil && link.Relation == relation {
			return true
		}
	}
	return false
}

func cloneMap(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values)+1)
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func canonicalFact(fact factWire) string {
	return fact.Kind + "\x1f" + strings.Join(fact.Parts, "\x1f")
}

func deduplicateFacts(facts []factWire) []factWire {
	result := make([]factWire, 0, len(facts))
	previous := ""
	for _, fact := range facts {
		canonical := canonicalFact(fact)
		if canonical == previous {
			continue
		}
		result = append(result, fact)
		previous = canonical
	}
	return result
}
