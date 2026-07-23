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

const adapterRevision = "go-sourceprojection-semantic-v1"

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
	event := &cerebrov1.EventEnvelope{
		Id:         record.ObservationID,
		TenantId:   run.TenantID,
		SourceId:   run.SourceID,
		Kind:       eventKind,
		Attributes: attributes,
	}
	entities, links, err := sourceprojection.ProjectEvent(event)
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
	default:
		return entityFacts(run, record, template, attributes, entities)
	}
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
	template string,
	attributes map[string]string,
	entities []*ports.ProjectedEntity,
) ([]factWire, error) {
	id := projectedID(template, attributes)
	if id == "" {
		id = record.ProviderID
	}
	label := projectedLabel(template, attributes)
	if label == "" {
		label = record.ProviderID
	}
	if !containsEntity(entities, label) {
		return nil, fmt.Errorf("legacy projector did not emit %s %q", template, id)
	}
	key := providerKey(run.SourceRuntimeID, run.SourceID+"."+template, id)
	return []factWire{{Kind: "entity", Parts: []string{key, entityKind(template), label}}}, nil
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
