package catalogruntime

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

// Source adapts a normalized connector catalog definition into a runnable JSON API source.
type Source struct {
	inner              *jsonapi.Source
	verificationPath   string
	verificationStatus []int
}

// New creates a runnable source from a connector catalog entry.
func New(entry connectorcatalog.Entry) (*Source, error) {
	return NewDefinition(entry.Definition)
}

// NewDefinition creates a runnable source from a connector definition.
func NewDefinition(definition connectordefinitions.Definition) (*Source, error) {
	definition, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, err
	}
	if runtime := strings.TrimSpace(definition.Runtime); runtime != "" && runtime != connectordefinitions.RuntimeJSONAPI {
		return nil, fmt.Errorf("%s runtime %q is not supported by catalogruntime", definition.SourceID, runtime)
	}
	if definition.Transport == nil {
		return nil, fmt.Errorf("%s transport is required", definition.SourceID)
	}
	if len(definition.ResourceFamilies) == 0 {
		return nil, fmt.Errorf("%s resource families are required", definition.SourceID)
	}
	families := make([]jsonapi.Family, 0, len(definition.ResourceFamilies))
	for _, resource := range definition.ResourceFamilies {
		family, err := jsonapiFamily(definition.SourceID, resource)
		if err != nil {
			return nil, err
		}
		families = append(families, family)
	}
	spec := &cerebrov1.SourceSpec{
		Id:          definition.SourceID,
		Name:        firstNonEmpty(definition.DisplayName, titleFromID(definition.SourceID)),
		Description: definition.Description,
	}
	options := jsonapi.Options{
		SourceID:                    definition.SourceID,
		DefaultBaseURL:              definition.Transport.BaseURL,
		DefaultFamily:               families[0].Name,
		RequireTenantID:             true,
		AuthModel:                   definition.Auth.Model,
		OAuthTokenURL:               definition.Auth.TokenURL,
		OAuthScopes:                 definition.Auth.Scopes,
		OAuthTokenParams:            definition.Auth.TokenParams,
		OAuthTokenRequestAuthMethod: definition.Auth.TokenRequestAuthMethod,
		StaticHeaders:               definition.Transport.Headers,
		Families:                    families,
	}
	inner, err := jsonapi.New(spec, options)
	if err != nil {
		return nil, err
	}
	source := &Source{inner: inner}
	if definition.Transport.Verification != nil {
		source.verificationPath = strings.TrimSpace(definition.Transport.Verification.Path)
		source.verificationStatus = append([]int(nil), definition.Transport.Verification.ExpectStatus...)
	}
	return source, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

// Check validates the catalog verification endpoint when present.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if s == nil || s.inner == nil {
		return fmt.Errorf("catalogruntime source is required")
	}
	if strings.TrimSpace(s.verificationPath) != "" {
		return s.inner.CheckPath(ctx, cfg, s.verificationPath, s.verificationStatus)
	}
	return s.inner.Check(ctx, cfg)
}

// Discover returns URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

// Read pages records for the configured family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

// ReadWithCheckpoint pages records while applying family-level checkpoint policy.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.inner.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func jsonapiFamily(sourceID string, resource connectordefinitions.ResourceFamily) (jsonapi.Family, error) {
	name := strings.TrimSpace(resource.ID)
	if name == "" {
		return jsonapi.Family{}, fmt.Errorf("%s family id is required", sourceID)
	}
	if strings.TrimSpace(resource.Path) == "" {
		return jsonapi.Family{}, fmt.Errorf("%s family %s path is required", sourceID, name)
	}
	class := projectionClass(resource)
	read := resource.Read
	if read == nil {
		read = &connectordefinitions.ResourceReadSpec{}
	}
	return jsonapi.Family{
		Name:                  name,
		Path:                  resource.Path,
		DetailPath:            read.DetailPath,
		AllowBareDetailRecord: read.AllowBareDetailRecord,
		PathParams:            append([]string(nil), read.PathParams...),
		CursorParam:           cursorParam(resource.Pagination),
		NextCursorKeys:        nextCursorKeys(resource.Pagination),
		HasMoreKey:            hasMoreKey(resource.Pagination),
		PageFirstCursor:       pageFirstCursor(resource.Pagination),
		URNKind:               firstNonEmpty(resource.Event.URNKind, "runtime_"+name),
		IDKeys:                idKeys(resource, class),
		TimestampKeys:         timestampKeys(resource),
		Attributes:            attributePaths(resource, class),
		StaticAttributes:      staticAttributes(sourceID, name, class),
		Config:                familyConfig(resource.Config),
		PageSizeParams:        pageSizeParams(resource.Pagination),
		DisablePageSize:       read.DisablePageSize,
		ListKeys:              listKeys(resource),
		MapRecords:            cloneStringMap(read.MapRecords),
		Singleton:             read.Singleton,
		IncrementalWatermark:  resource.Incremental != nil && strings.TrimSpace(resource.Incremental.State) == "high_watermark",
		Method:                strings.TrimSpace(resource.Method),
	}, nil
}

func cursorParam(pagination *connectordefinitions.PaginationSpec) string {
	if pagination == nil {
		return ""
	}
	return firstNonEmpty(pagination.CursorParam, pagination.PageParam, pagination.OffsetParam)
}

func pageFirstCursor(pagination *connectordefinitions.PaginationSpec) string {
	if pagination == nil || strings.TrimSpace(pagination.Type) != "page" || strings.TrimSpace(pagination.PageParam) == "" {
		return ""
	}
	return strconv.Itoa(pagination.StartPage)
}

func nextCursorKeys(pagination *connectordefinitions.PaginationSpec) []string {
	if pagination == nil {
		return nil
	}
	return append([]string(nil), pagination.NextCursorKeys...)
}

func hasMoreKey(pagination *connectordefinitions.PaginationSpec) string {
	if pagination == nil {
		return ""
	}
	return strings.TrimSpace(pagination.HasMoreKey)
}

func familyConfig(config *connectordefinitions.FamilyConfigSpec) jsonapi.FamilyConfig {
	if config == nil {
		return jsonapi.FamilyConfig{}
	}
	return jsonapi.FamilyConfig{
		StaticQuery:      cloneStringMap(config.StaticQuery),
		ConfigQuery:      cloneStringMap(config.ConfigQuery),
		ConfigAttributes: cloneStringMap(config.ConfigAttributes),
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func pageSizeParams(pagination *connectordefinitions.PaginationSpec) []string {
	if pagination == nil {
		return nil
	}
	values := nonEmpty([]string{pagination.PageSizeParam, pagination.LimitParam})
	if len(values) == 0 {
		return nil
	}
	return values
}

func listKeys(resource connectordefinitions.ResourceFamily) []string {
	values := nonEmpty([]string{resource.ListKey, selectorListKey(resource.RecordSelector)})
	if len(values) == 0 {
		return nil
	}
	return values
}

func selectorListKey(selector string) string {
	selector = strings.TrimSpace(strings.Trim(selector, `"`))
	if selector == "$[*]" {
		return ""
	}
	if strings.HasPrefix(selector, "$.") && strings.HasSuffix(selector, "[*]") {
		key := strings.TrimSuffix(strings.TrimPrefix(selector, "$."), "[*]")
		if !strings.Contains(key, ".") {
			return key
		}
	}
	return ""
}

func projectionClass(resource connectordefinitions.ResourceFamily) string {
	if resource.Projection == nil {
		return "asset"
	}
	switch strings.TrimSpace(resource.Projection.Template) {
	case "finding", "vulnerability":
		return "finding"
	case "secret":
		return "secret"
	case "policy":
		return "policy"
	case "deployment":
		return "deployment"
	case "alert":
		return "alert"
	case "identity_user", "identity_group", "group_membership", "audit_event", "evidence_cas_reference":
		return strings.TrimSpace(resource.Projection.Template)
	default:
		return "asset"
	}
}

func idKeys(resource connectordefinitions.ResourceFamily, class string) []string {
	keys := []string{resource.IDField}
	switch class {
	case "finding":
		keys = append(keys, "finding_id", "id", "resource_urn")
	case "identity_user":
		keys = append(keys, "user_id", "id", "email", "primary_email", "login")
	case "identity_group":
		keys = append(keys, "group_id", "id", "group_email", "email")
	case "group_membership":
		keys = append(keys, "membership_id", "id", "group_id", "member_id", "user_id", "email")
	case "audit_event":
		keys = append(keys, "event_id", "id", "uuid", "request_id")
	case "secret":
		keys = append(keys, "secret_id", "id", "key", "sid", "name")
	case "policy":
		keys = append(keys, "policy_id", "id", "control_id", "key", "sid")
	case "deployment":
		keys = append(keys, "deployment_id", "id", "name", "uid")
	case "alert":
		keys = append(keys, "alert_id", "id", "sid", "incident_id", "uuid")
	default:
		keys = append(keys, "id", "urn", "resource_urn", "name")
	}
	return nonEmpty(dedupe(keys))
}

func timestampKeys(resource connectordefinitions.ResourceFamily) []string {
	return nonEmpty(dedupe([]string{resource.UpdatedAtField, "observed_at", "updated_at", "last_seen_at", "created_at"}))
}

func attributePaths(resource connectordefinitions.ResourceFamily, class string) map[string]string {
	attrs := map[string]string{
		"tenant_id":       "tenant_id|metadata.tenant_id",
		"source_event_id": "event_id|id|metadata.event_id",
		"observed_at":     "observed_at|updated_at|last_seen_at",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"resource_type":   "resource_type|type|metadata.resource_type",
		"resource_id":     "resource_id|id|metadata.resource_id",
		"resource_name":   "name|display_name|hostname|metadata.resource_name",
	}
	if resource.NameField != "" {
		attrs["resource_name"] = resource.NameField + "|" + attrs["resource_name"]
	}
	switch class {
	case "finding":
		attrs["finding_id"] = "finding_id|id"
		attrs["severity"] = "severity"
		attrs["status"] = "status|state"
		attrs["title"] = "title|name|summary"
		attrs["description"] = "description|summary"
	case "identity_user":
		attrs["user_id"] = "user_id|id|uid"
		attrs["email"] = "email|primary_email|profile.email"
		attrs["display_name"] = "display_name|name|profile.display_name|profile.name"
		attrs["status"] = "status|state|lifecycle_state"
	case "identity_group":
		attrs["group_id"] = "group_id|id"
		attrs["group_email"] = "group_email|email"
		attrs["group_name"] = "group_name|name|display_name"
	case "group_membership":
		attrs["group_id"] = "group_id|group.id|groupId"
		attrs["member_id"] = "member_id|member.id|user_id|user.id|id"
		attrs["member_email"] = "member_email|user_email|email|member.email|user.email"
	case "audit_event":
		attrs["event_type"] = "event_type|event_name|action|type"
		attrs["actor_id"] = "actor_id|actor.id|actorId|user_id|user.id"
		attrs["actor_email"] = "actor_email|actor.email|email|user.email"
	case "secret":
		attrs["secret_id"] = "secret_id|id|key|sid|name"
		attrs["secret_name"] = "secret_name|name|display_name|label|title"
		attrs["secret_type"] = "secret_type|type|kind"
		attrs["secret_status"] = "secret_status|status|state"
		attrs["secret_rotation_enabled"] = "secret_rotation_enabled|rotation_enabled|auto_rotate"
		attrs["secret_last_rotated_at"] = "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at"
	case "policy":
		attrs["policy_id"] = "policy_id|id|control_id|key|sid"
		attrs["policy_name"] = "policy_name|name|display_name|title|label"
		attrs["policy_type"] = "policy_type|type|kind|category"
		attrs["policy_status"] = "policy_status|status|state|enabled"
		attrs["policy_severity"] = "severity|risk|priority"
	case "deployment":
		attrs["deployment_id"] = "deployment_id|id|name|uid"
		attrs["deployment_name"] = "deployment_name|name|display_name|title|label"
		attrs["deployment_environment"] = "environment|env|stage|target"
		attrs["deployment_status"] = "status|state|ready"
		attrs["deployment_url"] = "url|deployment_url|endpoint|domain"
		attrs["deployment_commit_sha"] = "commit_sha|commit|sha|revision|git_sha"
		attrs["deployment_branch"] = "branch|ref|git_branch|head_branch"
	case "alert":
		attrs["alert_id"] = "alert_id|id|sid|incident_id|uuid"
		attrs["alert_name"] = "alert_name|name|title|summary|subject"
		attrs["alert_severity"] = "severity|priority|level|risk"
		attrs["alert_status"] = "status|state|resolved|acknowledged"
		attrs["alert_type"] = "alert_type|type|category|kind"
		attrs["alert_source"] = "source|alert_source|monitor|check"
		attrs["alert_fired_at"] = "fired_at|triggered_at|created_at|occurred_at|timestamp"
		attrs["alert_resolved_at"] = "resolved_at|closed_at|acknowledged_at"
	}
	if resource.Projection != nil {
		for key, value := range resource.Projection.Fields {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				attrs[strings.TrimSpace(key)] = strings.TrimSpace(value)
			}
		}
	}
	return attrs
}

func staticAttributes(sourceID string, family string, class string) map[string]string {
	return map[string]string{
		"source_system": sourceID,
		"record_class":  class,
		"family":        family,
	}
}

func titleFromID(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	parts := strings.Fields(value)
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func dedupe(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
