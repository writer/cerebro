package sourceprojection

import (
	"fmt"
	"net/url"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func genericInventoryProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	sourceID := strings.TrimSpace(event.GetSourceId())
	family := strings.TrimSpace(attrs["family"])
	if family == "" {
		family = strings.TrimPrefix(strings.TrimSpace(event.GetKind()), sourceID+".")
	}
	entityID := inventoryEntityID(event.GetKind(), family, attrs)
	if entityID == "" {
		entityID = strings.TrimSpace(event.GetId())
	}
	entityType := sourceID + "." + family
	entityURN := fmt.Sprintf("urn:cerebro:%s:%s:%s", url.PathEscape(tenantID), url.PathEscape(strings.ReplaceAll(entityType, ".", "_")), url.PathEscape(entityID))
	entityAttrs := cloneAttributes(attrs)
	entityAttrs["event_kind"] = event.GetKind()
	entityAttrs["source_event_id"] = event.GetId()
	entity := &ports.ProjectedEntity{
		URN:        entityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: entityType,
		Label:      inventoryLabel(attrs, entityID),
		Attributes: entityAttrs,
	}
	stampProjectionRuntime(event, []*ports.ProjectedEntity{entity}, nil)
	return []*ports.ProjectedEntity{entity}, nil, nil
}

func inventoryEntityID(kind string, family string, attrs map[string]string) string {
	switch strings.TrimSpace(kind) {
	case "kubernetes.cluster":
		return joinProjectionIdentity(attrs, "cluster_id")
	case "kubernetes.namespace":
		return joinProjectionIdentity(attrs, "cluster_id", "resource_id", "namespace")
	case "kubernetes.pod":
		return joinProjectionIdentity(attrs, "cluster_id", "namespace", "resource_id", "name")
	case "kubernetes.container":
		return joinProjectionIdentity(attrs, "cluster_id", "namespace", "resource_id", "container_name")
	case "cloudflare.access_application", "cloudflare.zone_access_application":
		return joinProjectionIdentity(attrs, "application_id", "id")
	case "cloudflare.access_group", "cloudflare.zone_access_group":
		return joinProjectionIdentity(attrs, "group_id", "id")
	case "cloudflare.account_ruleset", "cloudflare.zone_ruleset":
		return joinProjectionIdentity(attrs, "ruleset_id", "id")
	case "cloudflare.audit_log":
		return joinProjectionIdentity(attrs, "audit_id", "id")
	case "cloudflare.gateway_rule":
		return joinProjectionIdentity(attrs, "rule_id", "id")
	case "cloudflare.load_balancer":
		return joinProjectionIdentity(attrs, "load_balancer_id", "id")
	case "cloudflare.load_balancer_pool":
		return joinProjectionIdentity(attrs, "pool_id", "id")
	case "cloudflare.worker_script":
		return joinRequiredScopedProjectionIdentity(attrs, "account_id", "script_id", "id")
	case "trivy.image_scan":
		return joinProjectionIdentity(attrs, "image_digest")
	case "trivy.image_package":
		return joinProjectionIdentity(attrs, "image_digest", "package", "version")
	case "trivy.image_vulnerability":
		return joinProjectionIdentity(attrs, "image_digest", "vulnerability_id", "package", "installed_version")
	case "trivy.fix":
		return joinProjectionIdentity(attrs, "image_digest", "vulnerability_id", "package", "fixed_version")
	}
	return firstProjectionValue(attrs,
		family+"_id",
		"record_id",
		"api_key_id",
		"service_account_id",
		"project_id",
		"workspace_id",
		"account_id",
		"member_id",
		"role_id",
		"zone_id",
		"endpoint_id",
		"group_id",
		"phone_id",
		"token_id",
		"credential_id",
		"team_id",
		"channel_id",
		"user_id",
		"device_id",
		"tailnet",
		"tag_id",
		"service_id",
		"grant_id",
		"schedule_id",
		"escalation_policy_id",
		"integration_id",
		"vendor_id",
		"resource_id",
		"uid",
		"id",
		"name",
		"email",
		"username",
		"vulnerability_id",
		"package",
		"external_id",
	)
}

func joinRequiredScopedProjectionIdentity(attrs map[string]string, scopeKey string, keys ...string) string {
	scope := strings.TrimSpace(attrs[scopeKey])
	if scope == "" {
		return ""
	}
	identity := firstProjectionValue(attrs, keys...)
	if identity == "" {
		return ""
	}
	return strings.Join([]string{scope, identity}, "|")
}

func joinProjectionIdentity(attrs map[string]string, keys ...string) string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, "|")
}

func inventoryLabel(attrs map[string]string, fallback string) string {
	if label := firstProjectionValue(attrs, "name", "display_name", "email", "username", "hostname", "package", "vulnerability_id", "title"); label != "" {
		return label
	}
	return strings.TrimSpace(fallback)
}

func firstProjectionValue(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func cloneAttributes(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	return out
}
