package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// openAIAPIKeyProjections materializes the shared AI credential graph slice for
// OpenAI API keys and then annotates the credential node with current ownership
// posture (privilege class, owner type, and whether the key has an accountable
// owner). Durable orphaned-privileged-key findings anchor on this projected
// state so they reflect the key's current ownership rather than transient audit
// events.
func openAIAPIKeyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := openAICredentialProjections(event)
	if err != nil {
		return nil, nil, err
	}
	enrichOpenAICredentialPosture(entities, event)
	return entities, links, nil
}

func enrichOpenAICredentialPosture(entities []*ports.ProjectedEntity, event *cerebrov1.EventEnvelope) {
	tenant, err := tenantID(event)
	if err != nil {
		return
	}
	attrs := event.GetAttributes()
	credentialID := firstNonEmpty(attrs["api_key_id"], attrs["external_key_id"], attrs["credential_id"], attrs["id"])
	credentialURN := projectionURN(tenant, "openai_credential", credentialID)
	if credentialURN == "" {
		return
	}
	privileged := openAICredentialPrivileged(event.GetKind(), attrs)
	hasOwner := strings.TrimSpace(attrs["owner_user_id"]) != "" || strings.TrimSpace(attrs["owner_service_account_id"]) != ""
	for _, entity := range entities {
		if entity == nil || entity.URN != credentialURN {
			continue
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		entity.Attributes["privileged"] = boolString(privileged)
		entity.Attributes["has_owner"] = boolString(hasOwner)
		entity.Attributes["orphaned_owner"] = boolString(privileged && !hasOwner)
		addEndpointAttribute(entity.Attributes, "owner_type", attrs["owner_type"])
		addEndpointAttribute(entity.Attributes, "key_class", attrs["key_class"])
	}
}

func openAICredentialPrivileged(kind string, attrs map[string]string) bool {
	if strings.TrimSpace(kind) == "openai.admin_api_key" {
		return true
	}
	if projectionBool(attrs["privileged"]) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(attrs["key_class"]), "admin")
}
