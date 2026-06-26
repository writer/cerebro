package sourceprojection

import (
	"encoding/json"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type grcPlatformAssetReference struct {
	Provider          string `json:"provider"`
	ResourceID        string `json:"resource_id"`
	ResourceName      string `json:"resource_name"`
	ResourceType      string `json:"resource_type"`
	ScannerResourceID string `json:"scanner_resource_id"`
	Hostnames         string `json:"hostnames"`
	IPs               string `json:"ips"`
}

func addGRCPlatformAssetLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, targetURN string, attrs map[string]string) {
	grcProviderName := grcProvider(attrs)
	integrationID := firstAttribute(attrs, "integration_id")
	integrationURN := grcIntegrationURN(tenantID, grcProviderName, integrationID)
	for _, ref := range grcPlatformAssetReferences(attrs) {
		provider := grcPlatformProvider(ref.Provider, ref.ResourceID)
		resourceID := strings.TrimSpace(ref.ResourceID)
		if provider == "" || provider == "vanta" || resourceID == "" {
			continue
		}
		resourceType := grcPlatformResourceType(provider, resourceID, ref.ResourceType)
		resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
		if resourceURN == "" {
			continue
		}
		// Prefer a human-readable label over the URN so the dashboard, finding
		// reports, and ask-the-graph traces are interpretable. Falling back to
		// the resource id keeps the label stable when the source omits a name.
		label := firstNonEmptyString(strings.TrimSpace(ref.ResourceName), strings.TrimSpace(ref.ScannerResourceID), resourceID)
		entityAttrs := map[string]string{
			"provider":      provider,
			"resource_id":   resourceID,
			"resource_type": resourceType,
			"resource_name": strings.TrimSpace(ref.ResourceName),
		}
		ownerLogin := githubRepositoryOwnerLogin(provider, resourceType, ref.ResourceName)
		if ownerLogin != "" {
			entityAttrs["owner_login"] = ownerLogin
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   provider,
			EntityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
			Label:      label,
			Attributes: entityAttrs,
		})
		addLink(links, projectedLink(tenantID, sourceID, targetURN, resourceURN, relationRepresents, map[string]string{
			"confidence":           "0.99",
			"event_id":             event.GetId(),
			"match_type":           "grc_vulnerable_asset_platform_resource",
			"platform_provider":    provider,
			"platform_resource_id": resourceID,
			"resource_type":        resourceType,
		}))
		// Connect the platform resource to the GRC integration that surfaced
		// it. Without this edge a github.code.repository or aws.* node has no
		// outgoing path back to the source/integration it was discovered
		// through, which leaves it dangling whenever the parent grc.target is
		// not the query starting point.
		if integrationURN != "" {
			addEntity(entities, grcIntegrationReferenceEntity(tenantID, sourceID, integrationURN, integrationID, grcProviderName))
			addLink(links, projectedLink(tenantID, sourceID, resourceURN, integrationURN, relationBelongsTo, grcIntegrationLinkAttributes(event, integrationID)))
		}
		addGRCGitHubRepositoryOrgLink(entities, links, tenantID, sourceID, event, resourceURN, ownerLogin)
		addGRCPlatformNetworkLinks(entities, links, tenantID, sourceID, event, resourceURN, ref)
	}
}

func addGRCPlatformNetworkLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, resourceURN string, ref grcPlatformAssetReference) {
	resourceURN = strings.TrimSpace(resourceURN)
	if resourceURN == "" {
		return
	}
	for _, rawHost := range splitCloudAttributeList(ref.Hostnames) {
		addInternetHostLink(entities, links, tenantID, sourceID, event, resourceURN, relationRepresents, rawHost, "grc_platform_resource_host", "0.90")
	}
	for _, rawIP := range splitCloudAttributeList(ref.IPs) {
		addInternetIPLink(entities, links, tenantID, sourceID, event, resourceURN, rawIP, "grc_platform_resource_ip", "0.90")
	}
}

func addGRCGitHubRepositoryOrgLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, repositoryURN string, ownerLogin string) {
	ownerLogin = strings.TrimSpace(ownerLogin)
	repositoryURN = strings.TrimSpace(repositoryURN)
	if ownerLogin == "" || repositoryURN == "" {
		return
	}
	orgURN := projectionURN(tenantID, "github_org", ownerLogin)
	if orgURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        orgURN,
		TenantID:   tenantID,
		SourceID:   "github",
		EntityType: "github.org",
		Label:      ownerLogin,
		Attributes: map[string]string{"org": ownerLogin, "owner_login": ownerLogin},
	})
	addLink(links, projectedLink(tenantID, sourceID, repositoryURN, orgURN, relationBelongsTo, map[string]string{
		"event_id":     event.GetId(),
		"match_type":   "grc_platform_repository_owner",
		"owner_login":  ownerLogin,
		"source_scope": "platform_asset_ref",
	}))
}

func githubRepositoryOwnerLogin(provider string, resourceType string, resourceName string) string {
	if provider != "github" || resourceType != "code_repository" {
		return ""
	}
	owner, _, ok := strings.Cut(strings.TrimSpace(resourceName), "/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(owner)
}

func grcPlatformAssetReferences(attrs map[string]string) []grcPlatformAssetReference {
	if raw := strings.TrimSpace(attrs["platform_asset_refs"]); raw != "" {
		var refs []grcPlatformAssetReference
		if err := json.Unmarshal([]byte(raw), &refs); err == nil {
			return refs
		}
	}
	resourceID := firstAttribute(attrs, "platform_resource_id", "cloud_resource_id", "cloud_resource_arn", "target_arn", "resource_arn")
	if resourceID == "" {
		return nil
	}
	return []grcPlatformAssetReference{{
		Provider:          firstAttribute(attrs, "platform_provider", "cloud_provider", "integration_id"),
		ResourceID:        resourceID,
		ResourceName:      firstAttribute(attrs, "platform_resource_name", "resource_name", "target_name"),
		ResourceType:      firstAttribute(attrs, "platform_resource_type", "cloud_resource_type", "resource_type", "asset_type"),
		ScannerResourceID: firstAttribute(attrs, "scanner_resource_id"),
		Hostnames:         firstAttribute(attrs, "hostnames", "hostname", "host"),
		IPs:               firstAttribute(attrs, "ip_addresses", "ip", "ip_address", "public_ip"),
	}}
}

func grcPlatformProvider(provider string, resourceID string) string {
	provider = normalizeIdentifier(provider)
	if provider != "" && provider != "vanta" {
		return provider
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(resourceID)), "arn:aws") {
		return "aws"
	}
	return provider
}

func grcPlatformResourceType(provider string, resourceID string, fallback string) string {
	if provider == "aws" {
		if resourceType := grcAWSResourceTypeFromARN(resourceID); resourceType != "" {
			return resourceType
		}
	}
	if resourceType := normalizeCloudType(fallback); resourceType != "" {
		return resourceType
	}
	return "resource"
}
