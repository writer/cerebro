package sourceprojection

import (
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

func grcTargetURN(tenantID string, provider string, targetID string) string {
	if strings.TrimSpace(targetID) == "" {
		return ""
	}
	return projectionURN(tenantID, "grc_target", provider, targetID)
}

func grcTargetEntity(tenantID string, sourceID string, urn string, targetID string, attrs map[string]string, provider string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "grc.target",
		Label:      firstAttribute(attrs, "target_name", "resource_name", "hostname", "target_id", "resource_id"),
		Attributes: grcAttributes(nil, map[string]string{
			"host":           grcTargetHost(attrs),
			"integration_id": firstAttribute(attrs, "integration_id"),
			"source_system":  provider,
			"target_id":      targetID,
			"target_type":    firstAttribute(attrs, "target_type", "resource_type", "asset_type"),
		}),
	}
}

func grcTargetHost(attrs map[string]string) string {
	if host := internetHost(firstAttribute(attrs, "hostname", "host", "target_url", "resource_url", "external_url", "url", "website_url")); host != "" {
		return host
	}
	return internetHostIfLikely(firstAttribute(attrs, "target_id", "resource_id", "asset_id", "endpoint_id"))
}

func grcTargetHosts(attrs map[string]string) []string {
	values := splitCloudAttributeList(strings.Join([]string{
		grcTargetHost(attrs),
		attrs["hostnames"],
		attrs["hosts"],
	}, ","))
	hosts := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		host := internetHost(value)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

func grcTargetIPs(attrs map[string]string) []string {
	values := splitCloudAttributeList(strings.Join([]string{
		attrs["ip"],
		attrs["ip_address"],
		attrs["ip_addresses"],
		attrs["public_ip"],
		attrs["public_ips"],
		attrs["private_ip"],
		attrs["private_ips"],
	}, ","))
	ips := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		ip := internetIP(value)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}
