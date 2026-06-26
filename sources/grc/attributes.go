package grc

import (
	"strconv"
	"strings"
)

func attributesFor(settings settings, family grcFamily, record grcRecord) map[string]string {
	values := record.Values
	attrs := map[string]string{
		"provider":        settings.provider,
		"source_provider": settings.provider,
		"external_id":     record.ID,
	}
	copyFieldPairs(attrs, values, grcDescriptorFor(family).AttributePairs)
	switch family {
	case familyControlTest:
		copyControlReferenceFields(attrs, values)
	case familyEventLog:
		if targets := eventLogTargets(values); targets != "" {
			attrs["targets"] = targets
		}
	case familyVulnerableAsset:
		copyFirstField(attrs, values, "asset_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_id", "id", "assetId", "targetId")
		copyFirstField(attrs, values, "target_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "resource_name", "displayName", "name", "hostname", "host", "url")
		copyFirstField(attrs, values, "hostname", "hostname", "host", "dnsName", "fqdn")
		copyFirstField(attrs, values, "ip", "ipAddress", "publicIp", "publicIP", "ip")
		copyFirstField(attrs, values, "asset_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "resource_type", "assetType", "resourceType", "type")
		copyFirstField(attrs, values, "integration_id", "integrationId", "integration.id")
		copyFirstField(attrs, values, "external_url", "externalURL", "url")
		copyFirstField(attrs, values, "target_url", "url", "externalURL")
		copyFirstField(attrs, values, "operating_system", "operatingSystem", "os")
		copyFirstField(attrs, values, "last_detected_at", "lastDetectedDate", "lastSeenDate", "updatedAt")
		copyVulnerableAssetPlatformReferences(attrs, values)
		copyVulnerableAssetReferences(attrs, values)
	case familyMonitoredComputer:
		attrs["source_product"] = settings.provider
		attrs["compliance_status"] = monitoredComputerComplianceStatus(attrs)
	case familyIntegration:
		attrs["connection_count"] = strconv.Itoa(len(arrayValue(values, "connections")))
		attrs["disabled_connection_count"] = strconv.Itoa(countConnections(values, true, false))
		attrs["connection_error_count"] = strconv.Itoa(countConnections(values, false, true))
	}
	return trimEmpty(attrs)
}

func copyFieldPairs(attrs map[string]string, values map[string]any, pairs []string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		target, source := pairs[i], pairs[i+1]
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
		}
	}
}

func copyFirstField(attrs map[string]string, values map[string]any, target string, sources ...string) {
	if strings.TrimSpace(attrs[target]) != "" {
		return
	}
	for _, source := range sources {
		if value := fieldString(values, source); value != "" {
			attrs[target] = value
			return
		}
	}
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
	return values
}
