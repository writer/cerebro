package builders

import "strings"

func awsSecurityGroupNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "arn"), queryRowString(record, "_cq_id"), queryRowString(record, "group_id"))
}

func awsSecurityGroupNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := awsSecurityGroupNodeID(record)
	if id == "" {
		return nil
	}
	public := awsSecurityGroupAllowsInternet(queryRow(record, "ip_permissions"))
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "group_name"), queryRowString(record, "group_id"), id),
		Provider: firstNonEmpty(provider, "aws"),
		Account:  firstNonEmpty(queryRowString(record, "account_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "region"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":          "security_group",
			"group_id":              queryRow(record, "group_id"),
			"group_name":            queryRow(record, "group_name"),
			"description":           queryRow(record, "description"),
			"vpc_id":                queryRow(record, "vpc_id"),
			"ip_permissions":        queryRow(record, "ip_permissions"),
			"ip_permissions_egress": queryRow(record, "ip_permissions_egress"),
			"public":                public,
		},
	}
}

func gcpFirewallNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "self_link"), queryRowString(record, "_cq_id"), queryRowString(record, "id"), queryRowString(record, "name"))
}

func gcpFirewallNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := gcpFirewallNodeID(record)
	if id == "" {
		return nil
	}
	public := gcpFirewallAllowsInternet(record)
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "name"), id),
		Provider: firstNonEmpty(provider, "gcp"),
		Account:  firstNonEmpty(queryRowString(record, "project_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "location"), queryRowString(record, "region"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":  "firewall",
			"network":       queryRow(record, "network"),
			"direction":     queryRow(record, "direction"),
			"source_ranges": queryRow(record, "source_ranges"),
			"allowed":       queryRow(record, "allowed"),
			"denied":        queryRow(record, "denied"),
			"disabled":      queryRow(record, "disabled"),
			"public":        public,
		},
	}
}

func azureNetworkSecurityGroupNodeID(record map[string]any) string {
	return firstNonEmpty(queryRowString(record, "id"), queryRowString(record, "_cq_id"), queryRowString(record, "name"))
}

func azureNetworkSecurityGroupNodeFromRecord(record map[string]any, provider, account, region string) *Node {
	id := azureNetworkSecurityGroupNodeID(record)
	if id == "" {
		return nil
	}
	public := azureNetworkSecurityGroupAllowsInternet(record)
	risk := RiskNone
	if public {
		risk = RiskHigh
	}
	return &Node{
		ID:       id,
		Kind:     NodeKindNetwork,
		Name:     firstNonEmpty(queryRowString(record, "name"), id),
		Provider: firstNonEmpty(provider, "azure"),
		Account:  firstNonEmpty(queryRowString(record, "subscription_id"), account),
		Region:   firstNonEmpty(queryRowString(record, "location"), region),
		Risk:     risk,
		Properties: map[string]any{
			"network_kind":           "network_security_group",
			"resource_group":         queryRow(record, "resource_group"),
			"security_rules":         queryRow(record, "security_rules"),
			"default_security_rules": queryRow(record, "default_security_rules"),
			"public":                 public,
		},
	}
}

func awsSecurityGroupAllowsInternet(value any) bool {
	return containsInternetCIDR(strings.ToLower(toString(value)))
}

func gcpFirewallAllowsInternet(record map[string]any) bool {
	if toBool(queryRow(record, "disabled")) {
		return false
	}
	direction := strings.ToUpper(strings.TrimSpace(queryRowString(record, "direction")))
	if direction != "INGRESS" {
		return false
	}
	return containsInternetCIDR(strings.ToLower(toString(queryRow(record, "source_ranges"))))
}

func azureNetworkSecurityGroupAllowsInternet(record map[string]any) bool {
	return azureRulesAllowInternet(queryRow(record, "security_rules")) ||
		azureRulesAllowInternet(queryRow(record, "default_security_rules"))
}

func containsInternetCIDR(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	return strings.Contains(value, "0.0.0.0/0") || strings.Contains(value, "::/0")
}

func azureRulesAllowInternet(value any) bool {
	value = normalizeStructuredValue(value)
	switch typed := value.(type) {
	case []map[string]any:
		for _, rule := range typed {
			if azureRuleAllowsInternet(rule) {
				return true
			}
		}
		return false
	case []any:
		for _, item := range typed {
			if azureRuleAllowsInternet(asAnyMap(item)) {
				return true
			}
		}
		return false
	case map[string]any:
		return azureRuleAllowsInternet(typed)
	default:
		return azureRulesAllowInternetFromString(strings.ToLower(toString(value)))
	}
}

func azureRuleAllowsInternet(rule map[string]any) bool {
	if len(rule) == 0 {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(azureRuleString(rule, "access", "Access")), "allow") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(azureRuleString(rule, "direction", "Direction")), "inbound") {
		return false
	}
	for _, prefix := range azureRuleSourcePrefixes(rule) {
		if azureSourcePrefixAllowsInternet(prefix) {
			return true
		}
	}
	return false
}

func azureRuleSourcePrefixes(rule map[string]any) []string {
	out := make([]string, 0, 4)
	for _, key := range []string{
		"source_address_prefix",
		"SourceAddressPrefix",
		"sourceAddressPrefix",
		"source_address_prefixes",
		"SourceAddressPrefixes",
		"sourceAddressPrefixes",
	} {
		if value, ok := queryRowValue(rule, key); ok {
			out = appendStringValues(out, value)
		}
	}
	return out
}

func appendStringValues(dst []string, value any) []string {
	value = normalizeStructuredValue(value)
	switch typed := value.(type) {
	case []string:
		for _, item := range typed {
			if item = strings.TrimSpace(item); item != "" {
				dst = append(dst, item)
			}
		}
	case []any:
		for _, item := range typed {
			if itemStr := strings.TrimSpace(toString(item)); itemStr != "" {
				dst = append(dst, itemStr)
			}
		}
	default:
		if item := strings.TrimSpace(toString(typed)); item != "" {
			dst = append(dst, item)
		}
	}
	return dst
}

func azureRuleString(rule map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := queryRowValue(rule, key); ok {
			if text := strings.TrimSpace(toString(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func azureSourcePrefixAllowsInternet(prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return false
	}
	return prefix == "*" || prefix == "internet" || prefix == "any" || containsInternetCIDR(prefix)
}

func azureRulesAllowInternetFromString(rules string) bool {
	if rules == "" {
		return false
	}
	if !strings.Contains(rules, "allow") || !strings.Contains(rules, "inbound") {
		return false
	}
	return containsInternetCIDR(rules) ||
		strings.Contains(rules, "internet") ||
		strings.Contains(rules, "\"*\"") ||
		strings.Contains(rules, "sourceaddressprefix:*") ||
		strings.Contains(rules, "source_address_prefix:*") ||
		strings.Contains(rules, "sourceaddressprefixes:[*]") ||
		strings.Contains(rules, "source_address_prefixes:[*]")
}

func asAnyMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}
