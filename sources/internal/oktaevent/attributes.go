package oktaevent

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type Identity struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type,omitempty"`
	AlternateID string `json:"alternate_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type SystemLogContext struct {
	Client                map[string]any
	Request               map[string]any
	SecurityContext       map[string]any
	AuthenticationContext map[string]any
	DebugContext          map[string]any
	Transaction           map[string]any
}

func AppAssignmentAttributes(domain string, family string, appID string, subjectID string, subjectType string, status string) map[string]string {
	return map[string]string{
		"domain":         domain,
		"family":         family,
		"app_id":         appID,
		"subject_id":     subjectID,
		"subject_type":   subjectType,
		"assignee_id":    subjectID,
		"assignee_type":  subjectType,
		"principal_type": subjectType,
		"status":         status,
	}
}

func AddSystemLogAttributes(attributes map[string]string, ctx SystemLogContext) {
	auth := ctx.AuthenticationContext
	addAttribute(attributes, "authentication_provider", stringMap(auth, "authenticationProvider"))
	addAttribute(attributes, "credential_provider", stringMap(auth, "credentialProvider"))
	addAttribute(attributes, "credential_type", stringMap(auth, "credentialType"))
	addAttribute(attributes, "authentication_step", anyString(auth, "authenticationStep"))
	addAttribute(attributes, "authentication_interface", stringMap(auth, "interface"))
	addAttribute(attributes, "session_id", firstNonEmpty(stringMap(auth, "externalSessionId"), stringMap(auth, "rootSessionId"), stringMap(ctx.Transaction, "id")))
	addAttribute(attributes, "external_session_id", stringMap(auth, "externalSessionId"))
	addAttribute(attributes, "root_session_id", stringMap(auth, "rootSessionId"))

	security := ctx.SecurityContext
	addAttribute(attributes, "asn", anyString(security, "asNumber"))
	addAttribute(attributes, "as_org", stringMap(security, "asOrg"))
	addAttribute(attributes, "isp", stringMap(security, "isp"))
	addAttribute(attributes, "security_domain", stringMap(security, "domain"))
	addAttribute(attributes, "is_proxy", anyString(security, "isProxy"))

	debugData := nestedMap(ctx.DebugContext, "debugData")
	addAttribute(attributes, "debug_request_id", stringMap(debugData, "requestId"))
	addAttribute(attributes, "debug_request_uri", firstNonEmpty(stringMap(debugData, "requestUri"), stringMap(debugData, "url")))
	addAttribute(attributes, "request_api_token_id", stringMap(debugData, "requestApiTokenId"))
	addAttribute(attributes, "risk_level", firstNonEmpty(stringMap(debugData, "riskLevel"), stringMap(debugData, "risk")))
	addAttribute(attributes, "risk", firstNonEmpty(stringMap(debugData, "risk"), stringMap(debugData, "riskLevel")))
	addAttribute(attributes, "threat_suspected", anyString(debugData, "threatSuspected"))
	addAttribute(attributes, "behaviors", firstNonEmpty(stringMap(debugData, "behaviors"), strings.Join(stringSliceMap(debugData, "behaviors"), ",")))

	ipChain := mapSlice(ctx.Request, "ipChain")
	if len(ipChain) == 0 {
		ipChain = mapSlice(ctx.Client, "ipChain")
	}
	if len(ipChain) == 0 {
		return
	}
	attributes["request_ip_count"] = strconv.Itoa(len(ipChain))
	ips := make([]string, 0, len(ipChain))
	for _, hop := range ipChain {
		if ip := firstNonEmpty(stringMap(hop, "ip"), stringMap(hop, "ipAddress")); ip != "" {
			ips = append(ips, ip)
		}
	}
	addAttribute(attributes, "request_ip_chain", strings.Join(ips, ","))
	addAttribute(attributes, "request_first_ip", firstNonEmpty(stringMap(ipChain[0], "ip"), stringMap(ipChain[0], "ipAddress")))
	geo := nestedMap(ipChain[0], "geographicalContext")
	addAttribute(attributes, "request_first_city", stringMap(geo, "city"))
	addAttribute(attributes, "request_first_state", stringMap(geo, "state"))
	addAttribute(attributes, "request_first_country", stringMap(geo, "country"))
}

func AddTargetAttributes(attributes map[string]string, targets []Identity) {
	if len(targets) == 0 {
		return
	}
	attributes["target_count"] = strconv.Itoa(len(targets))
	targetIDs := make([]string, 0, len(targets))
	targetTypes := make([]string, 0, len(targets))
	targetAlternateIDs := make([]string, 0, len(targets))
	targetDisplayNames := make([]string, 0, len(targets))
	for _, target := range targets {
		appendNonEmpty(&targetIDs, target.ID)
		appendNonEmpty(&targetTypes, target.Type)
		appendNonEmpty(&targetAlternateIDs, target.AlternateID)
		appendNonEmpty(&targetDisplayNames, target.DisplayName)
		if targetIsApp(target) {
			addAttribute(attributes, "target_app_id", target.ID)
			addAttribute(attributes, "target_app_label", target.DisplayName)
			addAttribute(attributes, "target_app_alternate_id", target.AlternateID)
		}
		if targetIsUser(target) {
			addAttribute(attributes, "target_user_id", target.ID)
			addAttribute(attributes, "target_user_email", target.AlternateID)
		}
	}
	addAttribute(attributes, "target_ids", strings.Join(targetIDs, ","))
	addAttribute(attributes, "target_types", strings.Join(targetTypes, ","))
	addAttribute(attributes, "target_alternate_ids", strings.Join(targetAlternateIDs, ","))
	addAttribute(attributes, "target_display_names", strings.Join(targetDisplayNames, ","))
}

func OAuthEventCategory(eventType string) string {
	action := strings.ToLower(strings.TrimSpace(eventType))
	if routineIdentityAssignmentAction(action) {
		return ""
	}
	switch action {
	case "app.oauth2.authorize.code", "app.oauth2.as.authorize.code":
		return "runtime_grant"
	}
	if strings.HasPrefix(action, "app.oauth2.token.grant.") ||
		strings.HasPrefix(action, "app.oauth2.as.token.grant.") {
		return "runtime_grant"
	}
	if containsAny(action, "api_token", "client_secret", "client.secret", "domain_wide", "domain-wide") &&
		containsAny(action, "create", "authorize", "grant", "add", "rotate", "generate") {
		return "credential_change"
	}
	if containsAny(action, "oauth", "api_client", "client_access", "application") &&
		containsAny(action, "create", "add") {
		return "credential_change"
	}
	return ""
}

func OAuthGrantType(eventType string) string {
	action := strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.Contains(action, "authorize.code"):
		return "authorization_code"
	case strings.HasSuffix(action, ".access_token"):
		return "access_token"
	case strings.HasSuffix(action, ".refresh_token"):
		return "refresh_token"
	case strings.HasSuffix(action, ".id_token"):
		return "id_token"
	default:
		return ""
	}
}

func OAuthClientIdentity(actor Identity, targets []Identity) Identity {
	if oauthClientLike(actor) {
		return actor
	}
	for _, target := range targets {
		if oauthClientLike(target) {
			return target
		}
	}
	return Identity{}
}

func routineIdentityAssignmentAction(action string) bool {
	switch action {
	case "application.user_membership.add",
		"application.user_membership.remove",
		"application.user_membership.update",
		"application.group_membership.add",
		"application.group_membership.remove",
		"application.group_membership.update",
		"group.application_assignment.add",
		"group.application_assignment.remove",
		"group.application_assignment.update",
		"group.user_membership.add",
		"group.user_membership.remove",
		"group.user_membership.update",
		"application.provision.group_push.mapping.created",
		"application.provision.group_push.mapping.deleted",
		"application.provision.group_push.mapping.updated":
		return true
	}
	return strings.Contains(action, "user_membership") ||
		strings.Contains(action, "group_membership") ||
		strings.Contains(action, "application_assignment") ||
		strings.Contains(action, "group_push.mapping")
}

func oauthClientLike(identity Identity) bool {
	id := strings.TrimSpace(identity.ID)
	kind := strings.ToLower(strings.TrimSpace(identity.Type))
	return id != "" && (strings.Contains(kind, "clientapp") || strings.Contains(kind, "application") || strings.HasSuffix(kind, "app") || strings.HasPrefix(id, "0oa"))
}

func targetIsApp(target Identity) bool {
	kind := strings.ToLower(strings.TrimSpace(target.Type))
	id := strings.TrimSpace(target.ID)
	return strings.Contains(kind, "app") || strings.HasPrefix(id, "0oa")
}

func targetIsUser(target Identity) bool {
	kind := strings.ToLower(strings.TrimSpace(target.Type))
	id := strings.TrimSpace(target.ID)
	return kind == "user" || strings.HasPrefix(id, "00u") || strings.Contains(target.AlternateID, "@")
}

func addAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) != "" {
		attributes[key] = strings.TrimSpace(value)
	}
}

func nestedMap(values map[string]any, key string) map[string]any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return child
}

func stringMap(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func stringSliceMap(values map[string]any, key string) []string {
	value, ok := values[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if ok && strings.TrimSpace(text) != "" {
			result = append(result, strings.TrimSpace(text))
		}
	}
	return result
}

func anyString(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		if math.Trunc(typed) == typed {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func mapSlice(values map[string]any, key string) []map[string]any {
	value, ok := values[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		mapped, ok := item.(map[string]any)
		if ok {
			result = append(result, mapped)
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func appendNonEmpty(values *[]string, value string) {
	if strings.TrimSpace(value) != "" {
		*values = append(*values, strings.TrimSpace(value))
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
