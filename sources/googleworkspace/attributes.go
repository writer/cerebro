package googleworkspace

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func userAttributes(settings settings, record userRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyUser,
		"user_id":            record.ID,
		"primary_email":      record.PrimaryEmail,
		"email":              record.PrimaryEmail,
		"login":              record.PrimaryEmail,
		"display_name":       record.Name.FullName,
		"created_at":         record.CreationTime,
		"last_login_at":      record.LastLoginTime,
		"is_admin":           boolString(record.IsAdmin),
		"is_delegated_admin": boolString(record.IsDelegatedAdmin),
		"mfa_enrolled":       boolString(record.IsEnrolledIn2SV),
		"mfa_enforced":       boolString(record.IsEnforcedIn2SV),
		"suspended":          boolString(record.Suspended),
		"archived":           boolString(record.Archived),
		"org_unit_path":      record.OrgUnitPath,
	})
}

func groupAttributes(settings settings, record groupRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":               settings.domain,
		"family":               familyGroup,
		"group_id":             record.ID,
		"group_email":          record.Email,
		"email":                record.Email,
		"group_name":           record.Name,
		"name":                 record.Name,
		"description":          record.Description,
		"admin_created":        boolString(record.AdminCreated),
		"direct_members_count": record.DirectMembersCount,
	})
}

func groupMemberAttributes(settings settings, record memberRecord) map[string]string {
	return trimEmpty(map[string]string{
		"domain":         settings.domain,
		"family":         familyGroupMember,
		"group_id":       settings.groupKey,
		"group_email":    settings.groupKey,
		"member_id":      record.ID,
		"member_email":   record.Email,
		"member_user_id": record.ID,
		"email":          record.Email,
		"member_type":    strings.ToLower(record.Type),
		"role":           record.Role,
		"member_status":  record.Status,
		"user_id":        record.ID,
	})
}

func roleAssignmentAttributes(settings settings, record roleAssignmentRecord) map[string]string {
	subjectEmail := firstNonEmpty(record.SubjectEmail, emailLike(record.AssignedTo))
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyRoleAssign,
		"role_assignment_id": record.RoleAssignmentID,
		"role_id":            record.RoleID,
		"subject_email":      subjectEmail,
		"subject_id":         record.AssignedTo,
		"subject_login":      subjectEmail,
		"subject_name":       record.SubjectName,
		"assigned_to":        record.AssignedTo,
		"subject_type":       strings.ToLower(record.AssigneeType),
		"principal_type":     strings.ToLower(record.AssigneeType),
		"scope_type":         record.ScopeType,
		"org_unit_id":        record.OrgUnitID,
		"event_type":         "admin.role.assignment",
		"action":             "admin.role.assignment",
	})
}

func auditAttributes(settings settings, record auditRecord, eventName string, eventType string) map[string]string {
	parameters := auditParameters(record)
	resourceID := firstNonEmpty(parameters["USER_EMAIL"], parameters["GROUP_EMAIL"], parameters["APP_NAME"], parameters["CLIENT_ID"], parameters["ROLE_NAME"], eventName)
	resourceType := firstNonEmpty(parameters["RESOURCE_TYPE"], eventType, "security_setting")
	return trimEmpty(map[string]string{
		"domain":             settings.domain,
		"family":             familyAudit,
		"event_type":         eventName,
		"event_name":         eventName,
		"action":             eventName,
		"resource_id":        resourceID,
		"resource_type":      normalizeResourceType(resourceType),
		"resource_name":      resourceID,
		"actor_email":        record.Actor.Email,
		"actor_id":           record.Actor.ProfileID,
		"actor_alternate_id": record.Actor.Email,
		"application":        record.ID.ApplicationName,
		"customer_id":        record.ID.CustomerID,
	})
}

func auditParameters(record auditRecord) map[string]string {
	values := map[string]string{}
	if len(record.Events) == 0 {
		return values
	}
	for _, parameter := range record.Events[0].Parameters {
		values[strings.ToUpper(strings.TrimSpace(parameter.Name))] = strings.TrimSpace(parameter.Value)
	}
	return values
}

func discoverURN(settings settings, raw json.RawMessage) (sourcecdk.URN, error) {
	event, err := sourceEvent(settings, raw)
	if err != nil {
		return "", err
	}
	kind := strings.TrimPrefix(strings.ReplaceAll(event.Kind, ".", "_"), "google_workspace_")
	id := firstNonEmpty(event.Attributes["user_id"], event.Attributes["group_id"], event.Attributes["role_assignment_id"], event.Attributes["event_type"])
	return sourcecdk.ParseURN("urn:cerebro:" + settings.domain + ":google_workspace_" + kind + ":" + id)
}

func firstParsedTime(values ...string) time.Time {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || trimmed == "1970-01-01T00:00:00.000Z" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}

func checkpointCursor(next string, fallback string) string {
	if strings.TrimSpace(next) != "" {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(fallback)
}

func boolString(value bool) string {
	return strconv.FormatBool(value)
}

func trimEmpty(values map[string]string) map[string]string {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			delete(values, key)
		}
	}
	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func normalizeResourceType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return normalized
}

func auditSourceEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	occurredAt := firstParsedTime(record.ID.Time)
	eventName := ""
	eventType := ""
	if len(record.Events) > 0 {
		eventName = record.Events[0].Name
		eventType = record.Events[0].Type
	}
	payload, err := sourcecdk.NewPayloadOverlay().Set("domain", settings.domain).MergeRawJSON(record.raw)
	if err != nil {
		return nil, err
	}
	id := firstNonEmpty(record.ID.UniqueQualifier, eventName, strconv.FormatInt(occurredAt.UnixMilli(), 10))
	return &primitives.Event{
		Id:         "google-workspace-audit-" + id,
		TenantId:   settings.domain,
		SourceId:   "google_workspace",
		Kind:       "google_workspace.audit",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "google_workspace/audit/v1",
		Payload:    payload,
		Attributes: auditAttributes(settings, record, eventName, eventType),
	}, nil
}
