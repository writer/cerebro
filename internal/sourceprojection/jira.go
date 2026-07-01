package sourceprojection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var jiraIdentityProfile = identityProjectionProfile{Provider: "jira"}

func jiraUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, jiraIdentityProfile)
}

func jiraGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, jiraIdentityProfile)
}

func jiraGroupMembersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, jiraIdentityProfile)
}

func jiraProjectsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	projectID := firstNonEmpty(attributes["project_id"], attributes["resource_id"], event.GetId())
	if projectID == "" {
		return nil, nil, nil
	}
	projectURN := projectionURN(tenantID, "jira_project", projectID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        projectURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "jira.project",
		Label:      firstNonEmpty(attributes["project_name"], attributes["resource_name"], attributes["project_key"], projectID),
		Attributes: map[string]string{
			"archived":          strings.TrimSpace(attributes["archived"]),
			"category_id":       strings.TrimSpace(attributes["category_id"]),
			"category_name":     strings.TrimSpace(attributes["category_name"]),
			"deleted":           strings.TrimSpace(attributes["deleted"]),
			"project_id":        projectID,
			"project_key":       strings.TrimSpace(attributes["project_key"]),
			"project_name":      firstNonEmpty(attributes["project_name"], attributes["resource_name"]),
			"project_type":      strings.TrimSpace(attributes["project_type"]),
			"project_uuid":      strings.TrimSpace(attributes["project_uuid"]),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
			"style":             strings.TrimSpace(attributes["style"]),
		},
	})
	if leadID := strings.TrimSpace(attributes["lead_user_id"]); leadID != "" {
		leadURN := identityUserURN(tenantID, jiraIdentityProfile.Provider, leadID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: leadURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "jira.user", Label: leadID, Attributes: map[string]string{"user_id": leadID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), projectURN, leadURN, relationOwnedBy, map[string]string{"event_id": event.GetId(), "match_type": "jira_project_lead"}))
	}
	addJiraEvidenceLink(entities, links, tenantID, event, projectURN, attributes)
	return identityProjectionResult(entities, links)
}

func jiraProjectRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	projectID := firstNonEmpty(attributes["project_id"], attributes["project_key"], attributes["project_id_or_key"])
	roleID := firstNonEmpty(attributes["role_id"], attributes["resource_id"], event.GetId())
	if roleID == "" {
		return nil, nil, nil
	}
	scopedRoleID := jiraScopedRoleID(projectID, roleID)
	roleKind := "role"
	if projectionBool(attributes["admin"]) {
		roleKind = "admin_role"
	}
	globalRoleURN := projectionURN(tenantID, "jira_role", roleID)
	roleURN := projectionURN(tenantID, "jira_"+roleKind, scopedRoleID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        globalRoleURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "jira.role",
		Label:      firstNonEmpty(attributes["role_name"], attributes["resource_name"], roleID),
		Attributes: map[string]string{
			"role_id":           roleID,
			"role_name":         firstNonEmpty(attributes["role_name"], attributes["resource_name"]),
			"role_type":         firstNonEmpty(attributes["role_type"], "project_role"),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        roleURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "jira." + roleKind,
		Label:      firstNonEmpty(attributes["role_name"], attributes["resource_name"], roleID),
		Attributes: map[string]string{
			"is_admin":          strings.TrimSpace(attributes["admin"]),
			"project_id":        projectID,
			"project_key":       strings.TrimSpace(attributes["project_key"]),
			"role_id":           roleID,
			"role_name":         firstNonEmpty(attributes["role_name"], attributes["resource_name"]),
			"scoped_role_id":    scopedRoleID,
			"role_type":         firstNonEmpty(attributes["role_type"], "project_role"),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		},
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, globalRoleURN, relationRepresents, map[string]string{"event_id": event.GetId(), "match_type": "jira_project_role_definition"}))
	if projectID != "" {
		projectURN := projectionURN(tenantID, "jira_project", projectID)
		addEntity(entities, &ports.ProjectedEntity{URN: projectURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "jira.project", Label: firstNonEmpty(attributes["project_key"], projectID), Attributes: map[string]string{"project_id": projectID, "project_key": strings.TrimSpace(attributes["project_key"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, projectURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "match_type": "jira_project_role_scope"}))
	}
	for _, actor := range jiraRoleActors(event) {
		subjectType, subjectID, subjectName := jiraActorSubject(actor)
		if subjectID == "" {
			continue
		}
		assignmentAttrs := cloneStringMap(attributes)
		assignmentAttrs["role"] = scopedRoleID
		assignmentAttrs["role_id"] = scopedRoleID
		assignmentAttrs["role_name"] = firstNonEmpty(attributes["role_name"], attributes["resource_name"], roleID)
		assignmentAttrs["role_type"] = "project_role"
		assignmentAttrs["subject_id"] = subjectID
		assignmentAttrs["subject_name"] = subjectName
		assignmentAttrs["subject_type"] = subjectType
		assignmentAttrs["is_admin"] = strings.TrimSpace(attributes["admin"])
		synthetic := &cerebrov1.EventEnvelope{
			Id:         event.GetId() + "-" + normalizeIdentifier(subjectType) + "-" + normalizeIdentifier(subjectID),
			TenantId:   event.GetTenantId(),
			SourceId:   event.GetSourceId(),
			Kind:       event.GetKind(),
			OccurredAt: event.GetOccurredAt(),
			Attributes: assignmentAttrs,
		}
		roleEntities, roleLinks, err := identityRoleAssignmentProjections(synthetic, jiraIdentityProfile)
		if err != nil {
			return nil, nil, err
		}
		for _, entity := range roleEntities {
			if entity.URN == roleURN {
				if entity.Attributes == nil {
					entity.Attributes = map[string]string{}
				}
				entity.Attributes["role_id"] = roleID
				entity.Attributes["scoped_role_id"] = scopedRoleID
			}
			addEntity(entities, entity)
		}
		for _, link := range roleLinks {
			addLink(links, link)
		}
	}
	addJiraEvidenceLink(entities, links, tenantID, event, roleURN, attributes)
	return identityProjectionResult(entities, links)
}

func jiraPermissionSchemesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	policyID := firstNonEmpty(attributes["policy_id"], attributes["resource_id"], event.GetId())
	if policyID == "" {
		return nil, nil, nil
	}
	policyURN := projectionURN(tenantID, "jira_permission_scheme", policyID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        policyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "jira.permission_scheme",
		Label:      firstNonEmpty(attributes["policy_name"], attributes["resource_name"], policyID),
		Attributes: map[string]string{
			"description":       strings.TrimSpace(attributes["description"]),
			"policy_id":         policyID,
			"policy_name":       strings.TrimSpace(attributes["policy_name"]),
			"policy_type":       firstNonEmpty(attributes["policy_type"], "permission_scheme"),
			"source_runtime_id": strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		},
	})
	for _, grant := range jiraPermissionGrants(event) {
		grantID := jiraPermissionGrantID(grant)
		permission := jiraAnyString(grant["permission"])
		grantURN := projectionURN(tenantID, "jira_permission_grant", policyID, grantID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        grantURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "jira.permission_grant",
			Label:      firstNonEmpty(permission, grantID),
			Attributes: map[string]string{"permission": permission, "policy_id": policyID, "policy_type": "permission_scheme"},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, grantURN, relationGrantsEntitlement, map[string]string{"event_id": event.GetId(), "permission": permission}))
		holder, _ := grant["holder"].(map[string]any)
		holderURN, holderType, holderID := jiraPermissionHolderURN(tenantID, holder)
		if holderURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        holderURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "jira." + strings.ReplaceAll(holderType, "_", "."),
			Label:      firstNonEmpty(jiraAnyString(holder["value"]), jiraAnyString(holder["parameter"]), holderID),
			Attributes: map[string]string{"holder_id": holderID, "holder_type": holderType},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), holderURN, grantURN, relationCanPerform, map[string]string{"event_id": event.GetId(), "permission": permission, "policy_id": policyID}))
	}
	addJiraEvidenceLink(entities, links, tenantID, event, policyURN, attributes)
	return identityProjectionResult(entities, links)
}

func jiraAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, jiraIdentityProfile)
}

func jiraRoleActors(event *cerebrov1.EventEnvelope) []map[string]any {
	payload := payloadMap(event)
	rawActors, _ := payload["actors"].([]any)
	actors := make([]map[string]any, 0, len(rawActors))
	for _, raw := range rawActors {
		actor, ok := raw.(map[string]any)
		if ok {
			actors = append(actors, actor)
		}
	}
	return actors
}

func jiraActorSubject(actor map[string]any) (string, string, string) {
	actorType := strings.ToLower(jiraAnyString(actor["type"]))
	displayName := jiraAnyString(actor["displayName"])
	if strings.Contains(actorType, "group") {
		group, _ := actor["actorGroup"].(map[string]any)
		return "group", firstNonEmpty(jiraAnyString(group["groupId"]), jiraAnyString(group["name"]), displayName), firstNonEmpty(displayName, jiraAnyString(group["name"]))
	}
	user, _ := actor["actorUser"].(map[string]any)
	return "user", firstNonEmpty(jiraAnyString(user["accountId"]), jiraAnyString(actor["name"]), displayName), displayName
}

func jiraPermissionGrants(event *cerebrov1.EventEnvelope) []map[string]any {
	payload := payloadMap(event)
	rawGrants, _ := payload["permissions"].([]any)
	grants := make([]map[string]any, 0, len(rawGrants))
	for _, raw := range rawGrants {
		grant, ok := raw.(map[string]any)
		if ok {
			grants = append(grants, grant)
		}
	}
	return grants
}

func jiraPermissionGrantID(grant map[string]any) string {
	if grantID := firstNonEmpty(jiraAnyString(grant["id"]), jiraAnyString(grant["permission"])); grantID != "" {
		return grantID
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return jiraStableID("permission_grant")
	}
	return jiraStableID(string(encoded))
}

func jiraPermissionHolderURN(tenantID string, holder map[string]any) (string, string, string) {
	holderType := normalizeIdentifier(jiraAnyString(holder["type"]))
	holderID := firstNonEmpty(jiraAnyString(holder["parameter"]), jiraAnyString(holder["value"]), holderType)
	switch holderType {
	case "group":
		return identityGroupURN(tenantID, jiraIdentityProfile.Provider, holderID, ""), "group", holderID
	case "user":
		return identityUserURN(tenantID, jiraIdentityProfile.Provider, holderID, ""), "user", holderID
	case "project_role", "projectrole":
		roleID := firstNonEmpty(jiraAnyString(holder["parameter"]), jiraAnyString(holder["value"]))
		if roleID == "" {
			return "", "", ""
		}
		return projectionURN(tenantID, "jira_role", roleID), "role", roleID
	case "application_role", "applicationrole":
		return projectionURN(tenantID, "jira_application_role", holderID), "application_role", holderID
	default:
		if holderID == "" {
			return "", "", ""
		}
		return projectionURN(tenantID, "jira_principal", holderType, holderID), firstNonEmpty(holderType, "principal"), holderID
	}
}

func jiraScopedRoleID(projectID string, roleID string) string {
	if strings.TrimSpace(projectID) == "" {
		return strings.TrimSpace(roleID)
	}
	return strings.TrimSpace(projectID) + ":" + strings.TrimSpace(roleID)
}

func jiraAnyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%.0f", typed))
	case bool:
		return boolString(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func addJiraEvidenceLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, attributes map[string]string) {
	evidenceID := strings.TrimSpace(attributes["evidence_id"])
	if evidenceID == "" || resourceURN == "" {
		return
	}
	evidenceURN := projectionURN(tenantID, "runtime_evidence", evidenceID)
	addEntity(entities, &ports.ProjectedEntity{URN: evidenceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "runtime.evidence", Label: evidenceID, Attributes: map[string]string{"evidence_id": evidenceID, "evidence_cas_uri": strings.TrimSpace(attributes["evidence_cas_uri"]), "evidence_cas_digest": strings.TrimSpace(attributes["evidence_cas_digest"])}})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, evidenceURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
}

func jiraStableID(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])[:16]
}
