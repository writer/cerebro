package sync

import (
	"context"
	"strings"
)

func (r *RelationshipExtractor) extractOktaRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	query := `SELECT GROUP_ID, USER_ID FROM OKTA_GROUP_MEMBERSHIPS WHERE GROUP_ID IS NOT NULL AND USER_ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "OKTA_GROUP_MEMBERSHIPS", query); err != nil {
		return 0, err
	} else if ok {
		rels = appendOktaGroupMembershipRelationships(rels, result.Rows)
	}

	query = `SELECT APP_ID, ASSIGNEE_ID, ASSIGNEE_TYPE FROM OKTA_APP_ASSIGNMENTS WHERE APP_ID IS NOT NULL AND ASSIGNEE_ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "OKTA_APP_ASSIGNMENTS", query); err != nil {
		return 0, err
	} else if ok {
		rels = appendOktaAppAssignmentRelationships(rels, result.Rows)
	}

	query = `SELECT USER_ID, ROLE_TYPE, ROLE_LABEL FROM OKTA_ADMIN_ROLES WHERE USER_ID IS NOT NULL AND ROLE_TYPE IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "OKTA_ADMIN_ROLES", query); err != nil {
		return 0, err
	} else if ok {
		rels = appendOktaAdminRoleRelationships(rels, result.Rows)
	}

	return r.persistRelationships(ctx, rels)
}

func appendOktaGroupMembershipRelationships(rels []Relationship, rows []map[string]interface{}) []Relationship {
	for _, row := range rows {
		groupID := toString(queryRow(row, "group_id"))
		userID := toString(queryRow(row, "user_id"))
		if groupID == "" || userID == "" {
			continue
		}

		rels = append(rels, Relationship{
			SourceID:   userID,
			SourceType: "okta:user",
			TargetID:   groupID,
			TargetType: "okta:group",
			RelType:    RelMemberOf,
		})
	}

	return rels
}

func appendOktaAppAssignmentRelationships(rels []Relationship, rows []map[string]interface{}) []Relationship {
	for _, row := range rows {
		appID := toString(queryRow(row, "app_id"))
		assigneeID := toString(queryRow(row, "assignee_id"))
		if appID == "" || assigneeID == "" {
			continue
		}

		assigneeType := strings.ToUpper(strings.TrimSpace(toString(queryRow(row, "assignee_type"))))
		sourceType := ""
		switch assigneeType {
		case "GROUP":
			sourceType = "okta:group"
		case "USER":
			sourceType = "okta:user"
		default:
			continue
		}

		rels = append(rels, Relationship{
			SourceID:   assigneeID,
			SourceType: sourceType,
			TargetID:   appID,
			TargetType: "okta:application",
			RelType:    RelCanAccess,
		})
	}

	return rels
}

func appendOktaAdminRoleRelationships(rels []Relationship, rows []map[string]interface{}) []Relationship {
	for _, row := range rows {
		userID := toString(queryRow(row, "user_id"))
		roleType := strings.TrimSpace(toString(queryRow(row, "role_type")))
		if userID == "" || roleType == "" {
			continue
		}

		roleID := oktaAdminRoleNodeID(roleType)
		if roleID == "" {
			continue
		}

		props, err := encodeProperties(map[string]interface{}{
			"role_type":  roleType,
			"role_label": toString(queryRow(row, "role_label")),
		})
		if err != nil {
			props = "{}"
		}

		rels = append(rels, Relationship{
			SourceID:   userID,
			SourceType: "okta:user",
			TargetID:   roleID,
			TargetType: "okta:admin_role",
			RelType:    RelHasRole,
			Properties: props,
		})
	}

	return rels
}

func oktaAdminRoleNodeID(roleType string) string {
	normalized := strings.ToLower(strings.TrimSpace(roleType))
	if normalized == "" {
		return ""
	}
	return "okta_admin_role:" + normalized
}
