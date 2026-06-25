package sourceprojection

import (
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type identityProjectionProfile struct {
	Provider string
}

var (
	awsIdentityProfile             = identityProjectionProfile{Provider: "aws"}
	azureIdentityProfile           = identityProjectionProfile{Provider: "azure"}
	gcpIdentityProfile             = identityProjectionProfile{Provider: "gcp"}
	oktaIdentityProfile            = identityProjectionProfile{Provider: "okta"}
	googleWorkspaceIdentityProfile = identityProjectionProfile{Provider: "google_workspace"}
)

func (p identityProjectionProfile) entityType(kind string) string {
	return p.Provider + "." + kind
}

func oktaGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, oktaIdentityProfile)
}

func oktaGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, oktaIdentityProfile)
}

func oktaApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := identityApplicationProjections(event, oktaIdentityProfile)
	if err != nil {
		return nil, nil, err
	}
	saasEntities, saasLinks, err := oktaSaaSApplicationProjections(event)
	if err != nil {
		return nil, nil, err
	}
	entityMap := map[string]*ports.ProjectedEntity{}
	linkMap := map[string]*ports.ProjectedLink{}
	for _, entity := range append(entities, saasEntities...) {
		addEntity(entityMap, entity)
	}
	for _, link := range append(links, saasLinks...) {
		addLink(linkMap, link)
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entityMap, linkMap)
	return projectedEntities, projectedLinks, nil
}

func oktaPolicyRuleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityPolicyRuleProjections(event, oktaIdentityProfile)
}

func oktaAppAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAppAssignmentProjections(event, oktaIdentityProfile)
}

func oktaAdminRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, oktaIdentityProfile)
}

type oktaSaaSApplicationClassification struct {
	Active         bool
	Confidence     string
	LifecycleState string
	Reasons        []string
}

func oktaSaaSApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	appID := firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"], attributes["id"])
	classification, ok := oktaSaaSApplicationClassificationFor(attributes)
	if appID == "" || !ok {
		return nil, nil, nil
	}
	appURN := identityApplicationURN(tenantID, oktaIdentityProfile.Provider, appID)
	saasURN := projectionURN(tenantID, "saas_application", oktaIdentityProfile.Provider, appID)
	if appURN == "" || saasURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	appDisplayName := firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"])
	appName := firstNonEmpty(appDisplayName, attributes["client_id"], appID)
	matchReason := strings.Join(classification.Reasons, ",")
	saasAttributes := map[string]string{
		"active":                         boolString(classification.Active),
		"app_id":                         appID,
		"app_label":                      strings.TrimSpace(attributes["app_label"]),
		"app_name":                       appName,
		"classification_confidence":      classification.Confidence,
		"client_id":                      strings.TrimSpace(attributes["client_id"]),
		"domain":                         strings.TrimSpace(attributes["domain"]),
		"lifecycle_state":                classification.LifecycleState,
		"match_reason":                   matchReason,
		"name":                           strings.TrimSpace(attributes["name"]),
		"oauth2":                         strings.TrimSpace(attributes["oauth2"]),
		"post_logout_redirect_uri_hosts": strings.TrimSpace(attributes["post_logout_redirect_uri_hosts"]),
		"redirect_uri_hosts":             strings.TrimSpace(attributes["redirect_uri_hosts"]),
		"saml":                           strings.TrimSpace(attributes["saml"]),
		"sign_on_mode":                   strings.TrimSpace(attributes["sign_on_mode"]),
		"source_app_id":                  appID,
		"source_provider":                oktaIdentityProfile.Provider,
		"status":                         strings.TrimSpace(attributes["status"]),
	}
	trimEmptyProjectionAttributes(saasAttributes)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        saasURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "saas.application",
		Label:      appName,
		Attributes: saasAttributes,
	})
	linkAttrs := map[string]string{
		"active":          boolString(classification.Active),
		"confidence":      classification.Confidence,
		"event_id":        event.GetId(),
		"match_reason":    matchReason,
		"match_type":      "okta_saas_application",
		"source_app_id":   appID,
		"source_provider": oktaIdentityProfile.Provider,
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), appURN, saasURN, relationRepresents, linkAttrs))
	addVendorAliasLink(entities, links, tenantID, event.GetSourceId(), event, saasURN, appDisplayName, "okta_saas_application_name", "0.80")
	for _, host := range splitCSV(attributes["redirect_uri_hosts"]) {
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, saasURN, relationHasIdentifier, host, "okta_saas_application_redirect_host", "0.95")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, "okta_saas_application_redirect_domain", "0.95")
	}
	for _, host := range splitCSV(attributes["post_logout_redirect_uri_hosts"]) {
		addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, saasURN, relationHasIdentifier, host, "okta_saas_application_post_logout_redirect_host", "0.90")
		addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, "okta_saas_application_post_logout_redirect_domain", "0.90")
	}
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaSaaSApplicationClassificationFor(attributes map[string]string) (oktaSaaSApplicationClassification, bool) {
	name := strings.ToLower(strings.Join([]string{
		attributes["app_name"],
		attributes["app_label"],
		attributes["name"],
	}, " "))
	if containsAnyNormalizedToken(name, "test", "sandbox", "dev", "internal") {
		return oktaSaaSApplicationClassification{}, false
	}
	status := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["status"], "active")))
	classification := oktaSaaSApplicationClassification{
		Active:         status == "active" || status == "enabled",
		Confidence:     "0.75",
		LifecycleState: status,
	}
	signOnMode := strings.ToLower(strings.TrimSpace(attributes["sign_on_mode"]))
	for _, marker := range []string{"saml", "oidc", "oauth", "openid"} {
		if strings.Contains(signOnMode, marker) {
			classification.Reasons = append(classification.Reasons, "sign_on_mode_"+marker)
			classification.Confidence = "0.95"
		}
	}
	if projectionBool(attributes["saml"]) {
		classification.Reasons = append(classification.Reasons, "saml_enabled")
		classification.Confidence = "0.95"
	}
	if projectionBool(attributes["oauth2"]) {
		classification.Reasons = append(classification.Reasons, "oauth2_enabled")
		classification.Confidence = "0.95"
	}
	nameTokens := map[string]struct{}{}
	for _, token := range normalizedTokens(name) {
		nameTokens[token] = struct{}{}
	}
	for _, marker := range []string{"org2org", "vendor", "partner", "supplier", "contractor", "external"} {
		if _, ok := nameTokens[marker]; ok {
			classification.Reasons = append(classification.Reasons, "name_hint_"+marker)
		}
	}
	return classification, len(classification.Reasons) != 0
}

func awsIAMUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, awsIdentityProfile)
}

func awsIAMRoleProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, awsIdentityProfile)
}

func awsAccessKeyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, awsIdentityProfile)
}

func awsIAMGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, awsIdentityProfile)
}

func awsIAMGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, awsIdentityProfile)
}

func awsIAMRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, awsIdentityProfile)
}

func awsCloudTrailProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, awsIdentityProfile)
}

func azureUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, azureIdentityProfile)
}

func azureServicePrincipalProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := identityUserProjections(event, azureIdentityProfile)
	if err != nil {
		return nil, nil, err
	}
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	servicePrincipalURN := identityPrincipalURN(tenantID, azureIdentityProfile.Provider, "service_principal", firstNonEmpty(attributes["user_id"], attributes["subject_id"], attributes["id"]), "")
	applicationURN := identityApplicationURN(tenantID, azureIdentityProfile.Provider, attributes["app_id"])
	if servicePrincipalURN != "" && applicationURN != "" {
		entities = append(entities, &ports.ProjectedEntity{
			URN:        applicationURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: azureIdentityProfile.entityType("application"),
			Label:      firstNonEmpty(attributes["app_name"], attributes["display_name"], attributes["app_id"]),
			Attributes: map[string]string{"app_id": attributes["app_id"]},
		})
		links = append(links, projectedLink(tenantID, event.GetSourceId(), servicePrincipalURN, applicationURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
	}
	return entities, links, nil
}

func azureApplicationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, azureIdentityProfile)
}

func azureCredentialProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, azureIdentityProfile)
}

func azureGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, azureIdentityProfile)
}

func azureGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, azureIdentityProfile)
}

func azureRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, azureIdentityProfile)
}

func azureAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, azureIdentityProfile)
}

func gcpServiceAccountProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, gcpIdentityProfile)
}

func gcpServiceAccountKeyProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, gcpIdentityProfile)
}

func gcpGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, gcpIdentityProfile)
}

func gcpGroupMembershipProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, gcpIdentityProfile)
}

func gcpIAMRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, gcpIdentityProfile)
}

func gcpAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, gcpIdentityProfile)
}

func googleWorkspaceUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, googleWorkspaceIdentityProfile)
}

func googleWorkspaceGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, googleWorkspaceIdentityProfile)
}

func googleWorkspaceGroupMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, googleWorkspaceIdentityProfile)
}

func googleWorkspaceRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, googleWorkspaceIdentityProfile)
}

func googleWorkspaceAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, googleWorkspaceIdentityProfile)
}

func identityUserProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	domain := strings.TrimSpace(attributes["domain"])
	userID := firstNonEmpty(attributes["user_id"], attributes["id"], attributes["primary_email"], attributes["email"], attributes["login"])
	email := firstNonEmpty(attributes["email"], attributes["primary_email"], attributes["login"])
	login := firstNonEmpty(attributes["login"], attributes["primary_email"], attributes["email"])
	principalType := identityPrincipalType(firstNonEmpty(attributes["principal_type"], attributes["subject_type"], "user"))

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := identityOrgURN(tenantID, provider, domain)
	addIdentityOrg(entities, tenantID, event.GetSourceId(), provider, domain, orgURN)

	userURN := identityPrincipalURN(tenantID, provider, principalType, userID, email)
	if userURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(principalType),
			Label:      firstNonEmpty(attributes["display_name"], attributes["name"], email, login, userID),
			Attributes: map[string]string{
				"domain":             domain,
				"user_id":            userID,
				"email":              email,
				"login":              login,
				"status":             strings.TrimSpace(attributes["status"]),
				"created_at":         firstNonEmpty(attributes["created_at"], attributes["creation_time"]),
				"last_login_at":      firstNonEmpty(attributes["last_login_at"], attributes["last_login_time"]),
				"is_admin":           firstNonEmpty(attributes["is_admin"], attributes["admin"]),
				"is_delegated_admin": strings.TrimSpace(attributes["is_delegated_admin"]),
				"department":         strings.TrimSpace(attributes["department"]),
				"job_title":          firstNonEmpty(attributes["job_title"], attributes["title"]),
				"organization":       strings.TrimSpace(attributes["organization"]),
				"manager":            strings.TrimSpace(attributes["manager"]),
				"manager_id":         strings.TrimSpace(attributes["manager_id"]),
				"employee_number":    strings.TrimSpace(attributes["employee_number"]),
				"user_type":          strings.TrimSpace(attributes["user_type"]),
				"mfa_enrolled":       firstNonEmpty(attributes["mfa_enrolled"], attributes["is_enrolled_in_2sv"]),
				"mfa_enforced":       firstNonEmpty(attributes["mfa_enforced"], attributes["is_enforced_in_2sv"]),
				"suspended":          strings.TrimSpace(attributes["suspended"]),
				"archived":           strings.TrimSpace(attributes["archived"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, userURN, profile, attributes, principalType, userID)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, login, event.GetOccurredAt())
		}
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, userURN, profile, attributes, principalType, userID, login, attributes["arn"])
	}
	return identityProjectionResult(entities, links)
}

func identityGroupProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	domain := strings.TrimSpace(attributes["domain"])
	groupID := firstNonEmpty(attributes["group_id"], attributes["id"], attributes["group_email"], attributes["email"])
	groupEmail := firstNonEmpty(attributes["group_email"], attributes["email"])
	groupURN := identityGroupURN(tenantID, provider, groupID, groupEmail)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := identityOrgURN(tenantID, provider, domain)
	addIdentityOrg(entities, tenantID, event.GetSourceId(), provider, domain, orgURN)
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("group"),
			Label:      firstNonEmpty(attributes["group_name"], attributes["name"], groupEmail, groupID),
			Attributes: map[string]string{
				"domain":             domain,
				"group_id":           groupID,
				"group_email":        groupEmail,
				"group_name":         firstNonEmpty(attributes["group_name"], attributes["name"]),
				"description":        strings.TrimSpace(attributes["description"]),
				"admin_created":      strings.TrimSpace(attributes["admin_created"]),
				"direct_members":     strings.TrimSpace(attributes["direct_members_count"]),
				"non_editable_alias": strings.TrimSpace(attributes["non_editable_alias"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), groupURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, groupURN, profile, attributes, "group", groupID)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), groupURN, groupEmail, event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, groupURN, profile, attributes, "group", groupID, attributes["group_name"], attributes["arn"])
	}
	return identityProjectionResult(entities, links)
}

func identityGroupMembershipProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	groupURN := identityGroupURN(tenantID, provider, attributes["group_id"], firstNonEmpty(attributes["group_email"], attributes["email"]))
	memberEmail := firstNonEmpty(attributes["member_email"], attributes["email"], attributes["user_email"])
	memberID := firstNonEmpty(attributes["member_user_id"], attributes["user_id"], attributes["member_id"], memberEmail)
	memberType := strings.ToLower(firstNonEmpty(attributes["member_type"], attributes["type"], "user"))
	memberURN := identityPrincipalURN(tenantID, provider, memberType, memberID, memberEmail)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if groupURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("group"),
			Label:      firstNonEmpty(attributes["group_name"], attributes["group_email"], attributes["group_id"]),
			Attributes: map[string]string{
				"group_id":    strings.TrimSpace(attributes["group_id"]),
				"group_email": strings.TrimSpace(attributes["group_email"]),
			},
		})
	}
	if memberURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        memberURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(memberType)),
			Label:      firstNonEmpty(attributes["member_name"], memberEmail, memberID),
			Attributes: map[string]string{
				"email":       memberEmail,
				"member_id":   memberID,
				"member_type": memberType,
				"role":        strings.TrimSpace(attributes["role"]),
				"status":      strings.TrimSpace(attributes["member_status"]),
			},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), memberURN, memberEmail, event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, memberURN, profile, attributes, memberType, memberID, attributes["member_user_id"], memberEmail)
		if groupURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, groupURN, relationMemberOf, map[string]string{
				"event_id": event.GetId(),
				"role":     strings.TrimSpace(attributes["role"]),
			}))
		}
	}
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), groupURN, firstNonEmpty(attributes["group_email"], attributes["group_id"]), event.GetOccurredAt())
	return identityProjectionResult(entities, links)
}

func identityApplicationProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	domain := strings.TrimSpace(attributes["domain"])
	appURN := identityApplicationURN(tenantID, provider, firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"], attributes["id"]))
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	orgURN := identityOrgURN(tenantID, provider, domain)
	addIdentityOrg(entities, tenantID, event.GetSourceId(), provider, domain, orgURN)
	if appURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        appURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("application"),
			Label:      firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"], attributes["client_id"], attributes["app_id"]),
			Attributes: map[string]string{
				"app_id":                         firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"], attributes["id"]),
				"app_name":                       firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"]),
				"application_type":               strings.TrimSpace(attributes["application_type"]),
				"client_id":                      strings.TrimSpace(attributes["client_id"]),
				"domain":                         domain,
				"grant_types":                    strings.TrimSpace(attributes["grant_types"]),
				"oauth2":                         strings.TrimSpace(attributes["oauth2"]),
				"oauth_client_type":              strings.TrimSpace(attributes["oauth_client_type"]),
				"oauth_public_client":            strings.TrimSpace(attributes["oauth_public_client"]),
				"post_logout_redirect_uri_count": strings.TrimSpace(attributes["post_logout_redirect_uri_count"]),
				"post_logout_redirect_uri_hosts": strings.TrimSpace(attributes["post_logout_redirect_uri_hosts"]),
				"redirect_uri_count":             strings.TrimSpace(attributes["redirect_uri_count"]),
				"redirect_uri_hosts":             strings.TrimSpace(attributes["redirect_uri_hosts"]),
				"response_types":                 strings.TrimSpace(attributes["response_types"]),
				"saml":                           strings.TrimSpace(attributes["saml"]),
				"domain_wide":                    strings.TrimSpace(attributes["domain_wide_delegation"]),
				"status":                         strings.TrimSpace(attributes["status"]),
				"sign_on_mode":                   strings.TrimSpace(attributes["sign_on_mode"]),
				"token_endpoint_auth_method":     strings.TrimSpace(attributes["token_endpoint_auth_method"]),
				"wildcard_redirect":              strings.TrimSpace(attributes["wildcard_redirect"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), appURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		for _, host := range splitCSV(attributes["redirect_uri_hosts"]) {
			addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, appURN, relationHasIdentifier, host, provider+"_application_redirect_host", "0.95")
			addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, provider+"_application_redirect_domain", "0.95")
		}
		for _, host := range splitCSV(attributes["post_logout_redirect_uri_hosts"]) {
			addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, appURN, relationHasIdentifier, host, provider+"_application_post_logout_redirect_host", "0.90")
			addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, provider+"_application_post_logout_redirect_domain", "0.90")
		}
		clientID := strings.TrimSpace(attributes["client_id"])
		if clientID != "" {
			clientAttrs := map[string]string{
				"app_id":                         firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["id"]),
				"app_name":                       firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"]),
				"client_id":                      clientID,
				"grant_types":                    strings.TrimSpace(attributes["grant_types"]),
				"oauth_client_type":              strings.TrimSpace(attributes["oauth_client_type"]),
				"oauth_public_client":            strings.TrimSpace(attributes["oauth_public_client"]),
				"post_logout_redirect_uri_hosts": strings.TrimSpace(attributes["post_logout_redirect_uri_hosts"]),
				"redirect_uri_hosts":             strings.TrimSpace(attributes["redirect_uri_hosts"]),
				"response_types":                 strings.TrimSpace(attributes["response_types"]),
				"token_endpoint_auth_method":     strings.TrimSpace(attributes["token_endpoint_auth_method"]),
			}
			clientURN := addIdentityOAuthClient(entities, tenantID, event.GetSourceId(), profile, clientID, firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["name"], clientID), clientAttrs)
			addLink(links, projectedLink(tenantID, event.GetSourceId(), appURN, clientURN, relationContains, map[string]string{"event_id": event.GetId(), "match_type": provider + "_application_oauth_client"}))
		}
	}
	return identityProjectionResult(entities, links)
}

func identityPolicyRuleProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	policyID := strings.TrimSpace(attributes["policy_id"])
	policyRuleID := firstNonEmpty(attributes["policy_rule_id"], attributes["rule_id"], attributes["resource_id"])
	if policyID == "" || policyRuleID == "" {
		return nil, nil, nil
	}
	domain := strings.TrimSpace(attributes["domain"])
	orgURN := identityOrgURN(tenantID, profile.Provider, domain)
	policyURN := projectionURN(tenantID, profile.Provider+"_policy", policyID)
	policyRuleURN := projectionURN(tenantID, profile.Provider+"_policy_rule", policyID, policyRuleID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addIdentityOrg(entities, tenantID, event.GetSourceId(), profile.Provider, domain, orgURN)
	if policyURN != "" {
		policyAttrs := map[string]string{
			"domain":      domain,
			"policy_id":   policyID,
			"policy_name": strings.TrimSpace(attributes["policy_name"]),
			"policy_type": strings.TrimSpace(attributes["policy_type"]),
			"status":      strings.TrimSpace(attributes["policy_status"]),
		}
		trimEmptyProjectionAttributes(policyAttrs)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        policyURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("policy"),
			Label:      firstNonEmpty(attributes["policy_name"], attributes["policy_type"], policyID),
			Attributes: policyAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), policyURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	if policyRuleURN != "" {
		policyRuleAttrs := map[string]string{
			"policy_id":      policyID,
			"policy_rule_id": policyRuleID,
			"policy_type":    strings.TrimSpace(attributes["policy_type"]),
			"name":           firstNonEmpty(attributes["name"], attributes["policy_rule_name"]),
			"status":         strings.TrimSpace(attributes["status"]),
			"priority":       strings.TrimSpace(attributes["priority"]),
			"system":         strings.TrimSpace(attributes["system"]),
		}
		for _, key := range []string{"access", "requires_mfa", "mfa_prompt", "mfa_lifetime_minutes", "session_max_lifetime_minutes", "session_idle_minutes", "session_persistent", "network_connection", "risk_level", "platform_types", "network_zone_include_ids", "network_zone_exclude_ids", "group_include_ids", "group_exclude_ids", "user_include_ids", "user_exclude_ids", "idp_ids", "idp_provider", "app_include_ids", "app_exclude_ids", "client_include_ids"} {
			if v := strings.TrimSpace(attributes[key]); v != "" {
				policyRuleAttrs[key] = v
			}
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        policyRuleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("policy_rule"),
			Label:      firstNonEmpty(attributes["name"], attributes["policy_rule_name"], policyRuleID),
			Attributes: policyRuleAttrs,
		})
		if policyURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), policyRuleURN, policyURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		addIdentityPolicyRuleConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, attributes)
	}
	return identityProjectionResult(entities, links)
}

func addIdentityOAuthClient(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, profile identityProjectionProfile, clientID string, label string, attributes map[string]string) string {
	clientURN := identityOAuthClientURN(tenantID, profile.Provider, clientID)
	if clientURN == "" {
		return ""
	}
	trimEmptyProjectionAttributes(attributes)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        clientURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: profile.entityType("oauth_client"),
		Label:      firstNonEmpty(label, clientID),
		Attributes: attributes,
	})
	return clientURN
}

func addIdentityPolicyRuleConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, attributes map[string]string) {
	addIdentityPolicyRuleGroupConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["group_include_ids"]), "include")
	addIdentityPolicyRuleGroupConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["group_exclude_ids"]), "exclude")
	addIdentityPolicyRuleUserConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["user_include_ids"]), "include")
	addIdentityPolicyRuleUserConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["user_exclude_ids"]), "exclude")
	addIdentityPolicyRuleApplicationConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["app_include_ids"]), "include")
	addIdentityPolicyRuleApplicationConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["app_exclude_ids"]), "exclude")
	addIdentityPolicyRuleNetworkZoneConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["network_zone_include_ids"]), "include")
	addIdentityPolicyRuleNetworkZoneConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["network_zone_exclude_ids"]), "exclude")
	addIdentityPolicyRuleIdentityProviderConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["idp_ids"]), "include")
	addIdentityPolicyRuleOAuthClientConditionLinks(entities, links, tenantID, event, profile, orgURN, policyRuleURN, splitCSV(attributes["client_include_ids"]), "include")
}

func addIdentityPolicyRuleGroupConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, groupIDs []string, scope string) {
	for _, groupID := range groupIDs {
		groupID = durableIdentityConditionReferenceID(groupID)
		if groupID == "" {
			continue
		}
		groupURN := identityGroupURN(tenantID, profile.Provider, groupID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: groupURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: profile.entityType("group"), Label: groupID, Attributes: map[string]string{"group_id": groupID}})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, groupURN, relationTargeted, "group", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, groupURN, orgURN)
	}
}

func addIdentityPolicyRuleUserConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, userIDs []string, scope string) {
	for _, userID := range userIDs {
		userID = durableIdentityConditionReferenceID(userID)
		if userID == "" {
			continue
		}
		userURN := identityUserURN(tenantID, profile.Provider, userID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: userURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: profile.entityType("user"), Label: userID, Attributes: map[string]string{"user_id": userID}})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, userURN, relationTargeted, "user", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, userURN, orgURN)
	}
}

func addIdentityPolicyRuleApplicationConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, appIDs []string, scope string) {
	for _, appID := range appIDs {
		appID = durableIdentityConditionReferenceID(appID)
		if appID == "" {
			continue
		}
		appURN := identityApplicationURN(tenantID, profile.Provider, appID)
		addEntity(entities, &ports.ProjectedEntity{URN: appURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: profile.entityType("application"), Label: appID, Attributes: map[string]string{"app_id": appID}})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, appURN, relationTargeted, "application", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, appURN, orgURN)
	}
}

func addIdentityPolicyRuleNetworkZoneConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, zoneIDs []string, scope string) {
	for _, zoneID := range zoneIDs {
		zoneID = durableIdentityConditionReferenceID(zoneID)
		if zoneID == "" {
			continue
		}
		zoneURN := projectionURN(tenantID, profile.Provider+"_network_zone", zoneID)
		addEntity(entities, &ports.ProjectedEntity{URN: zoneURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: profile.entityType("network_zone"), Label: zoneID, Attributes: map[string]string{"network_zone_id": zoneID, "zone_id": zoneID}})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, zoneURN, relationDependsOn, "network_zone", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, zoneURN, orgURN)
	}
}

func addIdentityPolicyRuleIdentityProviderConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, idpIDs []string, scope string) {
	for _, idpID := range idpIDs {
		idpID = durableIdentityConditionReferenceID(idpID)
		if idpID == "" {
			continue
		}
		idpURN := projectionURN(tenantID, profile.Provider+"_identity_provider", idpID)
		addEntity(entities, &ports.ProjectedEntity{URN: idpURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: profile.entityType("identity_provider"), Label: idpID, Attributes: map[string]string{"identity_provider_id": idpID, "idp_id": idpID}})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, idpURN, relationDependsOn, "identity_provider", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, idpURN, orgURN)
	}
}

func addIdentityPolicyRuleOAuthClientConditionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, orgURN string, policyRuleURN string, clientIDs []string, scope string) {
	for _, clientID := range clientIDs {
		clientID = durableIdentityConditionReferenceID(clientID)
		if clientID == "" {
			continue
		}
		clientURN := addIdentityOAuthClient(entities, tenantID, event.GetSourceId(), profile, clientID, clientID, map[string]string{"client_id": clientID})
		addIdentityPolicyRuleConditionLink(links, tenantID, event, policyRuleURN, clientURN, relationDependsOn, "oauth_client", scope)
		addIdentityOrgMembershipLink(links, tenantID, event, clientURN, orgURN)
	}
}

func addIdentityPolicyRuleConditionLink(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, toURN string, relation string, referenceType string, scope string) {
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, toURN, relation, map[string]string{
		"condition_scope": scope,
		"event_id":        event.GetId(),
		"match_type":      "okta_policy_rule_" + referenceType + "_condition",
	}))
}

func addIdentityOrgMembershipLink(links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, fromURN string, orgURN string) {
	if fromURN == "" || orgURN == "" {
		return
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), fromURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
}

func durableIdentityConditionReferenceID(value string) string {
	trimmed := strings.TrimSpace(value)
	switch strings.ToUpper(trimmed) {
	case "", "ALL", "ANY", "ANYONE", "EVERYONE", "ALL_APPS", "ALL_CLIENTS", "ALL_USERS":
		return ""
	default:
		return trimmed
	}
}

func identityAppAssignmentProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["user_id"], attributes["group_id"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	appURN := identityApplicationURN(tenantID, provider, firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"]))
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), subjectURN, subjectEmail, event.GetOccurredAt())
	}
	if appURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        appURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("application"),
			Label:      firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["client_id"], attributes["app_id"]),
			Attributes: map[string]string{"app_id": firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"])},
		})
	}
	if subjectURN != "" && appURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, appURN, relationAssignedTo, identityEventLinkAttributes(event)))
	}
	entitlementURN, capabilityURN := addIdentityAppEntitlement(entities, links, tenantID, event, profile, appURN, attributes)
	if capabilityURN != "" && entitlementURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func addIdentityAppEntitlement(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, appURN string, attributes map[string]string) (string, string) {
	appID := firstNonEmpty(attributes["app_id"], attributes["application_id"], attributes["client_id"])
	if appURN == "" || appID == "" {
		return "", ""
	}
	entitlementID := firstNonEmpty(attributes["entitlement_id"], attributes["entitlement"], attributes["scope"], "app_assignment:"+appID)
	entitlementURN := projectionURN(tenantID, profile.Provider+"_entitlement", entitlementID)
	if entitlementURN == "" {
		return "", ""
	}
	appName := firstNonEmpty(attributes["app_name"], attributes["app_label"], attributes["client_id"], appID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        entitlementURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.entityType("entitlement"),
		Label:      firstNonEmpty(attributes["entitlement_name"], attributes["scope"], appName+" access", entitlementID),
		Attributes: map[string]string{
			"app_id":         appID,
			"entitlement_id": entitlementID,
			"scope":          strings.TrimSpace(attributes["scope"]),
			"status":         strings.TrimSpace(attributes["status"]),
		},
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), appURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	capabilityID := identityAppCapabilityID(attributes, entitlementID)
	capabilityURN := addIdentityCapability(entities, tenantID, event.GetSourceId(), capabilityID, identityCapabilityLabel(capabilityID), map[string]string{"source": profile.Provider})
	return entitlementURN, capabilityURN
}

func addIdentityRoleEntitlement(entities map[string]*ports.ProjectedEntity, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, roleURN string, roleID string, privileged bool, attributes map[string]string) (string, string) {
	if roleURN == "" || roleID == "" {
		return "", ""
	}
	entitlementID := firstNonEmpty(attributes["entitlement_id"], attributes["entitlement"], "admin_role:"+roleID)
	entitlementURN := projectionURN(tenantID, profile.Provider+"_entitlement", entitlementID)
	if entitlementURN == "" {
		return "", ""
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        entitlementURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: profile.entityType("entitlement"),
		Label:      firstNonEmpty(attributes["entitlement_name"], attributes["role_name"], attributes["role_type"], roleID),
		Attributes: map[string]string{
			"entitlement_id": entitlementID,
			"is_admin":       boolString(privileged),
			"role_id":        roleID,
			"role_type":      strings.TrimSpace(attributes["role_type"]),
		},
	})
	capabilityID := firstNonEmpty(attributes["capability"], "identity_admin")
	if !privileged {
		capabilityID = firstNonEmpty(attributes["capability"], "identity_role")
	}
	capabilityURN := addIdentityCapability(entities, tenantID, event.GetSourceId(), capabilityID, identityCapabilityLabel(capabilityID), map[string]string{"source": profile.Provider})
	return entitlementURN, capabilityURN
}

func addIdentityCapability(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, capabilityID string, label string, attributes map[string]string) string {
	capabilityID = normalizeIdentityCapabilityID(capabilityID)
	if capabilityID == "" {
		return ""
	}
	capabilityURN := projectionURN(tenantID, "privileged_capability", capabilityID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        capabilityURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "privileged.capability",
		Label:      firstNonEmpty(label, capabilityID),
		Attributes: attributes,
	})
	return capabilityURN
}

func identityAppCapabilityID(attributes map[string]string, entitlementID string) string {
	if explicit := strings.TrimSpace(attributes["capability"]); explicit != "" {
		return explicit
	}
	switch normalizeIdentifier(entitlementID) {
	case "admin", "administrator", "administratoraccess", "owner", "root", "superadmin", "globaladmin", "globaladministrator":
		return "cloud_admin"
	}
	return "app_access"
}

func normalizeIdentityCapabilityID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}

func identityCapabilityLabel(capabilityID string) string {
	switch normalizeIdentityCapabilityID(capabilityID) {
	case "app_access":
		return "Application access"
	case "cloud_admin":
		return "Cloud administrator"
	case "identity_admin":
		return "Identity administrator"
	case "identity_role":
		return "Identity role"
	default:
		return strings.TrimSpace(capabilityID)
	}
}

func identityEventLinkAttributes(event *cerebrov1.EventEnvelope) map[string]string {
	attributes := map[string]string{"event_id": event.GetId()}
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		occurred := occurredAt.AsTime()
		attributes["at"] = occurred.UTC().Format(time.RFC3339Nano)
	}
	return attributes
}

func identityRoleAssignmentProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["assigned_to"], attributes["user_id"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	roleID := firstNonEmpty(attributes["role_id"], attributes["role_assignment_id"], attributes["role_name"], attributes["role_type"])
	privileged := identityProjectionPrivileged(attributes)
	roleKind := "role"
	relation := relationAssignedTo
	if privileged {
		roleKind = "admin_role"
		relation = relationCanAdmin
	}
	roleURN := projectionURN(tenantID, provider+"_"+roleKind, roleID)
	if subjectURN != "" {
		subjectAttributes := map[string]string{"email": subjectEmail, "subject_type": subjectType}
		if privileged {
			subjectAttributes["is_admin"] = "true"
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: subjectAttributes,
		})
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), subjectURN, firstNonEmpty(subjectEmail, subjectID), event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID, attributes["subject_login"], attributes["subject_name"], attributes["subject_arn"], attributes["principal_arn"])
	}
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(roleKind),
			Label:      firstNonEmpty(attributes["role_name"], attributes["role_type"], roleID),
			Attributes: map[string]string{"is_admin": boolString(privileged), "role_id": roleID, "role_type": strings.TrimSpace(attributes["role_type"])},
		})
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, roleURN, profile, attributes, roleKind, roleID)
	}
	if subjectURN != "" && roleURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, roleURN, relation, identityEventLinkAttributes(event)))
	}
	entitlementURN, capabilityURN := addIdentityRoleEntitlement(entities, tenantID, event, profile, roleURN, roleID, privileged, attributes)
	if roleURN != "" && entitlementURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	}
	if entitlementURN != "" && capabilityURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, capabilityURN, relationConfersCapability, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func identityCredentialProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["assigned_to"], attributes["user_id"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	credentialID := firstNonEmpty(attributes["credential_id"], attributes["access_key_id"], attributes["key_id"], attributes["resource_id"])
	credentialType := firstNonEmpty(attributes["credential_type"], attributes["resource_type"], "credential")
	credentialURN := projectionURN(tenantID, provider+"_credential", credentialID)
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), subjectURN, firstNonEmpty(subjectEmail, subjectID), event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID, attributes["subject_login"], attributes["subject_name"], attributes["subject_arn"], attributes["principal_arn"])
	}
	if credentialURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        credentialURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("credential"),
			Label:      firstNonEmpty(attributes["credential_name"], credentialID),
			Attributes: map[string]string{"credential_id": credentialID, "credential_type": credentialType, "status": strings.TrimSpace(attributes["status"])},
		})
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, credentialURN, profile, attributes, "credential", credentialID)
	}
	if subjectURN != "" && credentialURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, credentialURN, relationAssignedTo, map[string]string{"event_id": event.GetId()}))
	}
	return identityProjectionResult(entities, links)
}

func identityAuditProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	actorEmail := firstNonEmpty(attributes["actor_email"], attributes["email"])
	actorIdentifier := firstNonEmpty(actorEmail, attributes["actor_alternate_id"])
	actorID := firstNonEmpty(attributes["actor_id"], actorIdentifier)
	actorURN := identityUserURN(tenantID, provider, actorID, actorIdentifier)
	actorEntityType := profile.entityType("user")
	if isAWSAssumedRoleActor(profile, attributes["actor_type"], actorID) {
		actorURN = projectionURN(tenantID, "aws_assumed_role_session", actorID)
		actorEntityType = profile.entityType("assumed_role_session")
	}
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["target_id"], attributes["app_id"], attributes["group_id"], attributes["role_id"])
	resourceEmail := firstNonEmpty(attributes["resource_email"], attributes["target_email"])
	if resourceID == "" && extractEmailIdentifier(attributes["target_alternate_id"]) != "" {
		resourceID = attributes["target_alternate_id"]
	}
	resourceIdentifier := firstNonEmpty(resourceID, resourceEmail)
	resourceType := normalizeIdentifier(firstNonEmpty(attributes["resource_type"], attributes["target_type"], "resource"))
	resourceURN := projectionURN(tenantID, provider+"_"+resourceType, firstNonEmpty(normalizeIdentifier(extractEmailIdentifier(resourceIdentifier)), resourceIdentifier))
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: actorEntityType,
			Label:      firstNonEmpty(attributes["actor_name"], actorEmail, attributes["actor_alternate_id"], attributes["actor_id"]),
			Attributes: map[string]string{"email": actorEmail, "actor_id": strings.TrimSpace(attributes["actor_id"])},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorIdentifier, event.GetOccurredAt())
		if !sameIdentifier(actorIdentifier, attributes["actor_alternate_id"]) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, attributes["actor_alternate_id"], event.GetOccurredAt())
		}
		if !sameIdentifier(actorIdentifier, actorEmail) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorEmail, event.GetOccurredAt())
		}
		addCloudIdentityAccountLink(entities, links, tenantID, event.GetSourceId(), event, actorURN, profile, attributes, attributes["actor_type"], firstNonEmpty(attributes["actor_id"], actorIdentifier))
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, actorURN, profile, attributes, attributes["actor_type"], firstNonEmpty(attributes["actor_id"], actorIdentifier), attributes["actor_alternate_id"], attributes["actor_name"], actorEmail)
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["target_name"], resourceEmail, resourceID),
			Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType},
		})
		if resourceIdentifier := firstNonEmpty(resourceEmail, resourceID); extractEmailIdentifier(resourceIdentifier) != "" {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), resourceURN, resourceIdentifier, event.GetOccurredAt())
		}
		addIdentityAuditResourceContext(entities, links, tenantID, event, profile, resourceURN, attributes, resourceType, resourceID)
	}
	if actorURN != "" && resourceURN != "" {
		actedAttrs := map[string]string{
			"event_id":   event.GetId(),
			"event_type": firstNonEmpty(attributes["event_type"], attributes["event_name"]),
		}
		addProjectedAttribute(actedAttrs, "at", eventObservedAt(event))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, actedAttrs))
	}
	addAzureResourceGroupLinks(entities, links, tenantID, event.GetSourceId(), event, profile, attributes, resourceURN)
	return identityProjectionResult(entities, links)
}

func addIdentityAuditResourceContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, resourceURN string, attributes map[string]string, resourceType string, resourceID string) {
	switch profile.Provider {
	case "aws":
		if accountID := firstNonEmpty(awsAccountID(attributes["domain"]), awsAccountID(attributes["aws_account_id"]), awsAccountIDFromARN(resourceID)); accountID != "" {
			addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, accountID, profile.Provider)
		}
		if !strings.Contains(strings.TrimSpace(resourceID), ":role/") {
			return
		}
		roleURN := identityPrincipalURN(tenantID, profile.Provider, "role", resourceID, "")
		if roleURN == "" {
			return
		}
		roleName := awsRoleNameFromARN(resourceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("role"),
			Label:      firstNonEmpty(roleName, resourceID),
			Attributes: map[string]string{
				"role_arn":  strings.TrimSpace(resourceID),
				"role_name": roleName,
			},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, roleURN, relationRepresents, map[string]string{
			"event_id":       event.GetId(),
			"match_type":     "aws_audit_resource_role_arn",
			"resource_id":    strings.TrimSpace(resourceID),
			"resource_type":  strings.TrimSpace(resourceType),
			"canonical_type": "aws.role",
		}))
	case "gcp":
		if projectID := firstNonEmpty(attributes["gcp_project_id"], attributes["project_id"], gcpProjectIDFromResource(resourceID), attributes["domain"]); projectID != "" {
			addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, projectID, profile.Provider)
		}
	case "azure":
		if subscriptionID := firstNonEmpty(attributes["subscription_id"], azureSubscriptionIDFromScope(resourceID), azureSubscriptionIDFromScope(attributes["target_id"])); subscriptionID != "" {
			addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, subscriptionID, profile.Provider)
		}
	}
}

func awsRoleNameFromARN(value string) string {
	_, roleName, ok := strings.Cut(strings.TrimSpace(value), ":role/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(roleName)
}

func isAWSAssumedRoleActor(profile identityProjectionProfile, actorType string, actorID string) bool {
	if profile.Provider != "aws" {
		return false
	}
	normalizedType := normalizeIdentifier(actorType)
	trimmedID := strings.TrimSpace(actorID)
	return normalizedType == "assumedrole" ||
		normalizedType == "assumed_role" ||
		strings.Contains(trimmedID, ":assumed-role/") ||
		(strings.HasPrefix(trimmedID, "ARO") && strings.Contains(trimmedID, ":"))
}

func identityProjectionResult(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addIdentityOrg(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, provider string, domain string, orgURN string) {
	if orgURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        orgURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: provider + ".org",
		Label:      domain,
		Attributes: map[string]string{"domain": domain},
	})
}

func addAWSPrincipalIdentifierLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, profile identityProjectionProfile, attributes map[string]string, principalType string, principalID string, values ...string) {
	if profile.Provider != "aws" || strings.TrimSpace(fromURN) == "" {
		return
	}
	accountID := cloudIdentityAccountID(profile, attributes, principalType, principalID)
	kind := awsPrincipalIdentifierKind(principalType)
	seen := map[string]struct{}{}
	for _, value := range append([]string{principalID}, values...) {
		for _, identifier := range awsPrincipalScopedIdentifiers(accountID, kind, value) {
			if _, ok := seen[identifier]; ok {
				continue
			}
			seen[identifier] = struct{}{}
			addIdentifierLink(entities, links, tenantID, sourceID, event.GetId(), fromURN, identifier, event.GetOccurredAt())
		}
	}
}

func awsPrincipalScopedIdentifiers(accountID string, kind string, value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	parsedAccountID, parsedKind, parsedName := awsPrincipalIdentifierFromARN(trimmed)
	if parsedAccountID != "" && parsedName != "" {
		if identifier := awsPrincipalScopedIdentifier(parsedAccountID, parsedKind, parsedName); identifier != "" {
			return []string{identifier}
		}
		return nil
	}
	if accountID == "" || kind == "" || strings.Contains(trimmed, "@") {
		return nil
	}
	name := awsPrincipalName(trimmed)
	if name == "" {
		return nil
	}
	if identifier := awsPrincipalScopedIdentifier(accountID, kind, name); identifier != "" {
		return []string{identifier}
	}
	return nil
}

func awsPrincipalScopedIdentifier(accountID string, kind string, name string) string {
	accountID = strings.TrimSpace(accountID)
	kind = strings.TrimSpace(kind)
	name = awsPrincipalName(name)
	if accountID == "" || kind == "" || name == "" || strings.Contains(name, "@") {
		return ""
	}
	return "aws:" + accountID + ":" + kind + ":" + name
}

func awsPrincipalIdentifierKind(principalType string) string {
	switch identityPrincipalType(principalType) {
	case "role":
		return "role"
	case "group":
		return "group"
	case "user":
		return "user"
	default:
		return ""
	}
}

func awsPrincipalIdentifierFromARN(value string) (string, string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return "", "", ""
	}
	accountID := awsAccountID(parts[4])
	if accountID == "" {
		return "", "", ""
	}
	resource := strings.TrimSpace(parts[5])
	switch {
	case strings.HasPrefix(resource, "user/"):
		return accountID, "user", awsPrincipalName(strings.TrimPrefix(resource, "user/"))
	case strings.HasPrefix(resource, "role/"):
		return accountID, "role", awsPrincipalName(strings.TrimPrefix(resource, "role/"))
	case strings.HasPrefix(resource, "group/"):
		return accountID, "group", awsPrincipalName(strings.TrimPrefix(resource, "group/"))
	case strings.HasPrefix(resource, "assumed-role/"):
		remainder := strings.TrimPrefix(resource, "assumed-role/")
		roleName, _, _ := strings.Cut(remainder, "/")
		return accountID, "role", awsPrincipalName(roleName)
	case strings.HasPrefix(resource, "federated-user/"):
		return accountID, "user", awsPrincipalName(strings.TrimPrefix(resource, "federated-user/"))
	default:
		return "", "", ""
	}
}

func awsPrincipalName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, _, name := awsPrincipalIdentifierFromARN(value); name != "" {
		return name
	}
	if strings.Contains(value, "/") {
		parts := strings.Split(value, "/")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return value
}

func addCloudIdentityAccountLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, profile identityProjectionProfile, attributes map[string]string, principalType string, principalID string) {
	accountID := cloudIdentityAccountID(profile, attributes, principalType, principalID)
	if accountID == "" {
		return
	}
	addCloudAccountLink(entities, links, tenantID, sourceID, event, fromURN, accountID, profile.Provider)
}

func cloudIdentityAccountID(profile identityProjectionProfile, attributes map[string]string, principalType string, principalID string) string {
	switch profile.Provider {
	case "aws":
		return firstNonEmpty(
			awsAccountID(attributes["domain"]),
			awsAccountID(attributes["aws_account_id"]),
			awsAccountIDFromARN(principalID),
			awsAccountIDFromARN(attributes["subject_id"]),
			awsAccountIDFromARN(attributes["user_id"]),
			awsAccountIDFromARN(attributes["resource_id"]),
			awsAccountIDFromARN(attributes["target_id"]),
		)
	case "gcp":
		if identityPrincipalType(principalType) != "service_account" && !strings.EqualFold(principalType, "credential") {
			return ""
		}
		return firstNonEmpty(
			attributes["gcp_project_id"],
			attributes["project_id"],
			gcpProjectIDFromResource(attributes["credential_id"]),
			gcpProjectIDFromResource(principalID),
			gcpProjectIDFromServiceAccountEmail(attributes["subject_email"]),
			gcpProjectIDFromServiceAccountEmail(attributes["email"]),
			gcpProjectIDFromServiceAccountEmail(principalID),
			attributes["domain"],
		)
	case "azure":
		return firstNonEmpty(
			attributes["subscription_id"],
			azureSubscriptionIDFromScope(attributes["scope"]),
			azureSubscriptionIDFromScope(attributes["resource_id"]),
			azureSubscriptionIDFromScope(attributes["target_id"]),
		)
	default:
		return ""
	}
}

func awsAccountID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) != 12 {
		return ""
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return value
}

func awsAccountIDFromARN(value string) string {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 5 || parts[0] != "arn" || parts[2] == "" {
		return ""
	}
	return awsAccountID(parts[4])
}

func gcpProjectIDFromResource(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	for index := 0; index+1 < len(parts); index++ {
		if parts[index] == "projects" && strings.TrimSpace(parts[index+1]) != "" {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func gcpProjectIDFromServiceAccountEmail(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasSuffix(value, ".iam.gserviceaccount.com") {
		return ""
	}
	_, domain, ok := strings.Cut(value, "@")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
}

func azureSubscriptionIDFromScope(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "/")
	for index := 0; index+1 < len(parts); index++ {
		if strings.EqualFold(parts[index], "subscriptions") && strings.TrimSpace(parts[index+1]) != "" {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func addAzureResourceGroupLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, profile identityProjectionProfile, attributes map[string]string, resourceURN string) {
	if profile.Provider != "azure" || resourceURN == "" {
		return
	}
	subscriptionID := firstNonEmpty(
		attributes["subscription_id"],
		azureSubscriptionIDFromScope(attributes["scope"]),
		azureSubscriptionIDFromScope(attributes["resource_id"]),
		azureSubscriptionIDFromScope(attributes["target_id"]),
	)
	resourceGroup := azureResourceGroupName(attributes)
	if subscriptionID == "" || resourceGroup == "" {
		return
	}
	resourceGroupURN := projectionURN(tenantID, "azure_resource_group", subscriptionID, resourceGroup)
	if resourceGroupURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceGroupURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "azure.resource_group",
		Label:      resourceGroup,
		Attributes: map[string]string{
			"resource_group":  resourceGroup,
			"subscription_id": subscriptionID,
		},
	})
	addLink(links, projectedLink(tenantID, sourceID, resourceURN, resourceGroupURN, relationBelongsTo, map[string]string{
		"event_id":         event.GetId(),
		"resource_group":   resourceGroup,
		"subscription_id":  subscriptionID,
		"relationship_by":  "azure_resource_group",
		"source_attribute": "resource_group",
	}))
	addCloudAccountLink(entities, links, tenantID, sourceID, event, resourceGroupURN, subscriptionID, "azure")
}

func azureResourceGroupName(attributes map[string]string) string {
	if resourceGroup := firstNonEmpty(attributes["resource_group"], attributes["resource_group_name"]); resourceGroup != "" {
		return resourceGroup
	}
	for _, value := range []string{attributes["scope"], attributes["resource_id"], attributes["target_id"]} {
		parts := strings.Split(strings.TrimSpace(value), "/")
		for index := 0; index+1 < len(parts); index++ {
			if strings.EqualFold(parts[index], "resourceGroups") && strings.TrimSpace(parts[index+1]) != "" {
				return strings.TrimSpace(parts[index+1])
			}
		}
	}
	return ""
}

func identityOrgURN(tenantID string, provider string, domain string) string {
	return projectionURN(tenantID, provider+"_org", domain)
}

func identityUserURN(tenantID string, provider string, userID string, email string) string {
	if trimmed := strings.TrimSpace(userID); trimmed != "" {
		return projectionURN(tenantID, provider+"_user", trimmed)
	}
	if normalizedEmail := normalizeIdentifier(email); normalizedEmail != "" {
		return projectionURN(tenantID, provider+"_user", "email", normalizedEmail)
	}
	return ""
}

func identityGroupURN(tenantID string, provider string, groupID string, groupEmail string) string {
	if trimmed := strings.TrimSpace(groupID); trimmed != "" {
		return projectionURN(tenantID, provider+"_group", trimmed)
	}
	if normalizedEmail := normalizeIdentifier(groupEmail); normalizedEmail != "" {
		return projectionURN(tenantID, provider+"_group", "email", normalizedEmail)
	}
	return ""
}

func identityApplicationURN(tenantID string, provider string, appID string) string {
	return projectionURN(tenantID, provider+"_application", appID)
}

func identityOAuthClientURN(tenantID string, provider string, clientID string) string {
	return projectionURN(tenantID, provider+"_oauth_client", clientID)
}

func identityPrincipalURN(tenantID string, provider string, principalType string, principalID string, email string) string {
	switch identityPrincipalType(principalType) {
	case "group":
		return identityGroupURN(tenantID, provider, principalID, email)
	case "application":
		return identityApplicationURN(tenantID, provider, principalID)
	case "service_principal":
		return projectionURN(tenantID, provider+"_service_principal", firstNonEmpty(principalID, email))
	case "service_account":
		return projectionURN(tenantID, provider+"_service_account", firstNonEmpty(principalID, email))
	case "role":
		return projectionURN(tenantID, provider+"_role", principalID)
	case "account":
		return projectionURN(tenantID, provider+"_account", principalID)
	case "public":
		return projectionURN(tenantID, provider+"_public_principal", principalID)
	default:
		return identityUserURN(tenantID, provider, principalID, email)
	}
}

func identityPrincipalType(value string) string {
	normalized := normalizeIdentifier(value)
	if strings.Contains(normalized, "group") {
		return "group"
	}
	if strings.Contains(normalized, "service_principal") || strings.Contains(normalized, "serviceprincipal") {
		return "service_principal"
	}
	if strings.Contains(normalized, "service_account") || strings.Contains(normalized, "serviceaccount") {
		return "service_account"
	}
	if strings.Contains(normalized, "application") {
		return "application"
	}
	if strings.Contains(normalized, "role") {
		return "role"
	}
	if strings.Contains(normalized, "account") {
		return "account"
	}
	if strings.Contains(normalized, "public") || strings.Contains(normalized, "allusers") || strings.Contains(normalized, "allauthenticatedusers") {
		return "public"
	}
	return "user"
}

func identityProjectionPrivileged(attributes map[string]string) bool {
	if projectionBool(attributes["is_admin"]) || projectionBool(attributes["is_delegated_admin"]) || projectionBool(attributes["admin"]) || projectionBool(attributes["privileged"]) {
		return true
	}
	value := normalizeIdentifier(firstNonEmpty(attributes["role"], attributes["role_id"], attributes["role_type"], attributes["role_name"]))
	return strings.Contains(value, "admin") ||
		strings.Contains(value, "super") ||
		strings.Contains(value, "owner") ||
		strings.Contains(value, "editor") ||
		strings.Contains(value, "contributor") ||
		strings.Contains(value, "poweruser") ||
		strings.Contains(value, "administratoraccess") ||
		strings.Contains(value, "iamfullaccess") ||
		strings.Contains(value, "globaladministrator") ||
		strings.Contains(value, "privilegedroleadministrator") ||
		strings.Contains(value, "applicationadministrator") ||
		strings.Contains(value, "cloudapplicationadministrator") ||
		strings.Contains(value, "authenticationadministrator") ||
		strings.Contains(value, "useraccessadministrator")
}

func projectionBool(value string) bool {
	switch normalizeIdentifier(value) {
	case "1", "t", "true", "y", "yes", "enabled":
		return true
	default:
		return false
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
