package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func cloudAccountURN(tenantID string, accountID string) string {
	return projectionURN(tenantID, "cloud_account", strings.TrimSpace(accountID))
}

func addCloudAccountLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, accountID string, provider string) {
	accountID = strings.TrimSpace(accountID)
	fromURN = strings.TrimSpace(fromURN)
	if accountID == "" || fromURN == "" {
		return
	}
	accountURN := cloudAccountURN(tenantID, accountID)
	if accountURN == "" {
		return
	}
	provider = strings.TrimSpace(provider)
	accountAttrs := map[string]string{"account_id": accountID}
	linkAttrs := map[string]string{"account_id": accountID, "event_id": event.GetId()}
	if provider != "" {
		accountAttrs["provider"] = provider
		linkAttrs["provider"] = provider
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        accountURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "cloud.account",
		Label:      accountID,
		Attributes: accountAttrs,
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, accountURN, relationBelongsTo, linkAttrs))
}

func awsResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, awsIdentityProfile)
}

func awsPublicEndpointProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPublicEndpointProjections(event, awsIdentityProfile)
}

func azureResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, azureIdentityProfile)
}

func gcpResourceExposureProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceExposureProjections(event, gcpIdentityProfile)
}

func awsIAMRoleTrustProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, awsIdentityProfile)
}

func azureAppRoleAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, azureIdentityProfile)
}

func gcpServiceAccountImpersonationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, gcpIdentityProfile)
}

func awsEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, awsIdentityProfile)
}

func awsIdentityCenterPermissionSetProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceMetadataProjections(event, awsIdentityProfile, cloudResourceProjectionOptions{})
}

func awsIdentityCenterAccountAssignmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudPrivilegePathProjections(event, awsIdentityProfile)
}

func azureEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, azureIdentityProfile)
}

func gcpEffectivePermissionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudEffectivePermissionProjections(event, gcpIdentityProfile)
}

func awsCloudResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceMetadataProjections(event, awsIdentityProfile, cloudResourceProjectionOptions{})
}

func azureCloudResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceMetadataProjections(event, azureIdentityProfile, cloudResourceProjectionOptions{})
}

func gcpCloudResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudResourceMetadataProjections(event, gcpIdentityProfile, cloudResourceProjectionOptions{})
}

type cloudResourceProjectionOptions struct {
	CrownJewelEvent              bool
	DefaultUnknownClassification bool
	Provider                     string
}

func cloudResourceMetadataProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile, options cloudResourceProjectionOptions) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := normalizeCloudProvider(firstNonEmpty(options.Provider, profile.Provider, attributes["source_provider"], attributes["resource_provider"], event.GetSourceId()))
	if provider == "" {
		return nil, nil, nil
	}
	resourceType := cloudResourceProjectionType(event, provider, attributes)
	resourceID := cloudResourceProjectionID(attributes)
	resourceURN := firstNonEmpty(attributes["resource_urn"], projectionURN(tenantID, provider+"_"+resourceType, resourceID))
	if resourceURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	resourceAttributes := compactAttributes(cloneStringMap(attributes))
	resourceAttributes["resource_id"] = resourceID
	resourceAttributes["resource_provider"] = provider
	resourceAttributes["resource_type"] = resourceType
	addEntity(entities, &ports.ProjectedEntity{
		URN:        resourceURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: provider + "." + strings.ReplaceAll(resourceType, "_", "."),
		Label:      firstNonEmpty(attributes["resource_name"], attributes["name"], resourceID, resourceURN),
		Attributes: resourceAttributes,
	})

	if accountID := cloudResourceAccountID(provider, attributes, resourceID, resourceURN); accountID != "" {
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, accountID, provider)
	}
	addAzureResourceGroupLinks(entities, links, tenantID, event.GetSourceId(), event, identityProjectionProfile{Provider: provider}, attributes, resourceURN)
	addCloudResourceOwnerLink(entities, links, tenantID, event, resourceURN, firstNonEmpty(attributes["owner"], attributes["team"]))
	addCloudResourceClassificationLinks(entities, links, tenantID, event, resourceURN, attributes, options)
	addCloudResourcePublicReachability(entities, links, tenantID, event, resourceURN, provider, attributes)
	addCloudResourceRuntimeIdentityLinks(entities, links, tenantID, event, resourceURN, provider, attributes)
	addCloudFindingCorrelation(entities, links, tenantID, event, resourceURN, provider, attributes)
	return identityProjectionResult(entities, links)
}

func addCloudFindingCorrelation(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, provider string, attributes map[string]string) {
	family := cloudFindingFamily(event, provider, attributes)
	if family == "" {
		return
	}
	findingID := cloudFindingID(event, attributes)
	findingURN := projectionURN(tenantID, "security_finding", provider, findingID)
	if findingURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        findingURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "security.finding",
		Label:      firstNonEmpty(attributes["title"], attributes["resource_name"], attributes["display_name"], attributes["category"], findingID),
		Attributes: cloudFindingAttributes(event, provider, family, findingID, attributes),
	})
	if resourceURN != "" && resourceURN != findingURN {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, findingURN, relationRepresents, cloudFindingLinkAttributes(event, provider, family, "cloud_provider_finding")))
	}

	affectedIDRaw := firstNonEmpty(attributes["affected_resource_id"], attributes["assessed_resource_id"])
	if affectedIDRaw == "" {
		return
	}
	affectedType := cloudFindingAffectedResourceType(provider, firstNonEmpty(attributes["affected_resource_type"], attributes["assessed_resource_type"]), affectedIDRaw)
	affectedID := cloudFindingAffectedResourceID(provider, affectedType, affectedIDRaw, firstNonEmpty(attributes["affected_resource_name"], attributes["assessed_resource_name"]))
	affectedURN := projectionURN(tenantID, provider+"_"+affectedType, affectedID)
	if affectedURN == "" || affectedURN == resourceURN {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        affectedURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: provider + "." + strings.ReplaceAll(affectedType, "_", "."),
		Label:      firstNonEmpty(attributes["affected_resource_name"], attributes["assessed_resource_name"], cloudLastPathSegment(affectedID), affectedID),
		Attributes: compactAttributes(map[string]string{
			"resource_id":       affectedID,
			"resource_provider": provider,
			"resource_type":     affectedType,
		}),
	})
	linkAttrs := cloudFindingLinkAttributes(event, provider, family, "cloud_finding_affected_resource")
	addProjectedAttribute(linkAttrs, "finding_id", findingID)
	addProjectedAttribute(linkAttrs, "resource_id", affectedID)
	addProjectedAttribute(linkAttrs, "resource_type", affectedType)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), affectedURN, findingURN, relationHasEvidence, linkAttrs))
	reverseAttrs := cloneStringMap(linkAttrs)
	addLink(links, projectedLink(tenantID, event.GetSourceId(), findingURN, affectedURN, relationObservedOn, reverseAttrs))
}

func cloudFindingFamily(event *cerebrov1.EventEnvelope, provider string, attributes map[string]string) string {
	family := normalizeCloudType(firstNonEmpty(attributes["resource_type"], attributes["family"]))
	if family == "" {
		if kind := strings.TrimSpace(event.GetKind()); strings.HasPrefix(kind, provider+".") {
			family = normalizeCloudType(strings.TrimPrefix(kind, provider+"."))
		}
	}
	switch provider + ":" + family {
	case "aws:guardduty_finding", "aws:securityhub_finding", "aws:inspector2_finding", "aws:macie2_finding",
		"gcp:security_center_finding",
		"azure:server_vulnerability":
		return family
	default:
		return ""
	}
}

func cloudFindingID(event *cerebrov1.EventEnvelope, attributes map[string]string) string {
	return firstNonEmpty(
		attributes["finding_arn"],
		attributes["finding_name"],
		attributes["finding_id"],
		attributes["canonical_name"],
		attributes["resource_id"],
		attributes["name"],
		event.GetId(),
	)
}

func cloudFindingAttributes(event *cerebrov1.EventEnvelope, provider string, family string, findingID string, attributes map[string]string) map[string]string {
	return compactAttributes(map[string]string{
		"affected_resource_id":   firstNonEmpty(attributes["affected_resource_id"], attributes["assessed_resource_id"]),
		"affected_resource_type": firstNonEmpty(attributes["affected_resource_type"], attributes["assessed_resource_type"]),
		"category":               attributes["category"],
		"event_id":               event.GetId(),
		"finding_id":             findingID,
		"finding_type":           firstNonEmpty(attributes["finding_type"], family),
		"provider":               provider,
		"record_state":           attributes["record_state"],
		"resource_id":            attributes["resource_id"],
		"resource_provider":      provider,
		"severity":               firstNonEmpty(attributes["severity"], attributes["severity_label"], attributes["severity_normalized"]),
		"source_provider":        firstNonEmpty(attributes["source_provider"], attributes["product_name"]),
		"status":                 firstNonEmpty(attributes["status"], attributes["state"], attributes["workflow_status"], attributes["status_code"]),
	})
}

func cloudFindingLinkAttributes(event *cerebrov1.EventEnvelope, provider string, family string, matchType string) map[string]string {
	return compactAttributes(map[string]string{
		"at":         eventObservedAt(event),
		"event_id":   event.GetId(),
		"family":     family,
		"match_type": matchType,
		"provider":   provider,
	})
}

func cloudFindingAffectedResourceType(provider string, rawType string, resourceID string) string {
	if provider == "azure" && rawType == "" {
		rawType = azureResourceTypeFromID(resourceID)
	}
	cleanType := strings.ReplaceAll(strings.TrimSpace(rawType), "::", "_")
	if strings.HasPrefix(strings.ToLower(cleanType), "aws_") {
		cleanType = cleanType[len("aws_"):]
	}
	normalized := normalizeCloudType(cleanType)
	switch provider + ":" + normalized {
	case "aws:awss3bucket", "aws:s3bucket":
		return "s3_bucket"
	case "aws:awsec2instance", "aws:ec2instance", "aws:instance":
		return "ec2_instance"
	case "aws:awsiamrole", "aws:iamrole", "aws:iam_role":
		return "role"
	case "aws:awsiamuser", "aws:iamuser", "aws:iam_user":
		return "user"
	case "aws:awsiamgroup", "aws:iamgroup", "aws:iam_group":
		return "group"
	case "aws:awsiamaccesskey", "aws:iamaccesskey", "aws:iam_access_key", "aws:accesskey", "aws:access_key":
		return "credential"
	case "aws:awslambdafunction", "aws:lambdafunction":
		return "lambda_function"
	case "aws:awsrdsdbinstance", "aws:rdsdbinstance":
		return "rds_instance"
	case "gcp:googlecloudstoragebucket", "gcp:google_cloud_storage_bucket", "gcp:storage_googleapis_com_bucket", "gcp:storage_bucket", "gcp:gcs_bucket":
		return "gcs_bucket"
	case "gcp:googlecloudrunservice", "gcp:google_cloud_run_service":
		return "cloud_run_service"
	}
	if provider == "gcp" {
		if inferred := panopticonGCPResourceTypeFromID(resourceID); inferred != "" {
			return inferred
		}
	}
	return firstNonEmpty(normalized, "resource")
}

func cloudFindingAffectedResourceID(provider string, resourceType string, resourceID string, resourceName string) string {
	resourceID = strings.TrimSpace(resourceID)
	resourceName = strings.TrimSpace(resourceName)
	if provider == "gcp" {
		switch resourceType {
		case "gcs_bucket":
			return firstNonEmpty(gcpBucketNameFromResourceID(resourceID), resourceID)
		case "compute_instance":
			return firstNonEmpty(gcpNamedResourceSegment(resourceID, "instances"), resourceName, cloudLastPathSegment(resourceID), resourceID)
		case "cloud_run_service":
			return firstNonEmpty(gcpServiceRelativeName(resourceID, "run.googleapis.com"), resourceID)
		case "cloud_sql_instance":
			return firstNonEmpty(gcpServiceSelfLink(resourceID, "sqladmin.googleapis.com", "sql/v1beta4"), resourceID)
		case "gke_cluster":
			return firstNonEmpty(gcpServiceSelfLink(resourceID, "container.googleapis.com", "v1"), resourceID)
		}
	}
	return resourceID
}

func gcpServiceRelativeName(value string, host string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	path := gcpServicePath(value, host)
	if path != "" {
		return path
	}
	if strings.HasPrefix(value, "projects/") {
		return value
	}
	return ""
}

func gcpServiceSelfLink(value string, host string, apiPrefix string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if path := gcpServicePath(value, host); path != "" {
		return "https://" + strings.ToLower(strings.Trim(host, "/")) + "/" + strings.Trim(apiPrefix, "/") + "/" + path
	}
	lower := strings.ToLower(value)
	normalizedHost := strings.ToLower(strings.Trim(host, "/"))
	if strings.HasPrefix(lower, "https://"+normalizedHost+"/") || strings.HasPrefix(lower, "http://"+normalizedHost+"/") {
		return value
	}
	return ""
}

func gcpServicePath(value string, host string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	normalizedHost := strings.ToLower(strings.Trim(host, "/"))
	for _, prefix := range []string{"//" + normalizedHost + "/", normalizedHost + "/"} {
		if strings.HasPrefix(lower, prefix) {
			path := strings.TrimLeft(value[len(prefix):], "/")
			if path == "" {
				return ""
			}
			return path
		}
	}
	return ""
}

func gcpNamedResourceSegment(value string, marker string) string {
	value = strings.TrimSpace(value)
	marker = strings.Trim(strings.TrimSpace(marker), "/")
	if value == "" || marker == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if strings.EqualFold(parts[index], marker) && strings.TrimSpace(parts[index+1]) != "" {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func gcpBucketNameFromResourceID(value string) string {
	if strings.HasPrefix(strings.ToLower(value), "gs://") {
		bucket, _, _ := strings.Cut(value[len("gs://"):], "/")
		return strings.TrimSpace(bucket)
	}
	return gcpNamedResourceSegment(value, "buckets")
}

func azureResourceTypeFromID(resourceID string) string {
	lower := strings.ToLower(strings.TrimSpace(resourceID))
	providerIndex := strings.LastIndex(lower, "/providers/")
	if providerIndex < 0 {
		return ""
	}
	providerPath := strings.Trim(strings.TrimSpace(resourceID[providerIndex+len("/providers/"):]), "/")
	segments := strings.Split(providerPath, "/")
	if len(segments) < 2 {
		return providerPath
	}
	rawType := segments[0] + "/" + segments[1]
	switch strings.ToLower(rawType) {
	case "microsoft.compute/virtualmachines":
		return "virtual_machine"
	case "microsoft.storage/storageaccounts":
		return "storage_account"
	case "microsoft.sql/servers":
		if len(segments) >= 4 && strings.EqualFold(segments[3], "databases") {
			return "sql_database"
		}
		return "sql_server"
	default:
		return rawType
	}
}

func cloudLastPathSegment(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == ':' })
	for i := len(parts) - 1; i >= 0; i-- {
		if part := strings.TrimSpace(parts[i]); part != "" {
			return part
		}
	}
	return value
}

func normalizeCloudProvider(value string) string {
	switch normalizeIdentifier(value) {
	case "amazon_web_services":
		return "aws"
	case "microsoft_azure":
		return "azure"
	case "google_cloud", "google_cloud_platform":
		return "gcp"
	default:
		return normalizeIdentifier(value)
	}
}

func cloudResourceProjectionType(event *cerebrov1.EventEnvelope, provider string, attributes map[string]string) string {
	if kind := strings.TrimSpace(event.GetKind()); strings.HasPrefix(kind, provider+".") {
		resourceType := strings.TrimPrefix(kind, provider+".")
		switch resourceType {
		case "", "asset_metadata", "effective_permission", "resource_exposure", "public_endpoint":
		default:
			return normalizeCloudType(resourceType)
		}
	}
	return normalizeCloudType(firstNonEmpty(attributes["resource_type"], attributes["family"], "resource"))
}

func cloudResourceProjectionID(attributes map[string]string) string {
	return firstNonEmpty(
		attributes["resource_urn"],
		attributes["resource_arn"],
		attributes["resource_id"],
		attributes["id"],
		attributes["name"],
		attributes["resource_name"],
		attributes["endpoint_id"],
		attributes["host"],
		attributes["ip"],
	)
}

func cloudResourceAccountID(provider string, attributes map[string]string, resourceID string, resourceURN string) string {
	switch provider {
	case "aws":
		return firstNonEmpty(
			awsAccountID(attributes["aws_account_id"]),
			awsAccountID(attributes["account_id"]),
			awsAccountID(attributes["domain"]),
			awsAccountIDFromARN(attributes["resource_arn"]),
			awsAccountIDFromARN(resourceID),
			awsAccountIDFromARN(resourceURN),
			awsAccountIDFromARN(attributes["scope"]),
		)
	case "azure":
		return firstNonEmpty(
			attributes["subscription_id"],
			azureSubscriptionIDFromScope(resourceID),
			azureSubscriptionIDFromScope(resourceURN),
			azureSubscriptionIDFromScope(attributes["scope"]),
		)
	case "gcp":
		return firstNonEmpty(
			attributes["gcp_project_id"],
			attributes["project_id"],
			gcpProjectIDFromResource(resourceID),
			gcpProjectIDFromResource(resourceURN),
			attributes["domain"],
		)
	default:
		return ""
	}
}

func addCloudResourceOwnerLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, owner string) {
	owner = strings.TrimSpace(owner)
	if resourceURN == "" || owner == "" {
		return
	}
	ownerURN := projectionURN(tenantID, "owner", owner)
	if ownerURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        ownerURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "owner",
		Label:      owner,
		Attributes: map[string]string{"owner": owner},
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, ownerURN, relationOwnedBy, map[string]string{"event_id": event.GetId()}))
	if extractEmailIdentifier(owner) != "" {
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), ownerURN, owner, event.GetOccurredAt())
	}
}

func addCloudResourceClassificationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, attributes map[string]string, options cloudResourceProjectionOptions) {
	classification := firstNonEmpty(attributes["data_classification"], attributes["data_sensitivity"], attributes["sensitivity"])
	if classification == "" && options.DefaultUnknownClassification {
		classification = "unknown"
	}
	if classificationURN := projectionURN(tenantID, "data_classification", classification); resourceURN != "" && classificationURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        classificationURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "data.classification",
			Label:      classification,
			Attributes: map[string]string{"classification": classification},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, classificationURN, relationHasClassification, map[string]string{"event_id": event.GetId()}))
	}
	if (options.CrownJewelEvent || projectionBool(firstNonEmpty(attributes["crown_jewel"], attributes["tier0"], attributes["business_critical"]))) && resourceURN != "" {
		tagURN := projectionURN(tenantID, "asset_tag", "crown_jewel")
		addEntity(entities, &ports.ProjectedEntity{
			URN:        tagURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "asset.tag",
			Label:      "crown_jewel",
			Attributes: map[string]string{"tag": "crown_jewel"},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, tagURN, relationTaggedAs, map[string]string{"event_id": event.GetId()}))
	}
}

func addCloudResourcePublicReachability(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, provider string, attributes map[string]string) {
	if resourceURN == "" || !cloudResourcePubliclyReachable(attributes) {
		return
	}
	publicURN := identityPrincipalURN(tenantID, provider, "public", "public_internet", "")
	if publicURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        publicURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: provider + ".public_principal",
		Label:      "public internet",
		Attributes: map[string]string{"principal_type": "public"},
	})
	reachabilityAttrs := compactAttributes(map[string]string{
		"at":              eventObservedAt(event),
		"direction":       "ingress",
		"event_id":        event.GetId(),
		"exposure_type":   firstNonEmpty(attributes["exposure_type"], "public_resource"),
		"host":            firstNonEmpty(attributes["public_host"], attributes["host"]),
		"ip":              firstNonEmpty(attributes["public_ip"], attributes["ip"]),
		"public_endpoint": firstNonEmpty(attributes["public_endpoint"], attributes["uri"], attributes["endpoint"]),
	})
	addLink(links, projectedLink(tenantID, event.GetSourceId(), publicURN, resourceURN, relationCanReach, reachabilityAttrs))
	reverseAttrs := cloneStringMap(reachabilityAttrs)
	reverseAttrs["direction"] = "ingress_reverse"
	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, publicURN, relationCanReach, reverseAttrs))
}

func cloudResourcePubliclyReachable(attributes map[string]string) bool {
	if exposure := firstNonEmpty(attributes["internet_exposed"], attributes["external_exposure"], attributes["public"], attributes["public_network_access"]); strings.TrimSpace(exposure) != "" {
		return projectionBool(exposure)
	}
	return strings.TrimSpace(firstNonEmpty(attributes["public_endpoint"], attributes["uri"], attributes["endpoint"])) != ""
}

func addCloudResourceRuntimeIdentityLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, provider string, attributes map[string]string) {
	switch provider {
	case "aws":
		addAWSComputeRoleLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, firstNonEmpty(attributes["role_arn"], attributes["runtime_role_arn"]), firstNonEmpty(attributes["role_name"], attributes["runtime_role_name"]), "primary")
	case "gcp":
		for _, email := range splitCloudAttributeList(firstNonEmpty(attributes["service_account_email"], attributes["runtime_identity"], attributes["runtime_service_account"])) {
			addCloudResourceRuntimePrincipalLink(entities, links, tenantID, event, resourceURN, provider, "service_account", email, email, "gcp_runtime_service_account")
		}
	case "azure":
		for _, principalID := range splitCloudAttributeList(firstNonEmpty(attributes["identity_principal_id"], attributes["runtime_identity"])) {
			addCloudResourceRuntimePrincipalLink(entities, links, tenantID, event, resourceURN, provider, "service_principal", principalID, "", "azure_system_assigned_identity")
		}
		for _, principalID := range splitCloudAttributeList(attributes["user_assigned_principal_ids"]) {
			addCloudResourceRuntimePrincipalLink(entities, links, tenantID, event, resourceURN, provider, "service_principal", principalID, "", "azure_user_assigned_identity")
		}
	}
}

func addCloudResourceRuntimePrincipalLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, resourceURN string, provider string, principalType string, principalID string, principalEmail string, matchType string) {
	principalID = strings.TrimSpace(principalID)
	resourceURN = strings.TrimSpace(resourceURN)
	if resourceURN == "" || principalID == "" {
		return
	}
	principalURN := identityPrincipalURN(tenantID, provider, principalType, principalID, principalEmail)
	if principalURN == "" {
		return
	}
	entityType := identityProjectionProfile{Provider: provider}.entityType(identityPrincipalType(principalType))
	addEntity(entities, &ports.ProjectedEntity{
		URN:        principalURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: entityType,
		Label:      firstNonEmpty(principalEmail, principalID),
		Attributes: compactAttributes(map[string]string{
			"email":          principalEmail,
			"principal_id":   principalID,
			"principal_type": identityPrincipalType(principalType),
		}),
	})
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), principalURN, firstNonEmpty(principalEmail, principalID), event.GetOccurredAt())
	addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, principalURN, relationRunsAs, map[string]string{
		"event_id":       event.GetId(),
		"match_type":     matchType,
		"principal_id":   principalID,
		"principal_type": identityPrincipalType(principalType),
	}))
}

func cloudResourceExposureProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], "resource"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["resource_name"], attributes["exposure_id"])
	resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	publicURN := identityPrincipalURN(tenantID, provider, "public", firstNonEmpty(attributes["exposed_to"], "public_internet"), "")

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if publicURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        publicURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("public_principal"),
			Label:      firstNonEmpty(attributes["exposed_to"], "public internet"),
			Attributes: map[string]string{"principal_type": "public"},
		})
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], resourceID),
			Attributes: map[string]string{
				"domain":            strings.TrimSpace(attributes["domain"]),
				"exposure_id":       strings.TrimSpace(attributes["exposure_id"]),
				"exposure_type":     strings.TrimSpace(attributes["exposure_type"]),
				"external_exposure": strings.TrimSpace(attributes["external_exposure"]),
				"internet_exposed":  strings.TrimSpace(attributes["internet_exposed"]),
				"public":            strings.TrimSpace(attributes["public"]),
				"resource_id":       resourceID,
				"resource_provider": strings.TrimSpace(attributes["resource_provider"]),
				"resource_type":     resourceType,
				"source_cidr":       strings.TrimSpace(attributes["source_cidr"]),
			},
		})
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, cloudResourceExposureAccountID(attributes, provider), provider)
	}
	if publicURN != "" && resourceURN != "" {
		reachabilityAttrs := map[string]string{
			"action":        strings.TrimSpace(attributes["action"]),
			"at":            eventObservedAt(event),
			"direction":     strings.TrimSpace(attributes["direction"]),
			"event_id":      event.GetId(),
			"exposure_type": strings.TrimSpace(attributes["exposure_type"]),
			"port_range":    strings.TrimSpace(attributes["port_range"]),
			"protocol":      strings.TrimSpace(attributes["protocol"]),
			"source_cidr":   strings.TrimSpace(attributes["source_cidr"]),
		}
		addLink(links, projectedLink(tenantID, event.GetSourceId(), publicURN, resourceURN, relationCanReach, reachabilityAttrs))
		reverseAttrs := cloneStringMap(reachabilityAttrs)
		reverseAttrs["direction"] = firstNonEmpty(reverseAttrs["direction"], "ingress") + "_reverse"
		addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, publicURN, relationCanReach, reverseAttrs))
	}
	return identityProjectionResult(entities, links)
}

func cloudResourceExposureAccountID(attributes map[string]string, provider string) string {
	if provider == "azure" {
		return firstNonEmpty(attributes["subscription_id"], attributes["scope"], attributes["domain"])
	}
	return attributes["domain"]
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloudPublicEndpointProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], "public_endpoint"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["endpoint_id"], attributes["host"], attributes["ip"])
	resourceURN := projectionURN(tenantID, provider+"_"+resourceType, resourceID)
	publicURN := identityPrincipalURN(tenantID, provider, "public", "public_internet", "")
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if publicURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        publicURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("public_principal"),
			Label:      "public internet",
			Attributes: map[string]string{"principal_type": "public"},
		})
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["endpoint_id"], attributes["host"], attributes["ip"], resourceID),
			Attributes: map[string]string{
				"associated_instance_id": strings.TrimSpace(attributes["associated_instance_id"]),
				"attached_instance_id":   strings.TrimSpace(attributes["attached_instance_id"]),
				"domain":                 strings.TrimSpace(attributes["domain"]),
				"endpoint_id":            strings.TrimSpace(attributes["endpoint_id"]),
				"endpoint_type":          strings.TrimSpace(attributes["endpoint_type"]),
				"external_exposure":      strings.TrimSpace(attributes["external_exposure"]),
				"host":                   strings.TrimSpace(attributes["host"]),
				"hosted_zone_id":         strings.TrimSpace(attributes["hosted_zone_id"]),
				"hosted_zone_name":       strings.TrimSpace(attributes["hosted_zone_name"]),
				"internet_exposed":       strings.TrimSpace(attributes["internet_exposed"]),
				"ip":                     strings.TrimSpace(attributes["ip"]),
				"public":                 strings.TrimSpace(attributes["public"]),
				"resource_id":            resourceID,
				"resource_provider":      strings.TrimSpace(attributes["resource_provider"]),
				"resource_type":          resourceType,
				"service":                strings.TrimSpace(attributes["service"]),
				"target_host":            strings.TrimSpace(attributes["target_host"]),
				"target_ip":              strings.TrimSpace(attributes["target_ip"]),
			},
		})
		addCloudPublicEndpointInstanceLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, provider, resourceType, attributes)
		primaryHosts := splitCloudAttributeList(attributes["host"])
		targetHosts := splitCloudAttributeList(strings.Join([]string{attributes["alternate_hosts"], attributes["target_hosts"], attributes["target_host"]}, ","))
		ips := splitCloudAttributeList(strings.Join([]string{attributes["ip"], attributes["target_ips"], attributes["target_ip"]}, ","))
		for _, host := range primaryHosts {
			addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, relationRepresents, host, "aws_public_endpoint_host", "0.95")
			addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, "aws_public_endpoint_domain", "0.85")
		}
		for _, host := range targetHosts {
			addInternetHostLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, relationRepresents, host, "aws_public_endpoint_target_host", "0.90")
			addInternetHostDomainLink(entities, links, tenantID, event.GetSourceId(), event, host, "aws_public_endpoint_target_domain", "0.80")
		}
		for _, ip := range ips {
			addInternetIPLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, ip, "aws_public_endpoint_ip", "0.95")
		}
		for _, host := range primaryHosts {
			for _, ip := range ips {
				addInternetHostResolvesToIPLink(entities, links, tenantID, event.GetSourceId(), event, host, ip, "aws_public_endpoint_host_ip", "0.80")
			}
		}
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, cloudResourceExposureAccountID(attributes, provider), provider)
		if publicURN != "" && projectionBool(firstNonEmpty(attributes["internet_exposed"], attributes["public"], attributes["external_exposure"])) {
			reachabilityAttrs := map[string]string{
				"direction":     "ingress",
				"at":            eventObservedAt(event),
				"event_id":      event.GetId(),
				"exposure_type": "public_endpoint",
				"host":          strings.TrimSpace(attributes["host"]),
				"ip":            strings.TrimSpace(attributes["ip"]),
			}
			addLink(links, projectedLink(tenantID, event.GetSourceId(), publicURN, resourceURN, relationCanReach, reachabilityAttrs))
			reverseAttrs := cloneStringMap(reachabilityAttrs)
			reverseAttrs["direction"] = "ingress_reverse"
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, publicURN, relationCanReach, reverseAttrs))
		}
	}
	return identityProjectionResult(entities, links)
}

func addCloudPublicEndpointInstanceLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, resourceURN string, provider string, resourceType string, attributes map[string]string) {
	if provider != "aws" || resourceURN == "" {
		return
	}
	attachedInstanceID := strings.TrimSpace(attributes["attached_instance_id"])
	associatedInstanceID := strings.TrimSpace(attributes["associated_instance_id"])
	instanceID := firstNonEmpty(attachedInstanceID, associatedInstanceID)
	if instanceID == "" {
		return
	}
	instanceURN := projectionURN(tenantID, "aws_ec2_instance", instanceID)
	if instanceURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        instanceURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: "aws.ec2.instance",
		Label:      instanceID,
		Attributes: map[string]string{
			"domain":            strings.TrimSpace(attributes["domain"]),
			"instance_id":       instanceID,
			"resource_id":       instanceID,
			"resource_provider": "aws",
			"resource_type":     "ec2_instance",
		},
	})
	relation := relationAssociatedWith
	matchType := "aws_public_endpoint_associated_instance"
	if attachedInstanceID != "" && (resourceType == "network_interface" || associatedInstanceID == "") {
		relation = relationAttachedTo
		matchType = "aws_public_endpoint_attached_instance"
	}
	addLink(links, projectedLink(tenantID, sourceID, resourceURN, instanceURN, relation, map[string]string{
		"event_id":      event.GetId(),
		"instance_id":   instanceID,
		"match_type":    matchType,
		"resource_type": resourceType,
	}))
}

func addInternetIPLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, rawIP string, matchType string, confidence string) {
	if ipURN, ip := internetIPURN(tenantID, rawIP); ipURN != "" && fromURN != "" {
		addInternetIPEntity(entities, tenantID, sourceID, ipURN, ip)
		addLink(links, projectedLink(tenantID, sourceID, fromURN, ipURN, relationRepresents, map[string]string{
			"confidence": confidence,
			"event_id":   event.GetId(),
			"ip":         ip,
			"match_type": matchType,
		}))
	}
}

func splitCloudAttributeList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func cloudPrivilegePathProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["principal_id"], attributes["assigned_to"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["principal_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	targetType := strings.ToLower(firstNonEmpty(attributes["target_type"], attributes["resource_type"], "resource"))
	targetID := firstNonEmpty(attributes["target_id"], attributes["resource_id"], attributes["target_email"], attributes["target_app_id"], attributes["role_id"])
	targetEmail := firstNonEmpty(attributes["target_email"], attributes["resource_email"])
	targetURN := cloudTargetURN(tenantID, provider, targetType, targetID, targetEmail)
	relation := cloudPrivilegeRelation(attributes)

	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), subjectURN, firstNonEmpty(subjectEmail, subjectID), event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID, attributes["subject_login"], attributes["subject_name"], attributes["subject_arn"], attributes["principal_arn"])
	}
	if targetURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(normalizeCloudType(targetType), "_", ".")),
			Label:      firstNonEmpty(attributes["target_name"], attributes["resource_name"], targetEmail, targetID),
			Attributes: map[string]string{"target_id": targetID, "target_type": targetType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), targetURN, targetEmail, event.GetOccurredAt())
	}
	if subjectURN != "" && targetURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, targetURN, relation, map[string]string{
			"event_id":     event.GetId(),
			"path_type":    strings.TrimSpace(attributes["path_type"]),
			"relationship": strings.TrimSpace(attributes["relationship"]),
			"role_id":      strings.TrimSpace(attributes["role_id"]),
			"role_name":    strings.TrimSpace(attributes["role_name"]),
		}))
	}
	return identityProjectionResult(entities, links)
}

func cloudEffectivePermissionProjections(event *cerebrov1.EventEnvelope, profile identityProjectionProfile) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	provider := profile.Provider
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	subjectType := strings.ToLower(firstNonEmpty(attributes["subject_type"], attributes["principal_type"], "user"))
	subjectID := firstNonEmpty(attributes["subject_id"], attributes["principal_id"], attributes["assigned_to"], attributes["email"])
	subjectEmail := firstNonEmpty(attributes["subject_email"], attributes["principal_email"], attributes["email"])
	subjectURN := identityPrincipalURN(tenantID, provider, subjectType, subjectID, subjectEmail)
	resourceType := normalizeCloudType(firstNonEmpty(attributes["resource_type"], attributes["target_type"], "scope"))
	resourceID := firstNonEmpty(attributes["resource_id"], attributes["target_id"], attributes["scope"], attributes["policy_id"])
	resourceURN := cloudTargetURN(tenantID, provider, resourceType, resourceID, firstNonEmpty(attributes["resource_email"], attributes["target_email"]))
	if subjectURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        subjectURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(identityPrincipalType(subjectType)),
			Label:      firstNonEmpty(attributes["subject_name"], subjectEmail, subjectID),
			Attributes: map[string]string{"email": subjectEmail, "subject_type": subjectType},
		})
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), subjectURN, firstNonEmpty(subjectEmail, subjectID), event.GetOccurredAt())
		addAWSPrincipalIdentifierLinks(entities, links, tenantID, event.GetSourceId(), event, subjectURN, profile, attributes, subjectType, subjectID, attributes["subject_login"], attributes["subject_name"], attributes["subject_arn"], attributes["principal_arn"])
	}
	if resourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType(strings.ReplaceAll(resourceType, "_", ".")),
			Label:      firstNonEmpty(attributes["resource_name"], attributes["target_name"], resourceID),
			Attributes: map[string]string{"resource_id": resourceID, "resource_type": resourceType, "scope": strings.TrimSpace(attributes["scope"])},
		})
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, resourceURN, cloudEffectivePermissionAccountID(attributes, provider), provider)
	}
	roleID := strings.TrimSpace(attributes["role_id"])
	roleURN := ""
	if roleID != "" {
		roleURN = identityPrincipalURN(tenantID, provider, "role", roleID, "")
	}
	if roleURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        roleURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: profile.entityType("role"),
			Label:      firstNonEmpty(attributes["role_name"], attributes["role_id"]),
			Attributes: map[string]string{
				"role_id":   strings.TrimSpace(attributes["role_id"]),
				"role_name": strings.TrimSpace(attributes["role_name"]),
			},
		})
		addCloudAccountLink(entities, links, tenantID, event.GetSourceId(), event, roleURN, cloudEffectivePermissionAccountID(attributes, provider), provider)
	}
	canPerformAttrs := map[string]string{
		"actions":         strings.TrimSpace(attributes["actions"]),
		"condition":       strings.TrimSpace(attributes["condition"]),
		"effect":          strings.TrimSpace(attributes["effect"]),
		"event_id":        event.GetId(),
		"is_admin":        boolString(identityProjectionPrivileged(attributes)),
		"permission":      firstNonEmpty(attributes["permission"], attributes["actions"]),
		"policy_source":   strings.TrimSpace(attributes["policy_source"]),
		"privilege_level": strings.TrimSpace(attributes["privilege_level"]),
		"role_id":         strings.TrimSpace(attributes["role_id"]),
		"role_name":       strings.TrimSpace(attributes["role_name"]),
	}
	if roleURN != "" {
		canPerformAttrs["role_urn"] = roleURN
	}
	if subjectURN != "" && roleURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, roleURN, relationAssignedTo, map[string]string{
			"event_id":   event.GetId(),
			"match_type": "effective_permission_role_binding",
			"role_id":    strings.TrimSpace(attributes["role_id"]),
			"role_name":  strings.TrimSpace(attributes["role_name"]),
		}))
	}
	if roleURN != "" && resourceURN != "" {
		roleCanPerformAttrs := cloneStringMap(canPerformAttrs)
		roleCanPerformAttrs["match_type"] = "effective_permission_role_resource"
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, resourceURN, relationCanPerform, roleCanPerformAttrs))
	}
	if subjectURN != "" && resourceURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), subjectURN, resourceURN, relationCanPerform, canPerformAttrs))
	}
	return identityProjectionResult(entities, links)
}

func cloudTargetURN(tenantID string, provider string, targetType string, targetID string, targetEmail string) string {
	normalizedType := identityPrincipalType(targetType)
	switch normalizedType {
	case "application", "group", "public", "role", "service_account", "service_principal":
		return identityPrincipalURN(tenantID, provider, normalizedType, targetID, targetEmail)
	default:
		return projectionURN(tenantID, provider+"_"+normalizeCloudType(targetType), firstNonEmpty(targetID, targetEmail))
	}
}

func cloudPrivilegeRelation(attributes map[string]string) string {
	relationship := normalizeIdentifier(firstNonEmpty(attributes["relationship"], attributes["path_type"]))
	switch {
	case strings.Contains(relationship, "assume"):
		return relationCanAssume
	case strings.Contains(relationship, "impersonate"):
		return relationCanImpersonate
	case identityProjectionPrivileged(attributes):
		return relationCanAdmin
	default:
		return relationAssignedTo
	}
}

func cloudEffectivePermissionAccountID(attributes map[string]string, provider string) string {
	switch provider {
	case "aws":
		return firstNonEmpty(
			awsAccountID(attributes["domain"]),
			awsAccountID(attributes["account_id"]),
			awsAccountID(attributes["aws_account_id"]),
			awsAccountIDFromARN(attributes["scope"]),
			awsAccountIDFromARN(attributes["resource_id"]),
			awsAccountIDFromARN(attributes["target_id"]),
		)
	case "azure":
		return firstNonEmpty(
			attributes["subscription_id"],
			azureSubscriptionIDFromScope(attributes["scope"]),
			azureSubscriptionIDFromScope(attributes["resource_id"]),
			azureSubscriptionIDFromScope(attributes["target_id"]),
		)
	case "gcp":
		return firstNonEmpty(
			attributes["project_id"],
			attributes["gcp_project_id"],
			attributes["domain"],
			gcpProjectIDFromResource(attributes["scope"]),
			gcpProjectIDFromResource(attributes["resource_id"]),
			gcpProjectIDFromResource(attributes["target_id"]),
		)
	default:
		return ""
	}
}

func normalizeCloudType(value string) string {
	normalized := strings.ReplaceAll(normalizeIdentifier(value), ".", "_")
	normalized = strings.ReplaceAll(normalized, "/", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	return strings.Trim(normalized, "_")
}
