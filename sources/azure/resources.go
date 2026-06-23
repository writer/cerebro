package azure

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/azurearm"
)

type armRoleAssignmentRecord struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Type       string                `json:"type"`
	Properties armRoleAssignmentProp `json:"properties"`
	RoleName   string
	Principal  graphPrincipalRecord
	raw        json.RawMessage
}

type armRoleAssignmentProp struct {
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	Scope            string `json:"scope"`
	CreatedOn        string `json:"createdOn"`
	UpdatedOn        string `json:"updatedOn"`
}

type armRoleDefinitionRecord struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties armRoleDefinition `json:"properties"`
}

type armRoleDefinition struct {
	RoleName string `json:"roleName"`
	Type     string `json:"type"`
}

type armResourceRecord struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	raw      json.RawMessage
}

type azureVMRecord struct {
	Resource    armTypedResourceRecord
	SubnetIDs   []string
	NSGIDs      []string
	PublicIPIDs []string
	PublicHosts []string
}

type azurePrincipalLookup struct {
	record graphPrincipalRecord
	ok     bool
}

func listIAMRoleAssignmentsBase(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]armRoleAssignmentRecord, string, error) {
	query := url.Values{"api-version": {"2022-04-01"}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/Microsoft.Authorization/roleAssignments"
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure rbac role assignment", func(record *armRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	return records, response.Next, nil
}

func listIAMRoleAssignments(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armRoleAssignmentRecord, string, error) {
	records, next, err := listIAMRoleAssignmentsBase(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	roleNames := map[string]string{}
	principals := map[string]azurePrincipalLookup{}
	for i := range records {
		roleDefinitionID := strings.TrimSpace(records[i].Properties.RoleDefinitionID)
		if roleDefinitionID != "" {
			roleName, ok := roleNames[roleDefinitionID]
			if !ok {
				roleName = resolveARMRoleName(ctx, source, settings, roleDefinitionID)
				roleNames[roleDefinitionID] = roleName
			}
			records[i].RoleName = firstNonEmpty(records[i].RoleName, roleName)
		}
		principalID := strings.TrimSpace(records[i].Properties.PrincipalID)
		if principalID == "" {
			continue
		}
		principalKey := strings.ToLower(strings.TrimSpace(records[i].Properties.PrincipalType)) + ":" + principalID
		resolved, ok := principals[principalKey]
		if !ok {
			principal, found := resolveAzurePrincipal(ctx, source, settings, principalID, records[i].Properties.PrincipalType)
			resolved = azurePrincipalLookup{record: principal, ok: found}
			principals[principalKey] = resolved
		}
		if resolved.ok {
			principal := resolved.record
			records[i].Principal = principal
		}
	}
	return records, next, nil
}

func listAssetMetadata(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]armResourceRecord, string, error) {
	query := url.Values{"api-version": {"2021-04-01"}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/resources"
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure resource metadata", func(record *armResourceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.Next, err
}

func listARMTypedResources(ctx context.Context, source *Source, settings settings, pageToken string, providerPath string, apiVersion string, label string) ([]armTypedResourceRecord, string, error) {
	query := url.Values{"api-version": {apiVersion}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/" + providerPath
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, label, func(record *armTypedResourceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.Next, err
}

func listVirtualMachines(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]azureVMRecord, string, error) {
	resources, next, err := listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Compute/virtualMachines", "2024-07-01", "azure virtual machine")
	if err != nil {
		return nil, "", err
	}
	records := make([]azureVMRecord, 0, len(resources))
	nics := map[string]armTypedResourceRecord{}
	publicIPs := map[string]armTypedResourceRecord{}
	for _, resource := range resources {
		record := azureVMRecord{Resource: resource}
		for _, nicID := range azureNetworkInterfaceIDs(resource) {
			nic, ok := nics[nicID]
			if !ok {
				nic, ok = getARMTypedResourceByID(ctx, source, settings, nicID, "2023-09-01")
				if ok {
					nics[nicID] = nic
				}
			}
			if !ok {
				continue
			}
			record.SubnetIDs = append(record.SubnetIDs, azureNICSubnetIDs(nic)...)
			record.NSGIDs = append(record.NSGIDs, azureNICNSGIDs(nic)...)
			publicIPIDs := azureNICPublicIPIDs(nic)
			record.PublicIPIDs = append(record.PublicIPIDs, publicIPIDs...)
			for _, publicIPID := range publicIPIDs {
				publicIP, found := publicIPs[publicIPID]
				if !found {
					publicIP, found = getARMTypedResourceByID(ctx, source, settings, publicIPID, "2023-09-01")
					if found {
						publicIPs[publicIPID] = publicIP
					}
				}
				if found {
					record.PublicHosts = append(record.PublicHosts, azurePublicIPHosts(publicIP)...)
				}
			}
		}
		record.SubnetIDs = uniqueStrings(record.SubnetIDs)
		record.NSGIDs = uniqueStrings(record.NSGIDs)
		record.PublicIPIDs = uniqueStrings(record.PublicIPIDs)
		record.PublicHosts = uniqueStrings(record.PublicHosts)
		records = append(records, record)
	}
	return records, next, nil
}

func iamRoleAssignmentEvent(settings settings, record armRoleAssignmentRecord) (*primitives.Event, error) {
	roleName := firstNonEmpty(record.RoleName, record.Properties.RoleDefinitionID)
	principal := record.Principal
	subjectEmail := firstNonEmpty(emailLike(principal.Mail), emailLike(principal.UserPrincipalName), emailLike(record.Properties.PrincipalID))
	attributes := map[string]string{
		"domain":             tenantID(settings),
		"family":             familyIAMRoleAssign,
		"is_admin":           boolString(isAdminRole(roleName)),
		"role_assignment_id": firstNonEmpty(record.ID, record.Name),
		"role_id":            firstNonEmpty(record.Properties.RoleDefinitionID, roleName),
		"role_name":          roleName,
		"role_type":          "azure_rbac_role",
		"scope":              record.Properties.Scope,
		"subject_email":      subjectEmail,
		"subject_id":         record.Properties.PrincipalID,
		"subject_login":      subjectEmail,
		"subject_name":       firstNonEmpty(principal.DisplayName, principal.UserPrincipalName),
		"subject_type":       azurePrincipalType(record.Properties.PrincipalType, principal),
		"subscription_id":    settings.subscriptionID,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"subscription_id": settings.subscriptionID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-iam-role-assignment-"+firstNonEmpty(record.Name, record.ID), "azure.iam_role_assignment", "azure/iam_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func effectivePermissionEvent(settings settings, record armRoleAssignmentRecord) (*primitives.Event, error) {
	roleName := firstNonEmpty(record.RoleName, record.Properties.RoleDefinitionID)
	principal := record.Principal
	subjectEmail := firstNonEmpty(emailLike(principal.Mail), emailLike(principal.UserPrincipalName), emailLike(record.Properties.PrincipalID))
	admin := isAdminRole(roleName)
	scope := firstNonEmpty(record.Properties.Scope, "/subscriptions/"+settings.subscriptionID)
	attributes := map[string]string{
		"actions":            roleName,
		"domain":             tenantID(settings),
		"effect":             "allow",
		"family":             familyEffectivePermission,
		"is_admin":           boolString(admin),
		"permission":         roleName,
		"privilege_level":    privilegeLevel(admin),
		"resource_id":        scope,
		"resource_name":      azurearm.ResourceNameFromID(scope),
		"resource_type":      azurearm.ResourceTypeFromID(scope),
		"role_assignment_id": firstNonEmpty(record.ID, record.Name),
		"role_id":            firstNonEmpty(record.Properties.RoleDefinitionID, roleName),
		"role_name":          roleName,
		"role_type":          "azure_rbac_role",
		"scope":              scope,
		"subject_email":      subjectEmail,
		"subject_id":         record.Properties.PrincipalID,
		"subject_login":      subjectEmail,
		"subject_name":       firstNonEmpty(principal.DisplayName, principal.UserPrincipalName),
		"subject_type":       azurePrincipalType(record.Properties.PrincipalType, principal),
		"subscription_id":    settings.subscriptionID,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"subscription_id": settings.subscriptionID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-effective-permission-"+firstNonEmpty(record.Name, record.ID), "azure.effective_permission", "azure/effective_permission/v1", payload, attributes, time.Now().UTC())
}

func assetMetadataEvent(settings settings, record armResourceRecord) (*primitives.Event, error) {
	tags := record.Tags
	resourceID := firstNonEmpty(record.ID, record.Name)
	attributes := map[string]string{
		"asset_criticality":   firstNonEmpty(tagLookup(tags, "asset_criticality", "business_criticality", "criticality", "tier"), criticalityFromTags(tags)),
		"contains_pci":        tagLookup(tags, "contains_pci", "pci"),
		"contains_phi":        tagLookup(tags, "contains_phi", "phi"),
		"contains_pii":        tagLookup(tags, "contains_pii", "pii"),
		"contains_secrets":    tagLookup(tags, "contains_secrets", "secrets"),
		"crown_jewel":         boolString(crownJewelFromTags(tags)),
		"data_classification": tagLookup(tags, "data_classification", "DataClassification", "data-classification", "classification", "sensitivity", "data_sensitivity"),
		"domain":              tenantID(settings),
		"environment":         tagLookup(tags, "environment", "env", "stage"),
		"internet_exposed":    tagLookup(tags, "internet_exposed", "internet-exposed", "externally_exposed", "external_exposure"),
		"owner":               tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"public":              tagLookup(tags, "public", "public_access"),
		"region":              record.Location,
		"resource_id":         resourceID,
		"resource_name":       firstNonEmpty(record.Name, resourceID),
		"resource_provider":   "azure",
		"resource_type":       firstNonEmpty(record.Type, "resource"),
		"source_provider":     "azure",
		"subscription_id":     settings.subscriptionID,
		"team":                tagLookup(tags, "team", "squad", "group"),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"subscription_id": settings.subscriptionID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-asset-metadata-"+firstNonEmpty(resourceID, record.Type), "asset.data_sensitivity", "asset/data_sensitivity/v1", payload, attributes, time.Now().UTC())
}

func virtualMachineEvent(settings settings, record azureVMRecord) (*primitives.Event, error) {
	resource := record.Resource
	attributes := azureResourceAttributes(settings, resource, familyVirtualMachine)
	addAzureIdentityAttributes(attributes, resource.Identity)
	setAttributes(attributes, map[string]string{"computer_name": propertyString(resource, "osProfile", "computerName"), "admin_username": propertyString(resource, "osProfile", "adminUsername"), "vm_size": propertyString(resource, "hardwareProfile", "vmSize"), "os_type": propertyString(resource, "storageProfile", "osDisk", "osType"), "encryption_at_host": propertyBoolString(resource, "securityProfile", "encryptionAtHost"), "boot_diagnostics_enabled": propertyBoolString(resource, "diagnosticsProfile", "bootDiagnostics", "enabled"), "network_interface_ids": strings.Join(azureNetworkInterfaceIDs(resource), ","), "subnet_ids": strings.Join(record.SubnetIDs, ","), "nsg_ids": strings.Join(record.NSGIDs, ","), "public_ip_ids": strings.Join(record.PublicIPIDs, ","), "public_host": strings.Join(record.PublicHosts, ","), "public_network_access": boolString(len(record.PublicIPIDs) > 0 || len(record.PublicHosts) > 0), "internet_exposed": boolString(len(record.PublicIPIDs) > 0 || len(record.PublicHosts) > 0)})
	payload, err := payloadWithRaw(resource.raw, map[string]any{"tenant_id": settings.tenantID, "subscription_id": settings.subscriptionID, "subnet_ids": record.SubnetIDs, "nsg_ids": record.NSGIDs, "public_ip_ids": record.PublicIPIDs, "public_hosts": record.PublicHosts})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyVirtualMachine, resource), "azure.virtual_machine", "azure/virtual_machine/v1", payload, attributes, time.Now().UTC())
}

func resolveARMRoleName(ctx context.Context, source *Source, settings settings, roleDefinitionID string) string {
	if strings.TrimSpace(roleDefinitionID) == "" {
		return ""
	}
	path := roleDefinitionID
	if strings.HasPrefix(path, armBaseURL(settings)) {
		path = strings.TrimPrefix(path, armBaseURL(settings))
	}
	query := url.Values{"api-version": {"2022-04-01"}}
	var record armRoleDefinitionRecord
	if err := getARMJSON(ctx, source, settings, path, query, &record); err != nil {
		return ""
	}
	return record.Properties.RoleName
}
