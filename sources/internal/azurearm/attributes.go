package azurearm

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

type Properties map[string]any

func ResourceAttributes(family string, recordKind string, fallbackKind string, properties Properties) map[string]string {
	attributes := map[string]string{
		"kind":                  firstNonEmpty(recordKind, fallbackKind),
		"public_network_access": stringAt(properties, "publicNetworkAccess"),
		"state":                 firstNonEmpty(stringAt(properties, "provisioningState"), stringAt(properties, "status"), stringAt(properties, "state")),
	}
	switch family {
	case "activity_log_alert":
		set(attributes, "enabled", stringAt(properties, "enabled"))
		set(attributes, "scopes", strings.Join(stringsAt(properties, "scopes"), ","))
		set(attributes, "condition_fields", strings.Join(valuesFromArray(properties, []string{"condition", "allOf"}, "field"), ","))
		set(attributes, "condition_equals", strings.Join(valuesFromArray(properties, []string{"condition", "allOf"}, "equals"), ","))
		set(attributes, "condition_contains_any", strings.Join(valuesFromArray(properties, []string{"condition", "allOf"}, "containsAny"), ","))
		set(attributes, "action_group_ids", strings.Join(valuesFromArray(properties, []string{"actions", "actionGroups"}, "actionGroupId"), ","))
	case "aks_node_pool":
		set(attributes, "mode", stringAt(properties, "mode"))
		set(attributes, "vm_size", stringAt(properties, "vmSize"))
		set(attributes, "os_type", stringAt(properties, "osType"))
		set(attributes, "os_sku", stringAt(properties, "osSKU"))
		set(attributes, "node_count", stringAt(properties, "count"))
		set(attributes, "node_image_version", stringAt(properties, "nodeImageVersion"))
		set(attributes, "kubelet_disk_type", stringAt(properties, "kubeletDiskType"))
		set(attributes, "max_pods", stringAt(properties, "maxPods"))
		set(attributes, "enable_auto_scaling", stringAt(properties, "enableAutoScaling"))
		set(attributes, "vnet_subnet_id", stringAt(properties, "vnetSubnetID"))
	case "application_container":
		set(attributes, "managed_environment_id", stringAt(properties, "managedEnvironmentId"))
		set(attributes, "workload_profile_name", stringAt(properties, "workloadProfileName"))
		set(attributes, "latest_revision_name", stringAt(properties, "latestRevisionName"))
		set(attributes, "latest_revision_fqdn", stringAt(properties, "latestRevisionFqdn"))
		set(attributes, "revision_mode", stringAt(properties, "configuration", "activeRevisionsMode"))
		set(attributes, "ingress_external", stringAt(properties, "configuration", "ingress", "external"))
		set(attributes, "ingress_fqdn", stringAt(properties, "configuration", "ingress", "fqdn"))
		set(attributes, "ingress_target_port", stringAt(properties, "configuration", "ingress", "targetPort"))
		set(attributes, "ingress_transport", stringAt(properties, "configuration", "ingress", "transport"))
		set(attributes, "container_images", strings.Join(valuesFromArray(properties, []string{"template", "containers"}, "image"), ","))
		set(attributes, "outbound_ip_addresses", strings.Join(stringsAt(properties, "outboundIpAddresses"), ","))
	case "application_gateway":
		set(attributes, "operational_state", stringAt(properties, "operationalState"))
		set(attributes, "frontend_ip_configuration_names", strings.Join(valuesFromArray(properties, []string{"frontendIPConfigurations"}, "name"), ","))
		set(attributes, "frontend_ip_configuration_ids", strings.Join(valuesFromArray(properties, []string{"frontendIPConfigurations"}, "id"), ","))
		set(attributes, "public_ip_ids", strings.Join(referenceIDsFromArray(properties, []string{"frontendIPConfigurations"}, "publicIPAddress"), ","))
		set(attributes, "subnet_ids", strings.Join(referenceIDsFromArray(properties, []string{"gatewayIPConfigurations"}, "subnet"), ","))
		set(attributes, "backend_pool_names", strings.Join(valuesFromArray(properties, []string{"backendAddressPools"}, "name"), ","))
		set(attributes, "http_listener_names", strings.Join(valuesFromArray(properties, []string{"httpListeners"}, "name"), ","))
		set(attributes, "ssl_certificate_names", strings.Join(valuesFromArray(properties, []string{"sslCertificates"}, "name"), ","))
		set(attributes, "ssl_policy_min_protocol_version", stringAt(properties, "sslPolicy", "minProtocolVersion"))
		set(attributes, "firewall_policy_id", stringAt(properties, "firewallPolicy", "id"))
		set(attributes, "waf_enabled", stringAt(properties, "webApplicationFirewallConfiguration", "enabled"))
		set(attributes, "waf_firewall_mode", stringAt(properties, "webApplicationFirewallConfiguration", "firewallMode"))
	case "application_insight":
		set(attributes, "app_id", stringAt(properties, "AppId"))
		set(attributes, "application_type", stringAt(properties, "Application_Type"))
		set(attributes, "flow_type", stringAt(properties, "Flow_Type"))
		set(attributes, "request_source", stringAt(properties, "Request_Source"))
		set(attributes, "ingestion_mode", stringAt(properties, "IngestionMode"))
		set(attributes, "retention_in_days", stringAt(properties, "RetentionInDays"))
		set(attributes, "sampling_percentage", stringAt(properties, "SamplingPercentage"))
		set(attributes, "disable_local_auth", stringAt(properties, "DisableLocalAuth"))
		set(attributes, "workspace_resource_id", stringAt(properties, "WorkspaceResourceId"))
		set(attributes, "public_network_access_for_ingestion", stringAt(properties, "publicNetworkAccessForIngestion"))
		set(attributes, "public_network_access_for_query", stringAt(properties, "publicNetworkAccessForQuery"))
	case "cognitive_services_account":
		set(attributes, "endpoint", stringAt(properties, "endpoint"))
		set(attributes, "custom_subdomain_name", stringAt(properties, "customSubDomainName"))
		set(attributes, "disable_local_auth", stringAt(properties, "disableLocalAuth"))
		set(attributes, "network_default_action", stringAt(properties, "networkAcls", "defaultAction"))
		set(attributes, "network_bypass", stringAt(properties, "networkAcls", "bypass"))
		set(attributes, "virtual_network_subnet_ids", strings.Join(referenceIDsFromArray(properties, []string{"networkAcls", "virtualNetworkRules"}, "id"), ","))
		set(attributes, "ip_rules", strings.Join(valuesFromArray(properties, []string{"networkAcls", "ipRules"}, "value"), ","))
	case "cognitive_services_deployment":
		set(attributes, "model_format", stringAt(properties, "model", "format"))
		set(attributes, "model_name", stringAt(properties, "model", "name"))
		set(attributes, "model_version", stringAt(properties, "model", "version"))
		set(attributes, "scale_type", stringAt(properties, "scaleSettings", "scaleType"))
		set(attributes, "capacity", stringAt(properties, "scaleSettings", "capacity"))
	case "cosmos_postgresql":
		set(attributes, "postgresql_version", stringAt(properties, "postgresqlVersion"))
		set(attributes, "citus_version", stringAt(properties, "citusVersion"))
		set(attributes, "administrator_login", stringAt(properties, "administratorLogin"))
		set(attributes, "coordinator_server_edition", stringAt(properties, "coordinatorServerEdition"))
		set(attributes, "coordinator_vcores", stringAt(properties, "coordinatorVCores"))
		set(attributes, "node_server_edition", stringAt(properties, "nodeServerEdition"))
		set(attributes, "node_vcores", stringAt(properties, "nodeVCores"))
		set(attributes, "node_count", stringAt(properties, "nodeCount"))
		set(attributes, "ha_enabled", stringAt(properties, "enableHa"))
		set(attributes, "preferred_primary_zone", stringAt(properties, "preferredPrimaryZone"))
	case "cosmos_postgresql_firewall_rule", "postgresql_firewall_rule":
		set(attributes, "start_ip_address", stringAt(properties, "startIpAddress"))
		set(attributes, "end_ip_address", stringAt(properties, "endIpAddress"))
	case "databricks_workspace":
		set(attributes, "managed_resource_group_id", stringAt(properties, "managedResourceGroupId"))
		set(attributes, "required_nsg_rules", stringAt(properties, "requiredNsgRules"))
		set(attributes, "public_subnet_name", databricksParameter(properties, "customPublicSubnetName"))
		set(attributes, "private_subnet_name", databricksParameter(properties, "customPrivateSubnetName"))
		set(attributes, "nat_gateway_name", databricksParameter(properties, "natGatewayName"))
		set(attributes, "access_connector_id", stringAt(properties, "accessConnector", "id"))
	case "defender_config":
		set(attributes, "pricing_tier", stringAt(properties, "pricingTier"))
		set(attributes, "sub_plan", stringAt(properties, "subPlan"))
		set(attributes, "free_trial_remaining_time", stringAt(properties, "freeTrialRemainingTime"))
		set(attributes, "deprecated", stringAt(properties, "deprecated"))
		set(attributes, "replaced_by", strings.Join(stringsAt(properties, "replacedBy"), ","))
		set(attributes, "extension_names", strings.Join(valuesFromArray(properties, []string{"extensions"}, "name"), ","))
		set(attributes, "extension_enabled_states", strings.Join(valuesFromArray(properties, []string{"extensions"}, "isEnabled"), ","))
	case "diagnostic_setting":
		set(attributes, "workspace_id", stringAt(properties, "workspaceId"))
		set(attributes, "storage_account_id", stringAt(properties, "storageAccountId"))
		set(attributes, "event_hub_authorization_rule_id", stringAt(properties, "eventHubAuthorizationRuleId"))
		set(attributes, "event_hub_name", stringAt(properties, "eventHubName"))
		set(attributes, "log_categories", strings.Join(valuesFromArray(properties, []string{"logs"}, "category"), ","))
		set(attributes, "log_category_groups", strings.Join(valuesFromArray(properties, []string{"logs"}, "categoryGroup"), ","))
		set(attributes, "log_enabled_states", strings.Join(valuesFromArray(properties, []string{"logs"}, "enabled"), ","))
		set(attributes, "metric_categories", strings.Join(valuesFromArray(properties, []string{"metrics"}, "category"), ","))
		set(attributes, "metric_enabled_states", strings.Join(valuesFromArray(properties, []string{"metrics"}, "enabled"), ","))
	case "load_balancer":
		set(attributes, "frontend_ip_configuration_names", strings.Join(valuesFromArray(properties, []string{"frontendIPConfigurations"}, "name"), ","))
		set(attributes, "frontend_ip_configuration_ids", strings.Join(valuesFromArray(properties, []string{"frontendIPConfigurations"}, "id"), ","))
		set(attributes, "public_ip_ids", strings.Join(referenceIDsFromArray(properties, []string{"frontendIPConfigurations"}, "publicIPAddress"), ","))
		set(attributes, "subnet_ids", strings.Join(referenceIDsFromArray(properties, []string{"frontendIPConfigurations"}, "subnet"), ","))
		set(attributes, "backend_pool_names", strings.Join(valuesFromArray(properties, []string{"backendAddressPools"}, "name"), ","))
		set(attributes, "probe_names", strings.Join(valuesFromArray(properties, []string{"probes"}, "name"), ","))
		set(attributes, "load_balancing_rule_names", strings.Join(valuesFromArray(properties, []string{"loadBalancingRules"}, "name"), ","))
		set(attributes, "inbound_nat_rule_names", strings.Join(valuesFromArray(properties, []string{"inboundNatRules"}, "name"), ","))
	case "log_alert":
		set(attributes, "enabled", stringAt(properties, "enabled"))
		set(attributes, "scopes", strings.Join(stringsAt(properties, "scopes"), ","))
		set(attributes, "severity", stringAt(properties, "severity"))
		set(attributes, "query", stringAt(properties, "criteria", "allOf", "0", "query"))
		set(attributes, "evaluation_frequency", stringAt(properties, "evaluationFrequency"))
		set(attributes, "window_size", stringAt(properties, "windowSize"))
		set(attributes, "action_group_ids", strings.Join(stringsAt(properties, "actions", "actionGroups"), ","))
	case "machine_learning_workspace":
		set(attributes, "public_network_access", firstNonEmpty(attributes["public_network_access"], stringAt(properties, "publicNetworkAccess")))
		set(attributes, "discovery_url", stringAt(properties, "discoveryUrl"))
		set(attributes, "friendly_name", stringAt(properties, "friendlyName"))
		set(attributes, "key_vault_id", stringAt(properties, "keyVault"))
		set(attributes, "storage_account_id", stringAt(properties, "storageAccount"))
		set(attributes, "container_registry_id", stringAt(properties, "containerRegistry"))
		set(attributes, "application_insights_id", stringAt(properties, "applicationInsights"))
		set(attributes, "image_build_compute", stringAt(properties, "imageBuildCompute"))
		set(attributes, "hbi_workspace", stringAt(properties, "hbiWorkspace"))
		set(attributes, "private_endpoint_connection_count", strconv.Itoa(len(arrayAt(properties, "privateEndpointConnections"))))
	case "machine_learning_compute":
		set(attributes, "compute_type", stringAt(properties, "computeType"))
		set(attributes, "provisioning_state", stringAt(properties, "provisioningState"))
		set(attributes, "vm_size", stringAt(properties, "properties", "vmSize"))
		set(attributes, "subnet_id", stringAt(properties, "properties", "subnet", "id"))
		set(attributes, "ssh_public_access", stringAt(properties, "properties", "remoteLoginPortPublicAccess"))
	case "metric_alert_rule":
		set(attributes, "enabled", stringAt(properties, "enabled"))
		set(attributes, "scopes", strings.Join(stringsAt(properties, "scopes"), ","))
		set(attributes, "severity", stringAt(properties, "severity"))
		set(attributes, "evaluation_frequency", stringAt(properties, "evaluationFrequency"))
		set(attributes, "window_size", stringAt(properties, "windowSize"))
		set(attributes, "auto_mitigate", stringAt(properties, "autoMitigate"))
		set(attributes, "target_resource_type", stringAt(properties, "targetResourceType"))
		set(attributes, "target_resource_region", stringAt(properties, "targetResourceRegion"))
		set(attributes, "criteria_type", stringAt(properties, "criteria", "odata.type"))
		set(attributes, "criteria_metric_names", strings.Join(valuesFromArray(properties, []string{"criteria", "allOf"}, "metricName"), ","))
		set(attributes, "criteria_operators", strings.Join(valuesFromArray(properties, []string{"criteria", "allOf"}, "operator"), ","))
		set(attributes, "criteria_thresholds", strings.Join(valuesFromArray(properties, []string{"criteria", "allOf"}, "threshold"), ","))
		set(attributes, "action_group_ids", strings.Join(valuesFromArray(properties, []string{"actions"}, "actionGroupId"), ","))
	case "policy_assignment":
		set(attributes, "display_name", stringAt(properties, "displayName"))
		set(attributes, "description", stringAt(properties, "description"))
		set(attributes, "policy_definition_id", stringAt(properties, "policyDefinitionId"))
		set(attributes, "scope", stringAt(properties, "scope"))
		set(attributes, "enforcement_mode", stringAt(properties, "enforcementMode"))
	case "postgresql_server":
		set(attributes, "version", stringAt(properties, "version"))
		set(attributes, "administrator_login", stringAt(properties, "administratorLogin"))
		set(attributes, "public_host", stringAt(properties, "fullyQualifiedDomainName"))
		set(attributes, "storage_size_gb", stringAt(properties, "storage", "storageSizeGB"))
		set(attributes, "backup_retention_days", stringAt(properties, "backup", "backupRetentionDays"))
		set(attributes, "geo_redundant_backup", stringAt(properties, "backup", "geoRedundantBackup"))
		set(attributes, "high_availability_mode", stringAt(properties, "highAvailability", "mode"))
		set(attributes, "availability_zone", stringAt(properties, "availabilityZone"))
		set(attributes, "network_public_network_access", stringAt(properties, "network", "publicNetworkAccess"))
		set(attributes, "delegated_subnet_id", stringAt(properties, "network", "delegatedSubnetResourceId"))
		set(attributes, "private_dns_zone_id", stringAt(properties, "network", "privateDnsZoneArmResourceId"))
		set(attributes, "auth_active_directory_enabled", stringAt(properties, "authConfig", "activeDirectoryAuth"))
		set(attributes, "auth_password_enabled", stringAt(properties, "authConfig", "passwordAuth"))
	case "mysql_server":
		set(attributes, "version", stringAt(properties, "version"))
		set(attributes, "administrator_login", stringAt(properties, "administratorLogin"))
		set(attributes, "public_host", stringAt(properties, "fullyQualifiedDomainName"))
		set(attributes, "storage_size_gb", stringAt(properties, "storage", "storageSizeGB"))
		set(attributes, "backup_retention_days", stringAt(properties, "backup", "backupRetentionDays"))
		set(attributes, "network_public_network_access", stringAt(properties, "network", "publicNetworkAccess"))
	case "role":
		set(attributes, "role_name", stringAt(properties, "roleName"))
		set(attributes, "role_type", stringAt(properties, "type"))
		set(attributes, "assignable_scopes", strings.Join(stringsAt(properties, "assignableScopes"), ","))
		set(attributes, "actions", strings.Join(valuesFromArray(properties, []string{"permissions"}, "actions"), ","))
		set(attributes, "not_actions", strings.Join(valuesFromArray(properties, []string{"permissions"}, "notActions"), ","))
		set(attributes, "data_actions", strings.Join(valuesFromArray(properties, []string{"permissions"}, "dataActions"), ","))
		set(attributes, "not_data_actions", strings.Join(valuesFromArray(properties, []string{"permissions"}, "notDataActions"), ","))
	case "route_table":
		set(attributes, "disable_bgp_route_propagation", stringAt(properties, "disableBgpRoutePropagation"))
		set(attributes, "route_names", strings.Join(valuesFromArray(properties, []string{"routes"}, "name"), ","))
		set(attributes, "route_count", strconv.Itoa(len(arrayAt(properties, "routes"))))
		set(attributes, "address_prefixes", strings.Join(valuesFromArray(properties, []string{"routes"}, "addressPrefix"), ","))
		set(attributes, "next_hop_types", strings.Join(valuesFromArray(properties, []string{"routes"}, "nextHopType"), ","))
		set(attributes, "next_hop_ip_addresses", strings.Join(valuesFromArray(properties, []string{"routes"}, "nextHopIpAddress"), ","))
		set(attributes, "subnet_ids", strings.Join(valuesFromArray(properties, []string{"subnets"}, "id"), ","))
	case "security_contact":
		set(attributes, "emails", stringAt(properties, "emails"))
		set(attributes, "phone", stringAt(properties, "phone"))
		set(attributes, "alert_notifications", stringAt(properties, "alertNotifications"))
		set(attributes, "alerts_to_admins", stringAt(properties, "alertsToAdmins"))
	case "security_setting":
		set(attributes, "enabled", stringAt(properties, "enabled"))
		set(attributes, "setting_kind", stringAt(properties, "kind"))
	case "server_vulnerability":
		set(attributes, "display_name", stringAt(properties, "displayName"))
		set(attributes, "status_code", stringAt(properties, "status", "code"))
		set(attributes, "status_cause", stringAt(properties, "status", "cause"))
		set(attributes, "status_description", stringAt(properties, "status", "description"))
		set(attributes, "resource_source", stringAt(properties, "resourceDetails", "source"))
		set(attributes, "assessed_resource_id", stringAt(properties, "resourceDetails", "id"))
		set(attributes, "additional_data_keys", strings.Join(mapKeys(mapFromAny(nestedAny(properties, "additionalData"))), ","))
	case "server_vulnerability_subassessment":
		set(attributes, "display_name", stringAt(properties, "displayName"))
		set(attributes, "status_code", stringAt(properties, "status", "code"))
		set(attributes, "severity", stringAt(properties, "status", "severity"))
		set(attributes, "category", stringAt(properties, "category"))
		set(attributes, "impact", stringAt(properties, "impact"))
		set(attributes, "remediation", stringAt(properties, "remediation"))
		set(attributes, "assessed_resource_id", stringAt(properties, "resourceDetails", "id"))
	case "sql_managed_instance":
		set(attributes, "administrator_login", stringAt(properties, "administratorLogin"))
		set(attributes, "public_host", stringAt(properties, "fullyQualifiedDomainName"))
		set(attributes, "public_data_endpoint_enabled", stringAt(properties, "publicDataEndpointEnabled"))
		set(attributes, "min_tls_version", stringAt(properties, "minimalTlsVersion"))
		set(attributes, "subnet_id", stringAt(properties, "subnetId"))
		set(attributes, "license_type", stringAt(properties, "licenseType"))
		set(attributes, "vcores", stringAt(properties, "vCores"))
		set(attributes, "storage_size_gb", stringAt(properties, "storageSizeInGB"))
		set(attributes, "zone_redundant", stringAt(properties, "zoneRedundant"))
		set(attributes, "proxy_override", stringAt(properties, "proxyOverride"))
	case "sql_managed_instance_tde":
		set(attributes, "server_key_name", stringAt(properties, "serverKeyName"))
		set(attributes, "server_key_type", stringAt(properties, "serverKeyType"))
		set(attributes, "auto_rotation_enabled", stringAt(properties, "autoRotationEnabled"))
	case "sql_server_on_virtual_machine":
		set(attributes, "virtual_machine_resource_id", stringAt(properties, "virtualMachineResourceId"))
		set(attributes, "sql_image_offer", stringAt(properties, "sqlImageOffer"))
		set(attributes, "sql_image_sku", stringAt(properties, "sqlImageSku"))
		set(attributes, "sql_server_license_type", stringAt(properties, "sqlServerLicenseType"))
		set(attributes, "sql_management", stringAt(properties, "sqlManagement"))
		set(attributes, "least_privilege_mode", stringAt(properties, "leastPrivilegeMode"))
		set(attributes, "assessment_enabled", stringAt(properties, "assessmentSettings", "enable"))
		set(attributes, "auto_patching_enabled", stringAt(properties, "autoPatchingSettings", "enable"))
		set(attributes, "auto_backup_enabled", stringAt(properties, "autoBackupSettings", "enable"))
		set(attributes, "key_vault_credential_enabled", stringAt(properties, "keyVaultCredentialSettings", "enable"))
		set(attributes, "sql_connectivity_type", firstNonEmpty(stringAt(properties, "serverConfigurationsManagementSettings", "sqlConnectivityUpdateSettings", "connectivityType"), stringAt(properties, "sqlConnectivityType")))
		set(attributes, "sql_storage_disk_configuration_type", stringAt(properties, "serverConfigurationsManagementSettings", "sqlStorageUpdateSettings", "diskConfigurationType"))
	case "storage_container":
		set(attributes, "public_access", stringAt(properties, "publicAccess"))
		set(attributes, "has_immutability_policy", stringAt(properties, "hasImmutabilityPolicy"))
		set(attributes, "has_legal_hold", stringAt(properties, "hasLegalHold"))
		set(attributes, "lease_status", stringAt(properties, "leaseStatus"))
	case "storage_queue":
		set(attributes, "metadata_keys", strings.Join(mapKeys(mapFromAny(nestedAny(properties, "metadata"))), ","))
	case "synapse_sql_pool":
		set(attributes, "status", stringAt(properties, "status"))
		set(attributes, "collation", stringAt(properties, "collation"))
		set(attributes, "max_size_bytes", stringAt(properties, "maxSizeBytes"))
	case "subnet":
		set(attributes, "address_prefix", stringAt(properties, "addressPrefix"))
		set(attributes, "address_prefixes", strings.Join(stringsAt(properties, "addressPrefixes"), ","))
		set(attributes, "network_security_group_id", stringAt(properties, "networkSecurityGroup", "id"))
		set(attributes, "route_table_id", stringAt(properties, "routeTable", "id"))
		set(attributes, "nat_gateway_id", stringAt(properties, "natGateway", "id"))
		set(attributes, "service_endpoint_services", strings.Join(valuesFromArray(properties, []string{"serviceEndpoints"}, "service"), ","))
		set(attributes, "delegation_names", strings.Join(valuesFromArray(properties, []string{"delegations"}, "name"), ","))
		set(attributes, "private_endpoint_network_policies", stringAt(properties, "privateEndpointNetworkPolicies"))
		set(attributes, "private_link_service_network_policies", stringAt(properties, "privateLinkServiceNetworkPolicies"))
		set(attributes, "ip_configuration_ids", strings.Join(valuesFromArray(properties, []string{"ipConfigurations"}, "id"), ","))
		set(attributes, "application_gateway_ip_configuration_ids", strings.Join(valuesFromArray(properties, []string{"applicationGatewayIPConfigurations"}, "id"), ","))
	case "virtual_machine_scale_set":
		set(attributes, "upgrade_mode", stringAt(properties, "upgradePolicy", "mode"))
		set(attributes, "overprovision", stringAt(properties, "overprovision"))
		set(attributes, "single_placement_group", stringAt(properties, "singlePlacementGroup"))
		set(attributes, "orchestration_mode", stringAt(properties, "orchestrationMode"))
		set(attributes, "computer_name_prefix", stringAt(properties, "virtualMachineProfile", "osProfile", "computerNamePrefix"))
		set(attributes, "admin_username", stringAt(properties, "virtualMachineProfile", "osProfile", "adminUsername"))
		set(attributes, "image_publisher", stringAt(properties, "virtualMachineProfile", "storageProfile", "imageReference", "publisher"))
		set(attributes, "image_offer", stringAt(properties, "virtualMachineProfile", "storageProfile", "imageReference", "offer"))
		set(attributes, "image_sku", stringAt(properties, "virtualMachineProfile", "storageProfile", "imageReference", "sku"))
		set(attributes, "image_version", stringAt(properties, "virtualMachineProfile", "storageProfile", "imageReference", "version"))
		set(attributes, "subnet_ids", strings.Join(vmssSubnetIDs(properties), ","))
		set(attributes, "nsg_ids", strings.Join(vmssNetworkSecurityGroupIDs(properties), ","))
	case "virtual_machine_extension":
		set(attributes, "publisher", stringAt(properties, "publisher"))
		set(attributes, "extension_type", stringAt(properties, "type"))
		set(attributes, "type_handler_version", stringAt(properties, "typeHandlerVersion"))
		set(attributes, "auto_upgrade_minor_version", stringAt(properties, "autoUpgradeMinorVersion"))
		set(attributes, "protected_settings_present", strconv.FormatBool(mapFromAny(nestedAny(properties, "protectedSettings")) != nil))
	case "virtual_machine_scale_set_instance":
		set(attributes, "vm_id", stringAt(properties, "vmId"))
		set(attributes, "computer_name", stringAt(properties, "osProfile", "computerName"))
		set(attributes, "os_type", stringAt(properties, "storageProfile", "osDisk", "osType"))
		set(attributes, "vm_size", stringAt(properties, "hardwareProfile", "vmSize"))
		set(attributes, "subnet_ids", strings.Join(vmssSubnetIDs(properties), ","))
		set(attributes, "nsg_ids", strings.Join(vmssNetworkSecurityGroupIDs(properties), ","))
	}
	trimEmpty(attributes)
	return attributes
}

func databricksParameter(properties Properties, key string) string {
	return stringAt(properties, "parameters", key, "value")
}

func vmssSubnetIDs(properties Properties) []string {
	configs := arrayAt(properties, "virtualMachineProfile", "networkProfile", "networkInterfaceConfigurations")
	values := make([]string, 0)
	for _, configValue := range configs {
		config := mapFromAny(configValue)
		for _, ipValue := range arrayAt(mapFromAny(config["properties"]), "ipConfigurations") {
			ipConfig := mapFromAny(ipValue)
			values = append(values, stringAt(mapFromAny(ipConfig["properties"]), "subnet", "id"))
		}
	}
	return unique(values)
}

func vmssNetworkSecurityGroupIDs(properties Properties) []string {
	configs := arrayAt(properties, "virtualMachineProfile", "networkProfile", "networkInterfaceConfigurations")
	values := make([]string, 0, len(configs))
	for _, configValue := range configs {
		config := mapFromAny(configValue)
		values = append(values, stringAt(mapFromAny(config["properties"]), "networkSecurityGroup", "id"))
	}
	return unique(values)
}

func referenceIDsFromArray(values Properties, arrayPath []string, referenceKey string) []string {
	out := make([]string, 0)
	for _, item := range arrayAt(values, arrayPath...) {
		itemMap := mapFromAny(item)
		properties := mapFromAny(itemMap["properties"])
		out = append(out, firstNonEmpty(stringAt(itemMap, referenceKey, "id"), stringAt(properties, referenceKey, "id"), stringAt(itemMap, referenceKey)))
	}
	return unique(out)
}

func valuesFromArray(values Properties, arrayPath []string, field string) []string {
	out := make([]string, 0)
	for _, item := range arrayAt(values, arrayPath...) {
		itemMap := mapFromAny(item)
		if itemMap == nil {
			continue
		}
		properties := mapFromAny(itemMap["properties"])
		candidates := []any{nestedAny(itemMap, strings.Split(field, ".")...), nestedAny(properties, strings.Split(field, ".")...)}
		for _, candidate := range candidates {
			out = append(out, stringsAtAny(candidate)...)
		}
	}
	return unique(out)
}

func stringsAt(values Properties, keys ...string) []string {
	return stringsAtAny(nestedAny(values, keys...))
}

func stringsAtAny(value any) []string {
	switch typed := value.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, stringify(item))
		}
		return unique(values)
	case []string:
		return unique(typed)
	default:
		return unique([]string{stringify(typed)})
	}
}

func stringAt(values Properties, keys ...string) string {
	return stringify(nestedAny(values, keys...))
}

func arrayAt(values Properties, keys ...string) []any {
	value := nestedAny(values, keys...)
	if typed, ok := value.([]any); ok {
		return typed
	}
	return nil
}

func nestedAny(value any, keys ...string) any {
	current := value
	for _, key := range keys {
		if index, err := strconv.Atoi(key); err == nil {
			items, ok := current.([]any)
			if !ok || index < 0 || index >= len(items) {
				return nil
			}
			current = items[index]
			continue
		}
		currentMap := mapFromAny(current)
		if currentMap == nil {
			return nil
		}
		current = currentMap[key]
	}
	return current
}

func mapFromAny(value any) Properties {
	if typed, ok := value.(map[string]any); ok {
		return Properties(typed)
	}
	if typed, ok := value.(Properties); ok {
		return typed
	}
	return nil
}

func mapKeys(values Properties) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringify(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func set(attributes map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		delete(attributes, key)
		return
	}
	attributes[key] = value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmpty(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
