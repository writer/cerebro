package sourceprojection

import (
	"errors"
	"fmt"
	"log"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/ports"
)

// rustAuthoritativeKinds maps every source whose organizational projection is
// owned by the Rust source catalog to the event kinds it emits. A few sources
// also answer for a legacy kind namespace with no source directory of its own
// (duo_security.* for duo); those kinds are listed here too so retiring the
// source keeps refusing them exactly as its stub file did. Go must not
// project these events under any dispatch path.
//
// This replaces the per-source fail-closed stub files each retirement used to
// check in. The kinds are the source catalog's own emitted_kinds, so the
// registry keeps advertising a projector for every declared kind (tools like
// catalogcheck read Registry.Kinds), and TestRustAuthoritativeKindsMatchSourceCatalogs
// fails if a catalog adds a kind this table does not list.
var rustAuthoritativeKinds = map[string][]string{
	"abnormal_security": {
		"abnormal_security.audit_events",
		"abnormal_security.cases",
		"abnormal_security.posture_catalog",
		"abnormal_security.resources",
		"abnormal_security.threats",
	},
	"abuseipdb": {
		"abuseipdb.ip_addresses",
		"abuseipdb.reports",
	},
	"activecampaign": {
		"activecampaign.accounts",
		"activecampaign.automations",
		"activecampaign.campaigns",
		"activecampaign.contacts",
		"activecampaign.users",
	},
	"activtrak": {
		"activtrak.activity_log",
		"activtrak.clients",
		"activtrak.consumers",
		"activtrak.groups",
		"activtrak.users",
	},
	"acunetix": {
		"acunetix.reports",
		"acunetix.scanning_profiles",
		"acunetix.scans",
		"acunetix.targets",
		"acunetix.vulnerabilities",
	},
	"ada_support": {
		"ada_support.audit_events",
		"ada_support.conversations",
		"ada_support.end_users",
		"ada_support.knowledge_articles",
		"ada_support.platform_integrations",
	},
	"addigy": {
		"addigy.audit_events",
		"addigy.devices",
		"addigy.groups",
		"addigy.policies",
		"addigy.users",
	},
	"adobe_workfront": {
		"adobe_workfront.audit_events",
		"adobe_workfront.documents",
		"adobe_workfront.groups",
		"adobe_workfront.projects",
		"adobe_workfront.users",
	},
	"adp_workforce_now": {
		"adp_workforce_now.event_notifications",
		"adp_workforce_now.users",
	},
	"aha": {
		"aha.audit_events",
		"aha.features",
		"aha.products",
		"aha.releases",
		"aha.users",
	},
	"airbrake": {
		"airbrake.deploys",
		"airbrake.groups",
		"airbrake.project_activities",
		"airbrake.projects",
		"airbrake.source_maps",
	},
	"airbyte_cloud": {
		"airbyte_cloud.connections",
		"airbyte_cloud.organizations",
		"airbyte_cloud.permissions",
		"airbyte_cloud.sources",
		"airbyte_cloud.users",
	},
	"aircall": {
		"aircall.calls",
		"aircall.contacts",
		"aircall.numbers",
		"aircall.teams",
		"aircall.users",
	},
	"airfocus": {
		"airfocus.api_keys",
		"airfocus.link_types",
		"airfocus.users",
		"airfocus.workspace_groups",
		"airfocus.workspaces",
	},
	"airtable": {
		"airtable.audit_events",
		"airtable.bases",
		"airtable.users",
	},
	"akeneo": {
		"akeneo.asset",
		"akeneo.asset_families_attribute",
		"akeneo.asset_family",
		"akeneo.attribute",
		"akeneo.attribute_group",
		"akeneo.attributes_option",
		"akeneo.draft",
		"akeneo.option",
		"akeneo.products_draft",
		"akeneo.products_uuid_draft",
		"akeneo.reference_entities_attribute",
		"akeneo.v1_attribute",
	},
	"akeyless": {
		"akeyless.analytics",
		"akeyless.auth_methods",
		"akeyless.items",
		"akeyless.roles",
	},
	"alation": {
		"alation.data_sources",
		"alation.groups",
		"alation.policies",
		"alation.terms",
		"alation.users",
	},
	"alchemer": {
		"alchemer.account",
		"alchemer.account_teams",
		"alchemer.account_users",
		"alchemer.contact_lists",
		"alchemer.sso_integrations",
		"alchemer.surveys",
	},
	"alteryx": {
		"alteryx.audit_events",
		"alteryx.collections",
		"alteryx.usergroups",
		"alteryx.users",
		"alteryx.workflows",
	},
	"amplitude": {
		"amplitude.groups",
		"amplitude.users",
	},
	"anchore": {
		"anchore.assets",
		"anchore.findings",
		"anchore.vulnerabilities",
	},
	"anomalo": {
		"anomalo.checks",
		"anomalo.notification_channels",
		"anomalo.organizations",
		"anomalo.tables",
		"anomalo.warehouses",
	},
	"anthropic": {
		"anthropic.analytics_cost",
		"anthropic.api_key",
		"anthropic.compliance_activity",
		"anthropic.compliance_group",
		"anthropic.compliance_group_member",
		"anthropic.compliance_organization",
		"anthropic.compliance_organization_setting",
		"anthropic.compliance_organization_user",
		"anthropic.compliance_project",
		"anthropic.compliance_project_collaborator",
		"anthropic.compliance_role",
		"anthropic.compliance_role_permission",
		"anthropic.cost_report",
		"anthropic.external_key",
		"anthropic.federation_issuer",
		"anthropic.federation_rule",
		"anthropic.invite",
		"anthropic.organization",
		"anthropic.rate_limit",
		"anthropic.service_account",
		"anthropic.spend_limit",
		"anthropic.spend_limit_increase_request",
		"anthropic.usage_report_claude_code",
		"anthropic.usage_report_message",
		"anthropic.user",
		"anthropic.workspace",
		"anthropic.workspace_member",
		"anthropic.workspace_rate_limit",
	},
	"apache": {
		"apache.eventlog",
		"apache.permission",
		"apache.role",
		"apache.user",
	},
	"apacta": {
		"apacta.activity",
		"apacta.city",
		"apacta.contact_person",
		"apacta.projects_user",
		"apacta.user",
	},
	"api2cart": {
		"api2cart.attribute_attributeset_list_json",
		"api2cart.attribute_group_list_json",
	},
	"apideck": {
		"apideck.bill",
		"apideck.credit_note",
		"apideck.customer",
		"apideck.ledger_account",
	},
	"apigee": {
		"apigee.api_proxies",
		"apigee.apps",
		"apigee.deployments",
		"apigee.developers",
		"apigee.organizations",
	},
	"apollo": {
		"apollo.accounts",
		"apollo.contacts",
		"apollo.users",
	},
	"appwrite": {
		"appwrite.continent",
		"appwrite.log",
		"appwrite.membership",
		"appwrite.team",
	},
	"authentik_cloud": {
		"authentik_cloud.applications",
		"authentik_cloud.audit_events",
		"authentik_cloud.groups",
		"authentik_cloud.roles",
		"authentik_cloud.users",
	},
	"aws_bedrock": {
		"aws_bedrock.custom_models",
		"aws_bedrock.foundation_models",
		"aws_bedrock.guardrails",
		"aws_bedrock.model_customization_jobs",
		"aws_bedrock.provisioned_model_throughputs",
	},
	"azure_openai": {
		"azure_openai.deployments",
		"azure_openai.model_catalog",
		"azure_openai.private_endpoint_connections",
		"azure_openai.rai_blocklists",
		"azure_openai.rai_policies",
	},
	"backstage": {
		"backstage.component",
		"backstage.system",
	},
	"beezup": {
		"beezup.alert",
		"beezup.autoimport",
		"beezup.beezupcolumn",
		"beezup.catalogcolumn",
		"beezup.category",
		"beezup.channelcatalog",
		"beezup.customcolumn",
		"beezup.filter",
		"beezup.filteroperator",
		"beezup.offer",
		"beezup.random",
		"beezup.rule",
	},
	"bitwarden": {
		"bitwarden.audit_events",
		"bitwarden.collections",
		"bitwarden.groups",
		"bitwarden.policies",
		"bitwarden.users",
	},
	"botify": {
		"botify.analyses",
		"botify.datamodel",
		"botify.domain",
		"botify.export",
		"botify.filter",
		"botify.orphan_url",
		"botify.out_of_config",
		"botify.percentile",
		"botify.project",
		"botify.report",
		"botify.sitemap_only",
		"botify.url",
	},
	"box": {
		"box.audit_events",
		"box.content_assets",
		"box.group_memberships",
		"box.groups",
		"box.users",
	},
	"cloudflare": {
		"cloudflare.access_application",
		"cloudflare.access_group",
		"cloudflare.account",
		"cloudflare.account_ruleset",
		"cloudflare.audit_log",
		"cloudflare.dns_record",
		"cloudflare.gateway_rule",
		"cloudflare.load_balancer",
		"cloudflare.load_balancer_pool",
		"cloudflare.member",
		"cloudflare.role",
		"cloudflare.worker_script",
		"cloudflare.zone",
		"cloudflare.zone_access_application",
		"cloudflare.zone_access_group",
		"cloudflare.zone_ruleset",
	},
	"cloudflare_workers_ai": {
		"cloudflare_workers_ai.ai_gateways",
		"cloudflare_workers_ai.gateway_evaluations",
		"cloudflare_workers_ai.gateway_logs",
		"cloudflare_workers_ai.gateway_provider_configs",
		"cloudflare_workers_ai.model_catalog",
		"cloudflare_workers_ai.vectorize_indexes",
	},
	"cloudflare_zero_trust": {
		"cloudflare_zero_trust.applications",
		"cloudflare_zero_trust.audit_events",
		"cloudflare_zero_trust.groups",
		"cloudflare_zero_trust.roles",
		"cloudflare_zero_trust.users",
	},
	"cohere": {
		"cohere.connectors",
		"cohere.datasets",
		"cohere.fine_tuned_models",
		"cohere.model_catalog",
	},
	"conjur": {
		"conjur.authenticator",
		"conjur.resource",
		"conjur.resource_2",
		"conjur.resource_3",
	},
	"datadog": {
		"datadog.audit_events",
		"datadog.dashboards",
		"datadog.incidents",
		"datadog.monitors",
		"datadog.roles",
		"datadog.slos",
		"datadog.teams",
		"datadog.users",
	},
	"deepseek": {
		"deepseek.account_balances",
		"deepseek.model_catalog",
	},
	"digitalocean": {
		"digitalocean.droplets",
		"digitalocean.firewalls",
		"digitalocean.vpcs",
	},
	"doppler": {
		"doppler.audit_events",
		"doppler.projects",
		"doppler.secrets",
	},
	"duo": {
		"duo.administrator",
		"duo.application",
		"duo.audit_event",
		"duo.authentication_log",
		"duo.endpoint",
		"duo.group",
		"duo.phone",
		"duo.role",
		"duo.token",
		"duo.user",
		"duo.web_authn_credential",
		"duo_security.applications",
		"duo_security.audit_events",
		"duo_security.groups",
		"duo_security.roles",
		"duo_security.users",
	},
	"elevenlabs": {
		"elevenlabs.auth_connections",
		"elevenlabs.model_catalog",
		"elevenlabs.service_account_api_keys",
		"elevenlabs.service_accounts",
		"elevenlabs.voices",
		"elevenlabs.webhooks",
	},
	"fivetran": {
		"fivetran.account_info",
		"fivetran.account_log_service",
		"fivetran.accounts",
		"fivetran.audit_events",
		"fivetran.connection_certificates",
		"fivetran.connection_fingerprints",
		"fivetran.connection_schemas",
		"fivetran.connection_state",
		"fivetran.connection_table_columns",
		"fivetran.connections",
		"fivetran.connector_metadata",
		"fivetran.connector_metadata_details",
		"fivetran.connector_sdk_packages",
		"fivetran.destination_certificates",
		"fivetran.destination_fingerprints",
		"fivetran.destinations",
		"fivetran.external_secret_manager_assignments",
		"fivetran.external_secret_manager_entities",
		"fivetran.external_secret_managers",
		"fivetran.group_connections",
		"fivetran.group_public_keys",
		"fivetran.group_service_accounts",
		"fivetran.group_users",
		"fivetran.groups",
		"fivetran.hybrid_deployment_agents",
		"fivetran.log_services",
		"fivetran.policies",
		"fivetran.private_links",
		"fivetran.proxy_agent_connections",
		"fivetran.proxy_agents",
		"fivetran.public_connector_types",
		"fivetran.records",
		"fivetran.roles",
		"fivetran.system_keys",
		"fivetran.team_connections",
		"fivetran.team_groups",
		"fivetran.team_users",
		"fivetran.teams",
		"fivetran.transformation_package_details",
		"fivetran.transformation_package_metadata",
		"fivetran.transformation_projects",
		"fivetran.transformations",
		"fivetran.user_connections",
		"fivetran.user_groups",
		"fivetran.users",
		"fivetran.webhooks",
	},
	"gitguardian": {
		"gitguardian.audit_events",
		"gitguardian.incidents",
		"gitguardian.members",
	},
	"gitlab": {
		"gitlab.audit_events",
		"gitlab.repositories",
		"gitlab.users",
	},
	"google_vertex_ai": {
		"google_vertex_ai.batch_prediction_jobs",
		"google_vertex_ai.custom_jobs",
		"google_vertex_ai.endpoints",
		"google_vertex_ai.indexes",
		"google_vertex_ai.models",
		"google_vertex_ai.reasoning_engines",
	},
	"hashicorp_vault": {
		"hashicorp_vault.audit_events",
		"hashicorp_vault.secrets",
		"hashicorp_vault.users",
	},
	"increase": {
		"increase.account",
		"increase.account_number",
		"increase.account_statement",
		"increase.account_transfer",
		"increase.ach_prenotification",
		"increase.ach_transfer",
		"increase.card",
		"increase.digital_wallet_token",
		"increase.event",
		"increase.event_subscription",
		"increase.external_account",
		"increase.oauth_connection",
	},
	"jira": {
		"jira.audit_events",
		"jira.group_members",
		"jira.groups",
		"jira.permission_schemes",
		"jira.project_roles",
		"jira.projects",
		"jira.users",
	},
	"jumpcloud": {
		"jumpcloud.applications",
		"jumpcloud.audit_events",
		"jumpcloud.group_members",
		"jumpcloud.groups",
		"jumpcloud.system_groups",
		"jumpcloud.systems",
		"jumpcloud.users",
	},
	"langchain": {
		"langchain.api_key",
		"langchain.audit_log",
		"langchain.dataset",
		"langchain.feedback",
		"langchain.organization",
		"langchain.organization_member",
		"langchain.project",
		"langchain.role",
		"langchain.run",
		"langchain.service_account",
		"langchain.usage_limit",
		"langchain.workspace",
		"langchain.workspace_member",
	},
	"mailchimp": {
		"mailchimp.audit_events",
		"mailchimp.lists",
		"mailchimp.members",
	},
	"mastodon": {
		"mastodon.account",
		"mastodon.activity",
		"mastodon.notification",
		"mastodon.verify_credential",
	},
	"meraki": {
		"meraki.accesspolicy",
		"meraki.eventtype",
		"meraki.merakiauthuser",
		"meraki.organization",
	},
	"microsoft_entra_id": {
		"microsoft_entra_id.audit_events",
		"microsoft_entra_id.groups",
		"microsoft_entra_id.users",
	},
	"new_relic": {
		"new_relic.assets",
		"new_relic.audit_events",
		"new_relic.findings",
	},
	"onelogin": {
		"onelogin.app_rules",
		"onelogin.app_users",
		"onelogin.apps",
		"onelogin.audit_events",
		"onelogin.delegated_privileges",
		"onelogin.groups",
		"onelogin.mappings",
		"onelogin.mfa_devices",
		"onelogin.privilege_roles",
		"onelogin.privilege_users",
		"onelogin.privileges",
		"onelogin.role_admins",
		"onelogin.role_apps",
		"onelogin.role_users",
		"onelogin.roles",
		"onelogin.user_apps",
		"onelogin.user_privileges",
		"onelogin.users",
	},
	"openai": {
		"openai.admin_api_key",
		"openai.api_key",
		"openai.audit_log",
		"openai.certificate",
		"openai.cost",
		"openai.data_retention",
		"openai.group",
		"openai.group_role",
		"openai.group_user",
		"openai.invite",
		"openai.project",
		"openai.project_api_key",
		"openai.project_certificate",
		"openai.project_data_retention",
		"openai.project_group",
		"openai.project_group_role",
		"openai.project_hosted_tool_permission",
		"openai.project_model_permission",
		"openai.project_rate_limit",
		"openai.project_role",
		"openai.project_service_account",
		"openai.project_spend_alert",
		"openai.project_user",
		"openai.project_user_role",
		"openai.role",
		"openai.service_account",
		"openai.spend_alert",
		"openai.usage_audio_speech",
		"openai.usage_audio_transcription",
		"openai.usage_code_interpreter_session",
		"openai.usage_completion",
		"openai.usage_embedding",
		"openai.usage_file_search_call",
		"openai.usage_image",
		"openai.usage_moderation",
		"openai.usage_vector_store",
		"openai.usage_web_search_call",
		"openai.user",
		"openai.user_role",
	},
	"qdrant_cloud": {
		"qdrant_cloud.account_members",
		"qdrant_cloud.accounts",
		"qdrant_cloud.backup_restores",
		"qdrant_cloud.backup_schedules",
		"qdrant_cloud.backups",
		"qdrant_cloud.clusters",
		"qdrant_cloud.database_api_keys",
		"qdrant_cloud.roles",
	},
	"sailpoint_identitynow": {
		"sailpoint_identitynow.access_profile_entitlements",
		"sailpoint_identitynow.access_profiles",
		"sailpoint_identitynow.access_request_status",
		"sailpoint_identitynow.account_activities",
		"sailpoint_identitynow.account_entitlements",
		"sailpoint_identitynow.accounts",
		"sailpoint_identitynow.campaigns",
		"sailpoint_identitynow.certification_access_review_items",
		"sailpoint_identitynow.certifications",
		"sailpoint_identitynow.entitlements",
		"sailpoint_identitynow.identities",
		"sailpoint_identitynow.identity_entitlements",
		"sailpoint_identitynow.identity_profiles",
		"sailpoint_identitynow.identity_role_assignments",
		"sailpoint_identitynow.lifecycle_states",
		"sailpoint_identitynow.personal_access_tokens",
		"sailpoint_identitynow.role_assigned_identities",
		"sailpoint_identitynow.role_dimensions",
		"sailpoint_identitynow.role_entitlements",
		"sailpoint_identitynow.roles",
		"sailpoint_identitynow.segments",
		"sailpoint_identitynow.source_health",
		"sailpoint_identitynow.source_provisioning_policies",
		"sailpoint_identitynow.source_schedules",
		"sailpoint_identitynow.source_schemas",
		"sailpoint_identitynow.sources",
		"sailpoint_identitynow.workgroup_members",
		"sailpoint_identitynow.workgroups",
	},
	"slack": {
		"slack.access_log",
		"slack.audit_log",
		"slack.channel",
		"slack.channel_member",
		"slack.team",
		"slack.user",
		"slack.user_group",
		"slack.user_group_member",
	},
	"snyk": {
		"snyk.asset_project_relationships",
		"snyk.asset_target_relationships",
		"snyk.assets",
		"snyk.audit_logs",
		"snyk.cloud_environments",
		"snyk.cloud_resources",
		"snyk.cloud_scans",
		"snyk.collections",
		"snyk.findings",
		"snyk.group_audit_logs",
		"snyk.group_memberships",
		"snyk.group_service_accounts",
		"snyk.groups",
		"snyk.org_memberships",
		"snyk.orgs",
		"snyk.projects",
		"snyk.service_accounts",
		"snyk.targets",
		"snyk.vulnerabilities",
	},
	"telnyx": {
		"telnyx.billing_group",
		"telnyx.call_control_application",
		"telnyx.call_event",
		"telnyx.credential_connection",
		"telnyx.detail_records_report",
		"telnyx.managed_account",
		"telnyx.notification_channel",
		"telnyx.notification_event",
		"telnyx.notification_event_condition",
		"telnyx.sim_card_group",
		"telnyx.sim_card_group_action",
		"telnyx.wireless_connectivity_log",
	},
	"twilio": {
		"twilio.accounts",
		"twilio.audit_events",
		"twilio.keys",
	},
}

// errRustProjectionRequired is the sentinel every Rust-authoritative refusal
// wraps, so callers and tests match with errors.Is rather than on message text.
var errRustProjectionRequired = errors.New("projection requires Rust authority")

func rustProjectionRequiredError(sourceID string) error {
	return fmt.Errorf("%s %w", sourceID, errRustProjectionRequired)
}

func rustProjectionRequired(sourceID string) ProjectFunc {
	err := rustProjectionRequiredError(sourceID)
	return func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, err
	}
}

// rustAuthoritativeSource reports whether a source ID is Rust-authoritative.
func rustAuthoritativeSource(sourceID string) bool {
	_, retired := rustAuthoritativeKinds[strings.TrimSpace(sourceID)]
	return retired
}

// rustAuthoritativeEventSource returns the Rust-authoritative source an event
// belongs to, or "" when Go still owns it. The event's own source ID wins; a
// projection replayed without one falls back to the source prefix of its kind.
func rustAuthoritativeEventSource(event *cerebrov1.EventEnvelope) string {
	if sourceID := strings.TrimSpace(event.GetSourceId()); sourceID != "" {
		if rustAuthoritativeSource(sourceID) {
			return sourceID
		}
		return ""
	}
	kind := strings.TrimSpace(event.GetKind())
	prefix, _, found := strings.Cut(kind, ".")
	if !found || !rustAuthoritativeSource(prefix) {
		return ""
	}
	return prefix
}

// registerRustAuthoritativeProjectors binds every Rust-authoritative kind to a
// fail-closed projector. It runs after the static and catalog-runtime tables so
// it also displaces the live generic projector registerCatalogRuntimeProjectors
// installs for a declared family with no static entry.
func registerRustAuthoritativeProjectors(projectors map[string]ProjectFunc) {
	if projectors == nil {
		return
	}
	for sourceID, kinds := range rustAuthoritativeKinds {
		failClosed := rustProjectionRequired(sourceID)
		for _, kind := range kinds {
			projectors[kind] = failClosed
		}
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		log.Printf("sourceprojection: load connector catalog for Rust-authoritative sources: %v", err)
		return
	}
	registerRustAuthoritativeCatalogFamilies(projectors, catalog.Entries)
}

// registerRustAuthoritativeCatalogFamilies covers resource families the
// connector catalog declares for a retired source beyond its emitted kinds.
func registerRustAuthoritativeCatalogFamilies(projectors map[string]ProjectFunc, entries []connectorcatalog.Entry) {
	if projectors == nil {
		return
	}
	for _, entry := range entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if !rustAuthoritativeSource(sourceID) {
			continue
		}
		failClosed := rustProjectionRequired(sourceID)
		for _, resource := range entry.Definition.ResourceFamilies {
			if kind := catalogRuntimeEventKind(sourceID, resource); kind != "" {
				projectors[kind] = failClosed
			}
		}
	}
}
