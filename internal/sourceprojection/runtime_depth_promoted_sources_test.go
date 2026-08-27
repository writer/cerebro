package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// TestRuntimeDepthPromotedSourcesProjectMissingKinds covers sources whose Go
// projectors fall back to generic runtime-depth promotion for kinds without a
// dedicated profile. onelogin and sailpoint_identitynow used to have cases
// here; both became fully Rust-authoritative and their Go projection writers
// were retired (they now fail closed for every kind, so they no longer
// belong in this "still produces something despite missing kinds" list).
func TestRuntimeDepthPromotedSourcesProjectMissingKinds(t *testing.T) {
	tests := []struct {
		name  string
		event *cerebrov1.EventEnvelope
	}{
		{name: "auth0_connections", event: &cerebrov1.EventEnvelope{Id: "evt-auth0-connections", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.connections", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "auth0_guardian_factors", event: &cerebrov1.EventEnvelope{Id: "evt-auth0-guardian-factors", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.guardian_factors", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "auth0_organizations", event: &cerebrov1.EventEnvelope{Id: "evt-auth0-organizations", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organizations", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "auth0_user_roles", event: &cerebrov1.EventEnvelope{Id: "evt-auth0-user-roles", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.user_roles", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_bill", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-bill", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.bill", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_billpayment", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-billpayment", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.billpayment", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_company", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-company", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.company", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_contact", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-contact", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.contact", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_creditnote", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-creditnote", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.creditnote", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_currency", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-currency", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.currency", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_estimate", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-estimate", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.estimate", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_expense", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-expense", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.expense", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_userprofile", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-userprofile", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.userprofile", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "avaza_webhook", event: &cerebrov1.EventEnvelope{Id: "evt-avaza-webhook", TenantId: "tenant", SourceId: "avaza", Kind: "avaza.webhook", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "bigredcloud_bankaccount", event: &cerebrov1.EventEnvelope{Id: "evt-bigredcloud-bankaccount", TenantId: "tenant", SourceId: "bigredcloud", Kind: "bigredcloud.bankaccount", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "billingo_document_block", event: &cerebrov1.EventEnvelope{Id: "evt-billingo-document-block", TenantId: "tenant", SourceId: "billingo", Kind: "billingo.document_block", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "billingo_partner", event: &cerebrov1.EventEnvelope{Id: "evt-billingo-partner", TenantId: "tenant", SourceId: "billingo", Kind: "billingo.partner", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "callfire_call", event: &cerebrov1.EventEnvelope{Id: "evt-callfire-call", TenantId: "tenant", SourceId: "callfire", Kind: "callfire.call", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "fulfillment_com_return", event: &cerebrov1.EventEnvelope{Id: "evt-fulfillment-com-return", TenantId: "tenant", SourceId: "fulfillment_com", Kind: "fulfillment_com.return", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "fulfillment_com_track", event: &cerebrov1.EventEnvelope{Id: "evt-fulfillment-com-track", TenantId: "tenant", SourceId: "fulfillment_com", Kind: "fulfillment_com.track", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "hetzner_firewall", event: &cerebrov1.EventEnvelope{Id: "evt-hetzner-firewall", TenantId: "tenant", SourceId: "hetzner", Kind: "hetzner.firewall", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "hetzner_ssh_key", event: &cerebrov1.EventEnvelope{Id: "evt-hetzner-ssh-key", TenantId: "tenant", SourceId: "hetzner", Kind: "hetzner.ssh_key", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "journy_io_segments_account", event: &cerebrov1.EventEnvelope{Id: "evt-journy-io-segments-account", TenantId: "tenant", SourceId: "journy_io", Kind: "journy_io.segments_account", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "journy_io_segments_user", event: &cerebrov1.EventEnvelope{Id: "evt-journy-io-segments-user", TenantId: "tenant", SourceId: "journy_io", Kind: "journy_io.segments_user", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "journy_io_user", event: &cerebrov1.EventEnvelope{Id: "evt-journy-io-user", TenantId: "tenant", SourceId: "journy_io", Kind: "journy_io.user", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_checkout_custom_fields_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-checkout-custom-fields-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.checkout_custom_fields_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_countries_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-countries-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.countries_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_custom_fields_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-custom-fields-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.custom_fields_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_customer_categories_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-customer-categories-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.customer_categories_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_customers_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-customers-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.customers_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_fulfillments_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-fulfillments-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.fulfillments_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_jsapps_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-jsapps-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.jsapps_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_orders_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-orders-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.orders_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_pages_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-pages-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.pages_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_payment_methods_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-payment-methods-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.payment_methods_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "jumpseller_products_json", event: &cerebrov1.EventEnvelope{Id: "evt-jumpseller-products-json", TenantId: "tenant", SourceId: "jumpseller", Kind: "jumpseller.products_json", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "netlicensing_licensee", event: &cerebrov1.EventEnvelope{Id: "evt-netlicensing-licensee", TenantId: "tenant", SourceId: "netlicensing", Kind: "netlicensing.licensee", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "netlicensing_licensetemplate", event: &cerebrov1.EventEnvelope{Id: "evt-netlicensing-licensetemplate", TenantId: "tenant", SourceId: "netlicensing", Kind: "netlicensing.licensetemplate", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "neutrinoapi_bin_lookup", event: &cerebrov1.EventEnvelope{Id: "evt-neutrinoapi-bin-lookup", TenantId: "tenant", SourceId: "neutrinoapi", Kind: "neutrinoapi.bin_lookup", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "neutrinoapi_geocode_address", event: &cerebrov1.EventEnvelope{Id: "evt-neutrinoapi-geocode-address", TenantId: "tenant", SourceId: "neutrinoapi", Kind: "neutrinoapi.geocode_address", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "neutrinoapi_host_reputation", event: &cerebrov1.EventEnvelope{Id: "evt-neutrinoapi-host-reputation", TenantId: "tenant", SourceId: "neutrinoapi", Kind: "neutrinoapi.host_reputation", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "openfintech_country", event: &cerebrov1.EventEnvelope{Id: "evt-openfintech-country", TenantId: "tenant", SourceId: "openfintech", Kind: "openfintech.country", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "openfintech_currency", event: &cerebrov1.EventEnvelope{Id: "evt-openfintech-currency", TenantId: "tenant", SourceId: "openfintech", Kind: "openfintech.currency", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "stream_io_api_query_banned_user", event: &cerebrov1.EventEnvelope{Id: "evt-stream-io-api-query-banned-user", TenantId: "tenant", SourceId: "stream_io_api", Kind: "stream_io_api.query_banned_user", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "truora_check", event: &cerebrov1.EventEnvelope{Id: "evt-truora-check", TenantId: "tenant", SourceId: "truora", Kind: "truora.check", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "truora_config", event: &cerebrov1.EventEnvelope{Id: "evt-truora-config", TenantId: "tenant", SourceId: "truora", Kind: "truora.config", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "truora_report", event: &cerebrov1.EventEnvelope{Id: "evt-truora-report", TenantId: "tenant", SourceId: "truora", Kind: "truora.report", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "winsms_optout", event: &cerebrov1.EventEnvelope{Id: "evt-winsms-optout", TenantId: "tenant", SourceId: "winsms", Kind: "winsms.optout", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "winsms_sms_incoming", event: &cerebrov1.EventEnvelope{Id: "evt-winsms-sms-incoming", TenantId: "tenant", SourceId: "winsms", Kind: "winsms.sms_incoming", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_all", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-all", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.all", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_customer", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-customer", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.customer", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_customers_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-customers-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.customers_id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_id_2", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-id-2", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.id_2", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_invoices_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-invoices-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.invoices_id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_persons_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-persons-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.persons_id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_projects_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-projects-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.projects_id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_providers_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-providers-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.providers_id", Attributes: runtimeDepthPromotionAttributes()}},
		{name: "xtrf_eu_quotes_id", event: &cerebrov1.EventEnvelope{Id: "evt-xtrf-eu-quotes-id", TenantId: "tenant", SourceId: "xtrf_eu", Kind: "xtrf_eu.quotes_id", Attributes: runtimeDepthPromotionAttributes()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entities, links, err := BuiltinRegistry().Project(test.event)
			if err != nil {
				t.Fatalf("Project(%q) error = %v", test.event.GetKind(), err)
			}
			if len(entities) == 0 && len(links) == 0 {
				t.Fatalf("Project(%q) returned no graph records", test.event.GetKind())
			}
		})
	}
}

func runtimeDepthPromotionAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- static test fixture identifiers, not credentials.
		"account_id":         "account-1",
		"admin_id":           "admin-1",
		"actor_email":        "user@example.test",
		"actor_id":           "user-1",
		"api_id":             "api-1",
		"api_identifier":     "https://api.example.test",
		"api_name":           "Example API",
		"app_id":             "app-1",
		"app_name":           "Example App",
		"application_id":     "app-1",
		"authentication_id":  "auth-1",
		"audience":           "https://api.example.test",
		"certification_id":   "certification-1",
		"certification_name": "Access Review",
		"client_id":          "client-1",
		"connection_id":      "connection-1",
		"connection_name":    "Database",
		"credential_id":      "credential-1",
		"display_name":       "User One",
		"email":              "user@example.test",
		"entitlement_id":     "entitlement-1",
		"entitlement_name":   "Payroll Admin",
		"entitlement_value":  "payroll-admin",
		"endpoint_id":        "endpoint-1",
		"event_type":         "user.login",
		"external_id":        "resource-1",
		"factor_id":          "factor-1",
		"group_email":        "group@example.test",
		"group_id":           "group-1",
		"group_name":         "Group One",
		"id":                 "resource-1",
		"identity_id":        "identity-1",
		"identity_name":      "User One",
		"integration_key":    "DIAPP1",
		"member_email":       "user@example.test",
		"member_name":        "User One",
		"member_user_id":     "user-1",
		"name":               "Resource One",
		"organization_id":    "org-1",
		"organization_name":  "Organization One",
		"phone_id":           "phone-1",
		"policy_id":          "policy-1",
		"policy_name":        "Policy One",
		"policy_status":      "enabled",
		"policy_type":        "access",
		"resource_id":        "resource-1",
		"resource_name":      "Resource One",
		"resource_type":      "application",
		"review_item_id":     "review-item-1",
		"role_id":            "role-1",
		"role_name":          "Role One",
		"scope":              "read:reports",
		"source_id":          "source-1",
		"source_name":        "Source One",
		"subject_email":      "user@example.test",
		"subject_id":         "user-1",
		"subject_name":       "User One",
		"subject_type":       "user",
		"token_id":           "token-1",
		"type":               "application",
		"user_id":            "user-1",
	}
}
