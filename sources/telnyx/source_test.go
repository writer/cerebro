package telnyx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	testSIMCardID      = "00000000-0000-4000-8000-000000000010"
	testSIMCardGroupID = "00000000-0000-4000-8000-000000000011"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != sourceID {
		t.Fatalf("Spec().Id = %q, want %s", got, sourceID)
	}
}

func TestSourceCheckAndRead(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireTelnyxAuth(t, r)
		if r.URL.Path != "/call_events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"data": []map[string]any{callEventRecord()}})
	}))
	defer server.Close()

	cfg := testConfig(server.URL, defaultFamily)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "telnyx.call_event" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["event_type"]; got != "call.hangup" {
		t.Fatalf("event_type = %q, want call.hangup", got)
	}
}

func TestCallEventsDoNotDedupeSameCallLeg(t *testing.T) {
	source := newTestSource(t)
	first := callEventRecord()
	second := callEventRecord()
	second["event_timestamp"] = "2019-03-29T11:11:19.127783Z"
	second["name"] = "call.answered"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireTelnyxAuth(t, r)
		if r.URL.Path != "/call_events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"data": []map[string]any{first, second}})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), testConfig(server.URL, familyCallEvent), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(pull.Events))
	}
	gotTypes := map[string]bool{}
	for _, event := range pull.Events {
		gotTypes[event.Attributes["event_type"]] = true
	}
	for _, want := range []string{"call.hangup", "call.answered"} {
		if !gotTypes[want] {
			t.Fatalf("missing event_type %q from %#v", want, gotTypes)
		}
	}
}

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		family     string
		path       string
		body       map[string]any
		kind       string
		attr       string
		want       string
		externalID string
	}{
		{family: familyBillingGroup, path: "/billing_groups", body: listBody(billingGroupRecord()), kind: "telnyx.billing_group", attr: "group_id", want: "00000000-0000-4000-8000-000000000001", externalID: "00000000-0000-4000-8000-000000000001"},
		{family: familyCallControlApplication, path: "/call_control_applications", body: listBody(callControlApplicationRecord()), kind: "telnyx.call_control_application", attr: "policy_name", want: "Emergency routing", externalID: "1293384261075731499"},
		{family: familyCallEvent, path: "/call_events", body: listBody(callEventRecord()), kind: "telnyx.call_event", attr: "event_type", want: "call.hangup", externalID: "2019-03-29T11:10:19.127783Z"},
		{family: familyCredentialConnection, path: "/credential_connections", body: listBody(credentialConnectionRecord()), kind: "telnyx.credential_connection", attr: "secret_name", want: "sip-edge-primary", externalID: "1293384261075731500"},
		{family: familyDetailRecordsReport, path: "/wireless/detail_records_reports", body: listBody(detailRecordsReportRecord()), kind: "telnyx.detail_records_report", attr: "resource_type", want: "detail_records_report", externalID: "00000000-0000-4000-8000-000000000003"},
		{family: familyManagedAccount, path: "/managed_accounts", body: listBody(managedAccountRecord()), kind: "telnyx.managed_account", attr: "email", want: "managed-account@example.com", externalID: "00000000-0000-4000-8000-000000000004"},
		{family: familyNotificationChannel, path: "/notification_channels", body: listBody(notificationChannelRecord()), kind: "telnyx.notification_channel", attr: "alert_type", want: "webhook", externalID: "00000000-0000-4000-8000-000000000005"},
		{family: familyNotificationEvent, path: "/notification_events", body: listBody(notificationEventRecord()), kind: "telnyx.notification_event", attr: "event_type", want: "Emergency Number Dialed", externalID: "00000000-0000-4000-8000-000000000006"},
		{family: familyNotificationEventCondition, path: "/notification_event_conditions", body: listBody(notificationEventConditionRecord()), kind: "telnyx.notification_event_condition", attr: "event_type", want: "from phone number", externalID: "00000000-0000-4000-8000-000000000007"},
		{family: familySimCardGroup, path: "/sim_card_groups", body: listBody(simCardGroupRecord()), kind: "telnyx.sim_card_group", attr: "group_id", want: testSIMCardGroupID, externalID: testSIMCardGroupID},
		{family: familySimCardGroupAction, path: "/sim_card_group_actions", body: listBody(simCardGroupActionRecord()), kind: "telnyx.sim_card_group_action", attr: "group_id", want: testSIMCardGroupID, externalID: "00000000-0000-4000-8000-000000000008"},
		{family: familyWirelessConnectivityLog, path: "/sim_cards/" + testSIMCardID + "/wireless_connectivity_logs", body: listBody(wirelessConnectivityLogRecord()), kind: "telnyx.wireless_connectivity_log", attr: "event_type", want: "registration", externalID: "137509451"},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source := newTestSource(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireTelnyxAuth(t, r)
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("path = %q, want %q", got, tt.path)
				}
				if got := r.URL.Query().Get("page[size]"); got != "100" {
					t.Fatalf("page[size] = %q, want 100", got)
				}
				writeJSON(t, w, tt.body)
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), testConfig(server.URL, tt.family), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
			if got := event.Attributes["external_id"]; got != tt.externalID {
				t.Fatalf("external_id = %q, want %q", got, tt.externalID)
			}
			switch tt.family {
			case familyCallControlApplication:
				if got := event.Attributes["policy_status"]; got != "active" {
					t.Fatalf("policy_status = %q, want active", got)
				}
			case familyCredentialConnection:
				if got := event.Attributes["secret_status"]; got != "active" {
					t.Fatalf("secret_status = %q, want active", got)
				}
			case familyBillingGroup:
				if got := event.Attributes["resource_type"]; got != "billing_group" {
					t.Fatalf("resource_type = %q, want billing_group", got)
				}
				if got := event.Attributes["resource_id"]; got != "00000000-0000-4000-8000-000000000001" {
					t.Fatalf("resource_id = %q, want billing group id", got)
				}
			case familyNotificationChannel:
				if got := event.Attributes["alert_status"]; got != "" {
					t.Fatalf("alert_status = %q, want empty without provider status", got)
				}
				if got := event.Attributes["alert_severity"]; got != "" {
					t.Fatalf("alert_severity = %q, want empty without provider severity", got)
				}
				if got := event.Attributes["resource_type"]; got != "notification_channel" {
					t.Fatalf("resource_type = %q, want notification_channel", got)
				}
			case familyNotificationEvent:
				if got := event.Attributes["resource_type"]; got != "notification_event" {
					t.Fatalf("resource_type = %q, want notification_event", got)
				}
			case familyNotificationEventCondition:
				if got := event.Attributes["resource_type"]; got != "notification_event_condition" {
					t.Fatalf("resource_type = %q, want notification_event_condition", got)
				}
			case familySimCardGroup:
				if got := event.Attributes["resource_type"]; got != "sim_card_group" {
					t.Fatalf("resource_type = %q, want sim_card_group", got)
				}
				if got := event.Attributes["resource_id"]; got != testSIMCardGroupID {
					t.Fatalf("resource_id = %q, want SIM card group id", got)
				}
			case familyWirelessConnectivityLog:
				if got := event.Attributes["resource_id"]; got != "137509451" {
					t.Fatalf("resource_id = %q, want wireless log id", got)
				}
				if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:telnyx_wireless_connectivity_log:137509451" {
					t.Fatalf("resource_urn = %q, want wireless log URN", got)
				}
			}
			if got := event.Attributes["tenant_id"]; got != "tenant" {
				t.Fatalf("tenant_id = %q, want tenant", got)
			}
			if got := event.Attributes["resource_urn"]; strings.TrimSpace(got) == "" {
				t.Fatalf("resource_urn is empty: %#v", event.Attributes)
			}
		})
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"detail":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := source.Read(context.Background(), testConfig(server.URL, familyBillingGroup), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Read() error = %v, want HTTP 503", err)
	}
	if got := err.Error(); !strings.Contains(got, "telnyx API returned 503") {
		t.Fatalf("Read() error = %q, want Telnyx status", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyBillingGroup,
		familyCallControlApplication,
		familyCallEvent,
		familyCredentialConnection,
		familyDetailRecordsReport,
		familyManagedAccount,
		familyNotificationChannel,
		familyNotificationEvent,
		familyNotificationEventCondition,
		familySimCardGroup,
		familySimCardGroupAction,
		familyWirelessConnectivityLog,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":      family,
			"tenant_id":   "tenant",
			"sim_card_id": testSIMCardID,
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyBillingGroup, kind: "telnyx.billing_group", attr: "group_id", want: "00000000-0000-4000-8000-000000000001"},
		{family: familyCallControlApplication, kind: "telnyx.call_control_application", attr: "policy_name", want: "Emergency routing"},
		{family: familyCallEvent, kind: "telnyx.call_event", attr: "event_type", want: "call.hangup"},
		{family: familyCredentialConnection, kind: "telnyx.credential_connection", attr: "secret_name", want: "sip-edge-primary"},
		{family: familyDetailRecordsReport, kind: "telnyx.detail_records_report", attr: "resource_type", want: "detail_records_report"},
		{family: familyManagedAccount, kind: "telnyx.managed_account", attr: "email", want: "managed-account@example.com"},
		{family: familyNotificationChannel, kind: "telnyx.notification_channel", attr: "alert_type", want: "webhook"},
		{family: familyNotificationEvent, kind: "telnyx.notification_event", attr: "event_type", want: "Emergency Number Dialed"},
		{family: familyNotificationEventCondition, kind: "telnyx.notification_event_condition", attr: "event_type", want: "from phone number"},
		{family: familySimCardGroup, kind: "telnyx.sim_card_group", attr: "group_id", want: testSIMCardGroupID},
		{family: familySimCardGroupAction, kind: "telnyx.sim_card_group_action", attr: "group_id", want: testSIMCardGroupID},
		{family: familyWirelessConnectivityLog, kind: "telnyx.wireless_connectivity_log", attr: "event_type", want: "registration"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if got := event.Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func newTestSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func testConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"tenant_id":   "tenant",
		"base_url":    baseURL,
		"family":      family,
		"token":       "test-token",
		"sim_card_id": testSIMCardID,
		"per_page":    "100",
	})
}

func requireTelnyxAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want Bearer test-token", got)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func listBody(record map[string]any) map[string]any {
	return map[string]any{
		"data": []map[string]any{record},
		"meta": map[string]any{"page_number": 1, "page_size": 100, "total_pages": 1, "total_results": 1},
	}
}

func billingGroupRecord() map[string]any {
	return map[string]any{
		"created_at":      "2019-10-15T10:07:15.527Z",
		"deleted_at":      nil,
		"id":              "00000000-0000-4000-8000-000000000001",
		"name":            "Primary billing",
		"organization_id": "00000000-0000-4000-8000-000000000101",
		"record_type":     "billing_group",
		"updated_at":      "2019-10-15T10:07:15.527Z",
	}
}

func callControlApplicationRecord() map[string]any {
	return map[string]any{
		"active":                     true,
		"application_name":           "Emergency routing",
		"created_at":                 "2018-02-02T22:25:27.521Z",
		"id":                         "1293384261075731499",
		"inbound":                    map[string]any{"channel_limit": 10, "shaken_stir_enabled": true, "sip_subdomain": "example", "sip_subdomain_receive_settings": "only_my_connections"},
		"outbound":                   map[string]any{"channel_limit": 10, "outbound_voice_profile_id": "1293384261075731499"},
		"record_type":                "call_control_application",
		"updated_at":                 "2018-02-02T22:25:27.521Z",
		"webhook_api_version":        "2",
		"webhook_event_failover_url": "https://failover.example.com/telnyx/events",
		"webhook_event_url":          "https://example.com/telnyx/events",
		"webhook_timeout_secs":       25,
	}
}

func callEventRecord() map[string]any {
	return map[string]any{
		"call_leg_id":     "00000000-0000-4000-8000-000000000002",
		"call_session_id": "00000000-0000-4000-8000-000000000102",
		"event_timestamp": "2019-03-29T11:10:19.127783Z",
		"metadata":        map[string]any{"direction": "inbound"},
		"name":            "call.hangup",
		"record_type":     "call_event",
		"type":            "webhook",
	}
}

func credentialConnectionRecord() map[string]any {
	return map[string]any{
		"active":                     true,
		"connection_name":            "sip-edge-primary",
		"created_at":                 "2018-02-02T22:25:27.521Z",
		"dtmf_type":                  "RFC 2833",
		"id":                         "1293384261075731500",
		"inbound":                    map[string]any{"channel_limit": 10, "codecs": []string{"G722"}, "shaken_stir_enabled": true},
		"outbound":                   map[string]any{"channel_limit": 10, "outbound_voice_profile_id": "1293384261075731499"},
		"record_type":                "credential_connection",
		"sip_uri_calling_preference": "disabled",
		"tags":                       []string{"voice", "primary"},
		"updated_at":                 "2018-02-02T22:25:27.521Z",
		"user_name":                  "sipedgeprimary",
		"webhook_api_version":        "2",
		"webhook_event_url":          "https://example.com/telnyx/credential-events",
	}
}

func detailRecordsReportRecord() map[string]any {
	return map[string]any{
		"created_at":  "2018-02-02T22:25:27.521Z",
		"end_time":    "2018-02-03T00:00:00.000Z",
		"id":          "00000000-0000-4000-8000-000000000003",
		"record_type": "detail_records_report",
		"report_url":  "https://example.com/telnyx/wdr-report.csv",
		"start_time":  "2018-02-02T00:00:00.000Z",
		"status":      "complete",
		"updated_at":  "2018-02-02T22:25:27.521Z",
	}
}

func managedAccountRecord() map[string]any {
	return map[string]any{
		"api_user":                             "managed-account@example.com",
		"created_at":                           "2018-02-02T22:25:27.521Z",
		"email":                                "managed-account@example.com",
		"id":                                   "00000000-0000-4000-8000-000000000004",
		"managed_account_allow_custom_pricing": true,
		"manager_account_id":                   "00000000-0000-4000-8000-000000000104",
		"organization_name":                    "Example Managed Account",
		"record_type":                          "managed_account",
		"rollup_billing":                       false,
		"updated_at":                           "2018-02-02T22:25:27.521Z",
	}
}

func notificationChannelRecord() map[string]any {
	return map[string]any{
		"channel_destination":     "https://example.com/telnyx/notifications",
		"channel_type_id":         "webhook",
		"created_at":              "2019-10-15T10:07:15.527Z",
		"id":                      "00000000-0000-4000-8000-000000000005",
		"notification_profile_id": "00000000-0000-4000-8000-000000000105",
		"updated_at":              "2019-10-15T10:07:15.527Z",
	}
}

func notificationEventRecord() map[string]any {
	return map[string]any{
		"created_at":            "2019-10-15T10:07:15.527Z",
		"enabled":               true,
		"id":                    "00000000-0000-4000-8000-000000000006",
		"name":                  "Emergency Number Dialed",
		"notification_category": "Calls",
		"updated_at":            "2019-10-15T10:07:15.527Z",
	}
}

func notificationEventConditionRecord() map[string]any {
	return map[string]any{
		"allow_multiple_channels": false,
		"associated_record_type":  "phone_number",
		"asynchronous":            true,
		"created_at":              "2019-10-15T10:07:15.527Z",
		"description":             "When emergency number dialed from phone number",
		"enabled":                 true,
		"id":                      "00000000-0000-4000-8000-000000000007",
		"name":                    "from phone number",
		"notification_event_id":   "00000000-0000-4000-8000-000000000006",
		"parameters":              []map[string]any{{"data_type": "string", "name": "phone_number", "optional": false}},
		"supported_channels":      []string{"webhook", "sms", "email", "voice"},
		"updated_at":              "2019-10-15T10:07:15.527Z",
	}
}

func simCardGroupRecord() map[string]any {
	return map[string]any{
		"consumed_data":               map[string]any{"amount": "1024.5", "unit": "MB"},
		"created_at":                  "2018-02-02T22:25:27.521Z",
		"data_limit":                  map[string]any{"amount": "2048.1", "unit": "MB"},
		"default":                     false,
		"id":                          testSIMCardGroupID,
		"name":                        "IoT field devices",
		"private_wireless_gateway_id": "00000000-0000-4000-8000-000000000201",
		"record_type":                 "sim_card_group",
		"updated_at":                  "2018-02-02T22:25:27.521Z",
		"wireless_blocklist_id":       "00000000-0000-4000-8000-000000000202",
	}
}

func simCardGroupActionRecord() map[string]any {
	return map[string]any{
		"created_at":        "2018-02-02T22:25:27.521Z",
		"id":                "00000000-0000-4000-8000-000000000008",
		"record_type":       "sim_card_group_action",
		"settings":          map[string]any{"private_wireless_gateway_id": "00000000-0000-4000-8000-000000000201"},
		"sim_card_group_id": testSIMCardGroupID,
		"status":            "completed",
		"type":              "set_private_wireless_gateway",
		"updated_at":        "2018-02-02T22:25:27.521Z",
	}
}

func wirelessConnectivityLogRecord() map[string]any {
	return map[string]any{
		"apn":                     "data00.telnyx",
		"cell_id":                 "311210-6813",
		"created_at":              "2018-02-02T22:25:27.521Z",
		"id":                      137509451,
		"imei":                    "490154203237518",
		"imsi":                    "001010123456789",
		"ipv4":                    "192.0.2.10",
		"ipv6":                    "2001:db8::10",
		"last_seen":               "2018-02-02T22:25:27.521Z",
		"log_type":                "registration",
		"mobile_country_code":     "310",
		"mobile_network_code":     "410",
		"radio_access_technology": "LTE",
		"record_type":             "wireless_connectivity_log",
		"sim_card_id":             testSIMCardID,
		"start_time":              "2018-02-02T22:20:27.521Z",
		"state":                   "provisioned",
		"stop_time":               "2018-02-02T22:25:27.521Z",
	}
}
