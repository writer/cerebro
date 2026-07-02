package zuora

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		name           string
		family         string
		path           string
		kind           string
		response       map[string]any
		wantAttributes map[string]string
		wantPayloadKey string
		wantOccurredAt string
	}{
		{
			name:   "event trigger",
			family: familyEventTrigger,
			path:   "/events/event-triggers",
			kind:   "zuora.event_trigger",
			response: map[string]any{"data": []map[string]any{{
				"id":          "ac1ee535e8524858a72edb464212729d",
				"baseObject":  "Invoice",
				"condition":   "changeType == 'UPDATE' && Invoice.Status == 'Posted'",
				"description": "Invoice posted event",
				"eventType": map[string]any{
					"name":        "InvoicePosted",
					"displayName": "Invoice Posted",
					"description": "An invoice moved to Posted status",
				},
				"active": true,
			}}},
			wantAttributes: map[string]string{"event_type": "InvoicePosted", "resource_type": "Invoice"},
			wantPayloadKey: "eventType",
		},
		{
			name:   "accounting code",
			family: familyAccountingCode,
			path:   "/v1/accounting-codes",
			kind:   "zuora.accounting_code",
			response: map[string]any{"accountingCodes": []map[string]any{{
				"id":              "8a8081ae547aac1e01547efb61f20140",
				"name":            "Subscription Revenue",
				"type":            "SalesRevenue",
				"category":        "Revenue",
				"status":          "Active",
				"glAccountName":   "Revenue",
				"glAccountNumber": "4000",
				"createdOn":       "2026-06-01T00:00:00Z",
				"updatedOn":       "2026-06-02T00:00:00Z",
			}}},
			wantAttributes: map[string]string{"name": "Subscription Revenue", "observed_at": "2026-06-02T00:00:00Z", "resource_type": "accounting_code", "status": "Active"},
			wantPayloadKey: "glAccountNumber",
		},
		{
			name:   "accounting period",
			family: familyAccountingPeriod,
			path:   "/v1/accounting-periods",
			kind:   "zuora.accounting_period",
			response: map[string]any{"accountingPeriods": []map[string]any{{
				"id":                    "8a8081ae5374904f0153833918af1007",
				"name":                  "Jun 2026",
				"startDate":             "2026-06-01",
				"endDate":               "2026-06-30",
				"status":                "Open",
				"fiscalYear":            2026,
				"fiscalQuarter":         2,
				"runTrialBalanceStatus": "Completed",
				"createdOn":             "2026-06-01T00:00:00Z",
				"updatedOn":             "2026-06-02T00:00:00Z",
			}}},
			wantAttributes: map[string]string{"name": "Jun 2026", "observed_at": "2026-06-02T00:00:00Z", "resource_type": "accounting_period", "status": "Open"},
			wantPayloadKey: "runTrialBalanceStatus",
		},
		{
			name:   "callout history",
			family: familyCallout,
			path:   "/v1/notification-history/callout",
			kind:   "zuora.callout",
			response: map[string]any{"calloutHistories": []map[string]any{{
				"attemptedNum":  3,
				"requestUrl":    "https://callback.example.test/zuora",
				"requestMethod": "POST",
				"responseCode":  405,
				"eventCategory": 1210,
				"notification":  "New Subscription Created",
				"createTime":    "2026-06-01T03:33:51",
			}}},
			wantAttributes: map[string]string{"alert_id": "3", "alert_name": "New Subscription Created", "alert_source": "https://callback.example.test/zuora", "alert_status": "405", "observed_at": "2026-06-01T03:33:51", "resource_id": "3", "resource_name": "New Subscription Created", "source_event_id": "3"},
			wantPayloadKey: "requestUrl",
			wantOccurredAt: "2026-06-01T03:33:51Z",
		},
		{
			name:   "email history",
			family: familyEmail,
			path:   "/v1/notification-history/email",
			kind:   "zuora.email",
			response: map[string]any{"emailHistories": []map[string]any{{
				"accountId":     "2c9e8084769a87be0176f0cfa138001e",
				"result":        "OK",
				"eventCategory": 1210,
				"notification":  "New Subscription Created",
				"subject":       "New subscription was created",
				"toEmail":       "billing@example.test",
				"fromEmail":     "no-reply@example.test",
				"cc":            "ops@example.test",
				"replyTo":       "support@example.test",
				"sendTime":      "2026-06-01T03:31:43",
				"errorMessage":  nil,
			}}},
			wantAttributes: map[string]string{"email": "billing@example.test", "name": "New subscription was created", "provider_id": "2c9e8084769a87be0176f0cfa138001e-2026-06-01T03:31:43-1210-New Subscription Created", "resource_id": "2c9e8084769a87be0176f0cfa138001e-2026-06-01T03:31:43-1210-New Subscription Created", "resource_name": "New subscription was created", "resource_type": "email_history"},
			wantPayloadKey: "toEmail",
			wantOccurredAt: "2026-06-01T03:31:43Z",
		},
		{
			name:   "email template",
			family: familyEmailTemplate,
			path:   "/notifications/email-templates",
			kind:   "zuora.email_template",
			response: map[string]any{"data": []map[string]any{{
				"id":             "6e569e1e05f040eda51a927b140c0ac2",
				"createdBy":      "6e569e1e05f040eda51a927b140c0ac3",
				"createdOn":      "2026-06-01T07:36:19.798Z",
				"updatedBy":      "6e569e1e05f040eda51a927b140c0ac4",
				"updatedOn":      "2026-06-02T07:36:19.798Z",
				"eventTypeName":  "AccountEdit",
				"name":           "Account Edit Email",
				"description":    "Email when an account is edited",
				"encodingType":   "UTF8",
				"fromName":       "Example Co.",
				"fromEmailType":  "TenantEmail",
				"toEmailType":    "SpecificEmails",
				"toEmailAddress": "billing@example.test",
				"emailSubject":   "Account <Account.Number> has been edited",
				"active":         true,
				"isHtml":         true,
			}}},
			wantAttributes: map[string]string{"name": "Account Edit Email", "observed_at": "2026-06-02T07:36:19.798Z", "resource_type": "email_template", "user_id": "6e569e1e05f040eda51a927b140c0ac2"},
			wantPayloadKey: "emailSubject",
			wantOccurredAt: "2026-06-02T07:36:19.798Z",
		},
		{
			name:   "hosted page",
			family: familyHostedpage,
			path:   "/v1/hostedpages",
			kind:   "zuora.hostedpage",
			response: map[string]any{"hostedpages": []map[string]any{{
				"pageId":      "8a85858f49a3f2230149a71083d40019",
				"pageType":    "Credit Card",
				"pageVersion": "2.0",
			}}},
			wantAttributes: map[string]string{"provider_id": "8a85858f49a3f2230149a71083d40019", "resource_id": "8a85858f49a3f2230149a71083d40019", "resource_type": "hostedpage", "resource_urn": "urn:cerebro:tenant:zuora_hostedpage:8a85858f49a3f2230149a71083d40019", "source_event_id": "8a85858f49a3f2230149a71083d40019"},
			wantPayloadKey: "pageType",
		},
		{
			name:   "notification definition",
			family: familyNotificationDefinition,
			path:   "/notifications/notification-definitions",
			kind:   "zuora.notification_definition",
			response: map[string]any{"data": []map[string]any{{
				"id":            "6e569e1e05f040eda51a927b140c0ac2",
				"createdBy":     "6e569e1e05f040eda51a927b140c0ac3",
				"createdOn":     "2026-06-01T07:36:19.798Z",
				"updatedBy":     "6e569e1e05f040eda51a927b140c0ac4",
				"updatedOn":     "2026-06-02T07:36:19.798Z",
				"eventTypeName": "AccountEdit",
				"name":          "Account Edit Email",
				"description":   "Email when an account is edited",
				"emailSubject":  "Account <Account.Number> has been edited",
				"active":        true,
				"isHtml":        true,
			}}},
			wantAttributes: map[string]string{"alert_id": "6e569e1e05f040eda51a927b140c0ac2", "alert_name": "Account Edit Email", "alert_status": "active", "observed_at": "2026-06-02T07:36:19.798Z", "provider_id": "6e569e1e05f040eda51a927b140c0ac2", "resource_type": "notification_definition"},
			wantPayloadKey: "emailSubject",
			wantOccurredAt: "2026-06-02T07:36:19.798Z",
		},
		{
			name:   "product",
			family: familyProduct,
			path:   "/v1/catalog/products",
			kind:   "zuora.product",
			response: map[string]any{"products": []map[string]any{{
				"id":                 "40289f466463d683016463ef8b7301a0",
				"name":               "Enterprise Plan",
				"sku":                "SKU-ENT",
				"productNumber":      "P-00000001",
				"category":           "Base Products",
				"description":        "Enterprise subscription plan",
				"effectiveStartDate": "2026-01-01",
				"effectiveEndDate":   "2026-12-31",
				"productRatePlans":   "/v1/rateplan/40289f466463d683016463ef8b7301a0/productRatePlan",
			}}},
			wantAttributes: map[string]string{"resource_id": "40289f466463d683016463ef8b7301a0", "resource_type": "product"},
			wantPayloadKey: "productRatePlans",
		},
		{
			name:   "revenue event",
			family: familyRevenueEvent,
			path:   "/v1/revenue-items/revenue-events/REV-EVT-0001",
			kind:   "zuora.revenue_event",
			response: map[string]any{"revenueItems": []map[string]any{{
				"accountingPeriodEndDate": "2026-06-30",
				"amount":                  1250.00,
				"currency":                "USD",
				"eventType":               "Revenue Distributed",
				"eventNumber":             "REV-EVT-0001",
				"subscriptionNumber":      "A-S00000003",
			}}},
			wantAttributes: map[string]string{"source_event_id": "REV-EVT-0001", "event_type": "Revenue Distributed", "resource_id": "REV-EVT-0001"},
			wantPayloadKey: "eventNumber",
		},
		{
			name:   "revenue schedule",
			family: familyRevenueSchedule,
			path:   "/v1/revenue-events/revenue-schedules/RS-0001",
			kind:   "zuora.revenue_schedule",
			response: map[string]any{"revenueEventDetails": []map[string]any{{
				"accountId":             "2c92c0f86c99b4eb016cae1ee301728f",
				"amount":                1250.00,
				"currency":              "USD",
				"eventType":             "Revenue Schedule Updated",
				"revenueScheduleNumber": "RS-0001",
				"subscriptionNumber":    "A-S00000003",
			}}},
			wantAttributes: map[string]string{"source_event_id": "RS-0001", "event_type": "Revenue Schedule Updated", "resource_id": "RS-0001"},
			wantPayloadKey: "revenueScheduleNumber",
		},
		{
			name:   "account payment method",
			family: familyAccount,
			path:   "/v1/accounts/A00000001/payment-methods",
			kind:   "zuora.account",
			response: map[string]any{
				"defaultPaymentMethodId": "4028839f7d26a155017d26af16ef0001",
				"paymentGateway":         "Default Gateway",
				"creditcard": []map[string]any{{
					"id":                  "4028839f7d26a155017d26af16ef0001",
					"type":                "CreditCard",
					"isDefault":           true,
					"accountKey":          "A00000001",
					"status":              "Active",
					"creditCardType":      "Visa",
					"cardNumber":          "************1111",
					"expirationMonth":     12,
					"expirationYear":      2028,
					"lastTransaction":     "Approved",
					"lastTransactionTime": "2026-06-01 00:01:53",
					"accountHolderInfo": map[string]any{
						"accountHolderName": "Example Billing",
						"email":             "billing@example.test",
						"country":           "United States",
					},
				}},
			},
			wantAttributes: map[string]string{"name": "Example Billing", "resource_type": "CreditCard"},
			wantPayloadKey: "accountHolderInfo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Fatalf("Authorization = %q, want Bearer test-token", got)
				}
				if got := r.Header.Get("Accept"); got != "application/json" {
					t.Fatalf("Accept = %q, want application/json", got)
				}
				switch r.URL.Path {
				case defaultHealthPath:
					writeJSON(t, w, eventTriggerListResponse())
				case tc.path:
					writeJSON(t, w, tc.response)
				default:
					t.Fatalf("path = %q, want %q or %q", r.URL.Path, defaultHealthPath, tc.path)
				}
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(testConfig(server.URL, tc.family))
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
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tc.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			for key, want := range tc.wantAttributes {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %q = %q, want %q; attrs=%#v", key, got, want, event.Attributes)
				}
			}
			if tc.wantOccurredAt != "" {
				want, err := time.Parse(time.RFC3339Nano, tc.wantOccurredAt)
				if err != nil {
					t.Fatalf("parse wantOccurredAt: %v", err)
				}
				if got := event.OccurredAt.AsTime(); !got.Equal(want) {
					t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
				}
			}
			if tc.family == familyCallout {
				if got := event.Attributes["alert_severity"]; got != "" {
					t.Fatalf("alert_severity = %q, want empty without provider severity", got)
				}
			}
			if tc.family == familyEmail {
				for _, surface := range []string{event.Id, event.Attributes["provider_id"], event.Attributes["resource_id"], event.Attributes["resource_urn"], event.Attributes["source_event_id"], event.Attributes["user_id"]} {
					if strings.Contains(surface, "audit@example.test") {
						t.Fatalf("email identifier surface leaks BCC address: %#v", event.Attributes)
					}
				}
			}
			if tc.family == familyNotificationDefinition {
				if got := event.Attributes["alert_severity"]; got != "" {
					t.Fatalf("alert_severity = %q, want empty without provider severity", got)
				}
			}
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("unmarshal payload: %v", err)
			}
			if tc.family == familyEmail {
				if _, ok := payload["bcc"]; ok {
					t.Fatalf("email payload includes optional BCC field; test should cover missing BCC: %#v", payload)
				}
			}
			if _, ok := payload[tc.wantPayloadKey]; !ok {
				t.Fatalf("payload missing %q: %#v", tc.wantPayloadKey, payload)
			}
			rawPayload := string(event.Payload)
			if strings.Contains(rawPayload, "Record One") || strings.Contains(rawPayload, `"api_path"`) {
				t.Fatalf("payload still contains generated fixture markers: %s", rawPayload)
			}
		})
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"reasons":[{"code":"SystemError","message":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(testConfig(server.URL, familyEventTrigger)), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := sourcecdk.SourceErrorKind(err); got != sourcecdk.ErrorKindProvider {
		t.Fatalf("Read() error kind = %q, want %q; err=%v", got, sourcecdk.ErrorKindProvider, err)
	}
	if got := err.Error(); !strings.Contains(got, "zuora API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	fixture, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyAccount,
		familyAccountingCode,
		familyAccountingPeriod,
		familyCallout,
		familyEmail,
		familyEmailTemplate,
		familyEventTrigger,
		familyHostedpage,
		familyNotificationDefinition,
		familyProduct,
		familyRevenueEvent,
		familyRevenueSchedule,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": family})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          fixture,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})

	for _, tc := range []struct {
		family         string
		kind           string
		wantURNPrefix  string
		wantPayloadKey string
	}{
		{family: familyAccount, kind: "zuora.account", wantURNPrefix: "urn:cerebro:tenant:zuora_account:", wantPayloadKey: "accountHolderInfo"},
		{family: familyAccountingCode, kind: "zuora.accounting_code", wantURNPrefix: "urn:cerebro:tenant:zuora_accounting_code:", wantPayloadKey: "glAccountNumber"},
		{family: familyAccountingPeriod, kind: "zuora.accounting_period", wantURNPrefix: "urn:cerebro:tenant:zuora_accounting_period:", wantPayloadKey: "runTrialBalanceStatus"},
		{family: familyCallout, kind: "zuora.callout", wantURNPrefix: "urn:cerebro:tenant:zuora_callout:", wantPayloadKey: "requestUrl"},
		{family: familyEmail, kind: "zuora.email", wantURNPrefix: "urn:cerebro:tenant:zuora_email:", wantPayloadKey: "toEmail"},
		{family: familyEmailTemplate, kind: "zuora.email_template", wantURNPrefix: "urn:cerebro:tenant:zuora_email_template:", wantPayloadKey: "emailSubject"},
		{family: familyEventTrigger, kind: "zuora.event_trigger", wantURNPrefix: "urn:cerebro:tenant:zuora_event_trigger:", wantPayloadKey: "eventType"},
		{family: familyHostedpage, kind: "zuora.hostedpage", wantURNPrefix: "urn:cerebro:tenant:zuora_hostedpage:", wantPayloadKey: "pageType"},
		{family: familyNotificationDefinition, kind: "zuora.notification_definition", wantURNPrefix: "urn:cerebro:tenant:zuora_notification_definition:", wantPayloadKey: "emailSubject"},
		{family: familyProduct, kind: "zuora.product", wantURNPrefix: "urn:cerebro:tenant:zuora_product:", wantPayloadKey: "productRatePlans"},
		{family: familyRevenueEvent, kind: "zuora.revenue_event", wantURNPrefix: "urn:cerebro:tenant:zuora_revenue_event:", wantPayloadKey: "eventNumber"},
		{family: familyRevenueSchedule, kind: "zuora.revenue_schedule", wantURNPrefix: "urn:cerebro:tenant:zuora_revenue_schedule:", wantPayloadKey: "revenueScheduleNumber"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			cfg := familyConfigs[tc.family]
			urns, err := fixture.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tc.family, err)
			}
			if len(urns) != 1 || !strings.HasPrefix(urns[0].String(), tc.wantURNPrefix) {
				t.Fatalf("fixture URNs = %#v, want prefix %q", urns, tc.wantURNPrefix)
			}
			pull, err := fixture.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tc.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("fixture events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("fixture kind = %q, want %q", event.Kind, tc.kind)
			}
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("unmarshal fixture payload: %v", err)
			}
			if _, ok := payload[tc.wantPayloadKey]; !ok {
				t.Fatalf("fixture payload missing %q: %#v", tc.wantPayloadKey, payload)
			}
			rawPayload := string(event.Payload)
			genericNameMarker := "Record" + " One"
			for _, marker := range []string{`"api_path"`, genericNameMarker, "source-zuora", " Fixture"} {
				if strings.Contains(rawPayload, marker) {
					t.Fatalf("fixture payload still contains generated marker %q: %s", marker, rawPayload)
				}
			}
		})
	}
}

func eventTriggerListResponse() map[string]any {
	return map[string]any{"data": []map[string]any{{
		"id":          "ac1ee535e8524858a72edb464212729d",
		"baseObject":  "Invoice",
		"condition":   "changeType == 'UPDATE' && Invoice.Status == 'Posted'",
		"description": "Invoice posted event",
		"eventType": map[string]any{
			"name":        "InvoicePosted",
			"displayName": "Invoice Posted",
			"description": "An invoice moved to Posted status",
		},
		"active": true,
	}}}
}

func testConfig(baseURL string, family string) map[string]string {
	return map[string]string{
		"tenant_id":    "tenant",
		"base_url":     baseURL,
		"family":       family,
		"token":        "test-token",
		"account_key":  "A00000001",
		"event_number": "REV-EVT-0001",
		"rs_number":    "RS-0001",
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
