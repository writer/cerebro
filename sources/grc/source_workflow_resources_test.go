package grc

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestReadWorkflowResourceFamiliesAsCanonicalGRCEvents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true

	cases := []struct {
		family string
		kind   string
		attrs  map[string]string
	}{
		{
			family: familyContract,
			kind:   "grc.contract",
			attrs: map[string]string{
				"contract_id":               "contract-1",
				"customer_trust_account_id": "account-1",
				"vendor_id":                 "vendor-1",
				"owner_id":                  "user-1",
				"control_ids":               "control-1,control-2",
				"evidence_id":               "evidence-1",
				"evidence_cas_uri":          "evidencecas://contracts/contract-1",
				"status":                    "ACTIVE",
				"contract_type":             "msa",
				"executed_at":               "2026-04-01T00:00:00Z",
			},
		},
		{
			family: familyDiscoveredVendor,
			kind:   "grc.discovered_vendor",
			attrs: map[string]string{
				"discovered_vendor_id": "discovered-vendor-1",
				"normalized_name":      "Acme",
				"ignored_reason":       "duplicate",
			},
		},
		{
			family: familyEventLog,
			kind:   "grc.event_log",
			attrs: map[string]string{
				"event_log_id": "event-log-1",
				"actor_id":     "user-1",
				"actor_type":   "user",
				"targets":      "vendor:vendor-1;control:control-1",
			},
		},
		{
			family: familyGroup,
			kind:   "grc.group",
			attrs: map[string]string{
				"group_id":   "group-1",
				"group_name": "Security",
			},
		},
		{
			family: familyVendorRiskAttribute,
			kind:   "grc.vendor_risk_attribute",
			attrs: map[string]string{
				"vendor_risk_attribute_id": "risk-attr-1",
				"risk_level":               "HIGH",
				"vendor_categories":        "ai,infrastructure",
			},
		},
		{
			family: familyVulnerabilityRemediation,
			kind:   "grc.vulnerability_remediation",
			attrs: map[string]string{
				"remediation_id":      "remediation-1",
				"vulnerability_id":    "vuln-1",
				"vulnerable_asset_id": "asset-1",
				"sla_deadline_at":     "2026-06-30T00:00:00Z",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), testConfig(server.URL, tc.family), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tc.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tc.family, len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("event.Kind = %q, want %s", event.Kind, tc.kind)
			}
			for key, want := range tc.attrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("event.Attributes[%q] = %q, want %q", key, got, want)
				}
			}
		})
	}
}
