package grc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGRCFamilyDescriptorsAreComplete(t *testing.T) {
	if len(grcFamilyDescriptors) == 0 {
		t.Fatal("grcFamilyDescriptors is empty")
	}
	seenFamilies := map[grcFamily]struct{}{}
	seenEndpoints := map[string]grcFamily{}
	for _, descriptor := range grcFamilyDescriptors {
		t.Run(string(descriptor.Family), func(t *testing.T) {
			if descriptor.Family == "" {
				t.Fatal("Family is empty")
			}
			if strings.TrimSpace(descriptor.Endpoint) == "" {
				t.Fatal("Endpoint is empty")
			}
			if !strings.HasPrefix(descriptor.Endpoint, "/v1/") {
				t.Fatalf("Endpoint = %q, want /v1/ path", descriptor.Endpoint)
			}
			if len(descriptor.IDKeys) == 0 {
				t.Fatal("IDKeys is empty")
			}
			for _, key := range descriptor.IDKeys {
				if strings.TrimSpace(key) == "" {
					t.Fatalf("IDKeys contains empty key: %#v", descriptor.IDKeys)
				}
			}
			if len(descriptor.AttributePairs) == 0 && !hasCustomAttributeMapping(descriptor.Family) {
				t.Fatal("AttributePairs is empty")
			}
			if len(descriptor.AttributePairs)%2 != 0 {
				t.Fatalf("AttributePairs has odd length %d", len(descriptor.AttributePairs))
			}
			for i := 0; i+1 < len(descriptor.AttributePairs); i += 2 {
				if strings.TrimSpace(descriptor.AttributePairs[i]) == "" || strings.TrimSpace(descriptor.AttributePairs[i+1]) == "" {
					t.Fatalf("AttributePairs contains empty pair at %d: %#v", i, descriptor.AttributePairs[i:i+2])
				}
			}
			lookedUp := grcDescriptorFor(descriptor.Family)
			if lookedUp.Endpoint != descriptor.Endpoint {
				t.Fatalf("grcDescriptorFor(%q).Endpoint = %q, want %q", descriptor.Family, lookedUp.Endpoint, descriptor.Endpoint)
			}
			if !isSupportedFamily(descriptor.Family) {
				t.Fatalf("isSupportedFamily(%q) = false", descriptor.Family)
			}
		})
		if _, ok := seenFamilies[descriptor.Family]; ok {
			t.Fatalf("duplicate family descriptor %q", descriptor.Family)
		}
		seenFamilies[descriptor.Family] = struct{}{}
		if owner, ok := seenEndpoints[descriptor.Endpoint]; ok {
			t.Fatalf("endpoint %q is shared by %q and %q", descriptor.Endpoint, owner, descriptor.Family)
		}
		seenEndpoints[descriptor.Endpoint] = descriptor.Family
	}

	families := supportedFamilies()
	if len(families) != len(grcFamilyDescriptors) {
		t.Fatalf("supportedFamilies() has %d entries, want %d", len(families), len(grcFamilyDescriptors))
	}
}

func hasCustomAttributeMapping(family grcFamily) bool {
	return family == familyVulnerableAsset
}

func TestGRCFamilyDescriptorsCoverPlatformDomains(t *testing.T) {
	required := []grcFamily{
		familyFramework,
		familyControl,
		familyControlTest,
		familyPolicy,
		familyDocument,
		familyContract,
		familyRegulatoryNotification,
		familyRecoveryObjective,
		familyAuthorizationPackage,
		familyPOAMItem,
		familyTrainingAttestation,
		familyVendor,
		familyDiscoveredVendor,
		familyVendorRiskAttribute,
		familyEventLog,
		familyGroup,
		familyVulnerability,
		familyVulnerabilityRemediation,
		familyVulnerableAsset,
		familyMonitoredComputer,
		familyRiskScenario,
		familyPerson,
		familyUser,
		familyIntegration,
	}
	for _, family := range required {
		descriptor := grcDescriptorFor(family)
		if descriptor.Endpoint == "" {
			t.Fatalf("family %q missing descriptor endpoint", family)
		}
	}
}

func TestGRCFamilyDescriptorsDriveRecordIDsAndOccurrenceTimes(t *testing.T) {
	idCases := map[grcFamily]struct {
		values map[string]any
		want   string
	}{
		familyRiskScenario:           {values: map[string]any{"riskId": "risk/1"}, want: "risk_1"},
		familyIntegration:            {values: map[string]any{"integrationId": "asset scanner"}, want: "asset_scanner"},
		familyVulnerableAsset:        {values: map[string]any{"assetId": "asset/1"}, want: "asset_1"},
		familyMonitoredComputer:      {values: map[string]any{"serialNumber": "SN 123"}, want: "SN_123"},
		familyRegulatoryNotification: {values: map[string]any{"notificationId": "notice/1"}, want: "notice_1"},
		familyPerson:                 {values: map[string]any{"emailAddress": "owner@example.com"}, want: "owner@example.com"},
	}
	for family, tt := range idCases {
		t.Run(string(family), func(t *testing.T) {
			got := recordID(family, tt.values, json.RawMessage(`{"fallback":true}`))
			if got != tt.want {
				t.Fatalf("recordID() = %q, want %q", got, tt.want)
			}
		})
	}

	timeCases := map[grcFamily]struct {
		values map[string]any
		want   time.Time
	}{
		familyRecoveryObjective: {values: map[string]any{"reviewedAt": "2026-05-01T00:00:00Z"}, want: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
		familyPerson:            {values: map[string]any{"employment": map[string]any{"startDate": "2026-01-15T00:00:00Z"}}, want: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
		familyPOAMItem:          {values: map[string]any{"openedAt": "2026-04-20T00:00:00Z"}, want: time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)},
	}
	for family, tt := range timeCases {
		t.Run(string(family), func(t *testing.T) {
			got := occurredAtFor(family, tt.values)
			if !got.Equal(tt.want) {
				t.Fatalf("occurredAtFor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGRCFamilyDescriptorsDriveCanonicalAttributes(t *testing.T) {
	record := grcRecord{
		ID: "contract-1",
		Values: map[string]any{
			"id":             "contract-1",
			"name":           "Core service agreement",
			"vendorId":       "vendor-1",
			"controlIds":     []any{"cc-1", "cc-2"},
			"evidenceCasUri": "evidencecas://contracts/contract-1",
			"status":         "ACTIVE",
			"executedDate":   "2026-04-01T00:00:00Z",
		},
	}
	attrs := attributesFor(settings{provider: defaultProvider, tenantID: "writer"}, familyContract, record)
	for key, want := range map[string]string{
		"contract_id":      "contract-1",
		"name":             "Core service agreement",
		"vendor_id":        "vendor-1",
		"control_ids":      "cc-1,cc-2",
		"evidence_cas_uri": "evidencecas://contracts/contract-1",
		"status":           "ACTIVE",
		"executed_at":      "2026-04-01T00:00:00Z",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("attrs[%q] = %q, want %q", key, got, want)
		}
	}
}
