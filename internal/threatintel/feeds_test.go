package threatintel

import (
	"context"
	"testing"
)

func TestThreatIntelService_DefaultFeeds(t *testing.T) {
	svc := NewThreatIntelService()
	feeds := svc.ListFeeds()

	if len(feeds) == 0 {
		t.Error("expected default feeds to be loaded")
	}

	// Check for expected feeds
	feedIDs := make(map[string]bool)
	for _, f := range feeds {
		feedIDs[f.ID] = true
	}

	expectedFeeds := []string{"cisa-kev", "nvd-cve", "abuse-ch-ip", "abuse-ch-domains"}
	for _, id := range expectedFeeds {
		if !feedIDs[id] {
			t.Errorf("expected feed %s to be loaded", id)
		}
	}
}

func TestThreatIntelService_Stats(t *testing.T) {
	svc := NewThreatIntelService()
	stats := svc.Stats()

	if stats == nil {
		t.Error("stats should not be nil")
	}

	if _, ok := stats["feeds_count"]; !ok {
		t.Error("stats should contain feeds_count")
	}

	if _, ok := stats["total_indicators"]; !ok {
		t.Error("stats should contain total_indicators")
	}
}

func TestIndicatorStore_AddAndLookup(t *testing.T) {
	store := NewIndicatorStore()

	ind := &Indicator{
		ID:       "test-ip-1",
		Type:     IndicatorTypeIP,
		Value:    "192.168.1.100",
		Source:   "test",
		Severity: "high",
	}

	store.Add(ind)

	// Lookup by type and value
	found, ok := store.Lookup(IndicatorTypeIP, "192.168.1.100")
	if !ok {
		t.Error("expected to find indicator")
	}

	if found.ID != ind.ID {
		t.Errorf("got ID %s, want %s", found.ID, ind.ID)
	}

	// Lookup non-existent
	_, ok = store.Lookup(IndicatorTypeIP, "10.0.0.1")
	if ok {
		t.Error("expected not to find non-existent indicator")
	}
}

func TestIndicatorStore_CountByType(t *testing.T) {
	store := NewIndicatorStore()

	// Add various indicator types
	store.Add(&Indicator{ID: "ip-1", Type: IndicatorTypeIP, Value: "1.1.1.1"})
	store.Add(&Indicator{ID: "ip-2", Type: IndicatorTypeIP, Value: "2.2.2.2"})
	store.Add(&Indicator{ID: "domain-1", Type: IndicatorTypeDomain, Value: "evil.com"})
	store.Add(&Indicator{ID: "cve-1", Type: IndicatorTypeCVE, Value: "CVE-2024-1234"})

	counts := store.CountByType()

	if counts[IndicatorTypeIP] != 2 {
		t.Errorf("expected 2 IP indicators, got %d", counts[IndicatorTypeIP])
	}

	if counts[IndicatorTypeDomain] != 1 {
		t.Errorf("expected 1 domain indicator, got %d", counts[IndicatorTypeDomain])
	}

	if counts[IndicatorTypeCVE] != 1 {
		t.Errorf("expected 1 CVE indicator, got %d", counts[IndicatorTypeCVE])
	}
}

func TestThreatIntelService_LookupMethods(t *testing.T) {
	svc := NewThreatIntelService()

	// Add test indicators
	svc.indicators.Add(&Indicator{
		ID:     "test-ip",
		Type:   IndicatorTypeIP,
		Value:  "10.0.0.100",
		Source: "test",
	})

	svc.indicators.Add(&Indicator{
		ID:     "test-domain",
		Type:   IndicatorTypeDomain,
		Value:  "malware.example.com",
		Source: "test",
	})

	svc.indicators.Add(&Indicator{
		ID:     "test-cve",
		Type:   IndicatorTypeCVE,
		Value:  "CVE-2024-0001",
		Source: "cisa-kev",
	})

	// Test IP lookup
	if _, found := svc.LookupIP("10.0.0.100"); !found {
		t.Error("expected to find IP indicator")
	}

	if _, found := svc.LookupIP("10.0.0.1"); found {
		t.Error("expected not to find non-existent IP")
	}

	// Test domain lookup
	if _, found := svc.LookupDomain("malware.example.com"); !found {
		t.Error("expected to find domain indicator")
	}

	// Test CVE lookup
	if _, found := svc.LookupCVE("CVE-2024-0001"); !found {
		t.Error("expected to find CVE indicator")
	}
}

func TestThreatIntelService_SyncFeed_InvalidFeed(t *testing.T) {
	svc := NewThreatIntelService()

	err := svc.SyncFeed(context.Background(), "non-existent-feed")
	if err == nil {
		t.Error("expected error for non-existent feed")
	}
}

func TestParseCISAKEV(t *testing.T) {
	svc := NewThreatIntelService()

	// Sample KEV data
	kevJSON := `{
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1234",
				"vendorProject": "TestVendor",
				"product": "TestProduct",
				"vulnerabilityName": "Test Vulnerability",
				"dateAdded": "2024-01-01",
				"shortDescription": "A test vulnerability",
				"requiredAction": "Apply patch",
				"dueDate": "2024-02-01",
				"knownRansomwareCampaignUse": "Known"
			}
		]
	}`

	count := svc.parseCISAKEV([]byte(kevJSON))

	if count != 1 {
		t.Errorf("expected 1 indicator, got %d", count)
	}

	// Verify indicator was added
	ind, found := svc.indicators.Lookup(IndicatorTypeCVE, "CVE-2024-1234")
	if !found {
		t.Error("expected to find parsed CVE indicator")
	}

	if ind.Severity != "critical" {
		t.Errorf("KEV indicators should be critical, got %s", ind.Severity)
	}
}
