package sourceprojection

import "testing"

// TestVulnViewFindingCarriesDetailTruncatedAndSummaryCounts pins the R07
// fix: when the runner's own 160 KiB result-record bound (or the lifecycle
// module's own byte bound) replaced an oversized excess/sharing side with a
// bounded cardinality summary instead of list items (Contract C7's
// excessSummary/sharingSummary, see sources/vulnview/records.go), the
// importer's own "_count" attributes and "detail_truncated" must reach the
// projected finding entity -- never silently dropped the way the pre-fix
// list-only excess_declared/excess_observed mapping dropped them.
func TestVulnViewFindingCarriesDetailTruncatedAndSummaryCounts(t *testing.T) {
	event := vulnViewCloudIdentityFindingEvent(map[string]string{
		"detail_truncated":           "true",
		"excess_declared_count":      "1",
		"excess_observed_count":      "0",
		"sharing_services_count":     "2",
		"sharing_consumer_ids_count": "50",
	}, "")
	entities, _, err := vulnViewFindingProjections(event)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections() error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	want := map[string]string{
		"detail_truncated":           "true",
		"excess_declared_count":      "1",
		"excess_observed_count":      "0",
		"sharing_services_count":     "2",
		"sharing_consumer_ids_count": "50",
	}
	for key, value := range want {
		if got := finding.Attributes[key]; got != value {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, value)
		}
	}
}

// TestVulnViewFindingRetractsDetailSummaryCountsOnClear mirrors
// TestVulnViewFindingRetractsExcessAndSharingOnReset for the summary-count
// owned keys: a later version whose evidence no longer carries a truncated
// summary (the runner's bound no longer clipped it, or the durable excess/
// sharing cleared entirely) must retract the stale "_count"/
// "detail_truncated" attributes a prior version left on the finding entity,
// never leave them looking current.
func TestVulnViewFindingRetractsDetailSummaryCountsOnClear(t *testing.T) {
	truncatedKeys := []string{
		"detail_truncated", "excess_declared_count", "excess_observed_count",
		"sharing_services_count", "sharing_consumer_ids_count",
	}
	withSummary := vulnViewCloudIdentityFindingEvent(map[string]string{
		"detail_truncated":           "true",
		"excess_declared_count":      "1",
		"excess_observed_count":      "0",
		"sharing_services_count":     "2",
		"sharing_consumer_ids_count": "50",
	}, "")
	withSummaryEntities, _, err := vulnViewFindingProjections(withSummary)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(withSummary) error = %v", err)
	}
	withSummaryFinding := findEntity(withSummaryEntities, "vulnview.finding")
	if withSummaryFinding == nil {
		t.Fatal("missing finding entity")
	}
	for _, key := range truncatedKeys {
		if withSummaryFinding.Attributes[key] == "" {
			t.Fatalf("withSummary finding entity missing %s: %#v", key, withSummaryFinding.Attributes)
		}
	}

	cleared := vulnViewCloudIdentityFindingEvent(map[string]string{
		"detail_truncated": "", "excess_declared_count": "", "excess_observed_count": "",
		"sharing_services_count": "", "sharing_consumer_ids_count": "",
		"version": "4",
	}, "")
	clearedEntities, _, err := vulnViewFindingProjections(cleared)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(cleared) error = %v", err)
	}
	clearedFinding := findEntity(clearedEntities, "vulnview.finding")
	if clearedFinding == nil {
		t.Fatal("missing finding entity")
	}
	for _, key := range truncatedKeys {
		if _, ok := clearedFinding.Attributes[key]; ok {
			t.Fatalf("Attributes still carries stale %s: %#v", key, clearedFinding.Attributes)
		}
	}
	retracted := map[string]bool{}
	for _, key := range clearedFinding.RetractedAttributes {
		retracted[key] = true
	}
	for _, key := range truncatedKeys {
		if !retracted[key] {
			t.Fatalf("RetractedAttributes missing %s: %v", key, clearedFinding.RetractedAttributes)
		}
	}
}

// TestVulnViewFindingOlderReplayNeverRestoresRetractedSummaryCounts pins the
// no-restore half of R07's acceptance: a finding entity that no longer
// carries the summary-count/detail_truncated attributes (a newer, clearing
// version already applied) must never have them resurrected merely by
// re-running the same clearing projection again with an older
// observation_version -- strict version ordering is the store's job, but
// the projector itself must never fabricate a value this observation does
// not actually carry.
func TestVulnViewFindingOlderReplayNeverRestoresRetractedSummaryCounts(t *testing.T) {
	stale := vulnViewCloudIdentityFindingEvent(map[string]string{
		"detail_truncated": "", "excess_declared_count": "", "excess_observed_count": "",
		"sharing_services_count": "", "sharing_consumer_ids_count": "",
		"version": "1",
	}, "")
	entities, _, err := vulnViewFindingProjections(stale)
	if err != nil {
		t.Fatalf("vulnViewFindingProjections(stale) error = %v", err)
	}
	finding := findEntity(entities, "vulnview.finding")
	if finding == nil {
		t.Fatal("missing finding entity")
	}
	for _, key := range []string{
		"detail_truncated", "excess_declared_count", "excess_observed_count",
		"sharing_services_count", "sharing_consumer_ids_count",
	} {
		if _, ok := finding.Attributes[key]; ok {
			t.Fatalf("stale replay fabricated %s: %#v", key, finding.Attributes)
		}
	}
}
