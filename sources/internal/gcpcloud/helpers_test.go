package gcpcloud

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCheckpointStartNilCheckpoint(t *testing.T) {
	got, ok := CheckpointStart(nil, time.Minute)
	if ok {
		t.Fatal("expected ok=false for nil checkpoint")
	}
	if !got.IsZero() {
		t.Fatalf("expected zero time, got %v", got)
	}
}

func TestCheckpointStartNilWatermark(t *testing.T) {
	got, ok := CheckpointStart(&cerebrov1.SourceCheckpoint{}, time.Minute)
	if ok {
		t.Fatal("expected ok=false for nil watermark")
	}
	if !got.IsZero() {
		t.Fatalf("expected zero time, got %v", got)
	}
}

func TestCheckpointStartZeroWatermark(t *testing.T) {
	got, ok := CheckpointStart(&cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(time.Time{}),
	}, time.Minute)
	if ok {
		t.Fatal("expected ok=false for zero watermark")
	}
	if !got.IsZero() {
		t.Fatalf("expected zero time, got %v", got)
	}
}

func TestCheckpointStartValidWatermark(t *testing.T) {
	watermark := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	got, ok := CheckpointStart(&cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(watermark),
	}, 0)
	if !ok {
		t.Fatal("expected ok=true for valid watermark")
	}
	if !got.Equal(watermark) {
		t.Fatalf("got %v, want %v", got, watermark)
	}
}

func TestCheckpointStartSubtractsLookback(t *testing.T) {
	watermark := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	lookback := 5 * time.Minute
	got, ok := CheckpointStart(&cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(watermark),
	}, lookback)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := watermark.Add(-lookback)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v (watermark minus lookback)", got, want)
	}
}

func TestCheckpointStartFindingLookbackConstant(t *testing.T) {
	watermark := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	got, ok := CheckpointStart(&cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(watermark),
	}, FindingCheckpointLookback)
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := watermark.Add(-FindingCheckpointLookback)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCombineFiltersBothEmpty(t *testing.T) {
	if got := CombineFilters("", ""); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestCombineFiltersOnlyExisting(t *testing.T) {
	if got := CombineFilters("state=ACTIVE", ""); got != "state=ACTIVE" {
		t.Fatalf("got %q, want %q", got, "state=ACTIVE")
	}
}

func TestCombineFiltersOnlyIncremental(t *testing.T) {
	if got := CombineFilters("", "timestamp>2025-01-01"); got != "timestamp>2025-01-01" {
		t.Fatalf("got %q, want %q", got, "timestamp>2025-01-01")
	}
}

func TestCombineFiltersBothNonEmpty(t *testing.T) {
	got := CombineFilters("state=ACTIVE", "timestamp>2025-01-01")
	want := "(state=ACTIVE) AND (timestamp>2025-01-01)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCombineFiltersTrimsWhitespace(t *testing.T) {
	if got := CombineFilters("  ", "  "); got != "" {
		t.Fatalf("got %q, want empty for whitespace-only inputs", got)
	}
	if got := CombineFilters("  state=ACTIVE  ", ""); got != "state=ACTIVE" {
		t.Fatalf("got %q, want trimmed existing filter", got)
	}
}

func TestComputeAggregatedRawRecordsEmptyMap(t *testing.T) {
	type entry struct{ Records []json.RawMessage }
	got := ComputeAggregatedRawRecords(map[string]entry{}, func(e entry) []json.RawMessage { return e.Records }, "location")
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(got))
	}
}

func TestComputeAggregatedRawRecordsSingleScope(t *testing.T) {
	type entry struct{ Records []json.RawMessage }
	items := map[string]entry{
		"regions/us-central1": {Records: []json.RawMessage{json.RawMessage(`{"name":"vm-1"}`)}},
	}
	got := ComputeAggregatedRawRecords(items, func(e entry) []json.RawMessage { return e.Records }, "location")
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	var parsed map[string]any
	if err := json.Unmarshal(got[0], &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["name"] != "vm-1" {
		t.Fatalf("name = %v, want vm-1", parsed["name"])
	}
	if parsed["region"] != "regions/us-central1" {
		t.Fatalf("region = %v, want regions/us-central1", parsed["region"])
	}
}

func TestComputeAggregatedRawRecordsMultipleScopes(t *testing.T) {
	type entry struct{ Records []json.RawMessage }
	items := map[string]entry{
		"regions/us-central1": {Records: []json.RawMessage{json.RawMessage(`{"name":"a"}`)}},
		"zones/us-central1-a": {Records: []json.RawMessage{json.RawMessage(`{"name":"b"}`)}},
	}
	got := ComputeAggregatedRawRecords(items, func(e entry) []json.RawMessage { return e.Records }, "location")
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	regionFound, zoneFound := false, false
	for _, raw := range got {
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if parsed["region"] != nil {
			regionFound = true
		}
		if parsed["zone"] != nil {
			zoneFound = true
		}
	}
	if !regionFound || !zoneFound {
		t.Fatalf("expected both region and zone scope fields; region=%v zone=%v", regionFound, zoneFound)
	}
}

func TestComputeAggregatedRawRecordsScopeInjectionSkippedWhenPresent(t *testing.T) {
	type entry struct{ Records []json.RawMessage }
	items := map[string]entry{
		"regions/us-east1": {Records: []json.RawMessage{json.RawMessage(`{"name":"x","region":"already-set"}`)}},
	}
	got := ComputeAggregatedRawRecords(items, func(e entry) []json.RawMessage { return e.Records }, "location")
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	var parsed map[string]any
	if err := json.Unmarshal(got[0], &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["region"] != "already-set" {
		t.Fatalf("region = %v, want already-set (should not be overwritten)", parsed["region"])
	}
}

func TestComputeAggregatedRawRecordsSkipsEmptyRecords(t *testing.T) {
	type entry struct{ Records []json.RawMessage }
	items := map[string]entry{
		"regions/us-west1": {Records: []json.RawMessage{json.RawMessage(`{"name":"ok"}`), json.RawMessage(``)}},
	}
	got := ComputeAggregatedRawRecords(items, func(e entry) []json.RawMessage { return e.Records }, "location")
	if len(got) != 1 {
		t.Fatalf("expected 1 record (empty skipped), got %d", len(got))
	}
}

func TestComputeAggregatedScopeFieldRegions(t *testing.T) {
	if got := computeAggregatedScopeField("regions/us-central1", "fallback"); got != "region" {
		t.Fatalf("got %q, want region", got)
	}
}

func TestComputeAggregatedScopeFieldZones(t *testing.T) {
	if got := computeAggregatedScopeField("zones/us-central1-a", "fallback"); got != "zone" {
		t.Fatalf("got %q, want zone", got)
	}
}

func TestComputeAggregatedScopeFieldFallback(t *testing.T) {
	if got := computeAggregatedScopeField("projects/my-project", "location"); got != "location" {
		t.Fatalf("got %q, want location", got)
	}
}

func TestComputeAggregatedScopeFieldEmptyFallback(t *testing.T) {
	if got := computeAggregatedScopeField("other/scope", ""); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

func TestCerebroResourceIDComputeAddressSelfLink(t *testing.T) {
	record := ComputeAddressRecord{SelfLink: "https://compute/addresses/1", ID: "1", Name: "addr", Address: "10.0.0.1"}
	if got := record.CerebroResourceID(); got != "https://compute/addresses/1" {
		t.Fatalf("got %q, want SelfLink", got)
	}
}

func TestCerebroResourceIDComputeAddressFallbackToID(t *testing.T) {
	record := ComputeAddressRecord{ID: "123", Name: "addr"}
	if got := record.CerebroResourceID(); got != "123" {
		t.Fatalf("got %q, want ID", got)
	}
}

func TestCerebroResourceIDComputeAddressFallbackToName(t *testing.T) {
	record := ComputeAddressRecord{Name: "my-address"}
	if got := record.CerebroResourceID(); got != "my-address" {
		t.Fatalf("got %q, want Name", got)
	}
}

func TestCerebroResourceIDComputeAddressFallbackToAddress(t *testing.T) {
	record := ComputeAddressRecord{Address: "10.0.0.1"}
	if got := record.CerebroResourceID(); got != "10.0.0.1" {
		t.Fatalf("got %q, want Address", got)
	}
}

func TestCerebroResourceIDComputeAddressEmpty(t *testing.T) {
	record := ComputeAddressRecord{}
	if got := record.CerebroResourceID(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestCerebroResourceIDComputeBackendBucketPrefersSelfLink(t *testing.T) {
	record := ComputeBackendBucketRecord{SelfLink: "https://compute/bb/1", ID: "1", Name: "bb", BucketName: "my-bucket"}
	if got := record.CerebroResourceID(); got != "https://compute/bb/1" {
		t.Fatalf("got %q, want SelfLink", got)
	}
}

func TestCerebroResourceIDComputeBackendBucketFallbackToBucketName(t *testing.T) {
	record := ComputeBackendBucketRecord{BucketName: "my-bucket"}
	if got := record.CerebroResourceID(); got != "my-bucket" {
		t.Fatalf("got %q, want BucketName", got)
	}
}

func TestCerebroResourceIDComputeNetworkFirewallPolicyIncludesSelfLinkWithID(t *testing.T) {
	record := ComputeNetworkFirewallPolicyRecord{SelfLinkWithID: "https://compute/fp/id123", ID: "123", Name: "policy"}
	if got := record.CerebroResourceID(); got != "https://compute/fp/id123" {
		t.Fatalf("got %q, want SelfLinkWithID", got)
	}
}

func TestCerebroResourceIDCertificateManagerReturnsName(t *testing.T) {
	record := CertificateManagerCertificateRecord{Name: "projects/p/locations/global/certificates/c"}
	if got := record.CerebroResourceID(); got != record.Name {
		t.Fatalf("got %q, want Name", got)
	}
}

func TestCerebroResourceIDBigtableInstanceReturnsName(t *testing.T) {
	record := BigtableInstanceRecord{Name: "projects/p/instances/i"}
	if got := record.CerebroResourceID(); got != record.Name {
		t.Fatalf("got %q, want Name", got)
	}
}

func TestCerebroResourceIDSpannerDatabaseReturnsName(t *testing.T) {
	record := SpannerDatabaseRecord{Name: "projects/p/instances/i/databases/d"}
	if got := record.CerebroResourceID(); got != record.Name {
		t.Fatalf("got %q, want Name", got)
	}
}

func TestCerebroResourceIDWorkloadIdentityPoolReturnsName(t *testing.T) {
	record := WorkloadIdentityPoolRecord{Name: "projects/p/locations/global/workloadIdentityPools/pool"}
	if got := record.CerebroResourceID(); got != record.Name {
		t.Fatalf("got %q, want Name", got)
	}
}
