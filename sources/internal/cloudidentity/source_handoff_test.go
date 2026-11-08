package cloudidentitysource

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func sourceHandoffTestCollection(now time.Time) ci.Collection {
	principal := ci.Principal{ID: "arn:aws:iam::222222222222:role/example", Provider: ci.AWS, Kind: "aws_iam_role", Account: "222222222222"}
	evidence := ci.Evidence{
		Schema: ci.SchemaVersion, Principal: principal, Scope: "writer", CollectedAt: now,
		ConsumerInventoryComplete: true, Declared: ci.PolicyState{Complete: true}, Observed: ci.PolicyState{Complete: true},
	}
	return ci.Collection{Scope: "writer", Evidence: []ci.Evidence{evidence}, CollectedAt: now, InventoryComplete: true}
}

func sourceHandoffTestSettings(bucket, stream string) Settings {
	return Settings{TenantID: "writer", EvidenceHandoff: EvidenceHandoffSettings{Bucket: bucket, Stream: stream, Region: "us-east-1"}}
}

// TestPublishEvidenceHandoffAndAnnotateCoverageWritesHandoffField confirms
// the coverage event's payload carries the handoff outcome after a
// successful publish, and that the principal events are published exactly
// as emitted (collection events are never dropped on publish, success or
// failure).
func TestPublishEvidenceHandoffAndAnnotateCoverageWritesHandoffField(t *testing.T) {
	now := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)
	collection := sourceHandoffTestCollection(now)
	events, err := CollectionEvents("writer", collection)
	if err != nil {
		t.Fatalf("CollectionEvents() error = %v", err)
	}
	wantEventCount := len(events)

	publisher := &fakeHandoffPublisher{}
	source := &Source{handoffPublisherFactory: func(context.Context, string) (HandoffPublisher, error) { return publisher, nil }}
	settings := sourceHandoffTestSettings("intake-bucket", "security")

	updated := source.publishEvidenceHandoffAndAnnotateCoverage(context.Background(), sourcecdk.Config{}, settings, collection, events)
	if len(updated) != wantEventCount {
		t.Fatalf("event count = %d, want %d: collection events must never be dropped on publish", len(updated), wantEventCount)
	}
	coverageEvent := updated[len(updated)-1]
	if coverageEvent.Kind != ci.CoverageEventKind {
		t.Fatalf("last event kind = %q, want %q", coverageEvent.Kind, ci.CoverageEventKind)
	}
	var coverage CollectionCoverage
	if err := json.Unmarshal(coverageEvent.Payload, &coverage); err != nil {
		t.Fatalf("unmarshal coverage payload: %v", err)
	}
	if coverage.Handoff.Status != "published" {
		t.Fatalf("coverage.Handoff.Status = %q, want published", coverage.Handoff.Status)
	}
	if coverage.Handoff.Bucket != "intake-bucket" || coverage.Handoff.Stream != "security" || coverage.Handoff.SHA256 == "" {
		t.Fatalf("incomplete coverage.Handoff: %+v", coverage.Handoff)
	}
	if len(publisher.calls) != 1 {
		t.Fatalf("publisher calls = %d, want 1", len(publisher.calls))
	}
	for i, event := range updated[:len(updated)-1] {
		if string(event.Payload) != string(events[i].Payload) {
			t.Fatalf("principal event %d payload mutated by the handoff hook", i)
		}
	}
}

// TestPublishEvidenceHandoffAndAnnotateCoverageNeverDropsEventsOnFailure
// pins "collection events never dropped on publish failure": a failing
// publisher still returns every event, with the coverage event recording
// the failure.
func TestPublishEvidenceHandoffAndAnnotateCoverageNeverDropsEventsOnFailure(t *testing.T) {
	now := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)
	collection := sourceHandoffTestCollection(now)
	events, err := CollectionEvents("writer", collection)
	if err != nil {
		t.Fatalf("CollectionEvents() error = %v", err)
	}
	wantEventCount := len(events)

	source := &Source{handoffPublisherFactory: func(context.Context, string) (HandoffPublisher, error) {
		return nil, context.DeadlineExceeded
	}}
	settings := sourceHandoffTestSettings("intake-bucket", "security")
	updated := source.publishEvidenceHandoffAndAnnotateCoverage(context.Background(), sourcecdk.Config{}, settings, collection, events)
	if len(updated) != wantEventCount {
		t.Fatalf("event count = %d, want %d", len(updated), wantEventCount)
	}
	var coverage CollectionCoverage
	if err := json.Unmarshal(updated[len(updated)-1].Payload, &coverage); err != nil {
		t.Fatalf("unmarshal coverage payload: %v", err)
	}
	if coverage.Handoff.Status != "failed" || coverage.Handoff.ErrorCode == "" {
		t.Fatalf("coverage.Handoff = %+v, want a failed status with an error code", coverage.Handoff)
	}
}

// TestPublishEvidenceHandoffAndAnnotateCoverageDisabledLeavesNoHandoffStatus
// confirms the default (no evidence_handoff_bucket configured) records an
// explicit "disabled" status rather than silently omitting it.
func TestPublishEvidenceHandoffAndAnnotateCoverageDisabledLeavesNoHandoffStatus(t *testing.T) {
	now := time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC)
	collection := sourceHandoffTestCollection(now)
	events, err := CollectionEvents("writer", collection)
	if err != nil {
		t.Fatalf("CollectionEvents() error = %v", err)
	}
	source := &Source{}
	updated := source.publishEvidenceHandoffAndAnnotateCoverage(context.Background(), sourcecdk.Config{}, Settings{TenantID: "writer"}, collection, events)
	var coverage CollectionCoverage
	if err := json.Unmarshal(updated[len(updated)-1].Payload, &coverage); err != nil {
		t.Fatalf("unmarshal coverage payload: %v", err)
	}
	if coverage.Handoff.Status != "disabled" {
		t.Fatalf("coverage.Handoff.Status = %q, want disabled", coverage.Handoff.Status)
	}
}
