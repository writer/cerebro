package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// readContractFixture loads a synthetic copy of a VVExports-produced
// Contract B export page from sources/vulnview/testdata (vendored from the
// ACTUAL exports_api.py handler, not hand-written JSON).
func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name) //nolint:gosec // test-only read of a fixed vendored testdata file.
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

// fixtureNextCursor extracts the "nextCursor" field a fixture page carries,
// so tests assert against the exact VulnView-issued cursor instead of a
// hardcoded, easily-stale copy of it.
func fixtureNextCursor(t *testing.T, raw []byte) string {
	t.Helper()
	var decoded struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode fixture nextCursor: %v", err)
	}
	return decoded.NextCursor
}

// TestCloudIdentityAssessmentsContractFixturesEndToEnd is a producer
// (VVExports) -> consumer (PCImport) contract test: it drives Source.Read
// against an httptest server serving VVExports' real exporter output
// (testdata/exports-assessments-page-{1,2}.json), across the exact
// pagination boundary VVExports produced -- run scan-a's three assessment
// items split across both pages, assessmentsState "none" (scan-b, run event
// only) and "superseded" (scan-c, run event only) runs on page 2, and a
// terminal (hasMore=false) page whose nextCursor is still non-empty. It
// pins Contract H: the in-sync continuation cursor is VulnView's raw
// nextCursor unwrapped; the persisted checkpoint after the terminal page is
// a resumable envelope carrying that same terminal cursor as Token, so a
// later sync (simulated here via ReadWithCheckpoint with no cursor) resumes
// from it instead of restarting at cursor="".
func TestCloudIdentityAssessmentsContractFixturesEndToEnd(t *testing.T) {
	page1 := readContractFixture(t, "exports-assessments-page-1.json")
	page2 := readContractFixture(t, "exports-assessments-page-2.json")
	page1Cursor := fixtureNextCursor(t, page1)
	page2Cursor := fixtureNextCursor(t, page2)
	if page1Cursor == "" || page2Cursor == "" {
		t.Fatalf("fixtures must carry non-empty nextCursor values per Contract B; page1=%q page2=%q", page1Cursor, page2Cursor)
	}

	var sawPage2Cursor string
	var pageRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokenHandler(w)
		case r.URL.Path == "/exports/assessments" && r.URL.Query().Get("cursor") == "":
			pageRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(page1)
		case r.URL.Path == "/exports/assessments":
			pageRequests++
			sawPage2Cursor = r.URL.Query().Get("cursor")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(page2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer", "base_url": server.URL, "token_url": server.URL + "/token",
		"client_id": "client", "client_secret": "secret", "family": familyCloudIdentityAssessment,
		"per_page": "3",
	})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 3 {
		t.Fatalf("len(first.Events) = %d, want 3 (run scan-a + 2 of its 3 assessment items)", len(first.Events))
	}
	if first.NextCursor.GetOpaque() != page1Cursor {
		t.Fatalf("first.NextCursor = %q, want VulnView's raw page-1 nextCursor %q unwrapped", first.NextCursor.GetOpaque(), page1Cursor)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if sawPage2Cursor != page1Cursor {
		t.Fatalf("server received cursor %q on the second request, want the exact page-1 nextCursor %q", sawPage2Cursor, page1Cursor)
	}
	if len(second.Events) != 3 {
		t.Fatalf("len(second.Events) = %d, want 3 (the run's 3rd assessment item + the none/superseded runs)", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %v, want nil once hasMore=false", second.NextCursor)
	}
	if second.Checkpoint == nil {
		t.Fatal("second.Checkpoint = nil, want a resumable checkpoint even for a terminal page")
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(second.Checkpoint.GetCursorOpaque())
	if !ok || !envelope.ResumableCheckpoint {
		t.Fatalf("second.Checkpoint.CursorOpaque = %q, want a resumable sourcecdk.CursorEnvelope", second.Checkpoint.GetCursorOpaque())
	}
	if envelope.Token != page2Cursor {
		t.Fatalf("checkpoint envelope Token = %q, want VulnView's terminal nextCursor %q", envelope.Token, page2Cursor)
	}

	// Verify the wire-contract fields VVExports' assessment items carry are
	// actually consumed (severity/title/side/drift/timestamps/consumers)
	// and assessmentsState distinguishes available/none/superseded runs.
	allEvents := append(append([]*primitives.Event{}, first.Events...), second.Events...)
	var runStates []string
	assessmentCount := 0
	seenSvc1 := false
	for _, event := range allEvents {
		attrs := event.GetAttributes()
		switch event.GetKind() {
		case "vulnview.cloud_identity_run":
			runStates = append(runStates, attrs["assessments_state"])
			if attrs["finished_at"] == "" {
				t.Fatalf("run event missing finished_at attribute: %+v", attrs)
			}
		case "vulnview.cloud_identity_assessment":
			assessmentCount++
			for _, attr := range []string{"severity", "title", "side", "drift", "collected_at", "evaluated_at", "completed_at", "finished_at", "consumers_truncated"} {
				if attrs[attr] == "" {
					t.Fatalf("assessment event missing contracted attribute %q: %+v", attr, attrs)
				}
			}
			if attrs["consumers"] != "cluster-a/payments/worker" {
				t.Fatalf("assessment consumers = %q, want cluster-a/payments/worker (cloudAccount-qualified camelCase consumer fields consumed)", attrs["consumers"])
			}
			if strings.HasSuffix(attrs["principal_id"], "svc-1") {
				seenSvc1 = true
			}
		}
	}
	if assessmentCount != 3 {
		t.Fatalf("assessment event count = %d, want 3", assessmentCount)
	}
	if !seenSvc1 {
		t.Fatal("expected the page-1 2nd assessment item (svc-1) among the emitted events")
	}
	wantStates := []string{"available", "none", "superseded"}
	gotStates := map[string]bool{}
	for _, state := range runStates {
		gotStates[state] = true
	}
	for _, state := range wantStates {
		if !gotStates[state] {
			t.Fatalf("run assessments_state values = %v, missing %q", runStates, state)
		}
	}
	if pageRequests != 2 {
		t.Fatalf("server saw %d page requests, want exactly 2 (no re-fetch/skip across the resume boundary)", pageRequests)
	}

	// A later sync starts with no in-sync cursor (runtimeStartCursor falls
	// back to the persisted resumable checkpoint) and must resume from the
	// terminal VulnView cursor, not restart at cursor="".
	var sawThirdCursor string
	thirdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/assessments":
			sawThirdCursor = r.URL.Query().Get("cursor")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"items": [], "nextCursor": "` + page2Cursor + `", "hasMore": false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer thirdServer.Close()
	thirdSource, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	thirdSource.allowLoopbackBaseURL = true
	thirdCfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer", "base_url": thirdServer.URL, "token_url": thirdServer.URL + "/token",
		"client_id": "client", "client_secret": "secret", "family": familyCloudIdentityAssessment,
	})
	// sourceruntime.runtimeStartCursor falls back to the persisted resumable
	// checkpoint cursor when a sync starts with no in-sync NextCursor (end
	// of the prior sync); reproduce that here rather than re-implementing
	// sourceruntime's selection logic.
	startCursor := &cerebrov1.SourceCursor{Opaque: second.Checkpoint.GetCursorOpaque()}
	third, err := thirdSource.ReadWithCheckpoint(context.Background(), thirdCfg, startCursor, second.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(third) error = %v", err)
	}
	if sawThirdCursor != page2Cursor {
		t.Fatalf("third sync sent cursor %q, want the persisted terminal cursor %q (resume, not restart)", sawThirdCursor, page2Cursor)
	}
	if len(third.Events) != 0 {
		t.Fatalf("third.Events = %+v, want none for an empty page", third.Events)
	}
	if third.Checkpoint == nil {
		t.Fatal("third.Checkpoint = nil, want a checkpoint even for an empty terminal page")
	}
	thirdEnvelope, ok := sourcecdk.DecodeCursorEnvelope(third.Checkpoint.GetCursorOpaque())
	if !ok || !thirdEnvelope.ResumableCheckpoint || thirdEnvelope.Token != page2Cursor {
		t.Fatalf("third.Checkpoint envelope = %+v, want a resumable envelope still carrying %q", thirdEnvelope, page2Cursor)
	}
}

// TestCloudIdentityFindingsContractFixtureEndToEnd drives Source.Read
// against VVExports' real /exports/findings output and confirms the
// (now camelCase-corrected) consumer summary attribute is populated.
func TestCloudIdentityFindingsContractFixtureEndToEnd(t *testing.T) {
	fixture := readContractFixture(t, "exports-findings.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := cloudIdentityExportTestSource(t, server)
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Attributes["consumers"] != "cluster-a/payments/worker" {
		t.Fatalf("finding consumers = %q, want cluster-a/payments/worker", event.Attributes["consumers"])
	}
	if event.Attributes["evidence_principal_evidence_sha256"] == "" {
		t.Fatal("missing evidence_principal_evidence_sha256 attribute")
	}
}

// TestCloudIdentityFindingResumesFromTerminalCheckpointAcrossSyncs pins
// Contract H for the cloud_identity_finding family specifically (the
// cloud_identity_assessment family already has an equivalent proof in
// TestCloudIdentityAssessmentsContractFixturesEndToEnd): a sync that starts
// with no in-sync cursor but a resumable checkpoint persisted from a prior
// terminal (hasMore=false) page must resume from that checkpoint's
// terminal VulnView cursor, not restart at cursor="".
func TestCloudIdentityFindingResumesFromTerminalCheckpointAcrossSyncs(t *testing.T) {
	fixture := readContractFixture(t, "exports-findings.json")
	terminalCursor := fixtureNextCursor(t, fixture)
	if terminalCursor == "" {
		t.Fatal("fixture must carry a non-empty terminal nextCursor")
	}

	var sawCursor string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			sawCursor = r.URL.Query().Get("cursor")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := cloudIdentityExportTestSource(t, server)
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if first.NextCursor != nil {
		t.Fatalf("first.NextCursor = %v, want nil (terminal page)", first.NextCursor)
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(first.Checkpoint.GetCursorOpaque())
	if !ok || !envelope.ResumableCheckpoint || envelope.Token != terminalCursor {
		t.Fatalf("first.Checkpoint envelope = %+v, want a resumable envelope carrying %q", envelope, terminalCursor)
	}

	// Reproduce sourceruntime.runtimeStartCursor's resumable-checkpoint
	// fallback: NextCursor is nil, so the next sync's start cursor is the
	// checkpoint's own opaque value.
	startCursor := &cerebrov1.SourceCursor{Opaque: first.Checkpoint.GetCursorOpaque()}
	if _, err := source.ReadWithCheckpoint(context.Background(), cfg, startCursor, first.Checkpoint); err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if sawCursor != terminalCursor {
		t.Fatalf("second sync sent cursor %q, want the persisted terminal cursor %q (resume, not restart)", sawCursor, terminalCursor)
	}
}

// TestCloudIdentityAssessmentCollidingARNsProduceDistinctEventIDs pins
// review P1 defect #2 directly: two AWS role ARNs that only differ in
// whether a path segment separator is "-" or "/" ("role/a-b" vs "role/a/b")
// must never collide into the same record/event ID.
func TestCloudIdentityAssessmentCollidingARNsProduceDistinctEventIDs(t *testing.T) {
	first := cloudIdentityAssessmentItem("arn:aws:iam::111111111111:role/a-b")
	second := cloudIdentityAssessmentItem("arn:aws:iam::111111111111:role/a/b")
	firstID := cloudIdentityAssessmentRecordID(first)
	secondID := cloudIdentityAssessmentRecordID(second)
	if firstID == "" || secondID == "" {
		t.Fatalf("expected non-empty record IDs, got %q and %q", firstID, secondID)
	}
	if firstID == secondID {
		t.Fatalf("role/a-b and role/a/b collided on record ID %q, want distinct IDs", firstID)
	}

	settings := settings{tenantID: "writer", baseURL: "https://vulnview.example.test", clientID: "client", scope: "vulnview"}
	firstEventID := eventID(settings, familyCloudIdentityAssessment, firstID)
	secondEventID := eventID(settings, familyCloudIdentityAssessment, secondID)
	if firstEventID == secondEventID {
		t.Fatalf("role/a-b and role/a/b collided on event ID %q, want distinct IDs", firstEventID)
	}
}
