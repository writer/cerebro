package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func findingExportTestSource(t *testing.T, server *httptest.Server, source string) (*Source, sourcecdk.Config) {
	t.Helper()
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	src.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        familyFinding,
		"source":        source,
		"per_page":      "2",
	})
	return src, cfg
}

func tokenHandler(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
}

func nucleiFindingItem(version int) map[string]any {
	return map[string]any{
		"findingId": "f1", "source": "nuclei", "checkId": "exposed-panel",
		"title": "Exposed Admin Panel", "severity": "high", "status": "open",
		"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
		"version": version, "updatedAt": "2026-04-01T09:00:00Z",
	}
}

func cloudIdentityFindingItem(version int) map[string]any {
	return map[string]any{
		"findingId": "f1", "source": "cloud_identity", "checkId": "cloud_identity_excess_privilege",
		"title": "Excess privilege", "severity": "high", "status": "open",
		"resource": map[string]any{"provider": "aws", "account": "111111111111"},
		"version":  version, "updatedAt": "2026-04-01T09:00:00Z",
		"details": map[string]any{
			"principalId": "arn:aws:iam::111111111111:role/example", "principalKind": "aws_role",
			"cohortScope": "writer",
		},
	}
}

// TestFindingReadEmptyFilteredPageWithCursorContinues pins "empty pages
// with hasMore/cursor continue": an empty items array with hasMore=true
// must still surface a continuation cursor, not stop.
func TestFindingReadEmptyFilteredPageWithCursorContinues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokenHandler(w)
		case r.URL.Path == "/exports/findings" && r.URL.Query().Get("cursor") == "":
			if got := r.URL.Query().Get("source"); got != "nuclei" {
				t.Fatalf("source query = %q, want nuclei", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}, "nextCursor": "page-2", "hasMore": true})
		case r.URL.Path == "/exports/findings" && r.URL.Query().Get("cursor") == "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{nucleiFindingItem(1)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 0 {
		t.Fatalf("len(first.Events) = %d, want 0 for an empty filtered page", len(first.Events))
	}
	if first.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("first.NextCursor = %q, want page-2 (an empty page with hasMore=true must still continue)", first.NextCursor.GetOpaque())
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %v, want nil once hasMore=false", second.NextCursor)
	}
	if got, want := second.Events[0].Kind, "vulnview.finding"; got != want {
		t.Fatalf("event.Kind = %q, want %q", got, want)
	}
}

// TestFindingKeepsHighestVersionWithinOneRead pins "within one read keep
// only the highest version per findingId".
func TestFindingKeepsHighestVersionWithinOneRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				nucleiFindingItem(1),
				nucleiFindingItem(3),
				nucleiFindingItem(2),
			}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1 (deduped to the highest version)", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["version"]; got != "3" {
		t.Fatalf("surviving version = %q, want 3", got)
	}
}

// TestFindingReplayIsIdempotent pins deterministic event ids: replaying
// the exact same page produces the exact same event id.
func TestFindingReplayIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{nucleiFindingItem(1)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	second, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(first.Events) != 1 || len(second.Events) != 1 {
		t.Fatalf("expected one event per read, got %d and %d", len(first.Events), len(second.Events))
	}
	if first.Events[0].Id != second.Events[0].Id {
		t.Fatalf("replayed event id changed: %q != %q", first.Events[0].Id, second.Events[0].Id)
	}
}

// TestFindingPayloadCannotChooseTenant pins tenant isolation: a
// payload-supplied tenant-shaped field must never override the trusted
// runtime tenant.
func TestFindingPayloadCannotChooseTenant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			finding := nucleiFindingItem(1)
			finding["tenantId"] = "attacker-tenant"
			finding["tenant"] = "attacker-tenant"
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{finding}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].TenantId; got != "writer" {
		t.Fatalf("event.TenantId = %q, want writer (payload tenant field must be ignored)", got)
	}
}

// TestFindingCloudIdentityDetailsMapToAttributes confirms the
// cloud_identity source's "details" object (principalId, principalKind,
// cohortScope) reaches bounded event attributes.
func TestFindingCloudIdentityDetailsMapToAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			if got := r.URL.Query().Get("source"); got != "cloud_identity" {
				t.Fatalf("source query = %q, want cloud_identity", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{cloudIdentityFindingItem(1)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "cloud_identity")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["principal_id"] != "arn:aws:iam::111111111111:role/example" {
		t.Fatalf("principal_id = %q", attrs["principal_id"])
	}
	if attrs["cohort_scope"] != "writer" {
		t.Fatalf("cohort_scope = %q, want writer", attrs["cohort_scope"])
	}
	if attrs["resource_provider"] != "aws" {
		t.Fatalf("resource_provider = %q, want aws", attrs["resource_provider"])
	}
	if attrs["source"] != "cloud_identity" {
		t.Fatalf("source attribute = %q, want cloud_identity", attrs["source"])
	}
}

// TestFindingMatcherDetailsMapToAttributes pins F13: the check-engine
// "matcher"/"templatePath" details fields (Contract C7/X1's
// _matcher_details, carried for nuclei/caido/prowler/github findings)
// must reach bounded event attributes alongside the common fields,
// instead of being silently dropped because the importer only ever read
// the cloud_identity-shaped details fields.
func TestFindingMatcherDetailsMapToAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			item := map[string]any{
				"findingId": "f1", "source": "nuclei", "checkId": "exposed-panel",
				"title": "Exposed Admin Panel", "severity": "high", "status": "open",
				"asset": "admin.writer.com", "location": "https://admin.writer.com/login",
				"version": 1, "updatedAt": "2026-04-01T09:00:00Z",
				"details": map[string]any{
					"matcher": "status-and-word", "templatePath": "http/exposed-panels/admin-panel.yaml",
				},
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{item}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["matcher"] != "status-and-word" {
		t.Fatalf("matcher = %q, want status-and-word", attrs["matcher"])
	}
	if attrs["template_path"] != "http/exposed-panels/admin-panel.yaml" {
		t.Fatalf("template_path = %q, want http/exposed-panels/admin-panel.yaml", attrs["template_path"])
	}
}

// TestFindingCloudIdentityExcessAndSharingMapToAttributes pins the F13
// follow-up: a cloud_identity finding's details.excess/details.sharing
// (Contract C7/X1) must reach bounded event attributes rather than being
// dropped (the original defect text: "even that mapping omits retained
// excess/sharing context").
func TestFindingCloudIdentityExcessAndSharingMapToAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			item := cloudIdentityFindingItem(1)
			item["details"].(map[string]any)["excess"] = map[string]any{
				"declared": []map[string]any{
					{"action": "s3:PutObject", "resources": []string{"arn:aws:s3:::bucket/*"}},
				},
				"observed": []map[string]any{
					{"action": "s3:GetObject", "resources": []string{"arn:aws:s3:::bucket/*"}, "requiredResources": []string{"arn:aws:s3:::bucket/obj1"}},
				},
			}
			item["details"].(map[string]any)["sharing"] = map[string]any{
				"services": []string{"checkout", "billing"}, "consumerIds": []string{"w1", "w2"},
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{item}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "cloud_identity")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["excess_declared"] != "s3:PutObject(arn:aws:s3:::bucket/*)" {
		t.Fatalf("excess_declared = %q", attrs["excess_declared"])
	}
	if attrs["excess_observed"] != "s3:GetObject(arn:aws:s3:::bucket/*)[required:arn:aws:s3:::bucket/obj1]" {
		t.Fatalf("excess_observed = %q", attrs["excess_observed"])
	}
	if attrs["sharing_services"] != "checkout,billing" {
		t.Fatalf("sharing_services = %q, want checkout,billing", attrs["sharing_services"])
	}
	if attrs["sharing_consumer_ids"] != "w1,w2" {
		t.Fatalf("sharing_consumer_ids = %q, want w1,w2", attrs["sharing_consumer_ids"])
	}
}

// TestFindingCloudIdentityDetailTruncatedSummaryMapsToAttributes pins R07:
// when the export carries a truncated excess/sharing *count* summary
// (Contract C7's excessSummary/sharingSummary, the shape
// cloud_identity_runner._bound_record_detail leaves behind once it has
// clipped a side down from list items) alongside explicit
// excess/sharing: null and detailTruncated: true, the importer must still
// surface bounded "_count"/"detail_truncated" attributes -- never silently
// drop the retained counts and truncation marker just because excess and
// sharing themselves carry no list-shaped detail.
func TestFindingCloudIdentityDetailTruncatedSummaryMapsToAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			item := cloudIdentityFindingItem(1)
			item["details"].(map[string]any)["excess"] = nil
			item["details"].(map[string]any)["excessSummary"] = map[string]any{"declared": 1, "observed": 0}
			item["details"].(map[string]any)["sharing"] = nil
			item["details"].(map[string]any)["sharingSummary"] = map[string]any{"services": 2, "consumerIds": 50}
			item["details"].(map[string]any)["detailTruncated"] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{item}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "cloud_identity")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if _, ok := attrs["excess_declared"]; ok {
		t.Fatalf("excess_declared = %q, want absent (excess is null, not list-shaped)", attrs["excess_declared"])
	}
	want := map[string]string{
		"detail_truncated":           "true",
		"excess_declared_count":      "1",
		"excess_observed_count":      "0",
		"sharing_services_count":     "2",
		"sharing_consumer_ids_count": "50",
	}
	for key, value := range want {
		if attrs[key] != value {
			t.Fatalf("attrs[%q] = %q, want %q", key, attrs[key], value)
		}
	}
}

// TestFindingVersionsProduceDistinctEventIDs pins F02: the common importer
// must derive event identity from more than just findingId, or a later
// finding version silently collides with (and in JetStream, gets dropped
// by) an earlier one sharing the same append dedup key. Two incremental
// ReadWithCheckpoint syncs returning version 1 then version 2 of the same
// findingId must produce distinct event ids, while replaying the exact
// same version 2 sync (e.g. a resumed/retried checkpoint read) keeps the
// identical event id.
func TestFindingVersionsProduceDistinctEventIDs(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			calls++
			version := 1
			if calls >= 2 {
				version = 2
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{nucleiFindingItem(version)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "nuclei")
	v1, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(v1) error = %v", err)
	}
	if len(v1.Events) != 1 {
		t.Fatalf("len(v1.Events) = %d, want 1", len(v1.Events))
	}

	startCursor := &cerebrov1.SourceCursor{Opaque: v1.Checkpoint.GetCursorOpaque()}
	v2, err := source.ReadWithCheckpoint(context.Background(), cfg, startCursor, v1.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(v2) error = %v", err)
	}
	if len(v2.Events) != 1 {
		t.Fatalf("len(v2.Events) = %d, want 1", len(v2.Events))
	}
	if v1.Events[0].Id == v2.Events[0].Id {
		t.Fatalf("version 1 and version 2 event ids collide: %q", v1.Events[0].Id)
	}

	v2Replay, err := source.ReadWithCheckpoint(context.Background(), cfg, startCursor, v1.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(v2 replay) error = %v", err)
	}
	if len(v2Replay.Events) != 1 {
		t.Fatalf("len(v2Replay.Events) = %d, want 1", len(v2Replay.Events))
	}
	if v2Replay.Events[0].Id != v2.Events[0].Id {
		t.Fatalf("replaying the identical version changed the event id: %q != %q", v2Replay.Events[0].Id, v2.Events[0].Id)
	}
}
