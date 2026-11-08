package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func cloudIdentityExportTestSource(t *testing.T, server *httptest.Server) (*Source, sourcecdk.Config) {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        familyCloudIdentityFinding,
		"per_page":      "2",
	})
	return source, cfg
}

func tokenHandler(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
}

func cloudIdentityFinding(version int) map[string]any {
	return map[string]any{
		"findingId": "f1", "source": "cloud_identity", "checkId": "cloud_identity_excess_privilege",
		"checkVersion": 1, "detectorVersion": "1.0.0", "status": "open", "severity": "high",
		"title": "Excess privilege", "provider": "aws", "account": "111111111111", "project": "",
		"principalId": "arn:aws:iam::111111111111:role/example", "principalKind": "aws_role",
		"cohortScope": "writer", "evidenceStream": "staging", "updatedAt": "2026-04-01T09:00:00Z", "version": version,
	}
}

// TestCloudIdentityFindingReadEmptyFilteredPageWithCursorContinues pins
// "Empty pages with hasMore/cursor continue": an empty items array with
// hasMore=true must still surface a continuation cursor, not stop.
func TestCloudIdentityFindingReadEmptyFilteredPageWithCursorContinues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokenHandler(w)
		case r.URL.Path == "/exports/findings" && r.URL.Query().Get("cursor") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{}, "nextCursor": "page-2", "hasMore": true})
		case r.URL.Path == "/exports/findings" && r.URL.Query().Get("cursor") == "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{cloudIdentityFinding(1)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := cloudIdentityExportTestSource(t, server)
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
}

// TestCloudIdentityFindingKeepsHighestVersionWithinOneRead pins "within one
// read keep only the highest version per findingId".
func TestCloudIdentityFindingKeepsHighestVersionWithinOneRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityFinding(1),
				cloudIdentityFinding(3),
				cloudIdentityFinding(2),
			}, "nextCursor": "", "hasMore": false})
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
		t.Fatalf("len(pull.Events) = %d, want 1 (deduped to the highest version)", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["version"]; got != "3" {
		t.Fatalf("surviving version = %q, want 3", got)
	}
}

// TestCloudIdentityFindingReplayIsIdempotent pins deterministic event ids:
// replaying the exact same page produces the exact same event id.
func TestCloudIdentityFindingReplayIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{cloudIdentityFinding(1)}, "nextCursor": "", "hasMore": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := cloudIdentityExportTestSource(t, server)
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

// TestCloudIdentityFindingPayloadCannotChooseTenant pins tenant isolation:
// a payload-supplied tenant-shaped field must never override the trusted
// runtime tenant.
func TestCloudIdentityFindingPayloadCannotChooseTenant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			finding := cloudIdentityFinding(1)
			finding["tenantId"] = "attacker-tenant"
			finding["tenant"] = "attacker-tenant"
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{finding}, "nextCursor": "", "hasMore": false})
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
	if got := pull.Events[0].TenantId; got != "writer" {
		t.Fatalf("event.TenantId = %q, want writer (payload tenant field must be ignored)", got)
	}
}

func cloudIdentityRunItem() map[string]any {
	return map[string]any{
		"type": "run", "scanId": "scan-1", "runId": "run-1", "cohortScope": "writer", "evidenceStream": "staging",
		"authoritative": true, "completedAt": "2026-04-01T09:00:00Z", "detectorVersion": "1.0.0",
		"bundle": map[string]any{"key": "cloud-identity/staging/writer/key.json.gz", "sha256": "abc", "principalCount": 1},
	}
}

func cloudIdentityAssessmentItem(principalID string) map[string]any {
	return map[string]any{
		"type": "assessment", "scanId": "scan-1", "runId": "run-1", "checkId": "cloud_identity_excess_privilege",
		"checkVersion": 1, "provider": "aws", "principalId": principalID, "principalKind": "aws_role",
		"account": "111111111111", "cohortScope": "writer", "status": "supported", "severity": "high", "title": "Excess privilege",
		"findingId": "cloud_identity|cloud_identity_excess_privilege|aws|" + principalID + "|writer", "evidenceFresh": true,
		"gapCodes": []any{"none"},
	}
}

// TestCloudIdentityAssessmentAttributesCarryContractedFields pins finding
// #3: a contract-conforming assessment export item must have cohortScope,
// findingId, evidenceFresh, and gapCodes copied into event attributes --
// internal/sourceprojection's vulnViewCloudIdentityAssessmentProjections
// requires cohort_scope to build the assessment URN at all, so a dropped
// cohortScope silently discards every assessment event.
func TestCloudIdentityAssessmentAttributesCarryContractedFields(t *testing.T) {
	item := cloudIdentityAssessmentItem("arn:aws:iam::111111111111:role/example")
	attrs := cloudIdentityAssessmentAttributes(item)
	want := map[string]string{
		"cohort_scope":   "writer",
		"finding_id":     "cloud_identity|cloud_identity_excess_privilege|aws|arn:aws:iam::111111111111:role/example|writer",
		"evidence_fresh": "true",
		"gap_codes":      "none",
	}
	for attr, wantValue := range want {
		if got := attrs[attr]; got != wantValue {
			t.Fatalf("attrs[%q] = %q, want %q (attrs = %+v)", attr, got, wantValue, attrs)
		}
	}
}

// TestCloudIdentityAssessmentFlattenedFeedEmitsTwoKinds confirms one page
// of the flattened assessments feed emits both vulnview.cloud_identity_run
// and vulnview.cloud_identity_assessment events.
func TestCloudIdentityAssessmentFlattenedFeedEmitsTwoKinds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/assessments":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityRunItem(),
				cloudIdentityAssessmentItem("arn:aws:iam::111111111111:role/example"),
			}, "nextCursor": "", "hasMore": false})
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
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(pull.Events) = %d, want 2", len(pull.Events))
	}
	kinds := map[string]bool{}
	for _, event := range pull.Events {
		kinds[event.Kind] = true
	}
	if !kinds["vulnview.cloud_identity_run"] || !kinds["vulnview.cloud_identity_assessment"] {
		t.Fatalf("kinds = %v, want both run and assessment", kinds)
	}
}

// TestCloudIdentityAssessmentInterruptedPaginationResume pins resumable
// pagination: a cursor returned mid-feed, when fed back into Read, resumes
// from exactly that point rather than restarting or skipping.
func TestCloudIdentityAssessmentInterruptedPaginationResume(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			tokenHandler(w)
		case r.URL.Path == "/exports/assessments" && r.URL.Query().Get("cursor") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityRunItem(),
			}, "nextCursor": "run-1-done", "hasMore": true})
		case r.URL.Path == "/exports/assessments" && r.URL.Query().Get("cursor") == "run-1-done":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityAssessmentItem("arn:aws:iam::111111111111:role/example"),
			}, "nextCursor": "", "hasMore": false})
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
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.Events[0].Kind != "vulnview.cloud_identity_run" {
		t.Fatalf("first page = %+v, want one run event", first.Events)
	}
	if first.NextCursor.GetOpaque() != "run-1-done" {
		t.Fatalf("first.NextCursor = %q, want run-1-done", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Kind != "vulnview.cloud_identity_assessment" {
		t.Fatalf("second page = %+v, want one assessment event", second.Events)
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %v, want nil", second.NextCursor)
	}
}

// TestCloudIdentityExportsTenantIsolation confirms two tenants reading the
// identical upstream page produce events scoped to their own tenant only.
func TestCloudIdentityExportsTenantIsolation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{cloudIdentityFinding(1)}, "nextCursor": "", "hasMore": false})
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
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		cfg := sourcecdk.NewConfig(map[string]string{
			"tenant_id": tenant, "base_url": server.URL, "token_url": server.URL + "/token",
			"client_id": "client", "client_secret": "secret", "family": familyCloudIdentityFinding,
		})
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read(%s) error = %v", tenant, err)
		}
		if len(pull.Events) != 1 || pull.Events[0].TenantId != tenant {
			t.Fatalf("tenant %s events = %+v", tenant, pull.Events)
		}
	}
}

// TestCloudIdentityAssessmentErrorItemFailsReadWithoutAdvancingCursor pins
// finding #13: a VulnView "assessment_error" item (its assessment object
// was unavailable for that run) must fail the page read -- not be
// silently dropped while the cursor advances past it -- so the next
// scheduled read retries the exact same page instead of losing the run's
// posture data forever.
func TestCloudIdentityAssessmentErrorItemFailsReadWithoutAdvancingCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/assessments":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityRunItem(),
				{"type": "assessment_error", "scanId": "scan-1", "runId": "run-1", "error": "assessments_unavailable"},
			}, "nextCursor": "page-2", "hasMore": true})
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
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err == nil {
		t.Fatalf("Read() error = nil, want a retryable error for the assessment_error item; got pull = %+v", pull)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("pull.Events = %+v, want none: an assessment_error item must never be silently dropped while other items in the page are ingested", pull.Events)
	}
	if pull.NextCursor != nil {
		t.Fatalf("pull.NextCursor = %v, want nil: the checkpoint must never advance past an unresolved assessment_error item", pull.NextCursor)
	}
	// The error message must carry VulnView's fixed error code for
	// diagnosis, but never raw upstream response detail.
	if got := err.Error(); !strings.Contains(got, "assessments_unavailable") || !strings.Contains(got, "scan-1") || !strings.Contains(got, "run-1") {
		t.Fatalf("error = %q, want it to name the run and VulnView's stable error code", got)
	}
}

// cloudIdentityAssessmentItemWithProvider mirrors cloudIdentityAssessmentItem
// but lets the caller pick the provider/account, for defect #3's
// AWS-and-GCP-same-principal regression test.
func cloudIdentityAssessmentItemWithProvider(provider, principalID string) map[string]any {
	const checkID = "cloud_identity_excess_privilege"
	return map[string]any{
		"type": "assessment", "scanId": "scan-1", "runId": "run-1", "checkId": checkID,
		"checkVersion": 1, "provider": provider, "principalId": principalID, "principalKind": provider + "_kubernetes_service_account",
		"account": "", "cohortScope": "writer", "status": "incomplete", "severity": "medium", "title": "Unresolved placeholder principal",
		"findingId": "cloud_identity|" + checkID + "|" + provider + "|" + principalID + "|writer", "evidenceFresh": true,
		"gapCodes": []any{"none"},
	}
}

// TestCloudIdentityAssessmentRecordIDIncludesProvider pins defect #3's
// dedupe-key fix directly: the same (scanId, runId, checkId, principalId)
// observed for AWS and for GCP -- which legitimately recurs because cell
// targets run inventory for AWS and the paired GCP project -- must
// produce two distinct record IDs, while the identical provider still
// produces the identical ID (the documented highest-version/reject rule
// for a genuine duplicate is unaffected).
func TestCloudIdentityAssessmentRecordIDIncludesProvider(t *testing.T) {
	aws := cloudIdentityAssessmentItemWithProvider("aws", "k8s://prod-eks/billing/sa/worker")
	gcp := cloudIdentityAssessmentItemWithProvider("gcp", "k8s://prod-eks/billing/sa/worker")
	awsAgain := cloudIdentityAssessmentItemWithProvider("aws", "k8s://prod-eks/billing/sa/worker")

	awsID := cloudIdentityAssessmentRecordID(aws)
	gcpID := cloudIdentityAssessmentRecordID(gcp)
	awsAgainID := cloudIdentityAssessmentRecordID(awsAgain)

	if awsID == "" || gcpID == "" {
		t.Fatalf("expected non-empty record IDs, got aws=%q gcp=%q", awsID, gcpID)
	}
	if awsID == gcpID {
		t.Fatalf("AWS and GCP assessments for the same (checkId, principalId) in one run collided on record ID %q, want distinct keys", awsID)
	}
	if awsID != awsAgainID {
		t.Fatalf("two AWS assessments with identical (scanId, runId, checkId, provider, principalId) produced different record IDs %q != %q, want the documented dedupe rule to still apply within one provider", awsID, awsAgainID)
	}
}

// TestCloudIdentityAssessmentAWSAndGCPSamePrincipalBothImport is the
// end-to-end regression for defect #3: a real bundle duplicates
// (checkId, principalId) once per provider for unresolved placeholder
// principals. Both the AWS and the GCP assessment item for the identical
// (scanId, runId, checkId, principalId) must import as two distinct
// events (distinct Cerebro event ids derived from distinct record ids),
// never collapse to one and reject the run's assessment block.
func TestCloudIdentityAssessmentAWSAndGCPSamePrincipalBothImport(t *testing.T) {
	principalID := "k8s://prod-eks/billing/sa/worker"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/assessments":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
				cloudIdentityRunItem(),
				cloudIdentityAssessmentItemWithProvider("aws", principalID),
				cloudIdentityAssessmentItemWithProvider("gcp", principalID),
			}, "nextCursor": "", "hasMore": false})
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
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	assessmentIDs := map[string]bool{}
	for _, event := range pull.Events {
		if event.Kind == "vulnview.cloud_identity_assessment" {
			assessmentIDs[event.Id] = true
		}
	}
	if len(assessmentIDs) != 2 {
		t.Fatalf("got %d distinct assessment event ids for the same (checkId, principalId) across AWS and GCP, want 2 (no dedupe collision); events = %+v", len(assessmentIDs), pull.Events)
	}
}
