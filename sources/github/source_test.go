package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/githubaudit"
	"github.com/writer/cerebro/sources/internal/githubcanary"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "github" {
		t.Fatalf("Spec().Id = %q, want %q", source.Spec().Id, "github")
	}
}

func TestCheckRequiresOwner(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(nil)); err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestReadRequiresRepo(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"owner": "writer"}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestAuditRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family": "audit",
		"owner":  "writer",
	})); err == nil {
		t.Fatal("Check(audit) error = nil, want non-nil")
	}
}

func TestAuditSupportsGitHubAppAuth(t *testing.T) {
	privateKey := testGitHubAppPrivateKeyPEM(t)
	tokenRequests := 0
	apiHandler := newGitHubAPIHandler(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v3/app/installations/123/access_tokens" {
			tokenRequests++
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
				t.Fatalf("app token Authorization = %q, want bearer JWT", got)
			}
			if err := json.NewEncoder(w).Encode(map[string]string{
				"token":      "installation-token",
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			}); err != nil {
				t.Fatalf("encode installation token response: %v", err)
			}
			return
		}
		if r.URL.Path == "/api/v3/orgs/writer/audit-log" {
			if got := r.Header.Get("Authorization"); got != "Bearer installation-token" {
				t.Fatalf("audit Authorization = %q, want installation token", got)
			}
		}
		apiHandler.ServeHTTP(w, r)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"app_id":          "42",
		"base_url":        server.URL,
		"family":          familyAudit,
		"installation_id": "123",
		"owner":           "writer",
		"private_key":     privateKey,
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit app auth) error = %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("installation token requests = %d, want 1", tokenRequests)
	}
}

func TestGitHubAppAuthRejectsPartialCredentials(t *testing.T) {
	if _, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"app_id": "42",
		"family": familyAudit,
		"owner":  "writer",
	}), false, false); err == nil {
		t.Fatal("parseSettings() error = nil, want partial app auth error")
	}
}

func TestNewFixtureReturnsFixtureURNs(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test"}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(urns))
	}
	if got := urns[0].String(); got != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover()[0] = %q, want pull request repository URN", got)
	}
}

func testGitHubAppPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func assertGitHubCheckpointEnvelope(t *testing.T, checkpoint *cerebrov1.SourceCheckpoint, family string) {
	t.Helper()
	if checkpoint == nil {
		t.Fatal("checkpoint = nil, want resumable envelope")
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatalf("checkpoint cursor %q is not an envelope", checkpoint.GetCursorOpaque())
	}
	if envelope.Source != "github" {
		t.Fatalf("checkpoint source = %q, want github", envelope.Source)
	}
	if envelope.Family != family {
		t.Fatalf("checkpoint family = %q, want %q", envelope.Family, family)
	}
	if !envelope.ResumableCheckpoint {
		t.Fatalf("checkpoint resumable = false, want true")
	}
}

func TestNewFixtureReplaysFixturePages(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"token": "test"})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want non-nil")
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatal("second.NextCursor != nil, want nil")
	}

	final, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "2"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func TestNewFixtureReplaysRepositoryFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"family": familyRepository, "token": "test"})
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(repository) error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("len(repository Discover()) = %d, want 1", len(urns))
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(repository) error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "github.code.repository" {
		t.Fatalf("repository fixture events = %#v, want one github.code.repository event", pull.Events)
	}
	if got := pull.Events[0].Attributes["owner_login"]; got != "writer" {
		t.Fatalf("owner_login = %q, want writer", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	for _, tc := range []struct {
		family string
		kinds  []string
	}{
		{family: familyAudit, kinds: []string{"github.audit"}},
		{family: familyDependabot, kinds: []string{"github.dependabot_alert"}},
		{family: familyOrgInventory, kinds: []string{"github.org_member", "github.org_installation"}},
		{family: familyPullRequest, kinds: []string{"github.pull_request", "github.pull_request"}},
		{family: familyRepository, kinds: []string{"github.code.repository"}},
		{family: familySecretScanning, kinds: []string{"github.secret_scanning_alert"}},
	} {
		t.Run(tc.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{"family": tc.family, "token": "test"})
			_, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tc.family, err)
			}

			for index, wantKind := range tc.kinds {
				var cursor *cerebrov1.SourceCursor
				if index > 0 {
					cursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(index)}
				}
				pull, err := source.Read(context.Background(), cfg, cursor)
				if err != nil {
					t.Fatalf("Read(%s, cursor=%v) error = %v", tc.family, cursor, err)
				}
				if len(pull.Events) != 1 {
					t.Fatalf("len(Read(%s).Events) = %d, want 1", tc.family, len(pull.Events))
				}
				if got := pull.Events[0].Kind; got != wantKind {
					t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tc.family, got, wantKind)
				}
			}
		})
	}
}

func TestReadRejectsNegativeCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"owner": "writer", "repo": "cerebro"})

	if _, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "-1"}); err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestReadTrimsCursor(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})

	pull, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: " 1 "})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestCheckDiscoverAndReadLiveGitHubPullRequestPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	checkCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
	})
	if err := source.Check(context.Background(), checkCfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	discoverCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
	})
	discover, err := source.Discover(context.Background(), discoverCfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover()[0] = %q, want repo urn", discover[0])
	}

	readCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})
	first, err := source.Read(context.Background(), readCfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || sourcecdk.CursorToken(first.NextCursor) != "2" {
		t.Fatalf("first.NextCursor = %#v, want page 2", first.NextCursor)
	}
	if !sourcecdk.ResumableCursorOpaque(first.NextCursor.GetOpaque()) {
		t.Fatalf("first.NextCursor.Opaque = %q, want resumable envelope", first.NextCursor.GetOpaque())
	}
	assertGitHubCheckpointEnvelope(t, first.Checkpoint, familyPullRequest)
	firstCheckpoint, ok := sourcecdk.DecodeCursorEnvelope(first.Checkpoint.GetCursorOpaque())
	if !ok || firstCheckpoint.Token != "2" {
		t.Fatalf("first.Checkpoint = %#v, want resumable envelope with token 2", first.Checkpoint)
	}
	resumed, err := source.ReadWithCheckpoint(context.Background(), readCfg, first.NextCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(resumed from continuation cursor) error = %v", err)
	}
	if len(resumed.Events) != 1 || resumed.Events[0].GetId() != "github-pr-writer-cerebro-442-1776902400" {
		t.Fatalf("resumed events = %#v, want second fixture PR", resumed.Events)
	}

	second, err := source.Read(context.Background(), readCfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	assertGitHubCheckpointEnvelope(t, second.Checkpoint, familyPullRequest)
	if !sourcecdk.ResumableCursorOpaque(second.Checkpoint.GetCursorOpaque()) {
		t.Fatalf("second.Checkpoint.CursorOpaque = %q, want resumable envelope", second.Checkpoint.GetCursorOpaque())
	}

	final, err := source.Read(context.Background(), readCfg, &cerebrov1.SourceCursor{Opaque: "3"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func TestReadWithCheckpointShortCircuitsUnchangedPullRequests(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})
	watermark := time.Date(2026, 4, 23, 2, 0, 0, 0, time.UTC)
	checkpoint := sourcecdk.IncrementalWatermarkCheckpoint("github", familyPullRequest, []*cerebrov1.EventEnvelope{{
		Id:         "github-pr-writer-cerebro-443-1776909600",
		OccurredAt: timestamppb.New(watermark),
	}}, sourcecdk.IncrementalWatermarkState{})

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil after watermark short-circuit", pull.NextCursor)
	}
	if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonWatermarkReached {
		t.Fatalf("ShortCircuitReason = %q, want watermark_reached", pull.ShortCircuitReason)
	}
}

func TestReadWithCheckpointKeepsNewEqualTimestampPullRequest(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"state":    "all",
	})
	watermark := time.Date(2026, 4, 23, 2, 0, 0, 0, time.UTC)
	checkpoint := sourcecdk.IncrementalWatermarkCheckpoint("github", familyPullRequest, []*cerebrov1.EventEnvelope{{
		Id:         "different-boundary-id",
		OccurredAt: timestamppb.New(watermark),
	}}, sourcecdk.IncrementalWatermarkState{})

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want equal-timestamp new event", len(pull.Events))
	}
	if got := pull.Events[0].GetId(); got != "github-pr-writer-cerebro-443-1776909600" {
		t.Fatalf("event id = %q, want first fixture PR", got)
	}
}

func TestReadLiveGitHubRepositoryPreviewIncludesOwnerLogin(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyRepository,
		"owner":    "writer",
		"per_page": "1",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(repository) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(repository Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "github.code.repository" {
		t.Fatalf("repository event kind = %q, want github.code.repository", event.Kind)
	}
	for key, want := range map[string]string{
		"owner_login":   "writer",
		"repo_id":       "1",
		"repository":    "writer/cerebro",
		"resource_id":   "1",
		"resource_type": "code_repository",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("repository attribute %s = %q, want %q", key, got, want)
		}
	}
	var payload repositoryPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal repository payload: %v", err)
	}
	if payload.OwnerLogin != "writer" || payload.FullName != "writer/cerebro" {
		t.Fatalf("repository payload = %#v, want owner/full name", payload)
	}
}

func TestRepositoryMetadataCanaryShortCircuitsUnchangedInventory(t *testing.T) {
	var canaryRequests int
	var fullRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/repos" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") == "1" {
			canaryRequests++
		} else {
			fullRequests++
		}
		encodeRepositoryPage(t, w, "2026-04-23T00:00:00Z")
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyRepository,
		"owner":    "writer",
		"per_page": "10",
	})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("first events = %d, want 1", len(first.Events))
	}
	if metadata := sourcecdk.CheckpointFingerprint(first.Checkpoint, "github", familyRepository); metadata[sourcecdk.CanaryHashKey] == "" {
		t.Fatalf("first checkpoint metadata = %#v, want canary hash", metadata)
	}

	second, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("second events = %d, want short-circuit", len(second.Events))
	}
	if second.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("second reason = %q, want not_modified", second.ShortCircuitReason)
	}
	if canaryRequests != 2 || fullRequests != 1 {
		t.Fatalf("requests canary/full = %d/%d, want 2/1", canaryRequests, fullRequests)
	}
}

func TestRepositoryMetadataCanaryFallsThroughWhenChanged(t *testing.T) {
	var fullRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/repos" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") != "1" {
			fullRequests++
		}
		encodeRepositoryPage(t, w, "2026-04-24T00:00:00Z")
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyRepository,
		"owner":    "writer",
		"per_page": "10",
	})
	checkpoint := sourcecdk.ReconciledFingerprintCheckpoint(nil, "github", familyRepository, time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC), map[string]string{
		sourcecdk.CanaryHashKey:       "old-hash",
		sourcecdk.CanaryConfidenceKey: sourcecdk.CanaryConfidenceHeuristic,
		sourcecdk.ManifestVersionKey:  githubcanary.RepositoryManifestVersion,
		sourcecdk.CanaryConfigHashKey: sourcecdk.ConfigHash(cfg.Values()),
	}, time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC))

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want changed canary full read", len(pull.Events))
	}
	if pull.ShortCircuitReason != "" {
		t.Fatalf("ShortCircuitReason = %q, want empty on changed canary", pull.ShortCircuitReason)
	}
	if fullRequests != 1 {
		t.Fatalf("full requests = %d, want 1", fullRequests)
	}
}

func TestRepositoryMetadataCanaryForcesReconciliationAfterMaxSkips(t *testing.T) {
	var fullRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/repos" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") != "1" {
			fullRequests++
		}
		encodeRepositoryPage(t, w, "2026-04-23T00:00:00Z")
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyRepository,
		"owner":    "writer",
		"per_page": "10",
	})
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	checkpoint := first.Checkpoint
	for i := 0; i < githubcanary.MaxConsecutiveSkips; i++ {
		checkpoint = sourcecdk.SkippedFingerprintCheckpoint(checkpoint, "github", familyRepository, sourcecdk.CheckpointFingerprint(checkpoint, "github", familyRepository), time.Now().Add(time.Duration(i)*time.Minute))
	}

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(forced) error = %v", err)
	}
	if pull.ReconciliationReason != sourcecdk.PullReconciliationReasonMaxConsecutiveSkips {
		t.Fatalf("ReconciliationReason = %q, want max_consecutive_skips", pull.ReconciliationReason)
	}
	if fullRequests != 2 {
		t.Fatalf("full requests = %d, want initial and forced full reads", fullRequests)
	}
}

func TestRepositoryMetadataCanaryReturnsProviderError(t *testing.T) {
	var fullRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/repos" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") == "1" {
			http.Error(w, `{"message":"unavailable"}`, http.StatusInternalServerError)
			return
		}
		fullRequests++
		encodeRepositoryPage(t, w, "2026-04-23T00:00:00Z")
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyRepository,
		"owner":    "writer",
	})

	if _, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil); err == nil {
		t.Fatal("ReadWithCheckpoint() error = nil, want canary provider error")
	}
	if fullRequests != 0 {
		t.Fatalf("full requests = %d, want canary failure before full read", fullRequests)
	}
}

func TestLiveDiscoverKeepsLegacyOrgFamilyURNs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/members",
			"/api/v3/orgs/writer/secret-scanning/alerts":
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode discover check response: %v", err)
			}
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

	for _, tc := range []struct {
		family string
		want   sourcecdk.URN
	}{
		{family: familyOrgInventory, want: "urn:cerebro:writer:org_inventory"},
		{family: familySecretScanning, want: "urn:cerebro:writer:secret_scanning"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{
				"base_url": server.URL,
				"family":   tc.family,
				"owner":    "writer",
				"token":    "test-token",
			})
			discover, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tc.family, err)
			}
			if len(discover) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", tc.family, len(discover))
			}
			if discover[0] != tc.want {
				t.Fatalf("Discover(%s)[0] = %q, want legacy URN %q", tc.family, discover[0], tc.want)
			}
		})
	}
}

func encodeRepositoryPage(t *testing.T, w http.ResponseWriter, updatedAt string) {
	t.Helper()
	if err := json.NewEncoder(w).Encode([]map[string]any{{
		"id":             1,
		"name":           "cerebro",
		"full_name":      "writer/cerebro",
		"html_url":       "https://github.com/writer/cerebro",
		"visibility":     "public",
		"default_branch": "main",
		"private":        false,
		"archived":       false,
		"fork":           false,
		"created_at":     "2026-04-22T00:00:00Z",
		"updated_at":     updatedAt,
		"owner":          map[string]any{"login": "writer"},
	}}); err != nil {
		t.Fatalf("encode repos response: %v", err)
	}
}

func TestCheckDiscoverAndReadLiveGitHubAuditPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "audit",
		"include":  "all",
		"owner":    "writer",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(audit) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(audit)) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:org:writer" {
		t.Fatalf("Discover(audit)[0] = %q, want org urn", discover[0])
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(audit first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(audit first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || sourcecdk.CursorToken(first.NextCursor) != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "github.audit" {
		t.Fatalf("first.Events[0].Kind = %q, want github.audit", got)
	}
	if got := first.Events[0].Attributes["permission"]; got != "admin" {
		t.Fatalf("first.Events[0].Attributes[permission] = %q, want admin", got)
	}
	if got := first.Events[0].Attributes["previous_visibility"]; got != "private" {
		t.Fatalf("first.Events[0].Attributes[previous_visibility] = %q, want private", got)
	}
	if got := first.Events[0].Attributes["external_identity_nameid"]; got != "dependabot@writer.com" {
		t.Fatalf("first.Events[0].Attributes[external_identity_nameid] = %q, want dependabot@writer.com", got)
	}
	// Audit Read must resolve every actor login (not just those without
	// actor_id) so that GitHub-App identities — which always carry an
	// actor_id — still get actor_type=Bot stamped. Without resolution
	// the github.user node attributes_json would never reach the rule's
	// automation check for these accounts.
	if got := first.Events[0].Attributes["actor_type"]; got != "Bot" {
		t.Fatalf("first.Events[0].Attributes[actor_type] = %q, want Bot", got)
	}
	if got := first.Events[0].Attributes["actor_email"]; got != "dependabot@writer.com" {
		t.Fatalf("first.Events[0].Attributes[actor_email] = %q, want dependabot@writer.com", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}
	if got := payload["actor_email"]; got != "dependabot@writer.com" {
		t.Fatalf("audit payload actor_email = %#v, want dependabot@writer.com", got)
	}
	if got := payload["resource_type"]; got != "repository_vulnerability_alert" {
		t.Fatalf("audit payload resource_type = %#v, want repository_vulnerability_alert", got)
	}
	if got := payload["resource_id"]; got != "writer/cerebro" {
		t.Fatalf("audit payload resource_id = %#v, want writer/cerebro", got)
	}
	raw, ok := payload["raw"].(map[string]any)
	if !ok {
		t.Fatalf("audit payload raw = %#v, want object", payload["raw"])
	}
	if got := raw["action"]; got != "repository_vulnerability_alert.create" {
		t.Fatalf("audit raw action = %#v, want repository_vulnerability_alert.create", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(audit second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(audit second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil {
		t.Fatalf("second.Checkpoint = nil, want non-nil with empty CursorOpaque")
	}
	secondEnvelope, ok := sourcecdk.DecodeCursorEnvelope(second.Checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatalf("second.Checkpoint.CursorOpaque = %q, want canary envelope", second.Checkpoint.GetCursorOpaque())
	}
	if secondEnvelope.Token != "" {
		t.Fatalf("second checkpoint token = %q, want empty cursor on terminal audit page", secondEnvelope.Token)
	}
	if secondEnvelope.Extra[sourcecdk.FamilyFreshnessExtraKind] != "audit_log_latest_event" {
		t.Fatalf("second checkpoint canary kind = %q, want audit_log_latest_event", secondEnvelope.Extra[sourcecdk.FamilyFreshnessExtraKind])
	}
}

func TestGitHubAuditFreshnessProbeShortCircuitsUnchangedAuditLog(t *testing.T) {
	auditQueries := []url.Values{}
	auditEntry := map[string]any{
		"@timestamp":   1776916397852,
		"_document_id": "audit-doc-1",
		"action":       "org.update_member",
		"created_at":   1776916397852,
		"org":          "writer",
		"org_id":       1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/audit-log" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		auditQueries = append(auditQueries, query)
		switch query.Get("order") {
		case "desc":
			if got := query.Get("per_page"); got != "1" {
				t.Fatalf("audit canary per_page = %q, want 1", got)
			}
			if got := query.Get("after"); got != "" {
				t.Fatalf("audit canary after = %q, want empty", got)
			}
		case "asc":
		default:
			t.Fatalf("audit order = %q, want asc scan or desc canary", query.Get("order"))
		}
		if err := json.NewEncoder(w).Encode([]map[string]any{auditEntry}); err != nil {
			t.Fatalf("encode audit response: %v", err)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAudit,
		"owner":    "writer",
		"token":    "test-token",
	})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if len(auditQueries) != 2 {
		t.Fatalf("audit requests = %d, want canary plus scan", len(auditQueries))
	}
	if auditQueries[0].Get("order") != "desc" || auditQueries[1].Get("order") != "asc" {
		t.Fatalf("audit request order = %q/%q, want desc canary then asc scan", auditQueries[0].Get("order"), auditQueries[1].Get("order"))
	}
	probe, ok := sourcecdk.FamilyFreshnessProbeFromCheckpoint("github", familyAudit, first.Checkpoint)
	if !ok {
		t.Fatalf("first checkpoint %q missing freshness probe", first.Checkpoint.GetCursorOpaque())
	}
	if probe.Kind != "audit_log_latest_event" || probe.ResourceID != "latest_event" {
		t.Fatalf("probe = %#v, want audit log latest event canary", probe)
	}

	auditQueries = nil
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("len(second.Events) = %d, want unchanged short circuit", len(second.Events))
	}
	if second.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", second.ShortCircuitReason)
	}
	if len(auditQueries) != 1 || auditQueries[0].Get("order") != "desc" {
		t.Fatalf("audit requests after unchanged checkpoint = %#v, want one desc canary", auditQueries)
	}
}

func TestOrgInventoryAuditLogCanaryShortCircuitsWhenAuthorizedUnchanged(t *testing.T) {
	var auditRequests int
	var memberRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/audit-log":
			auditRequests++
			if got := r.URL.Query().Get("order"); got != "desc" {
				t.Fatalf("audit canary order = %q, want desc", got)
			}
			encodeAuditCanaryEntry(t, w, "audit-doc-1")
		case "/api/v3/orgs/writer/members":
			memberRequests++
			encodeOrgMembers(t, w)
		case "/api/v3/orgs/writer/outside_collaborators":
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode outside collaborators: %v", err)
			}
		case "/api/v3/orgs/writer/installations":
			if err := json.NewEncoder(w).Encode(map[string]any{"installations": []map[string]any{}}); err != nil {
				t.Fatalf("encode installations: %v", err)
			}
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
		"audit_log_canary": "true",
		"base_url":         server.URL,
		"family":           familyOrgInventory,
		"owner":            "writer",
		"token":            "test-token",
	})
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) == 0 {
		t.Fatal("first Events = 0, want org inventory read")
	}
	if metadata := sourcecdk.CheckpointFingerprint(first.Checkpoint, "github", familyOrgInventory); metadata[sourcecdk.CanaryKindKey] != githubcanary.AuditLogKind {
		t.Fatalf("first checkpoint metadata = %#v, want audit-log canary", metadata)
	}

	second, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("second Events = %d, want short-circuit", len(second.Events))
	}
	if second.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("second ShortCircuitReason = %q, want not_modified", second.ShortCircuitReason)
	}
	if auditRequests != 2 || memberRequests != 1 {
		t.Fatalf("audit/member requests = %d/%d, want 2/1", auditRequests, memberRequests)
	}
}

func TestOrgInstallationEventIncludesPolicyEvidenceFields(t *testing.T) {
	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	createdAt := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC)

	event, err := orgInstallationEvent(settings{owner: "writer"}, &gogithub.Installation{
		ID:                  gogithub.Int64(123),
		AppSlug:             gogithub.String("security-bot"),
		TargetType:          gogithub.String("Organization"),
		RepositorySelection: gogithub.String("all"),
		Events:              []string{"push", "pull_request"},
		Permissions: &gogithub.InstallationPermissions{
			Administration: gogithub.String("write"),
			Contents:       gogithub.String("write"),
			Members:        gogithub.String("read"),
			Metadata:       gogithub.String("read"),
			Secrets:        gogithub.String("write"),
			Workflows:      gogithub.String("write"),
		},
		CreatedAt: &gogithub.Timestamp{Time: createdAt},
		UpdatedAt: &gogithub.Timestamp{Time: updatedAt},
	}, now)
	if err != nil {
		t.Fatalf("orgInstallationEvent() error = %v", err)
	}

	wantAttrs := map[string]string{
		"app_slug":             "security-bot",
		"created_at":           createdAt.Format(time.RFC3339),
		"events":               "push,pull_request",
		"installation_id":      "123",
		"permissions":          "administration:write,contents:write,members:read,metadata:read,secrets:write,workflows:write",
		"repository_selection": "all",
		"target_type":          "Organization",
		"updated_at":           updatedAt.Format(time.RFC3339),
	}
	for key, want := range wantAttrs {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}

	var payload orgInstallationPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal org installation payload: %v", err)
	}
	if len(payload.Permissions) != 6 || payload.Permissions[0] != "administration:write" {
		t.Fatalf("payload permissions = %#v, want populated GitHub App permissions", payload.Permissions)
	}
	if len(payload.Events) != 2 || payload.Events[0] != "push" {
		t.Fatalf("payload events = %#v, want populated GitHub App events", payload.Events)
	}
}

func TestOrgInventoryAuditLogCanaryFallsThroughWhenAuthorizedChanged(t *testing.T) {
	var auditRequests int
	var memberRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/audit-log":
			auditRequests++
			encodeAuditCanaryEntry(t, w, "audit-doc-"+strconv.Itoa(auditRequests))
		case "/api/v3/orgs/writer/members":
			memberRequests++
			encodeOrgMembers(t, w)
		case "/api/v3/orgs/writer/outside_collaborators":
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode outside collaborators: %v", err)
			}
		case "/api/v3/orgs/writer/installations":
			if err := json.NewEncoder(w).Encode(map[string]any{"installations": []map[string]any{}}); err != nil {
				t.Fatalf("encode installations: %v", err)
			}
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
		"audit_log_canary": "true",
		"base_url":         server.URL,
		"family":           familyOrgInventory,
		"owner":            "writer",
		"token":            "test-token",
	})
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) == 0 {
		t.Fatal("second Events = 0, want changed canary full read")
	}
	if second.ShortCircuitReason != "" {
		t.Fatalf("second ShortCircuitReason = %q, want empty changed canary", second.ShortCircuitReason)
	}
	if auditRequests != 2 || memberRequests != 2 {
		t.Fatalf("audit/member requests = %d/%d, want 2/2", auditRequests, memberRequests)
	}
}

func TestOrgInventoryAuditLogCanaryUnauthorizedFallsBack(t *testing.T) {
	var memberRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/audit-log":
			http.Error(w, `{"message":"Resource not accessible by integration"}`, http.StatusForbidden)
		case "/api/v3/orgs/writer/members":
			memberRequests++
			encodeOrgMembers(t, w)
		case "/api/v3/orgs/writer/outside_collaborators":
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode outside collaborators: %v", err)
			}
		case "/api/v3/orgs/writer/installations":
			if err := json.NewEncoder(w).Encode(map[string]any{"installations": []map[string]any{}}); err != nil {
				t.Fatalf("encode installations: %v", err)
			}
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
		"audit_log_canary": "true",
		"base_url":         server.URL,
		"family":           familyOrgInventory,
		"owner":            "writer",
		"token":            "test-token",
	})
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) == 0 {
		t.Fatal("Events = 0, want fallback org inventory read")
	}
	if pull.ShortCircuitReason != "" {
		t.Fatalf("ShortCircuitReason = %q, want empty fallback", pull.ShortCircuitReason)
	}
	if memberRequests != 1 {
		t.Fatalf("member requests = %d, want 1", memberRequests)
	}
}

func TestOrgInventoryAuditLogCanaryProviderError(t *testing.T) {
	var memberRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/audit-log":
			http.Error(w, `{"message":"unavailable"}`, http.StatusInternalServerError)
		case "/api/v3/orgs/writer/members":
			memberRequests++
			encodeOrgMembers(t, w)
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
		"audit_log_canary": "true",
		"base_url":         server.URL,
		"family":           familyOrgInventory,
		"owner":            "writer",
		"token":            "test-token",
	})
	if _, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil); err == nil {
		t.Fatal("ReadWithCheckpoint() error = nil, want audit canary provider error")
	}
	if memberRequests != 0 {
		t.Fatalf("member requests = %d, want canary error before fallback read", memberRequests)
	}
}

func TestGitHubAuditFreshnessProbeForcesReconcileAfterMaxSkips(t *testing.T) {
	auditQueries := []url.Values{}
	auditEntry := map[string]any{
		"@timestamp":   1776916397852,
		"_document_id": "audit-doc-1",
		"action":       "org.update_member",
		"created_at":   1776916397852,
		"org":          "writer",
		"org_id":       1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/audit-log" {
			http.NotFound(w, r)
			return
		}
		auditQueries = append(auditQueries, r.URL.Query())
		if err := json.NewEncoder(w).Encode([]map[string]any{auditEntry}); err != nil {
			t.Fatalf("encode audit response: %v", err)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAudit,
		"owner":    "writer",
		"token":    "test-token",
	})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	probe, ok := sourcecdk.FamilyFreshnessProbeFromCheckpoint("github", familyAudit, first.Checkpoint)
	if !ok {
		t.Fatalf("first checkpoint %q missing freshness probe", first.Checkpoint.GetCursorOpaque())
	}
	probe.SkipCount = githubaudit.FreshnessMaxSkipCount
	probe.FullReadAt = time.Now().UTC()
	checkpoint := sourcecdk.FamilyFreshnessCheckpoint("github", familyAudit, first.Checkpoint, probe)

	auditQueries = nil
	forced, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(forced) error = %v", err)
	}
	if len(forced.Events) != 1 {
		t.Fatalf("len(forced.Events) = %d, want full audit scan after max skips", len(forced.Events))
	}
	if forced.ShortCircuitReason != "" {
		t.Fatalf("forced.ShortCircuitReason = %q, want empty after full scan", forced.ShortCircuitReason)
	}
	if len(auditQueries) != 2 || auditQueries[0].Get("order") != "desc" || auditQueries[1].Get("order") != "asc" {
		t.Fatalf("audit requests after max skips = %#v, want desc canary then asc scan", auditQueries)
	}
	nextProbe, ok := sourcecdk.FamilyFreshnessProbeFromCheckpoint("github", familyAudit, forced.Checkpoint)
	if !ok {
		t.Fatalf("forced checkpoint %q missing freshness probe", forced.Checkpoint.GetCursorOpaque())
	}
	if nextProbe.SkipCount != 0 {
		t.Fatalf("forced skip count = %d, want reset", nextProbe.SkipCount)
	}
	if nextProbe.Reason != sourcecdk.FamilyFreshnessReasonMaxSkipCount {
		t.Fatalf("forced reason = %q, want max_skip_count", nextProbe.Reason)
	}
}

func TestGitHubAuditFreshnessProbeFailsOpenToFullRead(t *testing.T) {
	auditQueries := []url.Values{}
	auditEntry := map[string]any{
		"@timestamp":   1776916397852,
		"_document_id": "audit-doc-1",
		"action":       "org.update_member",
		"created_at":   1776916397852,
		"org":          "writer",
		"org_id":       1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/audit-log" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		auditQueries = append(auditQueries, query)
		if query.Get("order") == "desc" {
			http.Error(w, "metadata probe failed", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode([]map[string]any{auditEntry}); err != nil {
			t.Fatalf("encode audit response: %v", err)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAudit,
		"owner":    "writer",
		"token":    "test-token",
	})

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want full audit scan after canary error", len(pull.Events))
	}
	if len(auditQueries) != 2 || auditQueries[0].Get("order") != "desc" || auditQueries[1].Get("order") != "asc" {
		t.Fatalf("audit requests after canary error = %#v, want desc canary then asc scan", auditQueries)
	}
}

func TestGitHubAuditUnavailableDoesNotFailCheckOrRead(t *testing.T) {
	auditRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/audit-log" {
			http.NotFound(w, r)
			return
		}
		auditRequests++
		http.NotFound(w, r)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAudit,
		"owner":    "writer",
		"token":    "test-token",
	})

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit unavailable) error = %v", err)
	}
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(audit unavailable) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
	}
	if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
	}
	if pull.Checkpoint == nil {
		t.Fatal("pull.Checkpoint = nil, want freshness checkpoint for unavailable audit log")
	}
	if auditRequests < 2 {
		t.Fatalf("audit requests = %d, want check and read attempts", auditRequests)
	}
}

func TestGitHubProviderUnavailableDoesNotFailGraphRuntimeFamilies(t *testing.T) {
	for _, tt := range []struct {
		name   string
		family string
		repo   string
	}{
		{name: "dependabot", family: familyDependabot, repo: "cerebro"},
		{name: "org inventory", family: familyOrgInventory},
		{name: "repository", family: familyRepository},
		{name: "secret scanning", family: familySecretScanning},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				requests++
				http.NotFound(w, r)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackBaseURL = true
			values := map[string]string{
				"base_url": server.URL,
				"family":   tt.family,
				"owner":    "writer",
				"token":    "test-token",
			}
			if tt.repo != "" {
				values["repo"] = tt.repo
			}
			cfg := sourcecdk.NewConfig(values)

			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check(%s unavailable) error = %v", tt.family, err)
			}
			pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
			if err != nil {
				t.Fatalf("ReadWithCheckpoint(%s unavailable) error = %v", tt.family, err)
			}
			if len(pull.Events) != 0 {
				t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
			}
			if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
				t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
			}
			if requests == 0 {
				t.Fatal("requests = 0, want provider probe attempted")
			}
		})
	}
}

func TestGitHubAppInstallationTokenUnavailableDoesNotFailRepositoryRuntime(t *testing.T) {
	privateKey := testGitHubAppPrivateKeyPEM(t)
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v3/app/installations/123/access_tokens" {
			tokenRequests++
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected GitHub API request after failed app token fetch: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"app_id":          "42",
		"base_url":        server.URL,
		"family":          familyRepository,
		"installation_id": "123",
		"owner":           "writer",
		"private_key":     privateKey,
	})

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(repository app token unavailable) error = %v", err)
	}
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(repository app token unavailable) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
	}
	if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
	}
	if tokenRequests < 2 {
		t.Fatalf("installation token requests = %d, want check and read attempts", tokenRequests)
	}
}

func TestGitHubAppInstallationTokenUnavailableDoesNotFailAuditRuntime(t *testing.T) {
	privateKey := testGitHubAppPrivateKeyPEM(t)
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v3/app/installations/123/access_tokens" {
			tokenRequests++
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected GitHub API request after failed app token fetch: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"app_id":          "42",
		"base_url":        server.URL,
		"family":          familyAudit,
		"installation_id": "123",
		"owner":           "writer",
		"private_key":     privateKey,
	})

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit app token unavailable) error = %v", err)
	}
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(audit app token unavailable) error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
	}
	if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
	}
	if tokenRequests < 2 {
		t.Fatalf("installation token requests = %d, want check and read attempts", tokenRequests)
	}
}

func TestGitHubPullRequestOwnerUnavailableStillFails(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests++
		http.NotFound(w, r)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyPullRequest,
		"owner":    "writer",
		"token":    "test-token",
	})

	if err := source.Check(context.Background(), cfg); err == nil {
		t.Fatal("Check(pull_request unavailable owner) error = nil, want non-nil")
	}
	if _, err := source.Discover(context.Background(), cfg); err == nil {
		t.Fatal("Discover(pull_request unavailable owner) error = nil, want non-nil")
	}
	if requests == 0 {
		t.Fatal("requests = 0, want provider probe attempted")
	}
}

func TestGitHubRepositoryCheckDoesNotDoubleWrapLookupErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"message":"server error"}`, http.StatusInternalServerError)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	for _, tt := range []struct {
		name   string
		values map[string]string
	}{
		{
			name:   "repo",
			values: map[string]string{"base_url": server.URL, "family": familyRepository, "owner": "writer", "repo": "cerebro"},
		},
		{
			name:   "owner",
			values: map[string]string{"base_url": server.URL, "family": familyRepository, "owner": "writer"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(tt.values))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
			if got := errorWrapDepth(err); got != 1 {
				t.Fatalf("error wrap depth = %d, want 1", got)
			}
		})
	}
}

func errorWrapDepth(err error) int {
	depth := 0
	for err != nil {
		err = errors.Unwrap(err)
		if err != nil {
			depth++
		}
	}
	return depth
}

func TestGitHubAuditFreshnessCheckpointDoesNotExposeProviderMetadata(t *testing.T) {
	auditEntry := map[string]any{
		"@timestamp":   1776916397852,
		"_document_id": "audit-doc-sensitive-tenant-123",
		"action":       "org.update_member",
		"actor":        "octocat-sensitive",
		"created_at":   1776916397852,
		"org":          "writer",
		"org_id":       1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/audit-log" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("phrase"); got != "actor:octocat-sensitive repo:writer/private" {
			t.Fatalf("audit phrase = %q, want configured phrase", got)
		}
		if err := json.NewEncoder(w).Encode([]map[string]any{auditEntry}); err != nil {
			t.Fatalf("encode audit response: %v", err)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAudit,
		"owner":    "writer",
		"phrase":   "actor:octocat-sensitive repo:writer/private",
		"token":    "test-token",
	})

	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(pull.Checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatalf("checkpoint cursor %q is not an envelope", pull.Checkpoint.GetCursorOpaque())
	}
	for _, forbidden := range []string{
		"audit-doc-sensitive-tenant-123",
		"octocat-sensitive",
		"actor:octocat-sensitive",
		"repo:writer/private",
	} {
		if strings.Contains(pull.Checkpoint.GetCursorOpaque(), forbidden) {
			t.Fatalf("checkpoint cursor leaked %q: %s", forbidden, pull.Checkpoint.GetCursorOpaque())
		}
		for key, value := range envelope.Extra {
			if strings.Contains(value, forbidden) {
				t.Fatalf("checkpoint extra %s leaked %q in %q", key, forbidden, value)
			}
		}
	}
	if got := envelope.Extra[sourcecdk.FamilyFreshnessExtraResourceID]; got != "latest_event" {
		t.Fatalf("canary resource id = %q, want opaque latest_event", got)
	}
}

func encodeAuditCanaryEntry(t *testing.T, w http.ResponseWriter, documentID string) {
	t.Helper()
	if err := json.NewEncoder(w).Encode([]map[string]any{{
		"@timestamp":   1776916397852,
		"_document_id": documentID,
		"action":       "org.update_member",
		"actor":        "octocat",
		"created_at":   1776916397852,
		"org":          "writer",
	}}); err != nil {
		t.Fatalf("encode audit canary entry: %v", err)
	}
}

func encodeOrgMembers(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	if err := json.NewEncoder(w).Encode([]map[string]any{{
		"login":    "octocat",
		"id":       1,
		"html_url": "https://github.com/octocat",
	}}); err != nil {
		t.Fatalf("encode org members: %v", err)
	}
}

func TestNextAuditCursorIgnoresBefore(t *testing.T) {
	if got := nextAuditCursor(&gogithub.Response{Before: "cursor-1"}); got != "" {
		t.Fatalf("nextAuditCursor() = %q, want empty cursor", got)
	}
}

func TestAuditScopeDefaultsToOrganization(t *testing.T) {
	if got := auditScope(&gogithub.AuditEntry{}, map[string]any{}, settings{owner: "writer"}); got != "organization" {
		t.Fatalf("auditScope() = %q, want organization", got)
	}
}

func TestAuditScopeKeepsOwnerBackedEntriesAtOrganizationScope(t *testing.T) {
	entry := &gogithub.AuditEntry{User: gogithub.String("octocat")}
	if got := auditScope(entry, map[string]any{}, settings{owner: "writer"}); got != "organization" {
		t.Fatalf("auditScope() = %q, want organization", got)
	}
}

func TestAuditAttributesForwardRulesetWeakeningMetadata(t *testing.T) {
	attributes := auditAttributes(&gogithub.AuditEntry{
		Action: gogithub.String("repository_ruleset.update"),
	}, map[string]any{
		"repo":                          "writer/cerebro",
		"ruleset_enforcement":           "active",
		"required_status_check_removed": true,
		"bypass_actor_added":            true,
		"changes": map[string]any{
			"required_status_checks": "removed",
		},
	}, settings{owner: "writer"}, auditActorResolution{})

	if got := attributes["required_status_check_removed"]; got != "true" {
		t.Fatalf("required_status_check_removed = %q, want true", got)
	}
	if got := attributes["bypass_actor_added"]; got != "true" {
		t.Fatalf("bypass_actor_added = %q, want true", got)
	}
	if got := attributes["changes"]; !strings.Contains(got, "required_status_checks") {
		t.Fatalf("changes = %q, want encoded ruleset changes", got)
	}
}

func TestAuditAttributesForwardResolvedActorTypeForGitEvents(t *testing.T) {
	attributes := auditAttributes(&gogithub.AuditEntry{
		Action: gogithub.String("git.clone"),
		Actor:  gogithub.String("deploy_key"),
	}, map[string]any{
		"org":                      "WriterInternal",
		"org_id":                   112636266,
		"programmatic_access_type": "Public Key (User/Deploy)",
		"repo":                     "WriterInternal/k8s",
		"transport_protocol_name":  "ssh",
		"user_id":                  0,
	}, settings{owner: "WriterInternal"}, auditActorResolution{Login: "deploy_key", Type: "Unresolved"})

	if got := attributes["actor_type"]; got != "Unresolved" {
		t.Fatalf("actor_type = %q, want Unresolved", got)
	}
	if got := attributes["programmatic_access_type"]; got != "Public Key (User/Deploy)" {
		t.Fatalf("programmatic_access_type = %q, want Public Key (User/Deploy)", got)
	}
	if got := attributes["org_id"]; got != "112636266" {
		t.Fatalf("org_id = %q, want 112636266", got)
	}
	if got := attributes["actor_id"]; got != "" {
		t.Fatalf("actor_id = %q, want empty for unresolved deploy-key actor", got)
	}
	if got := attributes["transport_protocol_name"]; got != "ssh" {
		t.Fatalf("transport_protocol_name = %q, want ssh", got)
	}
}

func TestCheckDiscoverAndReadLiveGitHubDependabotAlertPreview(t *testing.T) {
	server := httptest.NewServer(newGitHubAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "dependabot_alert",
		"owner":    "writer",
		"per_page": "1",
		"repo":     "cerebro",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(dependabot_alert) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(dependabot_alert) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(dependabot_alert)) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer:repo:writer/cerebro" {
		t.Fatalf("Discover(dependabot_alert)[0] = %q, want repo urn", discover[0])
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(dependabot_alert first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(dependabot_alert first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || sourcecdk.CursorToken(first.NextCursor) != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if !sourcecdk.ResumableCursorOpaque(first.NextCursor.GetOpaque()) {
		t.Fatalf("first.NextCursor.Opaque = %q, want resumable envelope", first.NextCursor.GetOpaque())
	}
	if got := first.Events[0].Kind; got != "github.dependabot_alert" {
		t.Fatalf("first.Events[0].Kind = %q, want github.dependabot_alert", got)
	}
	if got := first.Events[0].Attributes["severity"]; got != "high" {
		t.Fatalf("first.Events[0].Attributes[severity] = %q, want high", got)
	}
	if got := first.Events[0].Attributes["package"]; got != "golang.org/x/crypto" {
		t.Fatalf("first.Events[0].Attributes[package] = %q, want golang.org/x/crypto", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal dependabot payload: %v", err)
	}
	if got := payload["ghsa_id"]; got != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("dependabot payload ghsa_id = %#v, want GHSA", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(dependabot_alert second) error = %v", err)
	}
	if len(second.Events) != 0 {
		t.Fatalf("len(Read(dependabot_alert second).Events) = %d, want 0", len(second.Events))
	}
}

func TestDependabotAlertEventIncludesDismissedBy(t *testing.T) {
	observedAt := time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC)
	event, err := dependabotAlertEvent(settings{owner: "writer", repo: "cerebro"}, &gogithub.DependabotAlert{
		Number:      gogithub.Int(7),
		State:       gogithub.String("dismissed"),
		CreatedAt:   &gogithub.Timestamp{Time: observedAt},
		UpdatedAt:   &gogithub.Timestamp{Time: observedAt},
		DismissedBy: &gogithub.User{Login: gogithub.String("alice"), ID: gogithub.Int64(123)},
	})
	if err != nil {
		t.Fatalf("dependabotAlertEvent() error = %v", err)
	}
	if got := event.Attributes["dismissed_by"]; got != "alice" {
		t.Fatalf("dismissed_by = %q, want alice", got)
	}
	if got := event.Attributes["dismissed_by_id"]; got != "123" {
		t.Fatalf("dismissed_by_id = %q, want 123", got)
	}
	var payload dependabotAlertPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal dependabot payload: %v", err)
	}
	if payload.DismissedBy != "alice" || payload.DismissedByID != 123 {
		t.Fatalf("dependabot dismissed actor = %q/%d, want alice/123", payload.DismissedBy, payload.DismissedByID)
	}
}

func TestSecretScanningUsesUpdatedSortAndCursorPagination(t *testing.T) {
	queries := []url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/secret-scanning/alerts" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		queries = append(queries, query)
		if query.Get("after") == "" {
			w.Header().Set("Link", "</api/v3/orgs/writer/secret-scanning/alerts?after=cursor-2>; rel=\"next\"")
			encodeSecretScanningAlerts(t, w, 1, "2026-04-24T14:00:00Z")
			return
		}
		if query.Get("after") == "cursor-2" {
			encodeSecretScanningAlerts(t, w, 2, "2026-04-24T13:00:00Z")
			return
		}
		t.Fatalf("unexpected after cursor %q", query.Get("after"))
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familySecretScanning,
		"owner":    "writer",
		"per_page": "1",
		"token":    "test-token",
	})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || sourcecdk.CursorToken(first.NextCursor) != "after:cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want after cursor", first.NextCursor)
	}
	if !sourcecdk.ResumableCursorOpaque(first.NextCursor.GetOpaque()) {
		t.Fatalf("first.NextCursor.Opaque = %q, want resumable envelope", first.NextCursor.GetOpaque())
	}

	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["alert_number"]; got != "2" {
		t.Fatalf("second alert_number = %q, want 2", got)
	}
	if len(queries) != 2 {
		t.Fatalf("len(queries) = %d, want 2", len(queries))
	}
	for i, query := range queries {
		if got := query.Get("sort"); got != "updated" {
			t.Fatalf("query %d sort = %q, want updated", i, got)
		}
		if got := query.Get("direction"); got != "desc" {
			t.Fatalf("query %d direction = %q, want desc", i, got)
		}
	}
	if _, ok := queries[0]["after"]; !ok {
		t.Fatalf("first query missing empty after cursor: %#v", queries[0])
	}
	if got := queries[1].Get("after"); got != "cursor-2" {
		t.Fatalf("second query after = %q, want cursor-2", got)
	}
}

func TestSecretScanningShortCircuitsAtUpdatedWatermark(t *testing.T) {
	watermark := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	checkpoint := &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(watermark)}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests++
		w.Header().Set("Link", "</api/v3/orgs/writer/secret-scanning/alerts?after=cursor-2>; rel=\"next\"")
		encodeSecretScanningAlerts(t, w, 1, "2026-04-24T11:00:00Z")
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familySecretScanning,
		"owner":    "writer",
		"per_page": "1",
		"token":    "test-token",
	})
	pull, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if pull.ShortCircuitReason != sourcecdk.PullShortCircuitReasonWatermarkReached {
		t.Fatalf("ShortCircuitReason = %q, want watermark_reached", pull.ShortCircuitReason)
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil", pull.NextCursor)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one-page short circuit", requests)
	}
}

func encodeSecretScanningAlerts(t *testing.T, w http.ResponseWriter, number int, updatedAt string) {
	t.Helper()
	if err := json.NewEncoder(w).Encode([]map[string]any{{
		"number":      number,
		"state":       "open",
		"secret_type": "token",
		"created_at":  "2026-04-01T00:00:00Z",
		"updated_at":  updatedAt,
		"repository":  map[string]any{"full_name": "writer/cerebro"},
	}}); err != nil {
		t.Fatalf("encode secret scanning alerts: %v", err)
	}
}

func TestSecretScanningAlertEventIncludesActorLogins(t *testing.T) {
	observedAt := time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC)
	event, err := secretScanningAlertEvent(settings{owner: "writer"}, &gogithub.SecretScanningAlert{
		Number:                   gogithub.Int(42),
		State:                    gogithub.String("resolved"),
		CreatedAt:                &gogithub.Timestamp{Time: observedAt},
		UpdatedAt:                &gogithub.Timestamp{Time: observedAt},
		Repository:               &gogithub.Repository{FullName: gogithub.String("writer/cerebro")},
		ResolvedBy:               &gogithub.User{Login: gogithub.String("alice"), ID: gogithub.Int64(123)},
		PushProtectionBypassed:   gogithub.Bool(true),
		PushProtectionBypassedBy: &gogithub.User{Login: gogithub.String("bob"), ID: gogithub.Int64(456)},
	})
	if err != nil {
		t.Fatalf("secretScanningAlertEvent() error = %v", err)
	}
	if got := event.Attributes["resolved_by"]; got != "alice" {
		t.Fatalf("resolved_by = %q, want alice", got)
	}
	if got := event.Attributes["resolved_by_id"]; got != "123" {
		t.Fatalf("resolved_by_id = %q, want 123", got)
	}
	if got := event.Attributes["push_protection_bypassed_by"]; got != "bob" {
		t.Fatalf("push_protection_bypassed_by = %q, want bob", got)
	}
	if got := event.Attributes["push_protection_bypassed_by_id"]; got != "456" {
		t.Fatalf("push_protection_bypassed_by_id = %q, want 456", got)
	}
	var payload secretScanningAlertPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal secret scanning payload: %v", err)
	}
	if payload.ResolvedBy != "alice" || payload.ResolvedByID != 123 {
		t.Fatalf("secret resolved actor = %q/%d, want alice/123", payload.ResolvedBy, payload.ResolvedByID)
	}
	if payload.PushProtectionBypassedBy != "bob" || payload.PushProtectionBypassedByID != 456 {
		t.Fatalf("secret bypass actor = %q/%d, want bob/456", payload.PushProtectionBypassedBy, payload.PushProtectionBypassedByID)
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, baseURL := range []string{
		"http://github.example.com",
		"https://user@github.example.com",
		"https://github.example.com/path",
		"https://github.example.com?token=leak",
		"https://github.example.com?",
		"https://localhost",
		"https://localhost.",
		"https://[::1%25lo0]",
		"https://127.1",
		"https://10.0.0.1",
		"https://172.16.0.1",
		"https://192.168.1.10",
		"https://169.254.169.254",
		"https://[fe80::1]",
		"https://0.0.0.0",
		"https://2130706433",
		"https://0177.0.0.1",
		"https://0x7f000001",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url": baseURL,
				"owner":    "writer",
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestCheckDoesNotFollowRedirects(t *testing.T) {
	redirectHit := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectHit = true
	}))
	defer redirectTarget.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirector.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url": redirector.URL,
		"owner":    "writer",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil redirect response")
	}
	if redirectHit {
		t.Fatal("Check() followed redirect target")
	}
}

func TestSourceHTTPClientRejectsHostsResolvingToPrivateIPs(t *testing.T) {
	called := false
	client := sourceHTTPClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	})
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ghe.example.com/api/v3", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := client.Do(request)
	if response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("response.Body.Close() error = %v", closeErr)
		}
	}
	if err == nil {
		t.Fatal("Do() error = nil, want non-nil")
	}
	if called {
		t.Fatal("Do() reached wrapped transport for unsafe resolved host")
	}
}

func TestSourceHTTPClientFailsClosedWhenHostResolutionFails(t *testing.T) {
	called := false
	client := sourceHTTPClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("dns unavailable")
	})
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ghe.example.com/api/v3", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := client.Do(request)
	if response != nil && response.Body != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("response.Body.Close() error = %v", closeErr)
		}
	}
	if err == nil {
		t.Fatal("Do() error = nil, want non-nil")
	}
	if called {
		t.Fatal("Do() reached wrapped transport after DNS failure")
	}
}

func TestSourceHTTPClientFailsClosedWhenCustomTransportCannotPinResolvedIP(t *testing.T) {
	called := false
	client := sourceHTTPClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("140.82.113.5")}}, nil
	})
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ghe.example.com/api/v3", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(request)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, sourcehttp.ErrTransportPinningUnsupported) {
		t.Fatalf("Do() error = %v, want pinned host dialing error", err)
	}
	if called {
		t.Fatal("Do() reached wrapped transport after pinning failed")
	}
}

func TestAcceptsEnterpriseAPIBaseURL(t *testing.T) {
	for _, tt := range []struct {
		baseURL string
		want    string
	}{
		{baseURL: "https://ghe.example.com/api/v3", want: "https://ghe.example.com"},
		{baseURL: "https://ghe.example.com/api/v3/", want: "https://ghe.example.com"},
		{baseURL: "https://api.ghe.example.com/api/v3", want: "https://api.ghe.example.com/api/v3"},
		{baseURL: "https://ghe.api.example.com/api/v3/", want: "https://ghe.api.example.com/api/v3"},
	} {
		t.Run(tt.baseURL, func(t *testing.T) {
			settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
				"base_url": tt.baseURL,
				"owner":    "writer",
			}), false, false)
			if err != nil {
				t.Fatalf("parseSettings() error = %v", err)
			}
			if settings.baseURL != tt.want {
				t.Fatalf("baseURL = %q, want %q", settings.baseURL, tt.want)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newGitHubAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	repo := map[string]any{
		"id":             1,
		"name":           "cerebro",
		"full_name":      "writer/cerebro",
		"html_url":       "https://github.com/writer/cerebro",
		"visibility":     "public",
		"default_branch": "main",
		"private":        false,
		"archived":       false,
		"fork":           false,
		"created_at":     "2026-04-22T00:00:00Z",
		"updated_at":     "2026-04-23T00:00:00Z",
		"owner": map[string]any{
			"login": "writer",
		},
	}
	pulls := []map[string]any{
		{
			"number":     443,
			"title":      "feat(source): add source preview surfaces",
			"state":      "open",
			"html_url":   "https://github.com/writer/cerebro/pull/443",
			"created_at": "2026-04-23T01:00:00Z",
			"updated_at": "2026-04-23T02:00:00Z",
			"user": map[string]any{
				"login": "jonathan",
			},
			"draft": false,
			"head": map[string]any{
				"label": "writer:feat/cerebro-next-source-preview-20260423",
			},
			"base": map[string]any{
				"label": "writer:feat/cerebro-next-source-registry-20260423",
			},
		},
		{
			"number":     442,
			"title":      "feat(bootstrap): expose the source registry",
			"state":      "closed",
			"html_url":   "https://github.com/writer/cerebro/pull/442",
			"created_at": "2026-04-22T23:00:00Z",
			"updated_at": "2026-04-23T00:00:00Z",
			"closed_at":  "2026-04-23T00:30:00Z",
			"user": map[string]any{
				"login": "jonathan",
			},
			"draft": false,
			"head": map[string]any{
				"label": "writer:feat/cerebro-next-source-registry-20260423",
			},
			"base": map[string]any{
				"label": "writer:feat/cerebro-next-source-cdk-20260423",
			},
		},
	}
	auditEntries := []map[string]any{
		{
			"@timestamp":                  1776916397852,
			"_document_id":                "audit-doc-1",
			"action":                      "repository_vulnerability_alert.create",
			"actor":                       "dependabot[bot]",
			"actor_id":                    49699333,
			"actor_is_bot":                true,
			"business":                    "writer",
			"business_id":                 10550,
			"created_at":                  1776916397852,
			"external_identity_nameid":    "dependabot@writer.com",
			"operation_type":              "create",
			"org":                         "writer",
			"org_id":                      1,
			"permission":                  "admin",
			"previous_visibility":         "private",
			"programmatic_access_type":    "GitHub App server-to-server token",
			"public_repo":                 false,
			"repo":                        "writer/cerebro",
			"repo_id":                     1,
			"visibility":                  "internal",
			"request_id":                  "audit-1",
			"repository_vulnerability_id": 99,
		},
		{
			"@timestamp":     1776916385929,
			"_document_id":   "audit-doc-2",
			"action":         "org_credential_authorization.deauthorize",
			"actor":          "octocat",
			"actor_id":       1,
			"created_at":     1776916385929,
			"operation_type": "modify",
			"org":            "writer",
			"org_id":         1,
			"user":           "octocat",
			"user_id":        1,
			"actor_is_agent": false,
			"actor_is_bot":   false,
			"request_id":     "audit-2",
			"visibility":     "internal",
		},
	}
	dependabotAlerts := []map[string]any{
		{
			"number":     7,
			"state":      "open",
			"url":        "https://api.github.com/repos/writer/cerebro/dependabot/alerts/7",
			"html_url":   "https://github.com/writer/cerebro/security/dependabot/7",
			"created_at": "2026-04-23T00:00:00Z",
			"updated_at": "2026-04-24T00:00:00Z",
			"dependency": map[string]any{
				"package": map[string]any{
					"ecosystem": "go",
					"name":      "golang.org/x/crypto",
				},
				"manifest_path": "go.mod",
				"scope":         "runtime",
			},
			"security_advisory": map[string]any{
				"ghsa_id":  "GHSA-xxxx-yyyy-zzzz",
				"cve_id":   "CVE-2026-0001",
				"summary":  "High severity issue in golang.org/x/crypto",
				"severity": "high",
			},
			"security_vulnerability": map[string]any{
				"package": map[string]any{
					"ecosystem": "go",
					"name":      "golang.org/x/crypto",
				},
				"severity":                 "high",
				"vulnerable_version_range": "< 0.31.0",
				"first_patched_version": map[string]any{
					"identifier": "0.31.0",
				},
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/orgs/writer/repos":
			if err := json.NewEncoder(w).Encode([]map[string]any{repo}); err != nil {
				t.Fatalf("encode repos response: %v", err)
			}
		case "/api/v3/repos/writer/cerebro":
			if err := json.NewEncoder(w).Encode(repo); err != nil {
				t.Fatalf("encode repo response: %v", err)
			}
		case "/api/v3/repos/writer/cerebro/pulls":
			page := r.URL.Query().Get("page")
			if page == "" || page == "1" {
				w.Header().Set("Link", "</api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"next\", </api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"last\"")
				if err := json.NewEncoder(w).Encode(pulls[:1]); err != nil {
					t.Fatalf("encode pulls page 1: %v", err)
				}
				return
			}
			if page == "2" {
				if err := json.NewEncoder(w).Encode(pulls[1:2]); err != nil {
					t.Fatalf("encode pulls page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty pulls page: %v", err)
			}
		case "/api/v3/users/dependabot%5Bbot%5D",
			"/api/v3/users/dependabot[bot]":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"login": "dependabot[bot]",
				"id":    49699333,
				"type":  "Bot",
				"email": "dependabot@writer.com",
			}); err != nil {
				t.Fatalf("encode users response: %v", err)
			}
		case "/api/v3/users/octocat":
			if err := json.NewEncoder(w).Encode(map[string]any{
				"login": "octocat",
				"id":    1,
				"type":  "User",
				"email": "octocat@writer.com",
			}); err != nil {
				t.Fatalf("encode users response: %v", err)
			}
		case "/api/v3/orgs/writer/audit-log":
			switch got := r.URL.Query().Get("order"); got {
			case "desc":
				if got := r.URL.Query().Get("per_page"); got != "1" {
					t.Fatalf("audit canary per_page = %q, want 1", got)
				}
				if got := r.URL.Query().Get("after"); got != "" {
					t.Fatalf("audit canary after = %q, want empty", got)
				}
				if err := json.NewEncoder(w).Encode(auditEntries[:1]); err != nil {
					t.Fatalf("encode audit canary: %v", err)
				}
				return
			case "asc":
			default:
				t.Fatalf("audit order = %q, want asc or desc canary", got)
			}
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v3/orgs/writer/audit-log?after=cursor-2&before=>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(auditEntries[:1]); err != nil {
					t.Fatalf("encode audit page 1: %v", err)
				}
				return
			}
			if after == "cursor-2" {
				if err := json.NewEncoder(w).Encode(auditEntries[1:2]); err != nil {
					t.Fatalf("encode audit page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty audit page: %v", err)
			}
		case "/api/v3/repos/writer/cerebro/dependabot/alerts":
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v3/repos/writer/cerebro/dependabot/alerts?after=cursor-2&before=>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(dependabotAlerts); err != nil {
					t.Fatalf("encode dependabot alerts page 1: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty dependabot alerts page: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}
