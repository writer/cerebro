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
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
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
	if len(urns) != 2 {
		t.Fatalf("len(Discover()) = %d, want 2", len(urns))
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
	if first.NextCursor == nil || first.NextCursor.Opaque != "2" {
		t.Fatalf("first.NextCursor = %#v, want page 2", first.NextCursor)
	}
	assertGitHubCheckpointEnvelope(t, first.Checkpoint, familyPullRequest)
	firstCheckpoint, ok := sourcecdk.DecodeCursorEnvelope(first.Checkpoint.GetCursorOpaque())
	if !ok || firstCheckpoint.Token != "2" {
		t.Fatalf("first.Checkpoint = %#v, want resumable envelope with token 2", first.Checkpoint)
	}
	resumed, err := source.Read(context.Background(), readCfg, &cerebrov1.SourceCursor{Opaque: first.Checkpoint.GetCursorOpaque()})
	if err != nil {
		t.Fatalf("Read(resumed from checkpoint envelope) error = %v", err)
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
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
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
	if second.Checkpoint.CursorOpaque != "" {
		t.Fatalf("second.Checkpoint.CursorOpaque = %q, want empty cursor on terminal audit page", second.Checkpoint.CursorOpaque)
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
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
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

func TestSecretScanningContinuesPastWatermarkBecausePagesAreNotUpdatedOrdered(t *testing.T) {
	watermark := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	envelope := sourcecdk.CursorEnvelope{
		Version:             1,
		Source:              "github",
		Family:              familySecretScanning,
		Mode:                "incremental_watermark",
		ResumableCheckpoint: true,
	}
	sourcecdk.SetCursorWatermark(&envelope, watermark)
	opaque, err := sourcecdk.EncodeCursorEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	checkpoint := &cerebrov1.SourceCheckpoint{
		Watermark:    timestamppb.New(watermark),
		CursorOpaque: opaque,
	}
	requestedPages := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v3/orgs/writer/secret-scanning/alerts" {
			http.NotFound(w, r)
			return
		}
		page := r.URL.Query().Get("page")
		requestedPages = append(requestedPages, page)
		if page == "" || page == "1" {
			w.Header().Set("Link", "</api/v3/orgs/writer/secret-scanning/alerts?page=2>; rel=\"next\", </api/v3/orgs/writer/secret-scanning/alerts?page=2>; rel=\"last\"")
			if err := json.NewEncoder(w).Encode([]map[string]any{
				{
					"number":      1,
					"state":       "open",
					"secret_type": "token",
					"created_at":  "2026-04-24T00:00:00Z",
					"updated_at":  "2026-04-24T11:00:00Z",
					"repository": map[string]any{
						"full_name": "writer/cerebro",
					},
				},
			}); err != nil {
				t.Fatalf("encode secret scanning page 1: %v", err)
			}
			return
		}
		if page == "2" {
			if err := json.NewEncoder(w).Encode([]map[string]any{
				{
					"number":      2,
					"state":       "open",
					"secret_type": "token",
					"created_at":  "2026-04-01T00:00:00Z",
					"updated_at":  "2026-04-24T14:00:00Z",
					"repository": map[string]any{
						"full_name": "writer/cerebro",
					},
				},
			}); err != nil {
				t.Fatalf("encode secret scanning page 2: %v", err)
			}
			return
		}
		if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
			t.Fatalf("encode empty secret scanning page: %v", err)
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
		"family":   familySecretScanning,
		"owner":    "writer",
		"per_page": "1",
		"token":    "test-token",
	})

	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if len(first.Events) != 0 {
		t.Fatalf("len(first.Events) = %d, want 0", len(first.Events))
	}
	if first.ShortCircuitReason == sourcecdk.PullShortCircuitReasonWatermarkReached {
		t.Fatalf("first.ShortCircuitReason = %q, want no watermark stop", first.ShortCircuitReason)
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "2" {
		t.Fatalf("first.NextCursor = %#v, want page 2", first.NextCursor)
	}

	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want recently updated older-created alert", len(second.Events))
	}
	if got := second.Events[0].Attributes["alert_number"]; got != "2" {
		t.Fatalf("second alert_number = %q, want 2", got)
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requestedPages) != 2 || requestedPages[0] != "1" || requestedPages[1] != "2" {
		t.Fatalf("requested pages = %#v, want first page then page 2", requestedPages)
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
			if got := r.URL.Query().Get("order"); got != "asc" {
				t.Fatalf("audit order = %q, want asc", got)
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
