package github

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
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

func TestNewFixtureRejectsNegativeCursor(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"token": "test"})

	if _, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "-1"}); err == nil {
		t.Fatal("Read() error = nil, want non-nil")
	}
}

func TestNewFixtureTrimsCursor(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"token": "test"})

	pull, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: " 1 "})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestCheckDiscoverAndReadLiveGitHubPreview(t *testing.T) {
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
	if first.Checkpoint == nil || first.Checkpoint.CursorOpaque != "2" {
		t.Fatalf("first.Checkpoint = %#v, want cursor 2", first.Checkpoint)
	}
	var payload pullRequestPayload
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("json.Unmarshal(first payload) error = %v", err)
	}
	if got := payload.UpdatedAt.Format(time.RFC3339); got != "2026-04-23T02:00:00Z" {
		t.Fatalf("payload.updated_at = %q, want 2026-04-23T02:00:00Z", got)
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
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "3" {
		t.Fatalf("second.Checkpoint = %#v, want cursor 3", second.Checkpoint)
	}

	final, err := source.Read(context.Background(), readCfg, &cerebrov1.SourceCursor{Opaque: "3"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func newGitHubAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	repo := map[string]any{
		"id":        1,
		"name":      "cerebro",
		"full_name": "writer/cerebro",
		"html_url":  "https://github.com/writer/cerebro",
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encode := func(v any, subject string) bool {
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Errorf("%s: %v", subject, err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return false
			}
			return true
		}
		switch r.URL.Path {
		case "/api/v3/orgs/writer/repos":
			encode([]map[string]any{repo}, "encode repos response")
		case "/api/v3/repos/writer/cerebro":
			encode(repo, "encode repo response")
		case "/api/v3/repos/writer/cerebro/pulls":
			page := r.URL.Query().Get("page")
			if page == "" || page == "1" {
				w.Header().Set("Link", "</api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"next\", </api/v3/repos/writer/cerebro/pulls?page=2>; rel=\"last\"")
				encode(pulls[:1], "encode pulls page 1")
				return
			}
			if page == "2" {
				encode(pulls[1:2], "encode pulls page 2")
				return
			}
			encode([]map[string]any{}, "encode empty pulls page")
		default:
			http.NotFound(w, r)
		}
	})
}

func TestValidateBaseURLRejectsUnsafeHosts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		base string
	}{
		{"loopback_v4", "http://127.0.0.1/"},
		{"loopback_v6", "http://[::1]/"},
		{"localhost", "http://localhost/"},
		{"private_10", "http://10.0.0.1/"},
		{"private_172", "http://172.16.5.5/"},
		{"private_192", "http://192.168.1.1/"},
		{"link_local_v4", "http://169.254.169.254/"},
		{"link_local_v6", "http://[fe80::1]/"},
		{"unspecified", "http://0.0.0.0/"},
	}
	ctx := context.Background()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := validateBaseURL(ctx, tc.base, false); err == nil {
				t.Fatalf("validateBaseURL(%q, false) = nil, want unsafe-host error", tc.base)
			}
		})
	}
}

func TestValidateBaseURLRequiresHTTP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := []string{"file:///etc/passwd", "ssh://github.example.com/", "javascript:alert(1)"}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			if err := validateBaseURL(ctx, raw, false); err == nil {
				t.Fatalf("validateBaseURL(%q) = nil, want scheme error", raw)
			}
		})
	}
}

func TestValidateBaseURLAcceptsPublicHosts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, host := range []string{"https://api.github.com/", "https://1.1.1.1/api/v3/"} {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			if err := validateBaseURL(ctx, host, false); err != nil {
				t.Fatalf("validateBaseURL(%q) = %v, want nil", host, err)
			}
		})
	}
}

func TestValidateBaseURLLoopbackOptIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if err := validateBaseURL(ctx, "http://127.0.0.1/", true); err != nil {
		t.Fatalf("validateBaseURL(127.0.0.1, allow=true) = %v, want nil", err)
	}
	if err := validateBaseURL(ctx, "http://10.0.0.1/", true); err == nil {
		t.Fatalf("validateBaseURL(10.0.0.1, allow=true) = nil, want still rejected")
	}
}

func TestSafeDialContextRejectsDNSRebindingToPrivateIP(t *testing.T) {
	t.Parallel()
	_, err := safeDialContext(
		context.Background(),
		"tcp",
		"ghe.example.com:443",
		false,
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dial called for unsafe resolved host")
			return nil, errors.New("unexpected dial")
		},
	)
	if !errors.Is(err, errUnsafeBaseURLHost) {
		t.Fatalf("safeDialContext() error = %v, want %v", err, errUnsafeBaseURLHost)
	}
}

func TestSafeDialContextPinsResolvedPublicIP(t *testing.T) {
	t.Parallel()
	var dialAddress string
	errStopDial := errors.New("stop after address capture")
	_, err := safeDialContext(
		context.Background(),
		"tcp",
		"ghe.example.com:443",
		false,
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("140.82.113.5")}}, nil
		},
		func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialAddress = address
			return nil, errStopDial
		},
	)
	if !errors.Is(err, errStopDial) {
		t.Fatalf("safeDialContext() error = %v, want address-capture sentinel", err)
	}
	if dialAddress != "140.82.113.5:443" {
		t.Fatalf("dial address = %q, want pinned public IP", dialAddress)
	}
}
