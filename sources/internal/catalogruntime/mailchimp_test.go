package catalogruntime

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestMailchimpCatalogRuntimeReplaysCapturedFamilies(t *testing.T) {
	listsBundle, err := sourcefixture.FindBundle("../../..", "mailchimp", "lists", "list_lists")
	if err != nil {
		t.Fatalf("FindBundle(lists) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, listsBundle, sourcefixture.ReplayContract{
		SourceID: "mailchimp", Family: "lists", Case: "list_lists", Method: http.MethodGet,
		Host: "us19.api.mailchimp.com", Path: "/3.0/lists", RawQuery: "",
	})

	membersBundle, err := sourcefixture.FindBundle("../../..", "mailchimp", "members", "list_members")
	if err != nil {
		t.Fatalf("FindBundle(members) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, membersBundle, sourcefixture.ReplayContract{
		SourceID: "mailchimp", Family: "members", Case: "list_members", Method: http.MethodGet,
		Host: "us19.api.mailchimp.com", Path: "/3.0/lists/example-2e767a40/members", RawQuery: "",
	})

	entry, ok, err := connectorcatalog.BuiltinEntry("mailchimp")
	if err != nil {
		t.Fatalf("BuiltinEntry(mailchimp) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(mailchimp) ok = false, want true")
	}

	for _, test := range []struct {
		family      string
		kind        string
		requestPath string
		bundle      sourcefixture.Bundle
	}{
		{family: "lists", kind: "mailchimp.lists", requestPath: "/lists", bundle: listsBundle},
		{family: "members", kind: "mailchimp.members", requestPath: "/lists/example-2e767a40/members", bundle: membersBundle},
	} {
		t.Run(test.family, func(t *testing.T) {
			replayMailchimpBundle(t, entry, test.family, test.kind, test.requestPath, test.bundle, true)
		})
	}
}

func TestMailchimpCatalogRuntimeReplaysSpecShapedAuditEvents(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../../..", "mailchimp", "audit_events", "chimp_chatter")
	if err != nil {
		t.Fatalf("FindBundle(audit_events) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{
		SourceID: "mailchimp", Family: "audit_events", Case: "chimp_chatter", Method: http.MethodGet,
		Host: "us19.api.mailchimp.com", Path: "/3.0/activity-feed/chimp-chatter", RawQuery: "",
	})

	entry, ok, err := connectorcatalog.BuiltinEntry("mailchimp")
	if err != nil {
		t.Fatalf("BuiltinEntry(mailchimp) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(mailchimp) ok = false, want true")
	}
	replayMailchimpBundle(t, entry, "audit_events", "mailchimp.audit_events", "/activity-feed/chimp-chatter", bundle, false)
}

func replayMailchimpBundle(t *testing.T, entry connectorcatalog.Entry, family, kind, requestPath string, bundle sourcefixture.Bundle, captureTime bool) {
	t.Helper()
	wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("cerebro:fixture-api-key"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != requestPath {
			t.Fatalf("request = %s %s, want GET %s", r.Method, r.URL.RequestURI(), requestPath)
		}
		if got := r.Header.Get("Authorization"); got != wantAuthorization {
			t.Fatalf("Authorization = %q, want encoded Mailchimp Basic credential", got)
		}
		if r.URL.Query().Get("offset") != "0" || r.URL.Query().Get("count") != "100" {
			t.Fatalf("request query = %q, want offset=0&count=100", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()

	source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewDefinitionWithValidationOptions() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"dc":        "us19",
		"family":    family,
		"list_id":   "example-2e767a40",
		"password":  "fixture-api-key",
		"tenant_id": "tenant",
		"username":  "cerebro",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", family, err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != kind {
		t.Fatalf("Read(%s) events = %#v, want one %s event", family, pull.Events, kind)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(%s) error = %v", family, err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, captureTime); err != nil {
		t.Fatalf("StabilizeEvents(%s) error = %v", family, err)
	}
	fixtureRoot := filepath.Join("..", "..", "mailchimp")
	if err := sourcefixture.CompareOrUpdateSourceOutputs(fixtureRoot, family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}
