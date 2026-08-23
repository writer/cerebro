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

func TestSourceReplaysCapturedMailchimpFamilies(t *testing.T) {
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

func TestSourceReplaysSpecShapedMailchimpAuditEvents(t *testing.T) {
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

func TestMailchimpAuditIdentityDoesNotCollapseSameSecondActivity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/activity-feed/chimp-chatter" {
			t.Fatalf("request path = %q", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"chimp_chatter":[
			{"campaign_id":"campaign-a","list_id":"list-a","message":"subscriber a joined","title":"1 new subscriber","type":"lists:new-subscriber","update_time":"2017-08-04T11:09:01+00:00","url":"https://example.test/reports/a"},
			{"campaign_id":"campaign-b","list_id":"list-b","message":"subscriber b joined","title":"1 new subscriber","type":"lists:new-subscriber","update_time":"2017-08-04T11:09:01+00:00","url":"https://example.test/reports/b"}
		],"total_items":2}`))
	}))
	defer server.Close()

	entry, ok, err := connectorcatalog.BuiltinEntry("mailchimp")
	if err != nil {
		t.Fatalf("BuiltinEntry(mailchimp) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(mailchimp) ok = false, want true")
	}
	source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewDefinitionWithValidationOptions() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL, "dc": "us19", "family": "audit_events", "password": "fixture-api-key", "tenant_id": "tenant", "username": "cerebro",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(audit_events) error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("Read(audit_events) event count = %d, want 2", len(pull.Events))
	}
	firstID := pull.Events[0].Attributes["source_event_id"]
	secondID := pull.Events[1].Attributes["source_event_id"]
	if firstID == secondID {
		t.Fatalf("same-second activity collapsed to source_event_id %q", firstID)
	}
	if strings.Contains(firstID, "lists:new-subscriber") || strings.Contains(secondID, "lists:new-subscriber") {
		t.Fatalf("source_event_id contains an unencoded provider delimiter: %q, %q", firstID, secondID)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(audit_events) error = %v", err)
	}
	if len(urns) != 2 || urns[0] == urns[1] {
		t.Fatalf("Discover(audit_events) URNs = %#v, want two distinct URNs", urns)
	}
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
