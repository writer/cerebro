package mailchimp_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/sources/catalogruntime"
)

func TestSourceReplaysCapturedMailchimpFamilies(t *testing.T) {
	listsBundle, err := sourcefixture.FindBundle("../..", "mailchimp", "lists", "list_lists")
	if err != nil {
		t.Fatalf("FindBundle(lists) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, listsBundle, sourcefixture.ReplayContract{
		SourceID: "mailchimp", Family: "lists", Case: "list_lists", Method: http.MethodGet,
		Host: "us19.api.mailchimp.com", Path: "/3.0/lists", RawQuery: "",
	})

	membersBundle, err := sourcefixture.FindBundle("../..", "mailchimp", "members", "list_members")
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
		family string
		kind   string
		body   []byte
	}{
		{family: "lists", kind: "mailchimp.lists", body: listsBundle.Payload},
		{family: "members", kind: "mailchimp.members", body: membersBundle.Payload},
	} {
		t.Run(test.family, func(t *testing.T) {
			result, err := catalogruntime.ReadDefinitionFixture(context.Background(), entry.Definition, test.family, test.body)
			if err != nil {
				t.Fatalf("ReadDefinitionFixture(%s) error = %v", test.family, err)
			}
			if result.EventCount != 1 || len(result.EventKinds) != 1 || result.EventKinds[0] != test.kind {
				t.Fatalf("fixture result = %#v, want one %s event", result, test.kind)
			}
			if result.Query.Get("offset") != "0" || result.Query.Get("count") != "100" {
				t.Fatalf("fixture query = %q, want offset=0&count=100", result.Query.Encode())
			}
		})
	}
}

func TestMailchimpAuditEventsUseOfficialChimpChatterShape(t *testing.T) {
	entry, ok, err := connectorcatalog.BuiltinEntry("mailchimp")
	if err != nil {
		t.Fatalf("BuiltinEntry(mailchimp) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(mailchimp) ok = false, want true")
	}
	result, err := catalogruntime.ReadDefinitionFixture(context.Background(), entry.Definition, "audit_events", []byte(`{
		"chimp_chatter": [{
			"title": "1 new subscriber",
			"message": "A subscriber joined an audience.",
			"type": "lists:new-subscriber",
			"update_time": "2017-08-04T11:09:01+00:00",
			"url": "https://example.test/reports/summary?id=1",
			"list_id": "fixture-list"
		}],
		"total_items": 1
	}`))
	if err != nil {
		t.Fatalf("ReadDefinitionFixture(audit_events) error = %v", err)
	}
	if result.EventCount != 1 || len(result.EventKinds) != 1 || result.EventKinds[0] != "mailchimp.audit_events" {
		t.Fatalf("fixture result = %#v, want one mailchimp.audit_events event", result)
	}
	if result.Query.Get("offset") != "0" || result.Query.Get("count") != "100" {
		t.Fatalf("fixture query = %q, want offset=0&count=100", result.Query.Encode())
	}
}
