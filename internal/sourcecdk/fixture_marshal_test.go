package sourcecdk

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

func TestMarshalFixtureEvents(t *testing.T) {
	payload, err := MarshalFixtureEvents([]*primitives.Event{{
		Id:         "event-1",
		TenantId:   "tenant",
		SourceId:   "demo",
		Kind:       "demo.users",
		OccurredAt: timestamppb.New(time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)),
		SchemaRef:  "demo/users/v1",
		Payload:    []byte(`{"id":"user-1"}`),
		Attributes: map[string]string{"user_id": "user-1"},
	}})
	if err != nil {
		t.Fatalf("MarshalFixtureEvents() error = %v", err)
	}
	for _, want := range []string{`"id": "event-1"`, `"occurred_at": "2026-07-18T00:00:00Z"`, `"user_id": "user-1"`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("fixture payload missing %s:\n%s", want, payload)
		}
	}
}

func TestMarshalFixtureURNs(t *testing.T) {
	urn, err := ParseURN("urn:cerebro:tenant:demo:user-1")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := MarshalFixtureURNs([]URN{urn})
	if err != nil {
		t.Fatalf("MarshalFixtureURNs() error = %v", err)
	}
	if got := string(payload); got != "[\n  \"urn:cerebro:tenant:demo:user-1\"\n]\n" {
		t.Fatalf("fixture URNs = %q", got)
	}
}
