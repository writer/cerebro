package sourcecdk

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIdentityHelpersBuildStableURNsAndEventIDs(t *testing.T) {
	urn, err := URNForEscaped("tenant", "github.repo", "owner/name", "repo:1")
	if err != nil {
		t.Fatalf("URNForEscaped() error = %v", err)
	}
	if _, err := ParseURN(urn.String()); err != nil {
		t.Fatalf("ParseURN(%q) error = %v", urn, err)
	}
	if got, want := EventID("source", "family", "record"), EventID("source", "family", "record"); got != want {
		t.Fatalf("EventID not stable: %q != %q", got, want)
	}
	if StableExternalID("", "fallback") != "fallback" {
		t.Fatalf("StableExternalID empty fallback mismatch")
	}
}

func TestRenderConfigTemplate(t *testing.T) {
	cfg := NewConfig(map[string]string{"domain": "example.com", "region": "us"})
	got, err := RenderConfigTemplate("test", "https://${config.domain}/${credential.region}", cfg, []string{"domain", "region"})
	if err != nil {
		t.Fatalf("RenderConfigTemplate() error = %v", err)
	}
	if got != "https://example.com/us" {
		t.Fatalf("RenderConfigTemplate() = %q", got)
	}
	if _, err := RenderConfigTemplate("test", "https://${config.missing}", cfg, []string{"missing"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("RenderConfigTemplate missing error = %v, want ErrInvalidConfig", err)
	}
}

func TestSourceErrorKind(t *testing.T) {
	err := WrapSourceError(ErrorKindRateLimited, "github", "audit", errors.New("provider said slow down"))
	if got := SourceErrorKind(err); got != ErrorKindRateLimited {
		t.Fatalf("SourceErrorKind() = %q, want %q", got, ErrorKindRateLimited)
	}
	if got := SourceErrorKind(&HTTPStatusError{Code: 503, Message: "try later"}); got != ErrorKindTransient {
		t.Fatalf("SourceErrorKind(503) = %q, want transient", got)
	}
}

func TestFamilyFromPageReaderReadsAndDiscovers(t *testing.T) {
	type settings struct{ tenant string }
	type client struct{}
	type record struct{ id string }
	reader := PageReader[settings, client, record]{
		SourceID: "test",
		Family:   "resource",
		Clients: func(context.Context, settings) (client, error) {
			return client{}, nil
		},
		List: func(_ context.Context, _ client, _ settings, token string, _ int) ([]record, string, error) {
			if token == "" {
				return []record{{id: "one"}}, "next", nil
			}
			return []record{{id: "two"}}, "", nil
		},
		URN: func(s settings, r record) (URN, error) {
			return URNFor(s.tenant, "resource", r.id)
		},
		Event: func(s settings, r record) (*primitives.Event, error) {
			return &primitives.Event{
				Id:         EventID("test", r.id),
				TenantId:   s.tenant,
				SourceId:   "test",
				Kind:       "test.resource",
				OccurredAt: timestamppb.New(time.Unix(0, 0).UTC()),
				SchemaRef:  "test/resource/v1",
				Payload:    []byte(`{"id":"` + r.id + `"}`),
			}, nil
		},
	}
	family := FamilyFromPageReader(reader)
	urns, err := family.Discover(context.Background(), settings{tenant: "tenant"})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || urns[0] != "urn:cerebro:tenant:resource:one" {
		t.Fatalf("Discover() = %#v", urns)
	}
	pull, err := family.Read(context.Background(), settings{tenant: "tenant"}, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.NextCursor.GetOpaque() != "next" {
		t.Fatalf("Read() = %#v", pull)
	}
}

func TestValidateFixtureSuite(t *testing.T) {
	source, err := NewFixtureSource(FixtureSourceOptions{
		Spec: &cerebrov1.SourceSpec{Id: "fixture", Name: "Fixture", EmittedKinds: []string{"fixture.event"}},
		Contracts: []EventContract{{
			Kind:                  "fixture.event",
			SchemaRef:             "fixture/event/v1",
			RequiredPayloadFields: []string{"id"},
		}},
		DefaultFamily: "default",
		Families: []FixtureFamily{{
			Name: "default",
			URNs: []URN{"urn:cerebro:tenant:fixture:one"},
			Events: []*primitives.Event{{
				Id:         "event-1",
				TenantId:   "tenant",
				SourceId:   "fixture",
				Kind:       "fixture.event",
				OccurredAt: timestamppb.New(time.Unix(0, 0).UTC()),
				SchemaRef:  "fixture/event/v1",
				Payload:    []byte(`{"id":"one"}`),
			}},
		}},
	})
	if err != nil {
		t.Fatalf("NewFixtureSource() error = %v", err)
	}
	if err := ValidateFixtureSuite(context.Background(), FixtureSuiteOptions{Source: source, RequireDiscover: true}); err != nil {
		t.Fatalf("ValidateFixtureSuite() error = %v", err)
	}
}

func TestPullStatistics(t *testing.T) {
	stats := PullStatistics(Pull{Events: []*primitives.Event{{}}, NextCursor: &cerebrov1.SourceCursor{Opaque: "next"}})
	if stats.Events != 1 || !stats.HasNextCursor {
		t.Fatalf("PullStatistics() = %#v", stats)
	}
}
