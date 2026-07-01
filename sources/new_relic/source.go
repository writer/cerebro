package new_relic

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/newrelicapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID          = newrelicapi.SourceID
	defaultFamily     = familyAssets
	familyAssets      = newrelicapi.FamilyAssets
	familyFindings    = newrelicapi.FamilyFindings
	familyAuditEvents = newrelicapi.FamilyAuditEvents
)

type Source struct {
	spec          *cerebrov1.SourceSpec
	allowLoopback bool
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{spec: spec}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return s.spec
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	settings, err := newrelicapi.ResolveConfig(cfg)
	if err != nil {
		return err
	}
	var out struct {
		Actor struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"actor"`
	}
	return s.client().GraphQL(ctx, settings, newrelicapi.Request{Query: `query NewRelicSourceHealth { actor { user { name } } }`}, &out)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	pull, err := s.Read(ctx, cfg, nil)
	if err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, 0, len(pull.Events))
	for _, event := range pull.Events {
		rawURN := ""
		if event.GetKind() == sourceID+"."+familyFindings {
			rawURN = strings.TrimSpace(event.GetAttributes()["finding_urn"])
		}
		if rawURN == "" {
			rawURN = strings.TrimSpace(event.GetAttributes()["resource_urn"])
		}
		if rawURN == "" {
			rawURN = fmt.Sprintf("urn:cerebro:%s:%s:%s", event.GetTenantId(), event.GetKind(), event.GetId())
		}
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := newrelicapi.ResolveConfig(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	switch settings.Family {
	case familyAssets:
		return s.readAssets(ctx, settings, sourcecdk.CursorToken(cursor))
	case familyFindings:
		return s.readFindings(ctx, settings, sourcecdk.CursorToken(cursor))
	case familyAuditEvents:
		return s.readAuditEvents(ctx, settings)
	default:
		return sourcecdk.Pull{}, fmt.Errorf("%w: new_relic family must be one of %s, %s, %s", sourcecdk.ErrInvalidConfig, familyAssets, familyFindings, familyAuditEvents)
	}
}

func (s *Source) readAssets(ctx context.Context, settings newrelicapi.Settings, cursor string) (sourcecdk.Pull, error) {
	var out struct {
		Actor struct {
			EntitySearch struct {
				Results struct {
					NextCursor string               `json:"nextCursor"`
					Entities   []newrelicapi.Record `json:"entities"`
				} `json:"results"`
			} `json:"entitySearch"`
		} `json:"actor"`
	}
	req := newrelicapi.Request{
		Query: `query NewRelicEntitySearch($query: String!, $cursor: String) {
  actor {
    entitySearch(query: $query) {
      results(cursor: $cursor) {
        nextCursor
        entities {
          guid
          name
          type
          entityType
          domain
          permalink
          reporting
          account { id name }
        }
      }
    }
  }
}`,
		Variables: map[string]any{"query": settings.EntityQuery, "cursor": newrelicapi.NullableString(cursor)},
	}
	if err := s.client().GraphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.EntitySearch.Results.Entities))
	for _, entity := range out.Actor.EntitySearch.Results.Entities {
		events = append(events, newrelicapi.NewAssetEvent(settings, entity))
	}
	return newrelicapi.PullWithCursor(events, out.Actor.EntitySearch.Results.NextCursor), nil
}

func (s *Source) readFindings(ctx context.Context, settings newrelicapi.Settings, cursor string) (sourcecdk.Pull, error) {
	if settings.AccountID == 0 {
		return sourcecdk.Pull{}, fmt.Errorf("%w: account_id is required for new_relic findings", sourcecdk.ErrInvalidConfig)
	}
	var out struct {
		Actor struct {
			Account struct {
				AIIssues struct {
					Issues struct {
						NextCursor string               `json:"nextCursor"`
						Issues     []newrelicapi.Record `json:"issues"`
					} `json:"issues"`
				} `json:"aiIssues"`
			} `json:"account"`
		} `json:"actor"`
	}
	req := newrelicapi.Request{
		Query: `query NewRelicIssues($accountId: Int!, $cursor: String) {
  actor {
    account(id: $accountId) {
      aiIssues {
        issues(cursor: $cursor) {
          nextCursor
          issues {
            issueId
            title
            description
            priority
            state
            createdAt
            updatedAt
            entityGuids
          }
        }
      }
    }
  }
}`,
		Variables: map[string]any{"accountId": settings.AccountID, "cursor": newrelicapi.NullableString(cursor)},
	}
	if err := s.client().GraphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.Account.AIIssues.Issues.Issues))
	for _, issue := range out.Actor.Account.AIIssues.Issues.Issues {
		events = append(events, newrelicapi.NewFindingEvent(settings, issue))
	}
	return newrelicapi.PullWithCursor(events, out.Actor.Account.AIIssues.Issues.NextCursor), nil
}

func (s *Source) readAuditEvents(ctx context.Context, settings newrelicapi.Settings) (sourcecdk.Pull, error) {
	if settings.AccountID == 0 {
		return sourcecdk.Pull{}, fmt.Errorf("%w: account_id is required for new_relic audit_events", sourcecdk.ErrInvalidConfig)
	}
	var out struct {
		Actor struct {
			Account struct {
				NRQL struct {
					Results []newrelicapi.Record `json:"results"`
				} `json:"nrql"`
			} `json:"account"`
		} `json:"actor"`
	}
	req := newrelicapi.Request{
		Query: `query NewRelicAuditEvents($accountId: Int!, $nrql: Nrql!) {
  actor {
    account(id: $accountId) {
      nrql(query: $nrql) {
        results
      }
    }
  }
}`,
		Variables: map[string]any{"accountId": settings.AccountID, "nrql": settings.AuditNRQL},
	}
	if err := s.client().GraphQL(ctx, settings, req, &out); err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, len(out.Actor.Account.NRQL.Results))
	for _, row := range out.Actor.Account.NRQL.Results {
		events = append(events, newrelicapi.NewAuditEvent(settings, row))
	}
	return sourcecdk.Pull{Events: events}, nil
}

func (s *Source) client() newrelicapi.Client {
	return newrelicapi.Client{AllowLoopback: s != nil && s.allowLoopback}
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func (s *Source) allowLoopbackForTest() {
	if s != nil {
		s.allowLoopback = true
	}
}
