package sentinelone

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

// Source is the live SentinelOne source preview used by the builtin registry.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read pages through the configured SentinelOne family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

type listFunc[T any] func(context.Context, settings, string, int) ([]T, string, error)

type familyOptions[T any] struct {
	Name           string
	Label          string
	List           listFunc[T]
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string {
		return settings.family
	},
		family(familyOptions[threatRecord]{
			Name:  familyThreat,
			Label: "sentinelone threat",
			List:  s.listThreats,
			Event: threatEvent,
			URN: func(settings settings, threat threatRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:threat:%s", settings.host, threat.ID), nil
			},
			CursorFallback: func(t threatRecord) string { return t.ID },
		}),
		family(familyOptions[agentRecord]{
			Name:  familyAgent,
			Label: "sentinelone agent",
			List:  s.listAgents,
			Event: agentEvent,
			URN: func(settings settings, agent agentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, agent.ID), nil
			},
			CursorFallback: func(a agentRecord) string { return a.ID },
		}),
		family(familyOptions[siteRecord]{
			Name:  familySite,
			Label: "sentinelone site",
			List:  s.listSites,
			Event: siteEvent,
			URN: func(settings settings, site siteRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:site:%s", settings.host, site.ID), nil
			},
			CursorFallback: func(r siteRecord) string { return r.ID },
		}),
		family(familyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "sentinelone group",
			List:  s.listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:group:%s", settings.host, group.ID), nil
			},
			CursorFallback: func(r groupRecord) string { return r.ID },
		}),
		family(familyOptions[exclusionRecord]{
			Name:  familyExclusion,
			Label: "sentinelone exclusion",
			List:  s.listExclusions,
			Event: exclusionEvent,
			URN: func(settings settings, exclusion exclusionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:exclusion:%s", settings.host, exclusion.ID), nil
			},
			CursorFallback: func(r exclusionRecord) string { return r.ID },
		}),
		family(familyOptions[activityRecord]{
			Name:  familyActivity,
			Label: "sentinelone activity",
			List:  s.listActivities,
			Event: activityEvent,
			URN: func(settings settings, activity activityRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:activity:%s", settings.host, activity.ID), nil
			},
			CursorFallback: func(r activityRecord) string { return r.ID },
		}),
		family(familyOptions[applicationRecord]{
			Name:  familyApplication,
			Label: "sentinelone application inventory",
			List:  s.listApplications,
			Event: applicationEvent,
			Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
				if err := agentApplicationCheck(ctx, s, settings); err != nil {
					return nil, err
				}
				if settings.agentID != "" {
					urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, settings.agentID))
					if err != nil {
						return nil, err
					}
					return []sourcecdk.URN{urn}, nil
				}
				agents, _, err := s.listAgents(ctx, settings, "", settings.perPage)
				if err != nil {
					return nil, wrapLookupError(label("sentinelone agents", settings), err)
				}
				urns := make([]sourcecdk.URN, 0, len(agents))
				for _, agent := range agents {
					if strings.TrimSpace(agent.ID) == "" {
						continue
					}
					urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:agent:%s", settings.host, agent.ID))
					if err != nil {
						return nil, err
					}
					urns = append(urns, urn)
				}
				return urns, nil
			},
			URN: func(settings settings, app applicationRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:application_inventory:%s:%s", settings.host, applicationAgentID(settings, app), applicationID(settings, app)), nil
			},
			CursorFallback: func(app applicationRecord) string { return applicationID(settings{}, app) },
		}),
	)
}

func family[T any](options familyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := options.List(ctx, settings, "", 1)
			if err != nil {
				return wrapLookupError(label(options.Label, settings), err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, settings)
			}
			records, _, err := options.List(ctx, settings, "", settings.perPage)
			if err != nil {
				return nil, wrapLookupError(label(options.Label, settings), err)
			}
			return urnsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, wrapLookupError(label(options.Label, settings), err)
			}
			build := func(record T) (*primitives.Event, error) {
				return options.Event(settings, record)
			}
			return pullFromRecords(records, next, build, options.CursorFallback)
		},
	}
}

func label(prefix string, settings settings) string {
	return fmt.Sprintf("%s for %s", prefix, settings.host)
}

func urnsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		urn, err := sourcecdk.ParseURN(rawURN)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func pullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		pull := sourcecdk.Pull{}
		if next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
		}
		return pull, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: sourcecdk.ResolveCursorOpaque(next, fallback, events[len(events)-1].OccurredAt.AsTime()),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func agentApplicationCheck(ctx context.Context, source *Source, settings settings) error {
	_, _, err := source.listApplications(ctx, settings, "", 1)
	if err != nil {
		return wrapLookupError(label("sentinelone application inventory", settings), err)
	}
	return nil
}
