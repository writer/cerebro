package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graphingest"
)

func (a *App) tapEventMapper() (*graphingest.Mapper, error) {
	if a == nil {
		return nil, fmt.Errorf("app is required")
	}
	a.tapMapperOnce.Do(func() {
		path := strings.TrimSpace(os.Getenv("GRAPH_EVENT_MAPPING_PATH"))
		var config graphingest.MappingConfig
		var err error
		if path != "" {
			config, err = graphingest.LoadConfigFile(path)
			if err != nil {
				if a.Logger != nil {
					a.Logger.Warn("failed to load custom graph event mapping config; falling back to defaults",
						"path", path,
						"error", err,
					)
				}
				config, err = graphingest.LoadDefaultConfig()
				if err != nil {
					a.tapMapperErr = fmt.Errorf("load default graph event mapping config after custom config failure: %w", err)
					return
				}
			}
		} else {
			config, err = graphingest.LoadDefaultConfig()
			if err != nil {
				a.tapMapperErr = err
				return
			}
		}

		validationMode := graphingest.MapperValidationEnforce
		deadLetterPath := ""
		if a.Config != nil {
			validationMode = graphingest.MapperValidationMode(strings.ToLower(strings.TrimSpace(a.Config.GraphEventMapperValidationMode)))
			deadLetterPath = strings.TrimSpace(a.Config.GraphEventMapperDeadLetterPath)
		}
		mapperOpts := graphingest.MapperOptions{
			ValidationMode: validationMode,
			DeadLetterPath: deadLetterPath,
		}
		a.TapEventMapper, a.tapMapperErr = graphingest.NewMapperWithOptions(config, a.resolveTapMappingIdentity, mapperOpts)
	})
	if a.tapMapperErr != nil {
		return nil, a.tapMapperErr
	}
	return a.TapEventMapper, nil
}

func (a *App) applyTapDeclarativeMappings(ctx context.Context, evt events.CloudEvent) (bool, error) {
	mapper, err := a.tapEventMapper()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("tap declarative mapping unavailable; using legacy fallback mapping",
				"event_type", evt.Type,
				"error", err,
			)
		}
		return false, nil
	}
	if mapper == nil {
		return false, nil
	}
	var (
		result                   graphingest.ApplyResult
		refreshEventCorrelations bool
	)
	_, err = a.MutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		if err := a.withTapResolveGraph(securityGraph, func() error {
			var applyErr error
			result, applyErr = mapper.Apply(securityGraph, evt)
			return applyErr
		}); err != nil {
			return false, err
		}
		if result.Matched {
			refreshEventCorrelations = shouldRefreshEventCorrelations(securityGraph, result.NodesUpserted)
		}
		return result.Matched, nil
	})
	if err != nil {
		return false, err
	}
	if result.Matched && a.Logger != nil {
		a.Logger.Info("applied declarative tap graph mappings",
			"event_type", evt.Type,
			"mappings", result.MappingNames,
			"nodes", len(result.NodesUpserted),
			"edges", len(result.EdgesUpserted),
			"events_rejected", result.EventsRejected,
			"nodes_rejected", result.NodesRejected,
			"edges_rejected", result.EdgesRejected,
			"dead_lettered", result.DeadLettered,
		)
	}
	if result.Matched && refreshEventCorrelations {
		a.queueEventCorrelationRefresh("tap_mapping")
	}
	if (result.EventsRejected > 0 || result.NodesRejected > 0 || result.EdgesRejected > 0) && a.Logger != nil {
		a.Logger.Warn("tap declarative mapping rejected invalid writes",
			"event_type", evt.Type,
			"mappings", result.MappingNames,
			"events_rejected", result.EventsRejected,
			"nodes_rejected", result.NodesRejected,
			"edges_rejected", result.EdgesRejected,
			"dead_lettered", result.DeadLettered,
		)
	}
	return result.Matched, nil
}
