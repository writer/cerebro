package stream

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
)

func (r *Runtime) tapEventMapper() (*graphingest.Mapper, error) {
	if r == nil {
		return nil, fmt.Errorf("stream runtime is required")
	}

	r.mapperMu.Lock()
	defer r.mapperMu.Unlock()
	if !r.mapperInitialized {
		path := strings.TrimSpace(os.Getenv("GRAPH_EVENT_MAPPING_PATH"))
		var config graphingest.MappingConfig
		var err error
		if path != "" {
			config, err = graphingest.LoadConfigFile(path)
			if err != nil {
				if logger := r.logger(); logger != nil {
					logger.Warn("failed to load custom graph event mapping config; falling back to defaults",
						"path", path,
						"error", err,
					)
				}
				config, err = graphingest.LoadDefaultConfig()
				if err != nil {
					r.mapperErr = fmt.Errorf("load default graph event mapping config after custom config failure: %w", err)
					r.mapperInitialized = true
					return nil, r.mapperErr
				}
			}
		} else {
			config, err = graphingest.LoadDefaultConfig()
			if err != nil {
				r.mapperErr = err
				r.mapperInitialized = true
				return nil, r.mapperErr
			}
		}

		validationMode := graphingest.MapperValidationEnforce
		deadLetterPath := ""
		if cfg := r.config(); cfg != nil {
			validationMode = graphingest.MapperValidationMode(strings.ToLower(strings.TrimSpace(cfg.GraphEventMapperValidationMode)))
			deadLetterPath = strings.TrimSpace(cfg.GraphEventMapperDeadLetterPath)
		}
		mapperOpts := graphingest.MapperOptions{
			ValidationMode: validationMode,
			DeadLetterPath: deadLetterPath,
		}
		r.mapper, r.mapperErr = graphingest.NewMapperWithOptions(config, r.resolveTapMappingIdentity, mapperOpts)
		r.mapperInitialized = true
	}
	if r.mapperErr != nil {
		return nil, r.mapperErr
	}
	return r.mapper, nil
}

func (r *Runtime) applyTapDeclarativeMappings(ctx context.Context, evt events.CloudEvent) (bool, error) {
	mapper, err := r.tapEventMapper()
	if err != nil {
		if logger := r.logger(); logger != nil {
			logger.Warn("tap declarative mapping unavailable; using legacy fallback mapping",
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
	_, err = r.mutateSecurityGraphMaybe(ctx, func(securityGraph *graph.Graph) (bool, error) {
		if err := r.withTapResolveGraph(securityGraph, func() error {
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
	if result.Matched {
		if logger := r.logger(); logger != nil {
			logger.Info("applied declarative tap graph mappings",
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
		if refreshEventCorrelations {
			r.queueEventCorrelationRefresh("tap_mapping")
		}
	}
	if (result.EventsRejected > 0 || result.NodesRejected > 0 || result.EdgesRejected > 0) && r.logger() != nil {
		r.logger().Warn("tap declarative mapping rejected invalid writes",
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

func (r *Runtime) TapEventMapper() (*graphingest.Mapper, error) {
	return r.tapEventMapper()
}
