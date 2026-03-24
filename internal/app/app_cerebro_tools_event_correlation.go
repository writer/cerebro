package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

type cerebroCorrelateEventsRequest struct {
	Mode             string `json:"mode"`
	EventID          string `json:"event_id"`
	EntityID         string `json:"entity_id"`
	PatternID        string `json:"pattern_id"`
	Direction        string `json:"direction"`
	Limit            int    `json:"limit"`
	MaxDepth         int    `json:"max_depth"`
	Since            string `json:"since"`
	Until            string `json:"until"`
	IncludeAnomalies *bool  `json:"include_anomalies"`
}

func (a *App) toolCerebroCorrelateEvents(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	var req cerebroCorrelateEventsRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	if strings.TrimSpace(req.EventID) == "" && strings.TrimSpace(req.EntityID) == "" {
		return "", fmt.Errorf("event_id or entity_id is required")
	}

	var since time.Time
	if raw := strings.TrimSpace(req.Since); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return "", fmt.Errorf("since must be RFC3339")
		}
		since = parsed
	}

	var until time.Time
	if raw := strings.TrimSpace(req.Until); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return "", fmt.Errorf("until must be RFC3339")
		}
		until = parsed
	}

	includeAnomalies := false
	if req.IncludeAnomalies != nil {
		includeAnomalies = *req.IncludeAnomalies
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "correlations"
	}

	switch mode {
	case "correlations":
		result := graph.QueryEventCorrelations(g, time.Now().UTC(), graph.EventCorrelationQuery{
			EventID:          strings.TrimSpace(req.EventID),
			EntityID:         strings.TrimSpace(req.EntityID),
			PatternID:        strings.TrimSpace(req.PatternID),
			Limit:            req.Limit,
			Since:            since,
			Until:            until,
			IncludeAnomalies: includeAnomalies,
		})
		return marshalToolResponse(result)
	case "chains":
		result := graph.QueryEventCorrelationChains(g, time.Now().UTC(), graph.EventCorrelationChainQuery{
			EventID:   strings.TrimSpace(req.EventID),
			EntityID:  strings.TrimSpace(req.EntityID),
			PatternID: strings.TrimSpace(req.PatternID),
			Direction: strings.TrimSpace(req.Direction),
			Limit:     req.Limit,
			MaxDepth:  req.MaxDepth,
			Since:     since,
			Until:     until,
		})
		return marshalToolResponse(result)
	default:
		return "", fmt.Errorf("mode must be one of correlations or chains")
	}
}
