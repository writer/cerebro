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
	EventID          string `json:"event_id"`
	EntityID         string `json:"entity_id"`
	PatternID        string `json:"pattern_id"`
	Limit            int    `json:"limit"`
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

	includeAnomalies := false
	if req.IncludeAnomalies != nil {
		includeAnomalies = *req.IncludeAnomalies
	}

	result := graph.QueryEventCorrelations(g, time.Now().UTC(), graph.EventCorrelationQuery{
		EventID:          strings.TrimSpace(req.EventID),
		EntityID:         strings.TrimSpace(req.EntityID),
		PatternID:        strings.TrimSpace(req.PatternID),
		Limit:            req.Limit,
		IncludeAnomalies: includeAnomalies,
	})
	return marshalToolResponse(result)
}
