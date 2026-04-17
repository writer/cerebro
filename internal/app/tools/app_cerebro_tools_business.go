package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	reports "github.com/writer/cerebro/internal/graph/reports"
)

type cerebroKeyPersonRiskRequest struct {
	PersonID string `json:"person_id"`
	Limit    int    `json:"limit"`
}

func (a *Runtime) toolCerebroKeyPersonRisk(_ context.Context, args json.RawMessage) (string, error) {
	var req cerebroKeyPersonRiskRequest
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}

	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	personID := strings.TrimSpace(req.PersonID)
	report := reports.BuildKeyPersonRiskReport(g, time.Now().UTC(), personID, clampInt(req.Limit, 10, 1, 100))
	if personID != "" && report.Count == 0 {
		return "", fmt.Errorf("person not found: %s", personID)
	}
	return marshalToolResponse(report)
}
