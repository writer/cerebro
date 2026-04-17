package tools

import (
	"context"
	"encoding/json"
	"fmt"

	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (a *Runtime) toolCerebroAIWorkloads(_ context.Context, args json.RawMessage) (string, error) {
	g, err := a.requireReadableSecurityGraph()
	if err != nil {
		return "", err
	}

	var req struct {
		MaxWorkloads  int   `json:"max_workloads"`
		MinRiskScore  int   `json:"min_risk_score"`
		IncludeShadow *bool `json:"include_shadow"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	if req.MinRiskScore < 0 || req.MinRiskScore > 100 {
		return "", fmt.Errorf("min_risk_score must be between 0 and 100")
	}

	includeShadow := true
	if req.IncludeShadow != nil {
		includeShadow = *req.IncludeShadow
	}

	report := reports.BuildAIWorkloadInventoryReport(g, reports.AIWorkloadInventoryReportOptions{
		MaxWorkloads:  clampInt(req.MaxWorkloads, 50, 1, 200),
		MinRiskScore:  req.MinRiskScore,
		IncludeShadow: includeShadow,
	})
	return marshalToolResponse(report)
}
