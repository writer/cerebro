package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/writer/cerebro/internal/executions"
	"github.com/writer/cerebro/internal/executionstore"
)

func (a *App) toolCerebroExecutionStatus(ctx context.Context, args json.RawMessage) (string, error) {
	if a == nil || a.Config == nil {
		return "", fmt.Errorf("app config not initialized")
	}
	var req struct {
		Namespace []string `json:"namespace,omitempty"`
		Status    []string `json:"status,omitempty"`
		ReportID  string   `json:"report_id,omitempty"`
		Limit     int      `json:"limit,omitempty"`
		Order     string   `json:"order,omitempty"`
	}
	if err := decodeToolArgs(args, &req); err != nil {
		return "", err
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		return "", fmt.Errorf("limit must be <= 100")
	}
	store, err := executionstore.NewSQLiteStore(a.Config.ExecutionStoreFile)
	if err != nil {
		return "", fmt.Errorf("open shared execution store: %w", err)
	}
	defer func() { _ = store.Close() }()

	summaries, err := executions.List(ctx, store, executions.ListOptions{
		Namespaces:         req.Namespace,
		Statuses:           req.Status,
		ReportID:           req.ReportID,
		Limit:              limit,
		OrderBySubmittedAt: req.Order == "submitted",
	})
	if err != nil {
		return "", err
	}
	return marshalToolResponse(map[string]any{
		"count":      len(summaries),
		"executions": summaries,
	})
}
