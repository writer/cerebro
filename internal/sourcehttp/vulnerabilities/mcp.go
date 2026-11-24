package vulnerabilities

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/vulnpipeline"
)

// MCPResult is the result of one cerebro.vulnerabilities.* MCP tool. Exactly
// one field is set, and it serializes as that field's JSON.
type MCPResult struct {
	Observations *vulnpipeline.ObservationPageView
	Summary      *vulnpipeline.SummaryView
	Ingest       *vulnpipeline.IngestResult
}

// MarshalJSON encodes the populated result.
func (r MCPResult) MarshalJSON() ([]byte, error) {
	switch {
	case r.Observations != nil:
		return json.Marshal(r.Observations)
	case r.Summary != nil:
		return json.Marshal(r.Summary)
	case r.Ingest != nil:
		return json.Marshal(r.Ingest)
	default:
		return []byte("null"), nil
	}
}

type mcpArguments struct {
	ProfileID       mcpText         `json:"profile_id"`
	SourceIDs       mcpTextSet      `json:"source_id"`
	Severities      mcpTextSet      `json:"severity"`
	Statuses        mcpTextSet      `json:"status"`
	Classes         mcpTextSet      `json:"class"`
	VulnerabilityID mcpText         `json:"vulnerability_id"`
	Asset           mcpText         `json:"asset"`
	Query           mcpText         `json:"q"`
	Limit           mcpText         `json:"limit"`
	Cursor          mcpText         `json:"cursor"`
	Payload         json.RawMessage `json:"payload"`
	IdempotencyKey  mcpText         `json:"idempotency_key"`
	Format          mcpText         `json:"format"`
	FullSnapshot    mcpText         `json:"full_snapshot"`
}

// MCPTool runs one cerebro.vulnerabilities.* MCP tool for an already
// authorized tenant and actor. arguments is the JSON object of tool
// arguments.
func MCPTool(ctx context.Context, service *vulnpipeline.Service, name string, tenantID string, actor string, arguments json.RawMessage) (*MCPResult, error) {
	var args mcpArguments
	if len(bytes.TrimSpace(arguments)) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, fmt.Errorf("%w: invalid tool arguments", vulnpipeline.ErrInvalidRequest)
		}
	}
	switch name {
	case "cerebro.vulnerabilities.list":
		limit, err := optionalInt(string(args.Limit))
		if err != nil {
			return nil, err
		}
		page, err := service.ListObservations(ctx, ports.VulnerabilityObservationFilter{
			TenantID:        tenantID,
			SourceIDs:       args.SourceIDs,
			ProfileID:       string(args.ProfileID),
			Severities:      args.Severities,
			Statuses:        args.Statuses,
			Classes:         args.Classes,
			VulnerabilityID: string(args.VulnerabilityID),
			AssetIdentifier: string(args.Asset),
			Search:          string(args.Query),
			Limit:           limit,
			Cursor:          string(args.Cursor),
		})
		if err != nil {
			return nil, err
		}
		return &MCPResult{Observations: page}, nil
	case "cerebro.vulnerabilities.summary":
		summary, err := service.Summary(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		return &MCPResult{Summary: summary}, nil
	case "cerebro.vulnerabilities.ingest":
		payload, contentType, err := mcpPayload(args.Payload)
		if err != nil {
			return nil, err
		}
		fullSnapshot, err := optionalBool(string(args.FullSnapshot))
		if err != nil {
			return nil, err
		}
		result, err := service.Ingest(ctx, vulnpipeline.IngestRequest{
			TenantID:       tenantID,
			ProfileID:      string(args.ProfileID),
			Transport:      vulnpipeline.TransportMCP,
			ContentType:    contentType,
			IdempotencyKey: string(args.IdempotencyKey),
			Actor:          actor,
			Format:         string(args.Format),
			FullSnapshot:   fullSnapshot,
			Payload:        payload,
		})
		// A failed batch is still a recorded delivery; return it so the agent
		// sees the batch ID and error instead of a bare tool failure.
		if err != nil && result == nil {
			return nil, err
		}
		return &MCPResult{Ingest: result}, nil
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", vulnpipeline.ErrInvalidRequest, name)
	}
}

// mcpPayload accepts either a JSON value, ingested as JSON, or a string, whose
// contents are ingested as-is so CSV and other text formats can be detected.
func mcpPayload(raw json.RawMessage) ([]byte, string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, "", fmt.Errorf("%w: payload is required", vulnpipeline.ErrInvalidRequest)
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, "", fmt.Errorf("%w: payload must be JSON or a string", vulnpipeline.ErrInvalidRequest)
		}
		return []byte(text), "", nil
	}
	return trimmed, "application/json", nil
}

// mcpText decodes a scalar argument (string, number, or boolean) as trimmed
// text, since MCP clients are inconsistent about quoting numbers.
type mcpText string

func (t *mcpText) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil:
		*t = ""
	case string:
		*t = mcpText(strings.TrimSpace(typed))
	case float64:
		*t = mcpText(strconv.FormatFloat(typed, 'f', -1, 64))
	case bool:
		*t = mcpText(strconv.FormatBool(typed))
	default:
		return fmt.Errorf("expected a scalar value")
	}
	return nil
}

// mcpTextSet decodes either one string or an array of strings, dropping
// blanks.
type mcpTextSet []string

func (s *mcpTextSet) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var items []any
	switch typed := value.(type) {
	case nil:
	case string:
		items = []any{typed}
	case []any:
		items = typed
	default:
		return fmt.Errorf("expected a string or an array of strings")
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return fmt.Errorf("expected a string or an array of strings")
		}
		if text = strings.TrimSpace(text); text != "" {
			values = append(values, text)
		}
	}
	*s = values
	return nil
}
