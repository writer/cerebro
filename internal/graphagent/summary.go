package graphagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (s *Service) summarizeRows(ctx context.Context, request AskRequest, model string, cypher string, rows []map[string]any, history []HistoryMessage) (string, error) {
	if !s.options.EnableMapReduce || !shouldMapReduceRows(rows, s.options.MapReduceRowThreshold, s.options.MapReduceByteThreshold) {
		return s.llm.Summarize(ctx, SummarizeRequest{
			TenantID: strings.TrimSpace(request.TenantID),
			Question: strings.TrimSpace(request.Question),
			ScopeURN: strings.TrimSpace(request.ScopeURN),
			Model:    model,
			Cypher:   cypher,
			Rows:     rows,
			History:  history,
		})
	}
	chunks := chunkRowsForSummary(rows, s.options.MapReduceRowThreshold, s.options.MapReduceByteThreshold)
	reduceRows := make([]map[string]any, 0, len(chunks))
	for i, chunk := range chunks {
		chunkSummary, err := s.llm.Summarize(ctx, SummarizeRequest{
			TenantID: strings.TrimSpace(request.TenantID),
			Question: fmt.Sprintf("Summarize chunk %d of %d for: %s", i+1, len(chunks), strings.TrimSpace(request.Question)),
			ScopeURN: strings.TrimSpace(request.ScopeURN),
			Model:    model,
			Cypher:   cypher,
			Rows:     chunk,
			History:  history,
		})
		if err != nil {
			return "", err
		}
		reduceRows = append(reduceRows, map[string]any{
			"chunk":   i + 1,
			"summary": strings.TrimSpace(chunkSummary),
			"urns":    collectRowURNs(chunk),
		})
	}
	return s.llm.Summarize(ctx, SummarizeRequest{
		TenantID: strings.TrimSpace(request.TenantID),
		Question: "Combine the chunk summaries into one final answer for: " + strings.TrimSpace(request.Question),
		ScopeURN: strings.TrimSpace(request.ScopeURN),
		Model:    model,
		Cypher:   cypher,
		Rows:     reduceRows,
		History:  history,
	})
}

func shouldMapReduceRows(rows []map[string]any, rowThreshold int, byteThreshold int) bool {
	if len(rows) > rowThreshold {
		return true
	}
	raw, err := json.Marshal(rows)
	return err == nil && len(raw) > byteThreshold
}

func chunkRowsForSummary(rows []map[string]any, rowThreshold int, byteThreshold int) [][]map[string]any {
	if len(rows) == 0 {
		return nil
	}
	if rowThreshold <= 0 {
		rowThreshold = 100
	}
	if byteThreshold <= 0 {
		byteThreshold = 64 << 10
	}
	var chunks [][]map[string]any
	var current []map[string]any
	currentBytes := 0
	for _, row := range rows {
		raw, _ := json.Marshal(row)
		if len(current) > 0 && (len(current) >= rowThreshold || currentBytes+len(raw) > byteThreshold) {
			chunks = append(chunks, current)
			current = nil
			currentBytes = 0
		}
		current = append(current, row)
		currentBytes += len(raw)
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}
