package graphagent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSummarizeRowsRejectsSingleOversizedRow(t *testing.T) {
	llm := &StubLLMClient{}
	service := NewServiceWithOptions(nil, llm, ValidatorOptions{}, ServiceOptions{
		EnableMapReduce:        true,
		MapReduceByteThreshold: 64,
	})

	_, err := service.summarizeRows(context.Background(), AskRequest{TenantID: "writer", Question: "summarize"}, "", "RETURN row", []map[string]any{{
		"entity_urn": "urn:cerebro:writer:asset:alpha",
		"blob":       strings.Repeat("a", 128),
	}}, nil)
	if !errors.Is(err, ErrSummaryRowTooLarge) {
		t.Fatalf("summarizeRows() err = %v, want summary byte limit", err)
	}
	if len(llm.SummaryRequests) != 0 {
		t.Fatalf("summary requests = %d, want none", len(llm.SummaryRequests))
	}
}

func TestSummarizeRowsRejectsOversizedOneShotPayload(t *testing.T) {
	llm := &StubLLMClient{}
	service := NewServiceWithOptions(nil, llm, ValidatorOptions{}, ServiceOptions{
		MapReduceByteThreshold: 96,
	})

	_, err := service.summarizeRows(context.Background(), AskRequest{TenantID: "writer", Question: "summarize"}, "", "RETURN row", []map[string]any{
		{"entity_urn": "urn:cerebro:writer:asset:alpha", "label": strings.Repeat("a", 30)},
		{"entity_urn": "urn:cerebro:writer:asset:beta", "label": strings.Repeat("b", 30)},
	}, nil)
	if !errors.Is(err, ErrSummaryPayloadTooLarge) {
		t.Fatalf("summarizeRows() err = %v, want summary payload byte limit", err)
	}
	if len(llm.SummaryRequests) != 0 {
		t.Fatalf("summary requests = %d, want none", len(llm.SummaryRequests))
	}
}
