package graphagent

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

func TestInstrumentedLLMClientDraftDoesNotEmitPromptOrCypherText(t *testing.T) {
	question := "Which assets mention secret-token-shaped evidence?"
	cypher := "MATCH (e:Entity {secret: 'token-shaped'}) RETURN e LIMIT 1"
	client := instrumentLLMClient("openrouter", &StubLLMClient{
		DraftResponse: &DraftResponse{
			Cypher: cypher,
		},
	})

	stderr := captureGraphAgentStderr(t, func() {
		response, err := client.DraftCypher(context.Background(), DraftRequest{
			TenantID: "tenant-a",
			Question: question,
			ScopeURN: "urn:cerebro:example:scope",
			Model:    "claude-sonnet-4-6",
			Schema:   "(:Entity)-[:RELATES_TO]->(:Entity)",
			MaxRows:  25,
		})
		if err != nil {
			t.Fatalf("DraftCypher() error = %v", err)
		}
		if response == nil || response.Cypher != cypher {
			t.Fatalf("DraftCypher() response = %#v", response)
		}
	})

	if !strings.Contains(stderr, `"name":"graphagent.llm.draft"`) {
		t.Fatalf("telemetry missing graphagent llm draft span: %s", stderr)
	}
	if !strings.Contains(stderr, `"gen_ai.provider.name":"openrouter"`) || !strings.Contains(stderr, `"gen_ai.operation.name":"draft"`) {
		t.Fatalf("telemetry missing safe gen_ai attrs: %s", stderr)
	}
	if strings.Contains(stderr, question) || strings.Contains(stderr, cypher) {
		t.Fatalf("telemetry leaked prompt or cypher text: %s", stderr)
	}
}

func captureGraphAgentStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = writer
	t.Cleanup(func() {
		os.Stderr = original
	})
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	os.Stderr = original
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(data)
}
