package openapitsgen

import (
	"strings"
	"testing"
)

func TestGenerateBasicSchema(t *testing.T) {
	spec := `
components:
  schemas:
    HealthResponse:
      type: object
      properties:
        status:
          type: string
        version:
          type: string
      required:
        - status
    SeverityLevel:
      type: string
      enum:
        - LOW
        - MEDIUM
        - HIGH
        - CRITICAL
    FindingList:
      type: object
      properties:
        findings:
          type: array
          items:
            $ref: '#/components/schemas/HealthResponse'
        total:
          type: integer
`
	result, err := Generate([]byte(spec))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if result.TypeCount != 3 {
		t.Errorf("TypeCount = %d, want 3", result.TypeCount)
	}
	if !strings.Contains(result.TypeScript, "export type HealthResponse") {
		t.Error("expected HealthResponse type")
	}
	if !strings.Contains(result.TypeScript, "status: string") {
		t.Error("expected required status field without ?")
	}
	if !strings.Contains(result.TypeScript, "version?: string") {
		t.Error("expected optional version field with ?")
	}
	if !strings.Contains(result.TypeScript, "export type SeverityLevel =") {
		t.Error("expected SeverityLevel enum type")
	}
	if !strings.Contains(result.TypeScript, `"LOW"`) {
		t.Error("expected LOW enum value")
	}
	if !strings.Contains(result.TypeScript, "findings?: HealthResponse[]") {
		t.Error("expected array ref type")
	}
	if !strings.Contains(result.TypeScript, "total?: number") {
		t.Error("expected number type for integer")
	}
	if !strings.Contains(result.TypeScript, "DO NOT EDIT") {
		t.Error("expected generated file header")
	}
}

func TestGenerateAdditionalProperties(t *testing.T) {
	spec := `
components:
  schemas:
    Attributes:
      type: object
      additionalProperties:
        type: string
`
	result, err := Generate([]byte(spec))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(result.TypeScript, "Record<string, string>") {
		t.Errorf("expected Record<string, string>, got:\n%s", result.TypeScript)
	}
}

func TestGenerateEmptySchemas(t *testing.T) {
	spec := `
components:
  schemas: {}
`
	_, err := Generate([]byte(spec))
	if err == nil {
		t.Error("expected error for empty schemas")
	}
}
