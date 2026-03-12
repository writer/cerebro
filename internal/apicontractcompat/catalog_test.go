package apicontractcompat

import (
	"testing"
	"time"
)

func TestBuildAndCompareCatalogs(t *testing.T) {
	baselineYAML := []byte(`
openapi: 3.0.3
paths:
  /api/v1/widgets:
    get:
      parameters:
        - name: limit
          in: query
          required: false
          schema:
            type: integer
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: string
                        name:
                          type: string
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
      responses:
        '201':
          description: created
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
components:
  schemas: {}
`)
	currentYAML := []byte(`
openapi: 3.0.3
paths:
  /api/v1/widgets:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: string
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: integer
      responses:
        '200':
          description: created
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
components:
  schemas: {}
`)
	baseline, err := BuildCatalogFromYAML(baselineYAML, time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build baseline catalog: %v", err)
	}
	current, err := BuildCatalogFromYAML(currentYAML, time.Date(2026, 3, 10, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build current catalog: %v", err)
	}

	report := CompareCatalogs(baseline, current, time.Date(2026, 3, 10, 2, 0, 0, 0, time.UTC))
	if len(report.BreakingChanges) < 4 {
		t.Fatalf("expected multiple breaking changes, got %+v", report.BreakingChanges)
	}

	assertChange := func(changeType string) {
		t.Helper()
		for _, issue := range report.BreakingChanges {
			if issue.ChangeType == changeType {
				return
			}
		}
		t.Fatalf("expected change type %q in %+v", changeType, report.BreakingChanges)
	}
	assertChange("removed_query_parameter")
	assertChange("changed_required_request_field_type")
	assertChange("removed_success_status_code")
	assertChange("removed_response_field")
}
