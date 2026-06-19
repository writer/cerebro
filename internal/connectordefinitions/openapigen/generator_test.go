package openapigen

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

func TestGenerateBuildsSourcegenReadyDefinition(t *testing.T) {
	doc := loadFixture(t, securityFixture)
	definition, report, err := Generate(doc, Request{SourceID: "example_security"})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if definition.Auth.Model != "oauth_client_credentials" {
		t.Fatalf("auth model = %q, want oauth_client_credentials", definition.Auth.Model)
	}
	if definition.Auth.TokenURL != "https://auth.example.test/oauth/token" {
		t.Fatalf("token url = %q", definition.Auth.TokenURL)
	}
	if got := definition.Transport.BaseURL; got != "https://api.example.test/v1" {
		t.Fatalf("base url = %q", got)
	}
	if len(definition.ResourceFamilies) != 4 {
		t.Fatalf("resource families = %d, want 4", len(definition.ResourceFamilies))
	}
	audit := familyByID(t, definition.ResourceFamilies, "audit_log")
	if audit.Path != "/orgs/${config.org}/audit-log" {
		t.Fatalf("audit path = %q", audit.Path)
	}
	if audit.Projection == nil || audit.Projection.Template != "audit_event" {
		t.Fatalf("audit projection = %#v, want audit_event", audit.Projection)
	}
	if len(definition.ConfigFields) != 1 || definition.ConfigFields[0].Key != "org" {
		t.Fatalf("config fields = %#v, want org", definition.ConfigFields)
	}
	users := familyByID(t, definition.ResourceFamilies, "user")
	if users.RecordSelector != "$.data[*]" || users.ListKey != "data" {
		t.Fatalf("user selector/list key = %q/%q", users.RecordSelector, users.ListKey)
	}
	if users.Pagination == nil || users.Pagination.Type != "cursor" || users.Pagination.CursorParam != "cursor" || users.Pagination.PageSizeParam != "limit" {
		t.Fatalf("user pagination = %#v", users.Pagination)
	}
	alert := familyByID(t, definition.ResourceFamilies, "alert")
	if alert.Projection == nil || alert.Projection.Template != "finding" {
		t.Fatalf("alert projection = %#v, want finding", alert.Projection)
	}
	if report.EndpointCount != 4 || len(report.Selected) != 4 {
		t.Fatalf("report = %#v", report)
	}
	if _, err := sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
		DryRun:     true,
		Force:      true,
	}); err != nil {
		t.Fatalf("sourcegen.GenerateDefinition() error = %v", err)
	}
}

func TestGenerateInfersAPIKeyAndRootArray(t *testing.T) {
	doc := loadFixture(t, headerCredentialFixture)
	definition, report, err := Generate(doc, Request{MaxFamilies: 1, AllFamilies: true})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if definition.SourceID != "repository_api" {
		t.Fatalf("source id = %q", definition.SourceID)
	}
	if definition.Auth.Model != "api_key" {
		t.Fatalf("auth model = %q, want api_key", definition.Auth.Model)
	}
	if len(definition.Auth.CredentialFields) != 1 || definition.Auth.CredentialFields[0].Key != "api_key" {
		t.Fatalf("credential fields = %#v", definition.Auth.CredentialFields)
	}
	repo := familyByID(t, definition.ResourceFamilies, "repository")
	if repo.RecordSelector != "$[*]" || repo.ListKey != "" {
		t.Fatalf("repo selector/list key = %q/%q", repo.RecordSelector, repo.ListKey)
	}
	if len(definition.ResourceFamilies) != 2 {
		t.Fatalf("resource families = %d, want all 2", len(definition.ResourceFamilies))
	}
	if len(report.Skipped) != 0 {
		t.Fatalf("skipped = %#v, want none", report.Skipped)
	}
}

func loadFixture(t *testing.T, fixture string) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(fixture))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return doc
}

func familyByID(t *testing.T, families []connectordefinitions.ResourceFamily, id string) connectordefinitions.ResourceFamily {
	t.Helper()
	for _, family := range families {
		if family.ID == id {
			return family
		}
	}
	t.Fatalf("family %q not found in %#v", id, families)
	return connectordefinitions.ResourceFamily{}
}

const securityFixture = `
openapi: 3.0.3
info:
  title: Example Security
  description: Example security platform API.
servers:
  - url: https://api.example.test/v1
security:
  - OAuth2:
      - read:security
components:
  securitySchemes:
    OAuth2:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://auth.example.test/oauth/token
          scopes:
            read:security: Read security inventory.
  schemas:
    User:
      type: object
      properties:
        id: {type: string}
        email: {type: string}
        display_name: {type: string}
    Group:
      type: object
      properties:
        id: {type: string}
        name: {type: string}
    AuditEvent:
      type: object
      properties:
        id: {type: string}
        actor: {type: string}
        action: {type: string}
    Alert:
      type: object
      properties:
        id: {type: string}
        title: {type: string}
        severity: {type: string}
        status: {type: string}
paths:
  /users:
    get:
      tags: [Identity]
      operationId: listUsers
      parameters:
        - name: cursor
          in: query
          schema: {type: string}
        - name: limit
          in: query
          schema: {type: integer}
      responses:
        '200':
          description: Users.
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
  /groups:
    get:
      tags: [Identity]
      operationId: listGroups
      responses:
        '200':
          description: Groups.
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items:
                      $ref: '#/components/schemas/Group'
  /orgs/{org}/audit-log:
    parameters:
      - name: org
        in: path
        required: true
        schema: {type: string}
    get:
      tags: [Audit]
      operationId: listAuditEvents
      parameters:
        - name: page
          in: query
          schema: {type: integer}
        - name: per_page
          in: query
          schema: {type: integer}
      responses:
        '200':
          description: Audit events.
          content:
            application/json:
              schema:
                type: object
                properties:
                  records:
                    type: array
                    items:
                      $ref: '#/components/schemas/AuditEvent'
  /alerts:
    get:
      tags: [Findings]
      operationId: listAlerts
      responses:
        '200':
          description: Alerts.
          content:
            application/json:
              schema:
                type: object
                properties:
                  results:
                    type: array
                    items:
                      $ref: '#/components/schemas/Alert'
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: User detail.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
`

// #nosec G101 -- OpenAPI auth scheme fixture names only, not credential material.
const headerCredentialFixture = `
openapi: 3.0.3
info:
  title: Repository API
servers:
  - url: https://repos.example.test
components:
  securitySchemes:
    ApiKey:
      type: apiKey
      in: header
      name: X-API-Key
  schemas:
    Repository:
      type: object
      properties:
        id: {type: string}
        name: {type: string}
    Team:
      type: object
      properties:
        id: {type: string}
        name: {type: string}
paths:
  /repositories:
    get:
      operationId: listRepositories
      responses:
        '200':
          description: Repositories.
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Repository'
  /teams:
    get:
      operationId: listTeams
      responses:
        '200':
          description: Teams.
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/Team'
`
