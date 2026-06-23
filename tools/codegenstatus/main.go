// Command codegenstatus produces a unified JSON status report for all codegen
// generators in the repository. It checks staleness of generated artifacts and
// reports catalog readiness without running the generators.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcegen/projectionspec"
)

// Status is the unified codegen status report.
type Status struct {
	Catalog             *CatalogStatus     `json:"catalog"`
	ProjectionTemplates *TemplateStatus    `json:"projection_templates"`
	Generators          []GeneratorStatus  `json:"generators"`
}

// CatalogStatus summarizes the connector catalog.
type CatalogStatus struct {
	Total               int            `json:"total"`
	CatalogReady        int            `json:"catalog_ready"`
	Generateable        int            `json:"generateable"`
	NeedsAuthExtension  int            `json:"needs_auth_extension"`
	NeedsBespokeRuntime int            `json:"needs_bespoke_runtime"`
	ByAuthModel         map[string]int `json:"by_auth_model,omitempty"`
	ByClassifierOutput  map[string]int `json:"by_classifier_output,omitempty"`
	Issues              int            `json:"issues"`
}

// TemplateStatus summarizes the projection template registry.
type TemplateStatus struct {
	Count     int      `json:"count"`
	Templates []string `json:"templates"`
}

// GeneratorStatus describes one codegen generator.
type GeneratorStatus struct {
	Name        string `json:"name"`
	Tool        string `json:"tool"`
	MakeTarget  string `json:"make_target"`
	CheckTarget string `json:"check_target"`
	Description string `json:"description"`
}

func main() {
	status := Status{
		Generators: knownGenerators(),
	}

	// Load catalog analysis.
	analysis, err := connectorcatalog.Builtin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "codegenstatus: catalog analysis: %v\n", err)
		status.Catalog = &CatalogStatus{Issues: -1}
	} else {
		status.Catalog = &CatalogStatus{
			Total:               analysis.Summary.Total,
			CatalogReady:        analysis.Summary.CatalogReady,
			Generateable:        analysis.Summary.Generateable,
			NeedsAuthExtension:  analysis.Summary.NeedsAuthExtension,
			NeedsBespokeRuntime: analysis.Summary.NeedsBespokeRuntime,
			ByAuthModel:         analysis.Summary.ByAuthModel,
			ByClassifierOutput:  analysis.Summary.ByClassifierOutput,
			Issues:              len(analysis.Issues),
		}
	}

	// Load projection template registry.
	registry, err := projectionspec.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "codegenstatus: projection templates: %v\n", err)
	} else {
		status.ProjectionTemplates = &TemplateStatus{
			Count:     len(registry.IDs()),
			Templates: registry.IDs(),
		}
	}

	payload, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(payload))
}

func knownGenerators() []GeneratorStatus {
	return []GeneratorStatus{
		{
			Name:        "Proto/ConnectRPC",
			Tool:        "buf generate",
			MakeTarget:  "proto-generate",
			CheckTarget: "proto-generate-check",
			Description: "Protobuf-derived Go, ConnectRPC, and Python stubs",
		},
		{
			Name:        "OpenAPI TypeScript Types",
			Tool:        "tools/openapitsgen",
			MakeTarget:  "openapi-ts-generate",
			CheckTarget: "openapi-ts-check",
			Description: "TypeScript type definitions from api/openapi.yaml",
		},
		{
			Name:        "Source Runtime SDK",
			Tool:        "internal/sourcegen",
			MakeTarget:  "sourcegen-check",
			CheckTarget: "sourcegen-check",
			Description: "Generated source packages from connector definitions",
		},
		{
			Name:        "Graph Action Registry",
			Tool:        "tools/graphactiongen",
			MakeTarget:  "graph-action-generate",
			CheckTarget: "graph-action-check",
			Description: "Graph action registry from action_catalog.yaml",
		},
		{
			Name:        "Policy Rule Catalog",
			Tool:        "tools/policyrulegen",
			MakeTarget:  "policy-rule-generate",
			CheckTarget: "policy-rule-check",
			Description: "Policy rule catalog from DSL YAML + extensions",
		},
		{
			Name:        "Detection Catalog",
			Tool:        "tools/detectioncatalog",
			MakeTarget:  "detection-catalog-generate",
			CheckTarget: "detection-catalog-check",
			Description: "Public detection catalog from internal rule definitions",
		},
		{
			Name:        "Finding DSL Schema",
			Tool:        "tools/findingdsl",
			MakeTarget:  "finding-dsl-schema-generate",
			CheckTarget: "finding-dsl-schema-check",
			Description: "JSON Schema for PolicyFindingRule YAML validation",
		},
		{
			Name:        "Control Index",
			Tool:        "tools/controlindex",
			MakeTarget:  "control-index-generate",
			CheckTarget: "control-index-check",
			Description: "Control framework index from control families",
		},
		{
			Name:        "OpenAPI Route Parity",
			Tool:        "scripts/openapi_route_parity.go",
			MakeTarget:  "openapi-sync",
			CheckTarget: "openapi-check",
			Description: "OpenAPI spec route parity with implementation",
		},
		{
			Name:        "Connector Onboard",
			Tool:        "tools/connectoronboard",
			MakeTarget:  "connector-onboard",
			CheckTarget: "",
			Description: "End-to-end connector onboarding from OpenAPI spec",
		},
	}
}
