package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcegen"
)

const sourceRuntimeSDKNewUsage = "usage: %s source-runtime sdk [new <source-id> [catalog=true] [definition=<definition.json>] [source_type=json_api] [auth_model=bearer_token|api_token|api_key] [asset_schemas=<schema[,schema]>] [finding_schemas=<schema[,schema]>] [freshness_expectation=<duration>] [failure_modes=<mode[,mode]>] [name=<name>] [description=<description>] [health_path=<path>] [output_dir=<dir>] [dry_run=true] [force=true] | classify <definition.json>]"

type sourceRuntimeSDKNewRequest struct {
	sourcegen.Request
	CatalogDefinition bool
}

func runSourceRuntimeSDK(args []string) error {
	if len(args) == 0 {
		return usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
	switch args[0] {
	case "new":
		request, err := parseSourceRuntimeSDKNewArgs(args[1:])
		if err != nil {
			return err
		}
		result, err := generateSourceRuntimeSDK(request)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "classify":
		return runSourceRuntimeSDKClassify(args[1:])
	default:
		return usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
}

func generateSourceRuntimeSDK(request sourceRuntimeSDKNewRequest) (*sourcegen.Result, error) {
	if request.CatalogDefinition {
		if strings.TrimSpace(request.DefinitionPath) != "" {
			return nil, fmt.Errorf("catalog=true cannot be combined with definition")
		}
		entry, ok, err := connectorcatalog.BuiltinEntry(request.SourceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("connector catalog definition %q not found", request.SourceID)
		}
		return generateSourceRuntimeSDKDefinition(entry.Definition, request.Request)
	}
	if strings.TrimSpace(request.DefinitionPath) == "" {
		return sourcegen.Generate(request.Request)
	}
	definition, err := readConnectorDefinition(request.DefinitionPath)
	if err != nil {
		return nil, err
	}
	return generateSourceRuntimeSDKDefinition(definition, request.Request)
}

func generateSourceRuntimeSDKDefinition(definition connectordefinitions.Definition, request sourcegen.Request) (*sourcegen.Result, error) {
	if strings.TrimSpace(definition.SourceID) == "" {
		definition.SourceID = strings.TrimSpace(request.SourceID)
	}
	normalizedDefinition, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return nil, err
	}
	requestSourceID, err := normalizeConnectorSourceID(request.SourceID)
	if err != nil {
		return nil, err
	}
	if requestSourceID != "" && normalizedDefinition.SourceID != "" && requestSourceID != normalizedDefinition.SourceID {
		return nil, fmt.Errorf("source id %q does not match definition source_id %q", request.SourceID, definition.SourceID)
	}
	return sourcegen.GenerateDefinition(sourcegen.DefinitionRequest{
		Definition:           normalizedDefinition,
		FreshnessExpectation: request.FreshnessExpectation,
		HealthPath:           request.HealthPath,
		OutputDir:            request.OutputDir,
		DryRun:               request.DryRun,
		Force:                request.Force,
	})
}

func normalizeConnectorSourceID(sourceID string) (string, error) {
	normalized, err := connectordefinitions.Normalize(connectordefinitions.Definition{SourceID: sourceID})
	if err != nil {
		return "", err
	}
	return normalized.SourceID, nil
}

func runSourceRuntimeSDKClassify(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
	payload, err := readConnectorDefinitionPayload(args[0])
	if err != nil {
		return err
	}
	var definitions []connectordefinitions.Definition
	if err := json.Unmarshal(payload, &definitions); err == nil {
		summary, err := connectordefinitions.ClassifyAll(definitions, connectordefinitions.DefaultGrammar())
		if err != nil {
			return err
		}
		return printJSON(summary)
	}
	var definition connectordefinitions.Definition
	if err := json.Unmarshal(payload, &definition); err != nil {
		return fmt.Errorf("decode connector definition or definition list: %w", err)
	}
	report, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
	if err != nil {
		return err
	}
	return printJSON(report)
}

func readConnectorDefinition(path string) (connectordefinitions.Definition, error) {
	payload, err := readConnectorDefinitionPayload(path)
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	var definition connectordefinitions.Definition
	if err := json.Unmarshal(payload, &definition); err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("decode connector definition: %w", err)
	}
	return definition, nil
}

func readConnectorDefinitionPayload(path string) ([]byte, error) {
	payload, err := os.ReadFile(strings.TrimSpace(path)) // #nosec G304,G703 -- operator-provided CLI path.
	if err != nil {
		return nil, fmt.Errorf("read connector definition: %w", err)
	}
	return payload, nil
}

func parseSourceRuntimeSDKNewArgs(args []string) (sourceRuntimeSDKNewRequest, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return sourceRuntimeSDKNewRequest{}, usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
	allowedKeys := map[string]struct{}{
		"source_type":           {},
		"definition":            {},
		"catalog":               {},
		"auth_model":            {},
		"asset_schemas":         {},
		"finding_schemas":       {},
		"freshness_expectation": {},
		"freshness":             {},
		"failure_modes":         {},
		"name":                  {},
		"description":           {},
		"health_path":           {},
		"output_dir":            {},
		"dry_run":               {},
		"force":                 {},
	}
	values := map[string]string{}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return sourceRuntimeSDKNewRequest{}, fmt.Errorf("invalid source runtime SDK argument %q; want key=value", arg)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return sourceRuntimeSDKNewRequest{}, fmt.Errorf("source runtime SDK argument key is required")
		}
		if _, ok := allowedKeys[key]; !ok {
			return sourceRuntimeSDKNewRequest{}, fmt.Errorf("unsupported source runtime SDK argument %q", key)
		}
		values[key] = strings.TrimSpace(value)
	}
	dryRun, err := parseBoolValue(values["dry_run"])
	if err != nil {
		return sourceRuntimeSDKNewRequest{}, fmt.Errorf("parse dry_run: %w", err)
	}
	force, err := parseBoolValue(values["force"])
	if err != nil {
		return sourceRuntimeSDKNewRequest{}, fmt.Errorf("parse force: %w", err)
	}
	catalogDefinition, err := parseBoolValue(values["catalog"])
	if err != nil {
		return sourceRuntimeSDKNewRequest{}, fmt.Errorf("parse catalog: %w", err)
	}
	return sourceRuntimeSDKNewRequest{
		Request: sourcegen.Request{
			SourceID:             strings.TrimSpace(args[0]),
			SourceType:           firstNonEmptyCLI(values["source_type"], sourcegen.SourceTypeJSONAPI),
			DefinitionPath:       strings.TrimSpace(values["definition"]),
			AuthModel:            firstNonEmptyCLI(values["auth_model"], sourcegen.AuthModelBearerToken),
			AssetSchemas:         splitCSV(values["asset_schemas"]),
			FindingSchemas:       splitCSV(values["finding_schemas"]),
			FreshnessExpectation: firstNonEmptyCLI(values["freshness_expectation"], values["freshness"]),
			FailureModes:         splitCSV(values["failure_modes"]),
			Name:                 strings.TrimSpace(values["name"]),
			Description:          strings.TrimSpace(values["description"]),
			HealthPath:           strings.TrimSpace(values["health_path"]),
			OutputDir:            firstNonEmptyCLI(values["output_dir"], "."),
			DryRun:               dryRun,
			Force:                force,
		},
		CatalogDefinition: catalogDefinition,
	}, nil
}
