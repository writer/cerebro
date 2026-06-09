package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/writer/cerebro/internal/sourcegen"
)

const sourceRuntimeSDKNewUsage = "usage: %s source-runtime sdk new <source-id> [source_type=json_api] [auth_model=bearer_token|api_token|api_key] [asset_schemas=<schema[,schema]>] [finding_schemas=<schema[,schema]>] [freshness_expectation=<duration>] [failure_modes=<mode[,mode]>] [name=<name>] [description=<description>] [health_path=<path>] [output_dir=<dir>] [dry_run=true] [force=true]"

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
		result, err := sourcegen.Generate(request)
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
}

func parseSourceRuntimeSDKNewArgs(args []string) (sourcegen.Request, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return sourcegen.Request{}, usageError(fmt.Sprintf(sourceRuntimeSDKNewUsage, os.Args[0]))
	}
	allowedKeys := map[string]struct{}{
		"source_type":           {},
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
			return sourcegen.Request{}, fmt.Errorf("invalid source runtime SDK argument %q; want key=value", arg)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return sourcegen.Request{}, fmt.Errorf("source runtime SDK argument key is required")
		}
		if _, ok := allowedKeys[key]; !ok {
			return sourcegen.Request{}, fmt.Errorf("unsupported source runtime SDK argument %q", key)
		}
		values[key] = strings.TrimSpace(value)
	}
	dryRun, err := parseBoolValue(values["dry_run"])
	if err != nil {
		return sourcegen.Request{}, fmt.Errorf("parse dry_run: %w", err)
	}
	force, err := parseBoolValue(values["force"])
	if err != nil {
		return sourcegen.Request{}, fmt.Errorf("parse force: %w", err)
	}
	return sourcegen.Request{
		SourceID:             strings.TrimSpace(args[0]),
		SourceType:           firstNonEmptyCLI(values["source_type"], sourcegen.SourceTypeJSONAPI),
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
	}, nil
}
