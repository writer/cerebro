package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/bootstrap"
)

const investigationBriefUsage = "usage: %s graph investigation-brief <finding-id> [base_url=<url>] [api_key=<key>] [limit=N] [skip_graph=true] [format=json|markdown]"

type investigationBriefOptions struct {
	FindingID string
	BaseURL   string
	APIKey    string
	Limit     int
	SkipGraph bool
	Format    string
}

func runInvestigationBrief(args []string) error {
	options, err := parseInvestigationBriefOptions(args)
	if err != nil {
		return err
	}
	body, err := bootstrap.FetchInvestigationBrief(context.Background(), bootstrap.InvestigationBriefClientRequest{
		BaseURL:   options.BaseURL,
		APIKey:    options.APIKey,
		FindingID: options.FindingID,
		Limit:     options.Limit,
		SkipGraph: options.SkipGraph,
	})
	if err != nil {
		return err
	}
	if options.Format == "markdown" {
		var payload struct {
			Markdown string `json:"markdown"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return fmt.Errorf("decode investigation brief markdown: %w", err)
		}
		fmt.Println(payload.Markdown)
		return nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("decode investigation brief response: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(decoded); err != nil {
		return fmt.Errorf("print investigation brief: %w", err)
	}
	return nil
}

func parseInvestigationBriefOptions(args []string) (investigationBriefOptions, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return investigationBriefOptions{}, usageError(fmt.Sprintf(investigationBriefUsage, os.Args[0]))
	}
	options := investigationBriefOptions{
		FindingID: strings.TrimSpace(args[0]),
		BaseURL:   strings.TrimSpace(os.Getenv("CEREBRO_BASE_URL")),
		APIKey:    strings.TrimSpace(os.Getenv("CEREBRO_API_KEY")),
		Limit:     int(investigationBriefDefaultLimitForCLI()),
		Format:    "json",
	}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return investigationBriefOptions{}, usageError(fmt.Sprintf("expected key=value argument, got %q", arg))
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "base_url":
			options.BaseURL = value
		case "api_key":
			options.APIKey = value
		case "limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit <= 0 {
				return investigationBriefOptions{}, usageError("limit must be a positive integer")
			}
			options.Limit = limit
		case "skip_graph":
			options.SkipGraph = strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
		case "format":
			if value != "json" && value != "markdown" {
				return investigationBriefOptions{}, usageError("format must be json or markdown")
			}
			options.Format = value
		default:
			return investigationBriefOptions{}, usageError(fmt.Sprintf("unsupported investigation-brief argument %q", key))
		}
	}
	if options.BaseURL == "" {
		return investigationBriefOptions{}, usageError("base_url or CEREBRO_BASE_URL is required")
	}
	return options, nil
}

func investigationBriefDefaultLimitForCLI() uint32 {
	return 25
}
