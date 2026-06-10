package main

import (
	"errors"
	"testing"
)

func TestParseInvestigationBriefOptions(t *testing.T) {
	t.Setenv("CEREBRO_BASE_URL", "https://cerebro.example")
	t.Setenv("CEREBRO_API_KEY", "test-key")

	options, err := parseInvestigationBriefOptions([]string{"finding-1", "limit=10", "skip_graph=true", "format=markdown"})
	if err != nil {
		t.Fatalf("parseInvestigationBriefOptions error = %v", err)
	}
	if options.FindingID != "finding-1" || options.BaseURL != "https://cerebro.example" || options.APIKey != "test-key" {
		t.Fatalf("options identity = %#v", options)
	}
	if options.Limit != 10 || !options.SkipGraph || options.Format != "markdown" {
		t.Fatalf("options flags = %#v", options)
	}
}

func TestParseInvestigationBriefOptionsRequiresBaseURL(t *testing.T) {
	t.Setenv("CEREBRO_BASE_URL", "")
	_, err := parseInvestigationBriefOptions([]string{"finding-1"})
	var usage usageError
	if !errors.As(err, &usage) {
		t.Fatalf("parseInvestigationBriefOptions error = %v, want usageError", err)
	}
}
