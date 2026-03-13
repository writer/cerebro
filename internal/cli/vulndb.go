package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/vulndb"
)

var (
	vulnDBOutput       = FormatTable
	vulnDBImportInput  string
	vulnDBImportSource string
	vulnDBAllowHTTP    bool
	vulnDBSyncOSV      string
	vulnDBSyncKEV      string
	vulnDBSyncEPSS     string
)

var importHTTPTransport http.RoundTripper = http.DefaultTransport

var vulndbCmd = &cobra.Command{
	Use:   "vulndb",
	Short: "Manage the persisted vulnerability advisory database",
}

var vulndbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show advisory database stats",
	RunE:  runVulnDBStats,
}

var vulndbImportOSVCmd = &cobra.Command{
	Use:   "import-osv",
	Short: "Import OSV advisories from a JSON/JSONL file or URL",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runVulnDBImport(cmd.Context(), "osv", func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (any, error) {
			return service.ImportOSVJSON(ctx, source, reader)
		})
	},
}

var vulndbImportKEVCmd = &cobra.Command{
	Use:   "import-kev",
	Short: "Import CISA KEV JSON into the advisory database",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runVulnDBImport(cmd.Context(), "cisa-kev", func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (any, error) {
			return service.ImportKEVJSON(ctx, source, reader)
		})
	},
}

var vulndbImportEPSSCmd = &cobra.Command{
	Use:   "import-epss",
	Short: "Import EPSS CSV scores into the advisory database",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runVulnDBImport(cmd.Context(), "epss", func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (any, error) {
			return service.ImportEPSSCSV(ctx, source, reader)
		})
	},
}

var vulndbSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync one or more advisory feeds into the persisted vulnerability database",
	RunE:  runVulnDBSync,
}

func init() {
	vulndbStatsCmd.Flags().StringVarP(&vulnDBOutput, "output", "o", FormatTable, "Output format (table,json)")
	for _, cmd := range []*cobra.Command{vulndbImportOSVCmd, vulndbImportKEVCmd, vulndbImportEPSSCmd} {
		cmd.Flags().StringVar(&vulnDBImportInput, "input", "", "Path, URL, or - for stdin")
		cmd.Flags().StringVar(&vulnDBImportSource, "source", "", "Source label recorded in sync state")
		cmd.Flags().BoolVar(&vulnDBAllowHTTP, "allow-insecure-http", false, "Allow advisory imports over plaintext http:// transport")
		cmd.Flags().StringVarP(&vulnDBOutput, "output", "o", FormatTable, "Output format (table,json)")
	}
	vulndbSyncCmd.Flags().StringVar(&vulnDBSyncOSV, "osv", "", "OSV JSON/JSONL path or URL")
	vulndbSyncCmd.Flags().StringVar(&vulnDBSyncKEV, "kev", "", "CISA KEV JSON path or URL")
	vulndbSyncCmd.Flags().StringVar(&vulnDBSyncEPSS, "epss", "", "EPSS CSV path or URL")
	vulndbSyncCmd.Flags().BoolVar(&vulnDBAllowHTTP, "allow-insecure-http", false, "Allow advisory imports over plaintext http:// transport")
	vulndbSyncCmd.Flags().StringVarP(&vulnDBOutput, "output", "o", FormatTable, "Output format (table,json)")
	vulndbCmd.AddCommand(vulndbStatsCmd)
	vulndbCmd.AddCommand(vulndbImportOSVCmd)
	vulndbCmd.AddCommand(vulndbImportKEVCmd)
	vulndbCmd.AddCommand(vulndbImportEPSSCmd)
	vulndbCmd.AddCommand(vulndbSyncCmd)
}

func runVulnDBStats(cmd *cobra.Command, _ []string) error {
	cfg := app.LoadConfig()
	service, closer, err := openVulnDBService(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	stats, err := service.Stats(commandContextOrBackground(cmd))
	if err != nil {
		return err
	}
	syncStates, err := service.ListSyncStates(commandContextOrBackground(cmd))
	if err != nil {
		return err
	}
	if vulnDBOutput == FormatJSON {
		return JSONOutput(map[string]any{
			"db_path":     resolveVulnDBStateFile(cfg),
			"stats":       stats,
			"sync_states": syncStates,
		})
	}
	fmt.Printf("DB Path:         %s\n", resolveVulnDBStateFile(cfg))
	fmt.Printf("Vulnerabilities: %d\n", stats.VulnerabilityCount)
	fmt.Printf("Package ranges:  %d\n", stats.PackageRangeCount)
	fmt.Printf("KEV flagged:     %d\n", stats.KEVCount)
	if !stats.LastUpdatedAt.IsZero() {
		fmt.Printf("Last updated:    %s\n", stats.LastUpdatedAt.Format(time.RFC3339))
	}
	if len(syncStates) > 0 {
		fmt.Println("Sources:")
		for _, state := range syncStates {
			line := fmt.Sprintf("  - %s: records=%d", state.Source, state.RecordsSynced)
			if !state.LastSuccessAt.IsZero() {
				line += fmt.Sprintf(", last_success=%s", state.LastSuccessAt.Format(time.RFC3339))
			}
			fmt.Println(line)
		}
	}
	return nil
}

func runVulnDBSync(cmd *cobra.Command, _ []string) error {
	cfg := app.LoadConfig()
	service, closer, err := openVulnDBService(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()

	type syncResult struct {
		Kind   string              `json:"kind"`
		Input  string              `json:"input"`
		Source string              `json:"source"`
		Report vulndb.ImportReport `json:"report"`
	}

	sources := []struct {
		kind          string
		input         string
		defaultSource string
		importer      func(context.Context, *vulndb.Service, io.Reader, string) (vulndb.ImportReport, error)
	}{
		{
			kind:          "osv",
			input:         strings.TrimSpace(vulnDBSyncOSV),
			defaultSource: "osv",
			importer: func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (vulndb.ImportReport, error) {
				return service.ImportOSVJSON(ctx, source, reader)
			},
		},
		{
			kind:          "kev",
			input:         strings.TrimSpace(vulnDBSyncKEV),
			defaultSource: "cisa-kev",
			importer: func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (vulndb.ImportReport, error) {
				return service.ImportKEVJSON(ctx, source, reader)
			},
		},
		{
			kind:          "epss",
			input:         strings.TrimSpace(vulnDBSyncEPSS),
			defaultSource: "epss",
			importer: func(ctx context.Context, service *vulndb.Service, reader io.Reader, source string) (vulndb.ImportReport, error) {
				return service.ImportEPSSCSV(ctx, source, reader)
			},
		},
	}

	results := make([]syncResult, 0, len(sources))
	for _, item := range sources {
		if item.input == "" {
			continue
		}
		reader, closerFunc, source, err := openImportReader(commandContextOrBackground(cmd), item.input, "", item.defaultSource, vulnDBAllowHTTP)
		if err != nil {
			return fmt.Errorf("%s sync source: %w", item.kind, err)
		}
		report, importErr := item.importer(commandContextOrBackground(cmd), service, reader, source)
		if closerFunc != nil {
			_ = closerFunc()
		}
		if importErr != nil {
			return fmt.Errorf("%s sync import: %w", item.kind, importErr)
		}
		results = append(results, syncResult{
			Kind:   item.kind,
			Input:  item.input,
			Source: source,
			Report: report,
		})
	}
	if len(results) == 0 {
		return fmt.Errorf("at least one of --osv, --kev, or --epss is required")
	}
	if vulnDBOutput == FormatJSON {
		return JSONOutput(map[string]any{
			"db_path": resolveVulnDBStateFile(cfg),
			"results": results,
		})
	}
	fmt.Printf("DB Path: %s\n", resolveVulnDBStateFile(cfg))
	for _, result := range results {
		fmt.Printf("%s: source=%s imported=%d", strings.ToUpper(result.Kind), result.Source, result.Report.Imported)
		if result.Report.MatchedKEV > 0 {
			fmt.Printf(" kev_hits=%d", result.Report.MatchedKEV)
		}
		if result.Report.MatchedEPSS > 0 {
			fmt.Printf(" epss_hits=%d", result.Report.MatchedEPSS)
		}
		fmt.Println()
	}
	return nil
}

func runVulnDBImport(ctx context.Context, defaultSource string, importer func(context.Context, *vulndb.Service, io.Reader, string) (any, error)) error {
	cfg := app.LoadConfig()
	service, closer, err := openVulnDBService(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	reader, closerFunc, source, err := openImportReader(ctx, vulnDBImportInput, vulnDBImportSource, defaultSource, vulnDBAllowHTTP)
	if err != nil {
		return err
	}
	defer func() {
		if closerFunc != nil {
			_ = closerFunc()
		}
	}()
	result, err := importer(ctx, service, reader, source)
	if err != nil {
		return err
	}
	if vulnDBOutput == FormatJSON {
		return JSONOutput(result)
	}
	fmt.Printf("DB Path:  %s\n", resolveVulnDBStateFile(cfg))
	fmt.Printf("Source:   %s\n", source)
	if report, ok := result.(vulndb.ImportReport); ok {
		fmt.Printf("Imported: %d\n", report.Imported)
		if report.MatchedKEV > 0 {
			fmt.Printf("KEV hits:  %d\n", report.MatchedKEV)
		}
		if report.MatchedEPSS > 0 {
			fmt.Printf("EPSS hits: %d\n", report.MatchedEPSS)
		}
		return nil
	}
	fmt.Printf("%v\n", result)
	return nil
}

func openImportReader(ctx context.Context, input, explicitSource, fallbackSource string, allowInsecureHTTP bool) (io.Reader, func() error, string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil, "", fmt.Errorf("--input is required")
	}
	sourceLabel := sanitizeSourceLabel(firstNonEmptyString(explicitSource, fallbackSource, input))
	if input == "-" {
		return os.Stdin, nil, sourceLabel, nil
	}
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if strings.HasPrefix(input, "http://") && !allowInsecureHTTP {
			return nil, nil, "", fmt.Errorf("insecure http advisory feeds require --allow-insecure-http: %s", sanitizeSourceLabel(input))
		}
		requestContext := ctx
		if requestContext == nil {
			requestContext = context.Background()
		}
		if err := validateImportURLScheme(input, allowInsecureHTTP); err != nil {
			return nil, nil, "", err
		}
		req, err := http.NewRequestWithContext(requestContext, http.MethodGet, input, nil)
		if err != nil {
			return nil, nil, "", fmt.Errorf("build import request: %w", err)
		}
		resp, err := newImportHTTPClient(allowInsecureHTTP).Do(req) // #nosec G107 -- explicit user-provided ingest URL for feed import
		if err != nil {
			return nil, nil, "", fmt.Errorf("fetch import source: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return nil, nil, "", fmt.Errorf("import source returned status %d", resp.StatusCode)
		}
		return resp.Body, resp.Body.Close, sourceLabel, nil
	}
	file, err := os.Open(input) // #nosec G304 -- explicit operator-provided feed path for local advisory import
	if err != nil {
		return nil, nil, "", fmt.Errorf("open import source: %w", err)
	}
	return file, file.Close, sourceLabel, nil
}

func newImportHTTPClient(allowInsecureHTTP bool) *http.Client {
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: importHTTPTransport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if err := validateImportURLScheme(req.URL.String(), allowInsecureHTTP); err != nil {
				return err
			}
			return nil
		},
	}
}

func validateImportURLScheme(raw string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse import url: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if !allowInsecureHTTP {
			return fmt.Errorf("insecure http advisory feeds require --allow-insecure-http: %s", sanitizeSourceLabel(raw))
		}
		fmt.Fprintf(os.Stderr, "warning: allowing insecure advisory feed import over http: %s\n", sanitizeSourceLabel(raw))
		return nil
	default:
		return fmt.Errorf("unsupported import URL scheme %q", parsed.Scheme)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sanitizeSourceLabel(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return trimmed
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
