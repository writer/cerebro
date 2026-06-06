package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/bootstrap"
	appconfig "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"github.com/writer/cerebro/internal/vulndb"
)

const defaultVulnDBStateFile = ".cerebro-vulndb.json"

var errUnsupportedVulnDBURLScheme = errors.New("unsupported vulndb import URL scheme")

func runVulnDB(args []string) error {
	if len(args) == 0 {
		return usageError(vulnDBUsage())
	}
	command := strings.TrimSpace(args[0])
	options, err := parseVulnDBOptions(args[1:])
	if err != nil {
		return err
	}
	ctx := context.Background()
	opened, err := openVulnDBStore(ctx, options)
	if err != nil {
		return fmt.Errorf("open vulndb store: %w", err)
	}
	defer func() {
		_ = opened.Close()
	}()
	switch command {
	case "stats":
		stats, err := opened.Store.Stats(ctx)
		if err != nil {
			return err
		}
		return printJSON(stats)
	case "get":
		vulnerability, err := getVulnDBVulnerability(ctx, opened.Store, options)
		if err != nil {
			return err
		}
		return printJSON(vulnerability)
	case "match":
		matches, err := matchVulnDBPackage(ctx, opened.Store, options)
		if err != nil {
			return err
		}
		return printJSON(matches)
	case "import-osv":
		reader, closeReader, err := openVulnDBInput(ctx, options.Source, options.AllowInsecureHTTP)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceOSV, err)
		}
		defer closeReader()
		result, err := vulndb.ImportOSV(ctx, opened.Store, reader)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceOSV, err)
		}
		return printJSON(result)
	case "import-kev":
		reader, closeReader, err := openVulnDBInput(ctx, options.Source, options.AllowInsecureHTTP)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceCISAKEV, err)
		}
		defer closeReader()
		result, err := vulndb.ImportCISAKEV(ctx, opened.Store, reader)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceCISAKEV, err)
		}
		return printJSON(result)
	case "import-epss":
		reader, closeReader, err := openVulnDBInput(ctx, options.Source, options.AllowInsecureHTTP)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceEPSS, err)
		}
		defer closeReader()
		result, err := vulndb.ImportEPSS(ctx, opened.Store, reader)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceEPSS, err)
		}
		return printJSON(result)
	case "import-nvd":
		reader, closeReader, err := openVulnDBInput(ctx, options.Source, options.AllowInsecureHTTP)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceNVD, err)
		}
		defer closeReader()
		result, err := vulndb.ImportNVD(ctx, opened.Store, reader)
		if err != nil {
			return recordVulnDBCommandFailure(ctx, opened.Store, vulndb.SourceNVD, err)
		}
		return printJSON(result)
	case "sync":
		result, err := runVulnDBSync(ctx, opened.Store, options)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "job-put":
		job, err := putVulnDBSyncJob(ctx, opened.Jobs, options)
		if err != nil {
			return err
		}
		return printJSON(job)
	case "job-run":
		result, err := runVulnDBSyncJob(ctx, opened.Store, opened.Jobs, options)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "job-run-due":
		result, err := runDueVulnDBSyncJobs(ctx, opened.Store, opened.Jobs, options)
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return usageError(vulnDBUsage())
	}
}

type vulnDBOptions struct {
	StateFile                 string
	StateFileExplicit         bool
	StoreMode                 string
	Source                    string
	FeedSource                string
	OSVSource                 string
	KEVSource                 string
	EPSSSource                string
	NVDSource                 string
	AllowInsecureHTTP         bool
	AllowInsecureHTTPExplicit bool
	JobID                     string
	JobOwner                  string
	JobInterval               time.Duration
	JobLeaseTTL               time.Duration
	Limit                     int
	AdvisoryID                string
	Ecosystem                 string
	PackageName               string
	PackageVersion            string
}

type vulnDBSyncResult struct {
	OSV  *vulndb.ImportResult `json:"osv,omitempty"`
	KEV  *vulndb.ImportResult `json:"kev,omitempty"`
	EPSS *vulndb.ImportResult `json:"epss,omitempty"`
	NVD  *vulndb.ImportResult `json:"nvd,omitempty"`
}

func parseVulnDBOptions(args []string) (vulnDBOptions, error) {
	options := vulnDBOptions{StateFile: strings.TrimSpace(os.Getenv("VULNDB_STATE_FILE"))}
	options.StateFileExplicit = options.StateFile != ""
	if options.StateFile == "" {
		options.StateFile = defaultVulnDBStateFile
	}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			if options.Source != "" {
				return vulnDBOptions{}, usageError(vulnDBUsage())
			}
			options.Source = strings.TrimSpace(arg)
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "state_file":
			if value == "" {
				return vulnDBOptions{}, usageError("state_file is required")
			}
			options.StateFile = value
			options.StateFileExplicit = true
		case "store":
			switch value {
			case "", "auto":
				options.StoreMode = ""
			case "file", "state", "postgres":
				options.StoreMode = value
			default:
				return vulnDBOptions{}, usageError("store must be auto, file, state, or postgres")
			}
		case "file", "path", "url", "source":
			options.Source = value
		case "feed_source":
			options.FeedSource = value
		case "osv":
			options.OSVSource = value
		case "kev", "cisa_kev":
			options.KEVSource = value
		case "epss":
			options.EPSSSource = value
		case "nvd":
			options.NVDSource = value
		case "job_id":
			options.JobID = value
		case "owner":
			options.JobOwner = value
		case "interval":
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return vulnDBOptions{}, fmt.Errorf("parse interval: %w", err)
			}
			if parsed <= 0 {
				return vulnDBOptions{}, usageError("interval must be positive")
			}
			options.JobInterval = parsed
		case "lease_ttl":
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return vulnDBOptions{}, fmt.Errorf("parse lease_ttl: %w", err)
			}
			if parsed <= 0 {
				return vulnDBOptions{}, usageError("lease_ttl must be positive")
			}
			options.JobLeaseTTL = parsed
		case "limit":
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return vulnDBOptions{}, fmt.Errorf("parse limit: %w", err)
			}
			if parsed < 0 {
				return vulnDBOptions{}, usageError("limit must be non-negative")
			}
			options.Limit = int(parsed)
		case "id", "advisory_id", "vulnerability_id":
			options.AdvisoryID = value
		case "ecosystem":
			options.Ecosystem = value
		case "package", "package_name", "name":
			options.PackageName = value
		case "version", "package_version":
			options.PackageVersion = value
		case "allow_insecure_http":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return vulnDBOptions{}, fmt.Errorf("parse allow_insecure_http: %w", err)
			}
			options.AllowInsecureHTTP = parsed
			options.AllowInsecureHTTPExplicit = true
		default:
			return vulnDBOptions{}, usageError(fmt.Sprintf("unsupported vulndb argument %q", key))
		}
	}
	return options, nil
}

func getVulnDBVulnerability(ctx context.Context, store vulndb.Store, options vulnDBOptions) (vulndb.Vulnerability, error) {
	id := strings.TrimSpace(options.AdvisoryID)
	if id == "" {
		id = strings.TrimSpace(options.Source)
	}
	if id == "" {
		return vulndb.Vulnerability{}, usageError("id is required")
	}
	vulnerability, ok, err := store.FindVulnerability(ctx, id)
	if err != nil {
		return vulndb.Vulnerability{}, err
	}
	if !ok {
		return vulndb.Vulnerability{}, fmt.Errorf("vulnerability %q not found", id)
	}
	return vulnerability, nil
}

func matchVulnDBPackage(ctx context.Context, store vulndb.Store, options vulnDBOptions) ([]vulndb.Match, error) {
	query := vulndb.PackageQuery{
		Ecosystem: strings.TrimSpace(options.Ecosystem),
		Name:      strings.TrimSpace(options.PackageName),
		Version:   strings.TrimSpace(options.PackageVersion),
	}
	if query.Ecosystem == "" {
		return nil, usageError("ecosystem is required")
	}
	if query.Name == "" {
		return nil, usageError("package is required")
	}
	if query.Version == "" {
		return nil, usageError("version is required")
	}
	matcher, err := vulndb.NewMatcher(store)
	if err != nil {
		return nil, err
	}
	return matcher.MatchPackage(ctx, query)
}

func runVulnDBSync(ctx context.Context, store vulndb.Store, options vulnDBOptions) (vulnDBSyncResult, error) {
	var result vulnDBSyncResult
	if options.OSVSource == "" && options.KEVSource == "" && options.EPSSSource == "" && options.NVDSource == "" {
		return result, usageError("usage: cerebro vulndb sync [osv=<path-or-url>] [kev=<path-or-url>] [epss=<path-or-url>] [nvd=<path-or-url>] [state_file=<path>]")
	}
	if options.OSVSource != "" {
		imported, err := runVulnDBFeedSync(ctx, store, vulndb.SourceOSV, options.OSVSource, options.AllowInsecureHTTP)
		if err != nil {
			return result, err
		}
		result.OSV = &imported
	}
	if options.KEVSource != "" {
		imported, err := runVulnDBFeedSync(ctx, store, vulndb.SourceCISAKEV, options.KEVSource, options.AllowInsecureHTTP)
		if err != nil {
			return result, err
		}
		result.KEV = &imported
	}
	if options.EPSSSource != "" {
		imported, err := runVulnDBFeedSync(ctx, store, vulndb.SourceEPSS, options.EPSSSource, options.AllowInsecureHTTP)
		if err != nil {
			return result, err
		}
		result.EPSS = &imported
	}
	if options.NVDSource != "" {
		imported, err := runVulnDBFeedSync(ctx, store, vulndb.SourceNVD, options.NVDSource, options.AllowInsecureHTTP)
		if err != nil {
			return result, err
		}
		result.NVD = &imported
	}
	return result, nil
}

func runVulnDBFeedSync(ctx context.Context, store vulndb.Store, source string, location string, allowInsecureHTTP bool) (vulndb.ImportResult, error) {
	reader, closeReader, err := openVulnDBInput(ctx, location, allowInsecureHTTP)
	if err != nil {
		return vulndb.ImportResult{}, recordVulnDBCommandFailure(ctx, store, source, err)
	}
	defer closeReader()
	result, err := vulndb.ImportFeed(ctx, store, source, reader)
	if err != nil {
		return vulndb.ImportResult{}, recordVulnDBCommandFailure(ctx, store, source, err)
	}
	return result, nil
}

func recordVulnDBCommandFailure(ctx context.Context, store vulndb.Store, source string, syncErr error) error {
	if syncErr == nil {
		return nil
	}
	var usage usageError
	if errors.As(syncErr, &usage) {
		return syncErr
	}
	if err := vulndb.RecordSyncFailure(ctx, store, source, syncErr); err != nil {
		return errors.Join(syncErr, fmt.Errorf("record vulndb sync failure: %w", err))
	}
	return syncErr
}

func openVulnDBInput(ctx context.Context, source string, allowInsecureHTTP bool) (io.Reader, func(), error) {
	reader, err := (vulndbInputClient{}).Open(ctx, source, allowInsecureHTTP)
	if err != nil {
		return nil, func() {}, err
	}
	return reader, func() { _ = reader.Close() }, nil
}

type vulndbInputClient struct{}

func (vulndbInputClient) Open(ctx context.Context, source string, allowInsecureHTTP bool) (io.ReadCloser, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, usageError("vulndb import source is required")
	}
	if vulnDBSourceScheme(source) != "" {
		if !isRemoteVulnDBSource(source) {
			return nil, fmt.Errorf("%w %q", errUnsupportedVulnDBURLScheme, vulnDBSourceScheme(source))
		}
		return bootstrap.OpenVulnDBFeed(ctx, source, allowInsecureHTTP)
	}
	file, err := os.Open(source) // #nosec G304 -- operator-provided local vulnerability feed file.
	if err != nil {
		return nil, err
	}
	return file, nil
}

func isRemoteVulnDBSource(source string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func vulnDBSourceScheme(source string) string {
	source = strings.TrimSpace(source)
	if isWindowsDrivePath(source) {
		return ""
	}
	parsed, err := url.Parse(source)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Scheme))
}

func isWindowsDrivePath(source string) bool {
	if len(source) < 2 || source[1] != ':' {
		return false
	}
	return (source[0] >= 'A' && source[0] <= 'Z') || (source[0] >= 'a' && source[0] <= 'z')
}

type openedVulnDBStore struct {
	Store vulndb.Store
	Jobs  vulndb.SyncJobStore
	close func() error
}

func (s openedVulnDBStore) Close() error {
	if s.close == nil {
		return nil
	}
	return s.close()
}

func openVulnDBStore(ctx context.Context, options vulnDBOptions) (openedVulnDBStore, error) {
	if shouldUseStateVulnDBStore(options) {
		return openStateVulnDBStore(ctx)
	}
	store, err := vulndb.NewFileStore(ctx, options.StateFile)
	if err != nil {
		return openedVulnDBStore{}, err
	}
	return openedVulnDBStore{Store: store, Jobs: store}, nil
}

func shouldUseStateVulnDBStore(options vulnDBOptions) bool {
	switch options.StoreMode {
	case "state", "postgres":
		return true
	case "file":
		return false
	}
	if options.StateFileExplicit {
		return false
	}
	return strings.TrimSpace(os.Getenv("CEREBRO_STATE_STORE_DRIVER")) != "" ||
		strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN")) != ""
}

func openStateVulnDBStore(ctx context.Context) (openedVulnDBStore, error) {
	cfg, err := appconfig.Load()
	if err != nil {
		return openedVulnDBStore{}, err
	}
	store, err := postgres.Open(cfg.StateStore)
	if err != nil {
		return openedVulnDBStore{}, err
	}
	if err := store.Ping(ctx); err != nil {
		_ = store.Close()
		return openedVulnDBStore{}, err
	}
	return openedVulnDBStore{Store: store, Jobs: store, close: store.Close}, nil
}

func putVulnDBSyncJob(ctx context.Context, jobs vulndb.SyncJobStore, options vulnDBOptions) (vulndb.SyncJob, error) {
	if jobs == nil {
		return vulndb.SyncJob{}, fmt.Errorf("vulndb sync job store is unavailable")
	}
	jobID := strings.TrimSpace(options.JobID)
	if jobID == "" {
		return vulndb.SyncJob{}, usageError("job_id is required")
	}
	existing, hasExisting, err := jobs.GetSyncJob(ctx, jobID)
	if err != nil {
		return vulndb.SyncJob{}, err
	}
	allowInsecureHTTP := options.AllowInsecureHTTP
	if hasExisting && !options.AllowInsecureHTTPExplicit {
		allowInsecureHTTP = existing.AllowInsecureHTTP
	}
	feedURL := strings.TrimSpace(options.Source)
	if feedURL != "" && vulnDBSourceScheme(feedURL) != "" && !isRemoteVulnDBSource(feedURL) {
		if err := vulndb.ValidateFeedURL(feedURL, allowInsecureHTTP); err != nil {
			return vulndb.SyncJob{}, usageError(err.Error())
		}
	}
	if feedURL != "" && vulnDBSourceScheme(feedURL) == "" && !filepath.IsAbs(feedURL) {
		absolute, err := filepath.Abs(feedURL)
		if err != nil {
			return vulndb.SyncJob{}, err
		}
		feedURL = absolute
	}
	job := vulndb.SyncJob{
		ID:                jobID,
		Source:            strings.TrimSpace(options.FeedSource),
		FeedURL:           feedURL,
		AllowInsecureHTTP: allowInsecureHTTP,
		Interval:          options.JobInterval,
	}
	if job.Source == "" {
		return vulndb.SyncJob{}, usageError("feed_source is required")
	}
	if !vulndb.IsSupportedFeedSource(job.Source) {
		return vulndb.SyncJob{}, usageError(fmt.Sprintf("unsupported feed_source %q", job.Source))
	}
	if job.FeedURL == "" {
		return vulndb.SyncJob{}, usageError("url is required")
	}
	if job.Interval <= 0 {
		return vulndb.SyncJob{}, usageError("interval must be positive")
	}
	if isRemoteVulnDBSource(job.FeedURL) {
		if err := vulndb.ValidateFeedURL(job.FeedURL, job.AllowInsecureHTTP); err != nil {
			return vulndb.SyncJob{}, usageError(err.Error())
		}
	}
	if err := jobs.PutSyncJob(ctx, job); err != nil {
		return vulndb.SyncJob{}, err
	}
	stored, ok, err := jobs.GetSyncJob(ctx, job.ID)
	if err != nil {
		return vulndb.SyncJob{}, err
	}
	if !ok {
		return vulndb.SyncJob{}, fmt.Errorf("%w: %s", vulndb.ErrSyncJobNotFound, job.ID)
	}
	return stored, nil
}

func runVulnDBSyncJob(ctx context.Context, store vulndb.Store, jobs vulndb.SyncJobStore, options vulnDBOptions) (vulndb.SyncJobRunResult, error) {
	if strings.TrimSpace(options.JobID) == "" {
		return vulndb.SyncJobRunResult{}, usageError("job_id is required")
	}
	runner, err := newVulnDBSyncRunner(store, jobs, options)
	if err != nil {
		return vulndb.SyncJobRunResult{}, err
	}
	return runner.RunJob(ctx, options.JobID)
}

func runDueVulnDBSyncJobs(ctx context.Context, store vulndb.Store, jobs vulndb.SyncJobStore, options vulnDBOptions) (vulndb.SyncDueJobsResult, error) {
	runner, err := newVulnDBSyncRunner(store, jobs, options)
	if err != nil {
		return vulndb.SyncDueJobsResult{}, err
	}
	return runner.RunDue(ctx, options.Limit)
}

func newVulnDBSyncRunner(store vulndb.Store, jobs vulndb.SyncJobStore, options vulnDBOptions) (*vulndb.SyncRunner, error) {
	runner, err := vulndb.NewSyncRunner(store, jobs, func(ctx context.Context, job vulndb.SyncJob) (io.ReadCloser, error) {
		return (vulndbInputClient{}).Open(ctx, job.FeedURL, job.AllowInsecureHTTP)
	})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.JobOwner) != "" {
		runner = runner.WithOwner(options.JobOwner)
	}
	if options.JobLeaseTTL > 0 {
		runner = runner.WithLeaseTTL(options.JobLeaseTTL)
	}
	return runner, nil
}

func vulnDBUsage() string {
	return fmt.Sprintf("usage: %s vulndb [stats|get|match|import-osv|import-kev|import-epss|import-nvd|sync|job-put|job-run|job-run-due] [store=auto|file|state] [state_file=<path>] [path=<path>|url=<url>] [allow_insecure_http=true]", os.Args[0])
}
