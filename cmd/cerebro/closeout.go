package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findings"
)

const (
	closeoutEnvAllow         = "CEREBRO_CLOSEOUT_ALLOW"
	closeoutEnvAuditBucket   = "CEREBRO_CLOSEOUT_AUDIT_BUCKET"
	closeoutEnvTenantID      = "CEREBRO_CLOSEOUT_TENANT_ID"
	closeoutEnvGithubActor   = "GITHUB_ACTOR"
	closeoutEnvUser          = "USER"
	closeoutDefaultBatchSize = 1000

	closeoutEnvSecDev = "sec-dev"
	closeoutEnvGoProd = "go-prod"

	// Event vocabulary is pinned: only {closeout.start, closeout.batch,
	// closeout.end, closeout.refused} may appear in the "event" field of
	// any structured log line emitted by the closeout CLI. CloudWatch
	// consumers (VAL-CLI-009, VAL-INFRA-013) depend on this set being
	// closed.
	closeoutEventStart   = "closeout.start"
	closeoutEventBatch   = "closeout.batch"
	closeoutEventEnd     = "closeout.end"
	closeoutEventRefused = "closeout.refused"

	closeoutActorUnknown = "unknown"
)

// Typed sentinel errors for closeout flag validation. Tests assert on these
// via errors.Is so that user-facing wording can evolve without breaking the
// contract; the structural lint forbids matching on err.Error() content.
var (
	ErrCloseoutReasonRequired           = usageError("cerebro closeout: --reason is required")
	ErrCloseoutChangeTicketRequired     = usageError("cerebro closeout: --change-ticket is required for --apply with --allow-env go-prod")
	ErrCloseoutAllowEnvRequired         = usageError("cerebro closeout: --allow-env is required when --apply is set")
	ErrCloseoutAllowEnvInvalid          = usageError("cerebro closeout: --allow-env must be sec-dev or go-prod")
	ErrCloseoutAllowEnvMismatch         = usageError("cerebro closeout: CEREBRO_CLOSEOUT_ALLOW does not match --allow-env")
	ErrCloseoutAuditBucketRequired      = usageError("cerebro closeout: --apply requires --audit-s3-bucket or CEREBRO_CLOSEOUT_AUDIT_BUCKET")
	ErrCloseoutApplyDryRunConflict      = usageError("cerebro closeout: --apply and --dry-run=true are mutually exclusive")
	ErrCloseoutDryRunFalseRequiresApply = usageError("cerebro closeout: --dry-run=false requires --apply")
	ErrCloseoutRuleSelectorRequired     = usageError("cerebro closeout: at least one of --rule-id or --rule-id-file must be provided")
	ErrCloseoutRuleIDFileUnreadable     = usageError("cerebro closeout: --rule-id-file is not readable")
	ErrCloseoutOlderThanInvalid         = usageError("cerebro closeout: --older-than must be a positive duration (e.g. 7d, 24h)")
	ErrCloseoutMaxBatchSizeInvalid      = usageError("cerebro closeout: --max-batch-size must be a positive integer")
	ErrCloseoutTenantIDRequired         = usageError("cerebro closeout: --tenant-id or CEREBRO_CLOSEOUT_TENANT_ID is required")
	ErrCloseoutTombstoneSchemaMissing   = errors.New("closeout: tombstone schema is not present on the configured database")
	ErrCloseoutSummaryPutFailed         = errors.New("closeout: failed to put audit summary to s3")
)

// closeoutSTSIdentity is the resolved STS principal/role pair captured for the
// audit row and the per-run S3 summary's actor object.
type closeoutSTSIdentity struct {
	Principal string
	RoleARN   string
}

// closeoutSTSLookup resolves the AWS STS caller identity when AWS credentials
// are available. Implementations MUST return an empty identity (not an error)
// when no AWS credentials are configured so the actor fallback can proceed.
type closeoutSTSLookup func(ctx context.Context) (closeoutSTSIdentity, error)

// closeoutBackend is the service surface the closeout CLI orchestrates. It is
// implemented in production by a wrapper around findings.Service +
// postgres.Store; tests inject a fake.
type closeoutBackend interface {
	SupportsTombstones(ctx context.Context) (bool, error)
	Closeout(ctx context.Context, req findings.CloseoutRequest) (*findings.CloseoutResult, error)
	AfterCloseoutSummary(ctx context.Context, runID, summaryKey string, summaryErr error) error
}

// closeoutSummaryWriter persists the per-run S3 audit summary. The interface is
// declared here so the apply feature can wire a real S3 implementation while
// the scaffold feature retains a no-op default suitable for dry-runs and tests.
type closeoutSummaryWriter interface {
	PutCloseoutSummary(ctx context.Context, bucket, key string, body []byte) error
}

// closeoutEnv groups the runtime dependencies for the closeout CLI. Tests
// inject fakes to assert flag validation, actor resolution, and orchestration
// without touching Postgres or AWS.
type closeoutEnv struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Getenv    func(string) string
	Now       func() time.Time
	NewRunID  func() string
	Backend   closeoutBackend
	Summary   closeoutSummaryWriter
	LookupSTS closeoutSTSLookup
}

// closeoutFlags captures the parsed CLI surface.
type closeoutFlags struct {
	RuleIDs         []string
	RuleIDFile      string
	Sources         []string
	OlderThanRaw    string
	OlderThan       time.Duration
	StatusFilter    []string
	StatusRaw       string
	MaxBatchSize    int
	MaxBatchRaw     string
	MaxBatchSetExpl bool
	DryRun          bool
	DryRunSetExpl   bool
	Apply           bool
	Reason          string
	RunID           string
	Actor           string
	ChangeTicket    string
	AllowEnv        string
	AuditS3Bucket   string
	TenantID        string
}

// closeoutSummaryDocument is retained as a thin alias so test files that
// import the type continue to compile. The canonical shape now lives in
// internal/findings.CloseoutSummary so the apply path and downstream
// reconciliation tooling share one source of truth.
type closeoutSummaryDocument = findings.CloseoutSummary

var defaultCloseoutEnvFactory = defaultCloseoutEnv

// runCloseout is the production entry point invoked from main. It performs
// parse/help/local validation before constructing live Postgres/AWS
// dependencies so ergonomics errors are available on unconfigured machines.
func runCloseout(args []string) error {
	parseEnv := &closeoutEnv{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
	}
	flags, helpRequested, parseErr := parseCloseoutFlags(args, parseEnv)
	if parseErr != nil {
		return parseErr
	}
	if helpRequested {
		return nil
	}
	if err := validateCloseoutFlags(&flags, parseEnv); err != nil {
		return err
	}

	env, cleanup, err := defaultCloseoutEnvFactory()
	if err != nil {
		return err
	}
	defer cleanup()
	return executeCloseout(flags, env)
}

// defaultCloseoutEnv constructs the production closeoutEnv. The Backend +
// Summary implementations are wired to the live Postgres state store and the
// aws-sdk-go-v2 S3 + STS clients. Tests bypass this constructor and inject a
// closeoutEnv with fakes.
func defaultCloseoutEnv() (*closeoutEnv, func(), error) {
	deps, err := openCloseoutProductionDeps(context.Background())
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := deps.Cleanup
	if cleanup == nil {
		cleanup = func() {}
	}
	return closeoutEnvFromDeps(deps), cleanup, nil
}

// runCloseoutWithEnv is the testable entry point. Tests inject a custom
// closeoutEnv; production wires the default env via runCloseout.
func runCloseoutWithEnv(args []string, env *closeoutEnv) error {
	if env == nil {
		return errors.New("closeout: env is required")
	}
	flags, helpRequested, parseErr := parseCloseoutFlags(args, env)
	if parseErr != nil {
		return parseErr
	}
	if helpRequested {
		return nil
	}
	if err := validateCloseoutFlags(&flags, env); err != nil {
		return err
	}
	return executeCloseout(flags, env)
}

func executeCloseout(flags closeoutFlags, env *closeoutEnv) error {
	ctx := context.Background()

	supports, supportsErr := env.Backend.SupportsTombstones(ctx)
	if supportsErr != nil {
		return fmt.Errorf("check tombstone schema support: %w", supportsErr)
	}
	if !supports {
		emitCloseoutLog(env, map[string]any{
			"event":  closeoutEventRefused,
			"reason": "tombstone_schema_missing",
		})
		_, _ = fmt.Fprintln(env.Stderr, "cerebro closeout: tombstone schema is not present on the configured database; refusing to run")
		return ErrCloseoutTombstoneSchemaMissing
	}

	runID := strings.TrimSpace(flags.RunID)
	if runID == "" {
		runID = env.NewRunID()
		_, _ = fmt.Fprintf(env.Stdout, "closeout run id: %s\n", runID)
	}

	actor, sts, actorErr := resolveCloseoutActor(ctx, &flags, env)
	if actorErr != nil {
		return fmt.Errorf("resolve closeout actor: %w", actorErr)
	}

	bucket := resolveCloseoutBucket(&flags, env)
	auditBucketMissing := !flags.Apply && bucket == ""

	req := findings.CloseoutRequest{
		Selector: findings.CloseoutSelector{
			TenantID:  flags.TenantID,
			RuleIDs:   append([]string(nil), flags.RuleIDs...),
			Sources:   append([]string(nil), flags.Sources...),
			OlderThan: flags.OlderThan,
			Statuses:  append([]string(nil), flags.StatusFilter...),
		},
		Reason:       flags.Reason,
		Actor:        actor,
		RunID:        runID,
		DryRun:       !flags.Apply,
		MaxBatchSize: flags.MaxBatchSize,
		ChangeTicket: flags.ChangeTicket,
		Environment:  flags.AllowEnv,
		BatchLogger: func(event findings.CloseoutBatchEvent) {
			emitCloseoutLog(env, map[string]any{
				"event":       closeoutEventBatch,
				"run_id":      event.RunID,
				"actor":       event.Actor,
				"env":         event.Env,
				"batch_index": event.BatchIndex,
				"batch_size":  event.BatchSize,
			})
		},
	}

	startedAt := env.Now()
	startLog := map[string]any{
		"event":   closeoutEventStart,
		"run_id":  runID,
		"actor":   actor,
		"env":     flags.AllowEnv,
		"dry_run": req.DryRun,
	}
	if auditBucketMissing {
		startLog["audit_bucket_missing"] = true
	}
	emitCloseoutLog(env, startLog)

	result, closeoutErr := env.Backend.Closeout(ctx, req)
	if closeoutErr != nil {
		emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, closeoutErr, "closeout_failed"))
		return fmt.Errorf("closeout: %w", closeoutErr)
	}
	if result == nil {
		result = &findings.CloseoutResult{RunID: runID}
	}

	finishedAt := env.Now()
	doc := findings.BuildCloseoutSummary(result, findings.CloseoutSummaryInputs{
		Actor:        findings.CloseoutSummaryActor{Principal: actor, RoleARN: sts.RoleARN},
		Env:          flags.AllowEnv,
		Selector:     req.Selector,
		Reason:       flags.Reason,
		ChangeTicket: flags.ChangeTicket,
		DryRun:       req.DryRun,
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
	})
	body, marshalErr := doc.MarshalIndent()
	if marshalErr != nil {
		emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, marshalErr, "marshal_summary_failed"))
		return fmt.Errorf("marshal closeout summary: %w", marshalErr)
	}

	summaryKey := strings.TrimSpace(result.S3SummaryKey)
	if flags.Apply {
		if summaryKey == "" {
			summaryKey = findings.CloseoutSummaryKey(runID)
			putErr := env.Summary.PutCloseoutSummary(ctx, bucket, summaryKey, body)
			afterErr := env.Backend.AfterCloseoutSummary(ctx, runID, summaryKey, putErr)
			if putErr != nil {
				_, _ = fmt.Fprintf(env.Stderr, "cerebro closeout: failed to put audit summary to s3://%s/%s: %v\n", bucket, summaryKey, putErr)
				emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, putErr, "s3_put_failed"))
				return fmt.Errorf("%w: %w", ErrCloseoutSummaryPutFailed, putErr)
			}
			if afterErr != nil {
				emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, afterErr, "after_closeout_summary_failed"))
				return fmt.Errorf("after closeout summary: %w", afterErr)
			}
		}
	} else if bucket != "" && env.Summary != nil {
		if summaryKey == "" {
			summaryKey = findings.CloseoutSummaryKey(runID)
			putErr := env.Summary.PutCloseoutSummary(ctx, bucket, summaryKey, body)
			afterErr := env.Backend.AfterCloseoutSummary(ctx, runID, summaryKey, putErr)
			if putErr != nil {
				_, _ = fmt.Fprintf(env.Stderr, "cerebro closeout: failed to put audit summary to s3://%s/%s: %v\n", bucket, summaryKey, putErr)
				emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, putErr, "s3_put_failed"))
				return fmt.Errorf("%w: %w", ErrCloseoutSummaryPutFailed, putErr)
			}
			if afterErr != nil {
				emitCloseoutLog(env, closeoutFailedEndLog(runID, actor, flags.AllowEnv, req.DryRun, result, afterErr, "after_closeout_summary_failed"))
				return fmt.Errorf("after closeout summary: %w", afterErr)
			}
		}
	} else if !flags.Apply {
		_, _ = fmt.Fprintln(env.Stdout, string(body))
	}

	endLog := map[string]any{
		"event":          closeoutEventEnd,
		"run_id":         runID,
		"actor":          actor,
		"env":            flags.AllowEnv,
		"status":         "succeeded",
		"proposed_count": result.ProposedCount,
		"applied_count":  result.AppliedCount,
		"dry_run":        req.DryRun,
	}
	if summaryKey != "" {
		endLog["s3_summary_key"] = summaryKey
		if bucket != "" {
			endLog["s3_summary_bucket"] = bucket
		}
	}
	emitCloseoutLog(env, endLog)
	return nil
}

// parseCloseoutFlags reads the flag surface from args. The flag set is
// configured to print our golden help text rather than the Go flag package's
// default usage so the help output is stable for golden-file assertions.
func parseCloseoutFlags(args []string, env *closeoutEnv) (closeoutFlags, bool, error) {
	out := closeoutFlags{
		StatusFilter: []string{"open"},
		MaxBatchSize: closeoutDefaultBatchSize,
		DryRun:       true,
	}
	helpRequested := false

	fs := flag.NewFlagSet("closeout", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(env.Stdout, closeoutHelpText)
	}

	var ruleIDs multiValueFlag
	var sources multiValueFlag
	fs.Var(&ruleIDs, "rule-id", "rule id to close out (repeatable)")
	fs.StringVar(&out.RuleIDFile, "rule-id-file", "", "newline-delimited file of rule ids")
	fs.Var(&sources, "source", "source family (repeatable)")
	fs.StringVar(&out.OlderThanRaw, "older-than", "", "select only findings whose last_observed_at is older than this duration")
	fs.StringVar(&out.StatusRaw, "status-filter", "open", "comma-separated statuses to include (default: open)")
	fs.StringVar(&out.MaxBatchRaw, "max-batch-size", strconv.Itoa(closeoutDefaultBatchSize), "maximum findings per batch")
	fs.BoolVar(&out.DryRun, "dry-run", true, "dry-run mode")
	fs.BoolVar(&out.Apply, "apply", false, "apply mutations (mutually exclusive with --dry-run=true)")
	fs.StringVar(&out.Reason, "reason", "", "closeout reason (required with --apply)")
	fs.StringVar(&out.RunID, "run-id", "", "closeout run UUIDv4 (auto-generated when absent)")
	fs.StringVar(&out.Actor, "actor", "", "operator identity (resolved from GITHUB_ACTOR / STS / USER when absent)")
	fs.StringVar(&out.ChangeTicket, "change-ticket", "", "change-management ticket reference (required for go-prod)")
	fs.StringVar(&out.AllowEnv, "allow-env", "", "approved environment (must match CEREBRO_CLOSEOUT_ALLOW)")
	fs.StringVar(&out.AuditS3Bucket, "audit-s3-bucket", "", "audit-summary S3 bucket")
	fs.StringVar(&out.TenantID, "tenant-id", "", "tenant identifier (or CEREBRO_CLOSEOUT_TENANT_ID)")

	help := fs.Bool("help", false, "show help")
	hShort := fs.Bool("h", false, "show help")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(env.Stdout, closeoutHelpText)
			return out, true, nil
		}
		return out, false, usageError(fmt.Sprintf("cerebro closeout: %v", err))
	}
	if *help || *hShort {
		_, _ = fmt.Fprint(env.Stdout, closeoutHelpText)
		helpRequested = true
		return out, helpRequested, nil
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "dry-run":
			out.DryRunSetExpl = true
		case "max-batch-size":
			out.MaxBatchSetExpl = true
		}
	})
	out.RuleIDs = ruleIDs.values()
	out.Sources = sources.values()
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.AllowEnv = strings.TrimSpace(out.AllowEnv)
	out.AuditS3Bucket = strings.TrimSpace(out.AuditS3Bucket)
	out.ChangeTicket = strings.TrimSpace(out.ChangeTicket)
	out.Reason = strings.TrimSpace(out.Reason)
	out.RunID = strings.TrimSpace(out.RunID)
	out.Actor = strings.TrimSpace(out.Actor)
	out.RuleIDFile = strings.TrimSpace(out.RuleIDFile)
	out.OlderThanRaw = strings.TrimSpace(out.OlderThanRaw)
	out.MaxBatchRaw = strings.TrimSpace(out.MaxBatchRaw)
	out.StatusRaw = strings.TrimSpace(out.StatusRaw)
	return out, helpRequested, nil
}

// validateCloseoutFlags performs every fail-fast check BEFORE any DB or S3 IO.
// The checks here gate the orchestration steps below; a failure here MUST exit
// non-zero with a stderr message naming the offending flag.
func validateCloseoutFlags(flags *closeoutFlags, env *closeoutEnv) error {
	if !flags.MaxBatchSetExpl {
		flags.MaxBatchSize = closeoutDefaultBatchSize
	} else {
		size, err := strconv.Atoi(flags.MaxBatchRaw)
		if err != nil {
			return fmt.Errorf("%w (got %q)", ErrCloseoutMaxBatchSizeInvalid, flags.MaxBatchRaw)
		}
		if size <= 0 {
			return fmt.Errorf("%w (got %d)", ErrCloseoutMaxBatchSizeInvalid, size)
		}
		flags.MaxBatchSize = size
	}

	if flags.OlderThanRaw != "" {
		duration, err := parseCloseoutDuration(flags.OlderThanRaw)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrCloseoutOlderThanInvalid, err)
		}
		flags.OlderThan = duration
	}

	if flags.StatusRaw != "" {
		statuses := splitAndTrim(flags.StatusRaw, ",")
		if len(statuses) == 0 {
			flags.StatusFilter = []string{"open"}
		} else {
			flags.StatusFilter = statuses
		}
	} else if len(flags.StatusFilter) == 0 {
		flags.StatusFilter = []string{"open"}
	}

	if flags.Apply && flags.DryRunSetExpl && flags.DryRun {
		return ErrCloseoutApplyDryRunConflict
	}
	if !flags.Apply && flags.DryRunSetExpl && !flags.DryRun {
		return ErrCloseoutDryRunFalseRequiresApply
	}
	if flags.Apply {
		flags.DryRun = false
	}

	// --source is a narrowing filter on top of the rule selector, not a
	// selector in its own right. The rule-selector precondition is
	// satisfied only by --rule-id or --rule-id-file (or both); sources are
	// intentionally excluded from this check.
	hasRuleSelector := len(flags.RuleIDs) > 0 || flags.RuleIDFile != ""
	if !hasRuleSelector {
		return ErrCloseoutRuleSelectorRequired
	}
	if flags.RuleIDFile != "" {
		fileIDs, err := readCloseoutRuleIDFile(flags.RuleIDFile)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", ErrCloseoutRuleIDFileUnreadable, flags.RuleIDFile, err)
		}
		flags.RuleIDs = mergeUnique(flags.RuleIDs, fileIDs)
	}
	if len(flags.RuleIDs) == 0 {
		return ErrCloseoutRuleSelectorRequired
	}

	if flags.Reason == "" {
		return ErrCloseoutReasonRequired
	}
	if flags.TenantID == "" {
		flags.TenantID = strings.TrimSpace(env.Getenv(closeoutEnvTenantID))
	}
	if flags.TenantID == "" {
		return ErrCloseoutTenantIDRequired
	}

	if flags.Apply {
		if flags.AllowEnv == "" {
			return ErrCloseoutAllowEnvRequired
		}
		if flags.AllowEnv != closeoutEnvSecDev && flags.AllowEnv != closeoutEnvGoProd {
			return fmt.Errorf("%w (got %q)", ErrCloseoutAllowEnvInvalid, flags.AllowEnv)
		}
		gotAllow := strings.TrimSpace(env.Getenv(closeoutEnvAllow))
		if gotAllow == "" {
			return fmt.Errorf("%w: %s must be set to %q", ErrCloseoutAllowEnvMismatch, closeoutEnvAllow, flags.AllowEnv)
		}
		if gotAllow != flags.AllowEnv {
			return fmt.Errorf("%w: %s=%q vs --allow-env=%q", ErrCloseoutAllowEnvMismatch, closeoutEnvAllow, gotAllow, flags.AllowEnv)
		}
		if flags.AllowEnv == closeoutEnvGoProd && flags.ChangeTicket == "" {
			return ErrCloseoutChangeTicketRequired
		}
		bucket := resolveCloseoutBucket(flags, env)
		if bucket == "" {
			return ErrCloseoutAuditBucketRequired
		}
	}
	return nil
}

func resolveCloseoutBucket(flags *closeoutFlags, env *closeoutEnv) string {
	if strings.TrimSpace(flags.AuditS3Bucket) != "" {
		return strings.TrimSpace(flags.AuditS3Bucket)
	}
	return strings.TrimSpace(env.Getenv(closeoutEnvAuditBucket))
}

// resolveCloseoutActor implements the precedence chain documented by
// VAL-CLI-017: --actor flag override → GITHUB_ACTOR → STS principal → $USER →
// "unknown". The STS lookup carries role_arn into the audit summary even when
// it is not chosen as the principal.
func resolveCloseoutActor(ctx context.Context, flags *closeoutFlags, env *closeoutEnv) (string, closeoutSTSIdentity, error) {
	identity := closeoutSTSIdentity{}
	if env.LookupSTS != nil {
		got, err := env.LookupSTS(ctx)
		if err != nil {
			return "", identity, err
		}
		identity = got
	}
	if flags.Actor != "" {
		return flags.Actor, identity, nil
	}
	if got := strings.TrimSpace(env.Getenv(closeoutEnvGithubActor)); got != "" {
		return got, identity, nil
	}
	if identity.Principal != "" {
		return identity.Principal, identity, nil
	}
	if got := strings.TrimSpace(env.Getenv(closeoutEnvUser)); got != "" {
		return got, identity, nil
	}
	return closeoutActorUnknown, identity, nil
}

func readCloseoutRuleIDFile(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-provided local rule-id file.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	var ids []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		ids = append(ids, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func parseCloseoutDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, errors.New("empty duration")
	}
	if strings.HasPrefix(raw, "-") {
		return 0, errors.New("duration must be positive")
	}
	if strings.HasSuffix(raw, "d") {
		const maxCloseoutDurationDays = int64(1<<63-1) / int64(24*time.Hour)
		days, err := strconv.ParseInt(strings.TrimSuffix(raw, "d"), 10, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", raw)
		}
		if days > maxCloseoutDurationDays {
			return 0, fmt.Errorf("day duration %q is too large", raw)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return d, nil
}

func splitAndTrim(value, sep string) []string {
	parts := strings.Split(value, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func mergeUnique(base, addition []string) []string {
	seen := make(map[string]struct{}, len(base)+len(addition))
	out := make([]string, 0, len(base)+len(addition))
	for _, v := range append(base, addition...) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// closeoutFailedEndLog builds the closeout.end payload for the
// post-Closeout failure exit paths. The key set is fixed by the
// run-boundary invariant: every exit path after Closeout returns must
// emit closeout.end with run_id, actor, env, dry_run, status, error,
// batch_count, and applied_count so CloudWatch consumers can correlate
// the run end with its outcome regardless of which downstream step
// (S3 put, post-summary hook) was the proximate failure.
func closeoutFailedEndLog(runID, actor, env string, dryRun bool, result *findings.CloseoutResult, err error, reason string) map[string]any {
	batchCount := 0
	appliedCount := 0
	if result != nil {
		batchCount = len(result.BatchSizes)
		appliedCount = result.AppliedCount
	}
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	payload := map[string]any{
		"event":         closeoutEventEnd,
		"run_id":        runID,
		"actor":         actor,
		"env":           env,
		"dry_run":       dryRun,
		"status":        "failed",
		"error":         errMsg,
		"batch_count":   batchCount,
		"applied_count": appliedCount,
	}
	if reason != "" {
		payload["reason"] = reason
	}
	return payload
}

// emitCloseoutLog writes one structured JSON log line to env.Stdout. The
// vocabulary is pinned (closeout.start, closeout.batch, closeout.end,
// closeout.refused) so CloudWatch consumers (and VAL-CLI-009) can rely on it.
func emitCloseoutLog(env *closeoutEnv, fields map[string]any) {
	if env == nil || env.Stdout == nil {
		return
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(env.Stdout, string(payload))
}

// newCloseoutRunID returns a fresh RFC 4122 v4 UUID using crypto/rand. The
// closeout CLI prints it on stdout so operators can correlate the audit row,
// the workflow event, the S3 summary key, and the CloudWatch log lines.
func newCloseoutRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// multiValueFlag captures repeated --flag values as a string slice.
type multiValueFlag struct {
	collected []string
}

func (m *multiValueFlag) Set(v string) error {
	if v != "" {
		m.collected = append(m.collected, strings.TrimSpace(v))
	}
	return nil
}

func (m *multiValueFlag) String() string { return strings.Join(m.collected, ",") }
func (m *multiValueFlag) values() []string {
	out := make([]string, 0, len(m.collected))
	for _, v := range m.collected {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

const closeoutHelpText = `cerebro closeout selects and bulk-tombstones findings.

Usage:
  cerebro closeout [flags]

Flags:
  --rule-id <id>            Rule ID to close out. Repeatable.
  --rule-id-file <path>     Newline-delimited rule IDs. Comments (#) and blank lines allowed.
  --source <name>           Source family (e.g. github, okta). Repeatable.
  --older-than <duration>   Only close findings whose last_observed_at is older than this duration (e.g. 7d, 24h).
  --status-filter <list>    Comma-separated statuses to include (default: open).
  --max-batch-size <int>    Maximum findings per batch (default: 1000).
  --dry-run <bool>          Dry-run mode (default: true). Mutually exclusive with --apply.
  --apply                   Apply mutations. Requires the gates below.
  --reason <text>           Closeout reason. Required for every run.
  --run-id <uuid>           Closeout run UUIDv4. Auto-generated when absent.
  --actor <text>            Operator identity. Resolved from GITHUB_ACTOR / STS / USER when absent.
  --change-ticket <text>    Change-management ticket. Required for --apply with --allow-env go-prod.
  --allow-env <env>         Approved environment (sec-dev|go-prod). Must equal CEREBRO_CLOSEOUT_ALLOW when --apply is set.
  --audit-s3-bucket <name>  S3 bucket for the audit summary. Required for --apply (or via CEREBRO_CLOSEOUT_AUDIT_BUCKET).
  --tenant-id <id>          Tenant identifier (or CEREBRO_CLOSEOUT_TENANT_ID).

Environment variables:
  CEREBRO_CLOSEOUT_ALLOW         Must equal --allow-env when --apply is set.
  CEREBRO_CLOSEOUT_AUDIT_BUCKET  Fallback for --audit-s3-bucket.
  CEREBRO_CLOSEOUT_TENANT_ID     Fallback for --tenant-id.
  GITHUB_ACTOR                   First-precedence actor.
  USER                           Last-precedence actor.
`
