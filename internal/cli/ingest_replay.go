package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/setutil"
)

var ingestReplayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay historical TAP events from JetStream",
	Long: `Replay historical TAP events from JetStream through the graph ingest path.

Replay uses an ephemeral pull consumer with a bounded upper sequence so it does
not mutate the live durable consumer cursor or chase new live traffic forever.

By default, successful non-dry-run replays materialize a graph snapshot artifact
into GRAPH_SNAPSHOT_PATH (or .cerebro/graph-snapshots when unset).`,
	RunE: runReplayStream,
}

var (
	replayStreamFromSequence uint64
	replayStreamFromTime     string
	replayStreamStream       string
	replayStreamSubject      string
	replayStreamLimit        int
	replayStreamCheckpoint   string
	replayStreamResume       bool
	replayStreamDryRun       bool
	replayStreamOutputMode   string
	replayStreamSnapshotDir  string
)

var replayStreamHistoryFn = events.ReplayJetStreamHistory

type replayStreamOptions struct {
	FromSequence uint64
	FromTime     string
	Stream       string
	Subject      string
	Limit        int
	Checkpoint   string
	Resume       bool
	DryRun       bool
	SnapshotDir  string
}

type replayStreamReport struct {
	Stream               string    `json:"stream"`
	Subject              string    `json:"subject"`
	CheckpointPath       string    `json:"checkpoint_path,omitempty"`
	CheckpointLoaded     bool      `json:"checkpoint_loaded,omitempty"`
	CheckpointSaved      bool      `json:"checkpoint_saved,omitempty"`
	DryRun               bool      `json:"dry_run,omitempty"`
	StartedAt            time.Time `json:"started_at"`
	CompletedAt          time.Time `json:"completed_at"`
	Duration             string    `json:"duration"`
	RequestedFromTime    string    `json:"requested_from_time,omitempty"`
	RequestedFromSeq     uint64    `json:"requested_from_sequence,omitempty"`
	StartSequence        uint64    `json:"start_sequence,omitempty"`
	UpperBoundSequence   uint64    `json:"upper_bound_sequence,omitempty"`
	LastStreamSequence   uint64    `json:"last_stream_sequence,omitempty"`
	MessagesFetched      int       `json:"messages_fetched"`
	EventsParsed         int       `json:"events_parsed"`
	EventsReplayed       int       `json:"events_replayed"`
	ParseErrors          int       `json:"parse_errors"`
	HandlerErrors        int       `json:"handler_errors"`
	LastHandlerError     string    `json:"last_handler_error,omitempty"`
	StoppedByUpperBound  bool      `json:"stopped_by_upper_bound,omitempty"`
	StoppedByLimit       bool      `json:"stopped_by_limit,omitempty"`
	SnapshotSaved        bool      `json:"snapshot_saved,omitempty"`
	SnapshotDir          string    `json:"snapshot_dir,omitempty"`
	SnapshotSkipped      bool      `json:"snapshot_skipped,omitempty"`
	SnapshotSkipReason   string    `json:"snapshot_skip_reason,omitempty"`
	GraphNodeCount       int       `json:"graph_node_count,omitempty"`
	GraphEdgeCount       int       `json:"graph_edge_count,omitempty"`
	GraphSnapshotID      string    `json:"graph_snapshot_id,omitempty"`
	GraphSnapshotBuiltAt time.Time `json:"graph_snapshot_built_at,omitempty"`
}

type replayStreamCheckpointState struct {
	Version            int    `json:"version"`
	Stream             string `json:"stream"`
	Subject            string `json:"subject"`
	UpdatedAt          string `json:"updated_at"`
	LastStreamSequence uint64 `json:"last_stream_sequence"`
}

func init() {
	ingestReplayCmd.Flags().Uint64Var(&replayStreamFromSequence, "from-sequence", 0, "Replay from an inclusive JetStream stream sequence")
	ingestReplayCmd.Flags().StringVar(&replayStreamFromTime, "from-time", "", "Replay from an inclusive RFC3339 timestamp")
	ingestReplayCmd.Flags().StringVar(&replayStreamStream, "stream", "", "JetStream stream name (defaults to NATS consumer stream config)")
	ingestReplayCmd.Flags().StringVar(&replayStreamSubject, "subject", "", "JetStream subject filter (defaults to the first configured NATS consumer subject)")
	ingestReplayCmd.Flags().IntVar(&replayStreamLimit, "limit", 0, "Maximum number of historical messages to fetch (0 for all available)")
	ingestReplayCmd.Flags().StringVar(&replayStreamCheckpoint, "checkpoint-path", "", "Optional checkpoint JSON path for replay progress")
	ingestReplayCmd.Flags().BoolVar(&replayStreamResume, "resume", true, "Resume from the last successful checkpointed stream sequence when available")
	ingestReplayCmd.Flags().BoolVar(&replayStreamDryRun, "dry-run", false, "Validate replay by running the ingest handler without materializing a graph snapshot")
	ingestReplayCmd.Flags().StringVar(&replayStreamSnapshotDir, "snapshot-dir", "", "Directory for replayed graph snapshots (defaults to GRAPH_SNAPSHOT_PATH or .cerebro/graph-snapshots)")
	ingestReplayCmd.Flags().StringVarP(&replayStreamOutputMode, "output", "o", "table", "Output format (table,json)")
	ingestCmd.AddCommand(ingestReplayCmd)
}

func runReplayStream(cmd *cobra.Command, _ []string) error {
	report, err := replayJetStream(replayStreamOptions{
		FromSequence: replayStreamFromSequence,
		FromTime:     strings.TrimSpace(replayStreamFromTime),
		Stream:       strings.TrimSpace(replayStreamStream),
		Subject:      strings.TrimSpace(replayStreamSubject),
		Limit:        replayStreamLimit,
		Checkpoint:   strings.TrimSpace(replayStreamCheckpoint),
		Resume:       replayStreamResume,
		DryRun:       replayStreamDryRun,
		SnapshotDir:  strings.TrimSpace(replayStreamSnapshotDir),
	})
	if err != nil {
		return err
	}
	if replayStreamOutputMode == FormatJSON {
		return JSONOutput(report)
	}
	return renderReplayStreamReport(report)
}

func replayJetStream(opts replayStreamOptions) (replayStreamReport, error) {
	if opts.Limit < 0 {
		return replayStreamReport{}, fmt.Errorf("--limit must be >= 0")
	}
	if opts.FromSequence > 0 && strings.TrimSpace(opts.FromTime) != "" {
		return replayStreamReport{}, fmt.Errorf("--from-sequence and --from-time are mutually exclusive")
	}

	cfg := app.LoadConfig()
	stream := strings.TrimSpace(opts.Stream)
	if stream == "" {
		stream = strings.TrimSpace(cfg.NATSConsumerStream)
	}
	if stream == "" {
		stream = "ENSEMBLE_TAP"
	}
	subject := firstConfiguredReplaySubject(cfg, opts.Subject)
	checkpointPath := resolveReplayStreamCheckpointPath(stream, subject, opts.Checkpoint)
	snapshotDir := resolveReplaySnapshotDir(opts.SnapshotDir)
	report := replayStreamReport{
		Stream:            stream,
		Subject:           subject,
		CheckpointPath:    checkpointPath,
		DryRun:            opts.DryRun,
		RequestedFromSeq:  opts.FromSequence,
		RequestedFromTime: strings.TrimSpace(opts.FromTime),
		StartedAt:         time.Now().UTC(),
	}

	var fromTime *time.Time
	if strings.TrimSpace(opts.FromTime) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(opts.FromTime))
		if err != nil {
			return replayStreamReport{}, fmt.Errorf("--from-time must be RFC3339: %w", err)
		}
		at := parsed.UTC()
		fromTime = &at
	}

	startSequence := opts.FromSequence
	if checkpointPath != "" && opts.Resume {
		state, err := loadReplayStreamCheckpoint(checkpointPath, stream, subject)
		if err != nil {
			return replayStreamReport{}, err
		}
		if state != nil && state.LastStreamSequence > 0 {
			startSequence = state.LastStreamSequence + 1
			fromTime = nil
			report.CheckpointLoaded = true
		}
	}

	replayApp := app.NewTapReplayApp(cfg, nil)
	lastSuccessfulSequence := uint64(0)
	dirtyCheckpoint := false
	replayResult, err := replayStreamHistoryFn(context.Background(), events.ReplayConfig{
		URLs:                   cfg.NATSJetStreamURLs,
		Stream:                 stream,
		Subject:                subject,
		BatchSize:              cfg.NATSConsumerBatchSize,
		FetchTimeout:           cfg.NATSConsumerFetchTimeout,
		ConnectTimeout:         cfg.NATSJetStreamConnectTimeout,
		Limit:                  opts.Limit,
		FromSequence:           startSequence,
		FromTime:               fromTime,
		AuthMode:               cfg.NATSJetStreamAuthMode,
		Username:               cfg.NATSJetStreamUsername,
		Password:               cfg.NATSJetStreamPassword,
		NKeySeed:               cfg.NATSJetStreamNKeySeed,
		UserJWT:                cfg.NATSJetStreamUserJWT,
		TLSEnabled:             cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:              cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:            cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:             cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:          cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify:  cfg.NATSJetStreamTLSInsecure,
		AllowInsecureTLS:       cfg.AllowInsecureTLS,
		ContinueOnHandlerError: true,
	}, func(ctx context.Context, evt events.ReplayEvent) error {
		if err := replayApp.ReplayTapCloudEvent(ctx, evt.CloudEvent); err != nil {
			return err
		}
		lastSuccessfulSequence = evt.StreamSequence
		dirtyCheckpoint = checkpointPath != ""
		if dirtyCheckpoint && lastSuccessfulSequence%50 == 0 {
			if err := saveReplayStreamCheckpoint(checkpointPath, stream, subject, lastSuccessfulSequence); err != nil {
				return err
			}
			report.CheckpointSaved = true
			dirtyCheckpoint = false
		}
		return nil
	})
	if err != nil {
		return report, err
	}

	report.StartedAt = replayResult.StartedAt
	report.CompletedAt = replayResult.CompletedAt
	report.Duration = replayResult.CompletedAt.Sub(replayResult.StartedAt).Round(time.Millisecond).String()
	report.StartSequence = replayResult.StartSequence
	report.UpperBoundSequence = replayResult.UpperBoundSequence
	report.LastStreamSequence = replayResult.LastStreamSequence
	report.MessagesFetched = replayResult.MessagesFetched
	report.EventsParsed = replayResult.EventsParsed
	report.EventsReplayed = replayResult.EventsHandled
	report.ParseErrors = replayResult.ParseErrors
	report.HandlerErrors = replayResult.HandlerErrors
	report.LastHandlerError = replayResult.LastHandlerError
	report.StoppedByUpperBound = replayResult.StoppedByUpperBound
	report.StoppedByLimit = replayResult.StoppedByLimit

	if checkpointPath != "" && lastSuccessfulSequence > 0 && (dirtyCheckpoint || !report.CheckpointSaved) {
		if err := saveReplayStreamCheckpoint(checkpointPath, stream, subject, lastSuccessfulSequence); err != nil {
			return report, err
		}
		report.CheckpointSaved = true
	}

	replayGraph := replayApp.SecurityGraph
	if replayGraph != nil {
		report.GraphNodeCount = replayGraph.NodeCount()
		report.GraphEdgeCount = replayGraph.EdgeCount()
	}

	if opts.DryRun || replayGraph == nil {
		return report, nil
	}
	if report.HandlerErrors > 0 {
		report.SnapshotSkipped = true
		report.SnapshotSkipReason = "handler_errors"
		return report, nil
	}
	if replayGraph.NodeCount() == 0 && replayGraph.EdgeCount() == 0 {
		report.SnapshotSkipped = true
		report.SnapshotSkipReason = "empty_graph"
		return report, nil
	}

	builtAt := time.Now().UTC()
	applyReplayGraphMetadata(replayGraph, builtAt)
	store := graph.NewSnapshotStore(snapshotDir, 10)
	if err := store.Save(replayGraph); err != nil {
		return report, fmt.Errorf("save replay graph snapshot: %w", err)
	}
	report.SnapshotSaved = true
	report.SnapshotDir = snapshotDir
	report.GraphSnapshotBuiltAt = builtAt
	if record, ok := latestReplaySnapshotRecord(store); ok {
		report.GraphSnapshotID = record.ID
	}

	return report, nil
}

func renderReplayStreamReport(report replayStreamReport) error {
	fmt.Println(bold("Graph Stream Replay"))
	fmt.Printf("  Stream:   %s\n", report.Stream)
	fmt.Printf("  Subject:  %s\n\n", report.Subject)

	tw := NewTableWriter(os.Stdout, "Metric", "Value")
	tw.AddRow("messages_fetched", fmt.Sprintf("%d", report.MessagesFetched))
	tw.AddRow("events_parsed", fmt.Sprintf("%d", report.EventsParsed))
	tw.AddRow("events_replayed", fmt.Sprintf("%d", report.EventsReplayed))
	tw.AddRow("parse_errors", fmt.Sprintf("%d", report.ParseErrors))
	tw.AddRow("handler_errors", fmt.Sprintf("%d", report.HandlerErrors))
	if report.RequestedFromSeq > 0 {
		tw.AddRow("requested_from_sequence", fmt.Sprintf("%d", report.RequestedFromSeq))
	}
	if report.RequestedFromTime != "" {
		tw.AddRow("requested_from_time", report.RequestedFromTime)
	}
	if report.StartSequence > 0 {
		tw.AddRow("start_sequence", fmt.Sprintf("%d", report.StartSequence))
	}
	if report.UpperBoundSequence > 0 {
		tw.AddRow("upper_bound_sequence", fmt.Sprintf("%d", report.UpperBoundSequence))
	}
	if report.LastStreamSequence > 0 {
		tw.AddRow("last_stream_sequence", fmt.Sprintf("%d", report.LastStreamSequence))
	}
	tw.AddRow("checkpoint_path", report.CheckpointPath)
	tw.AddRow("checkpoint_loaded", fmt.Sprintf("%t", report.CheckpointLoaded))
	tw.AddRow("checkpoint_saved", fmt.Sprintf("%t", report.CheckpointSaved))
	tw.AddRow("graph_node_count", fmt.Sprintf("%d", report.GraphNodeCount))
	tw.AddRow("graph_edge_count", fmt.Sprintf("%d", report.GraphEdgeCount))
	tw.AddRow("snapshot_saved", fmt.Sprintf("%t", report.SnapshotSaved))
	if report.SnapshotDir != "" {
		tw.AddRow("snapshot_dir", report.SnapshotDir)
	}
	if report.GraphSnapshotID != "" {
		tw.AddRow("graph_snapshot_id", report.GraphSnapshotID)
	}
	if report.SnapshotSkipped {
		tw.AddRow("snapshot_skipped", fmt.Sprintf("%t", report.SnapshotSkipped))
		tw.AddRow("snapshot_skip_reason", report.SnapshotSkipReason)
	}
	tw.AddRow("duration", report.Duration)
	tw.Render()
	return nil
}

func resolveReplayStreamCheckpointPath(stream, subject, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return raw
	}
	stream = strings.TrimSpace(stream)
	subject = strings.TrimSpace(subject)
	if stream == "" || subject == "" {
		return ""
	}
	return filepath.Join(".cerebro", "ingest-replay", slugifyReplayPathPart(stream+"-"+subject)+".checkpoint.json")
}

func slugifyReplayPathPart(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func loadReplayStreamCheckpoint(path, stream, subject string) (*replayStreamCheckpointState, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- operator supplied checkpoint path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read replay checkpoint %s: %w", path, err)
	}
	var state replayStreamCheckpointState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("decode replay checkpoint %s: %w", path, err)
	}
	if strings.TrimSpace(state.Stream) != "" && strings.TrimSpace(state.Stream) != strings.TrimSpace(stream) {
		return nil, fmt.Errorf("replay checkpoint %s targets stream %q, expected %q", path, state.Stream, stream)
	}
	if strings.TrimSpace(state.Subject) != "" && strings.TrimSpace(state.Subject) != strings.TrimSpace(subject) {
		return nil, fmt.Errorf("replay checkpoint %s targets subject %q, expected %q", path, state.Subject, subject)
	}
	return &state, nil
}

func saveReplayStreamCheckpoint(path, stream, subject string, lastSequence uint64) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create replay checkpoint directory: %w", err)
	}
	state := replayStreamCheckpointState{
		Version:            1,
		Stream:             strings.TrimSpace(stream),
		Subject:            strings.TrimSpace(subject),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
		LastStreamSequence: lastSequence,
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal replay checkpoint: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write replay checkpoint temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace replay checkpoint: %w", err)
	}
	return nil
}

func resolveReplaySnapshotDir(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return raw
	}
	if env := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH")); env != "" {
		return env
	}
	return filepath.Join(".cerebro", "graph-snapshots")
}

func firstConfiguredReplaySubject(cfg *app.Config, explicit string) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if cfg != nil {
		for _, candidate := range cfg.NATSConsumerSubjects {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" {
				return candidate
			}
		}
	}
	return "ensemble.tap.>"
}

func applyReplayGraphMetadata(g *graph.Graph, builtAt time.Time) {
	if g == nil {
		return
	}
	providers := make(map[string]struct{})
	accounts := make(map[string]struct{})
	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		if provider := strings.TrimSpace(node.Provider); provider != "" {
			providers[provider] = struct{}{}
		}
		if account := strings.TrimSpace(node.Account); account != "" {
			accounts[account] = struct{}{}
		}
	}
	meta := graph.Metadata{
		BuiltAt:   builtAt.UTC(),
		NodeCount: g.NodeCount(),
		EdgeCount: g.EdgeCount(),
		Providers: setutil.SortedStrings(providers),
		Accounts:  setutil.SortedStrings(accounts),
	}
	g.SetMetadata(meta)
}

func latestReplaySnapshotRecord(store *graph.SnapshotStore) (graph.GraphSnapshotRecord, bool) {
	if store == nil {
		return graph.GraphSnapshotRecord{}, false
	}
	records, err := store.ListGraphSnapshotRecords()
	if err != nil || len(records) == 0 {
		return graph.GraphSnapshotRecord{}, false
	}
	sort.Slice(records, func(i, j int) bool {
		left := replaySnapshotRecordSortTime(records[i])
		right := replaySnapshotRecordSortTime(records[j])
		if !left.Equal(right) {
			return left.After(right)
		}
		return records[i].ID < records[j].ID
	})
	return records[0], true
}

func replaySnapshotRecordSortTime(record graph.GraphSnapshotRecord) time.Time {
	switch {
	case record.CapturedAt != nil && !record.CapturedAt.IsZero():
		return record.CapturedAt.UTC()
	case record.BuiltAt != nil && !record.BuiltAt.IsZero():
		return record.BuiltAt.UTC()
	default:
		return time.Time{}
	}
}
