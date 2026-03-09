package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graphingest"
)

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Manage ingestion workflows",
}

var replayDeadLetterCmd = &cobra.Command{
	Use:   "replay-dead-letter",
	Short: "Replay graph mapper dead-letter records",
	Long: `Replay graph mapper dead-letter records through current mapping rules.

This command deduplicates by event identity, skips malformed JSONL records, and
reports whether events now replay cleanly or still fail schema/mapping checks.`,
	RunE: runReplayDeadLetter,
}

var (
	replayDeadLetterPath       string
	replayDeadLetterMapping    string
	replayDeadLetterLimit      int
	replayDeadLetterCheckpoint string
	replayDeadLetterResume     bool
	replayDeadLetterOutputMode string
)

type replayDeadLetterOptions struct {
	Path        string
	MappingPath string
	Limit       int
	Checkpoint  string
	Resume      bool
}

type replayDeadLetterReport struct {
	Path                string         `json:"path"`
	MappingSource       string         `json:"mapping_source"`
	CheckpointPath      string         `json:"checkpoint_path,omitempty"`
	CheckpointLoaded    bool           `json:"checkpoint_loaded,omitempty"`
	CheckpointSaved     bool           `json:"checkpoint_saved,omitempty"`
	StartedAt           time.Time      `json:"started_at"`
	CompletedAt         time.Time      `json:"completed_at"`
	Duration            string         `json:"duration"`
	LinesRead           int            `json:"lines_read"`
	RecordsParsed       int            `json:"records_parsed"`
	ParseErrors         int            `json:"parse_errors"`
	UniqueEvents        int            `json:"unique_events"`
	EventsProcessed     int            `json:"events_processed"`
	EventsReplayed      int            `json:"events_replayed"`
	EventsStillRejected int            `json:"events_still_rejected"`
	EventsUnmatched     int            `json:"events_unmatched"`
	EventsSkippedNoData int            `json:"events_skipped_no_data"`
	EventsApplyErrors   int            `json:"events_apply_errors"`
	EventsDeduplicated  int            `json:"events_deduplicated"`
	EventsCheckpointed  int            `json:"events_checkpoint_skipped"`
	EventsLimitSkipped  int            `json:"events_limit_skipped"`
	NodesUpserted       int            `json:"nodes_upserted"`
	EdgesUpserted       int            `json:"edges_upserted"`
	RejectByCode        map[string]int `json:"reject_by_code,omitempty"`
}

type replayDeadLetterCheckpointState struct {
	Version            int      `json:"version"`
	Path               string   `json:"path"`
	UpdatedAt          string   `json:"updated_at"`
	ProcessedEventKeys []string `json:"processed_event_keys,omitempty"`
}

func init() {
	replayDeadLetterCmd.Flags().StringVar(&replayDeadLetterPath, "path", "", "Path to graph mapper dead-letter JSONL file")
	replayDeadLetterCmd.Flags().StringVar(&replayDeadLetterMapping, "mapping-path", "", "Optional graph event mapping YAML path (defaults to GRAPH_EVENT_MAPPING_PATH or embedded mappings)")
	replayDeadLetterCmd.Flags().IntVar(&replayDeadLetterLimit, "limit", 0, "Maximum unique events to process (0 for all)")
	replayDeadLetterCmd.Flags().StringVar(&replayDeadLetterCheckpoint, "checkpoint-path", "", "Optional checkpoint JSON path for replay progress (defaults to <path>.checkpoint.json)")
	replayDeadLetterCmd.Flags().BoolVar(&replayDeadLetterResume, "resume", true, "Resume from checkpoint progress when available")
	replayDeadLetterCmd.Flags().StringVarP(&replayDeadLetterOutputMode, "output", "o", "table", "Output format (table,json)")
	ingestCmd.AddCommand(replayDeadLetterCmd)
}

func runReplayDeadLetter(cmd *cobra.Command, _ []string) error {
	path := strings.TrimSpace(replayDeadLetterPath)
	if path == "" {
		if cfgPath := strings.TrimSpace(os.Getenv("GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH")); cfgPath != "" {
			path = cfgPath
		} else {
			path = strings.TrimSpace(app.LoadConfig().GraphEventMapperDeadLetterPath)
		}
	}

	report, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        path,
		MappingPath: strings.TrimSpace(replayDeadLetterMapping),
		Limit:       replayDeadLetterLimit,
		Checkpoint:  resolveReplayCheckpointPath(path, replayDeadLetterCheckpoint),
		Resume:      replayDeadLetterResume,
	})
	if err != nil {
		return err
	}

	if replayDeadLetterOutputMode == FormatJSON {
		return JSONOutput(report)
	}
	return renderReplayDeadLetterReport(report)
}

func replayDeadLetter(opts replayDeadLetterOptions) (replayDeadLetterReport, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return replayDeadLetterReport{}, fmt.Errorf("--path is required or set GRAPH_EVENT_MAPPER_DEAD_LETTER_PATH")
	}
	if opts.Limit < 0 {
		return replayDeadLetterReport{}, fmt.Errorf("--limit must be >= 0")
	}
	checkpointPath := strings.TrimSpace(opts.Checkpoint)

	config, mappingSource, err := loadReplayMappingConfig(opts.MappingPath)
	if err != nil {
		return replayDeadLetterReport{}, err
	}

	mapper, err := graphingest.NewMapperWithOptions(config, replayIdentityResolver, graphingest.MapperOptions{
		ValidationMode: graphingest.MapperValidationEnforce,
	})
	if err != nil {
		return replayDeadLetterReport{}, fmt.Errorf("initialize mapper for replay: %w", err)
	}

	report := replayDeadLetterReport{
		Path:           path,
		MappingSource:  mappingSource,
		CheckpointPath: checkpointPath,
		StartedAt:      time.Now().UTC(),
	}

	graphState := graph.New()
	beforeStats := mapper.Stats()
	seen := make(map[string]struct{})
	restoredSeen := make(map[string]struct{})
	checkpointSeen := make(map[string]struct{})
	dirtyCheckpoint := false

	if checkpointPath != "" && opts.Resume {
		loaded, err := loadReplayCheckpoint(checkpointPath)
		if err != nil {
			return replayDeadLetterReport{}, err
		}
		if len(loaded) > 0 {
			report.CheckpointLoaded = true
			for key := range loaded {
				seen[key] = struct{}{}
				restoredSeen[key] = struct{}{}
				checkpointSeen[key] = struct{}{}
			}
		}
	}

	scanStats, err := graphingest.StreamDeadLetterPath(path, func(record graphingest.DeadLetterRecord) error {
		key := replayEventKey(record)
		if _, ok := seen[key]; ok {
			if _, fromCheckpoint := restoredSeen[key]; fromCheckpoint {
				report.EventsCheckpointed++
			} else {
				report.EventsDeduplicated++
			}
			return nil
		}
		seen[key] = struct{}{}
		report.UniqueEvents++

		if opts.Limit > 0 && report.EventsProcessed >= opts.Limit {
			report.EventsLimitSkipped++
			return nil
		}
		report.EventsProcessed++

		evt, hasData := record.ReplayEvent()
		if !hasData {
			report.EventsSkippedNoData++
			return nil
		}
		result, err := mapper.Apply(graphState, evt)
		if err != nil {
			report.EventsApplyErrors++
			return nil
		}
		report.NodesUpserted += len(result.NodesUpserted)
		report.EdgesUpserted += len(result.EdgesUpserted)
		if !result.Matched {
			report.EventsUnmatched++
			return nil
		}
		if result.NodesRejected > 0 || result.EdgesRejected > 0 || result.DeadLettered > 0 {
			report.EventsStillRejected++
			return nil
		}
		report.EventsReplayed++
		if checkpointPath != "" {
			checkpointSeen[key] = struct{}{}
			dirtyCheckpoint = true
			if len(checkpointSeen)%50 == 0 {
				if err := saveReplayCheckpoint(checkpointPath, path, checkpointSeen); err != nil {
					return err
				}
				report.CheckpointSaved = true
				dirtyCheckpoint = false
			}
		}
		return nil
	})
	if err != nil {
		return replayDeadLetterReport{}, err
	}
	if checkpointPath != "" && (dirtyCheckpoint || !report.CheckpointSaved) {
		if err := saveReplayCheckpoint(checkpointPath, path, checkpointSeen); err != nil {
			return replayDeadLetterReport{}, err
		}
		report.CheckpointSaved = true
	}

	afterStats := mapper.Stats()
	report.LinesRead = scanStats.LinesRead
	report.RecordsParsed = scanStats.RecordsParsed
	report.ParseErrors = scanStats.ParseErrors
	report.RejectByCode = mapperRejectDelta(beforeStats, afterStats)
	report.CompletedAt = time.Now().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
	return report, nil
}

func loadReplayMappingConfig(rawPath string) (graphingest.MappingConfig, string, error) {
	path := strings.TrimSpace(rawPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("GRAPH_EVENT_MAPPING_PATH"))
	}
	if path == "" {
		config, err := graphingest.LoadDefaultConfig()
		if err != nil {
			return graphingest.MappingConfig{}, "", fmt.Errorf("load default graph mappings: %w", err)
		}
		return config, "embedded-default", nil
	}

	config, err := graphingest.LoadConfigFile(path)
	if err != nil {
		return graphingest.MappingConfig{}, "", fmt.Errorf("load mapping config %s: %w", path, err)
	}
	return config, path, nil
}

func replayIdentityResolver(raw string, _ events.CloudEvent) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, ":") {
		return raw
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "@") {
		return "person:" + lower
	}
	return raw
}

func replayEventKey(record graphingest.DeadLetterRecord) string {
	if id := strings.TrimSpace(record.EventID); id != "" {
		return "id:" + id
	}
	parts := []string{
		strings.TrimSpace(record.EventType),
		strings.TrimSpace(record.EventSource),
		strings.TrimSpace(record.EventSubj),
		strings.TrimSpace(record.EventTenant),
		strings.TrimSpace(record.EntityType),
		strings.TrimSpace(record.EntityID),
	}
	if !record.EventTime.IsZero() {
		parts = append(parts, record.EventTime.UTC().Format(time.RFC3339Nano))
	}
	return strings.Join(parts, "|")
}

func mapperRejectDelta(before, after graphingest.MapperStats) map[string]int {
	delta := make(map[string]int)
	for code, value := range after.NodeRejectByCode {
		if diff := value - before.NodeRejectByCode[code]; diff > 0 {
			delta[code] += diff
		}
	}
	for code, value := range after.EdgeRejectByCode {
		if diff := value - before.EdgeRejectByCode[code]; diff > 0 {
			delta[code] += diff
		}
	}
	if len(delta) == 0 {
		return nil
	}
	return delta
}

func renderReplayDeadLetterReport(report replayDeadLetterReport) error {
	fmt.Println(bold("Graph Dead-Letter Replay"))
	fmt.Printf("  DLQ:      %s\n", report.Path)
	fmt.Printf("  Mappings: %s\n\n", report.MappingSource)

	tw := NewTableWriter(os.Stdout, "Metric", "Value")
	tw.AddRow("lines_read", fmt.Sprintf("%d", report.LinesRead))
	tw.AddRow("records_parsed", fmt.Sprintf("%d", report.RecordsParsed))
	tw.AddRow("parse_errors", fmt.Sprintf("%d", report.ParseErrors))
	tw.AddRow("unique_events", fmt.Sprintf("%d", report.UniqueEvents))
	tw.AddRow("events_processed", fmt.Sprintf("%d", report.EventsProcessed))
	tw.AddRow("events_replayed", fmt.Sprintf("%d", report.EventsReplayed))
	tw.AddRow("events_still_rejected", fmt.Sprintf("%d", report.EventsStillRejected))
	tw.AddRow("events_unmatched", fmt.Sprintf("%d", report.EventsUnmatched))
	tw.AddRow("events_skipped_no_data", fmt.Sprintf("%d", report.EventsSkippedNoData))
	tw.AddRow("events_apply_errors", fmt.Sprintf("%d", report.EventsApplyErrors))
	tw.AddRow("events_deduplicated", fmt.Sprintf("%d", report.EventsDeduplicated))
	tw.AddRow("events_checkpoint_skipped", fmt.Sprintf("%d", report.EventsCheckpointed))
	tw.AddRow("events_limit_skipped", fmt.Sprintf("%d", report.EventsLimitSkipped))
	tw.AddRow("nodes_upserted", fmt.Sprintf("%d", report.NodesUpserted))
	tw.AddRow("edges_upserted", fmt.Sprintf("%d", report.EdgesUpserted))
	if report.CheckpointPath != "" {
		tw.AddRow("checkpoint_path", report.CheckpointPath)
		tw.AddRow("checkpoint_loaded", fmt.Sprintf("%t", report.CheckpointLoaded))
		tw.AddRow("checkpoint_saved", fmt.Sprintf("%t", report.CheckpointSaved))
	}
	tw.AddRow("duration", report.Duration)
	tw.Render()

	if len(report.RejectByCode) > 0 {
		fmt.Println()
		fmt.Println(bold("Reject Deltas"))
		keys := make([]string, 0, len(report.RejectByCode))
		for key := range report.RejectByCode {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		rejectTable := NewTableWriter(os.Stdout, "Issue Code", "Count")
		for _, key := range keys {
			rejectTable.AddRow(key, fmt.Sprintf("%d", report.RejectByCode[key]))
		}
		rejectTable.Render()
	}
	return nil
}

func resolveReplayCheckpointPath(dlqPath, rawCheckpoint string) string {
	rawCheckpoint = strings.TrimSpace(rawCheckpoint)
	if rawCheckpoint != "" {
		return rawCheckpoint
	}
	dlqPath = strings.TrimSpace(dlqPath)
	if dlqPath == "" {
		return ""
	}
	base := filepath.Base(dlqPath)
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return dlqPath + ".checkpoint.json"
}

func loadReplayCheckpoint(path string) (map[string]struct{}, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- path is operator supplied checkpoint path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read replay checkpoint %s: %w", path, err)
	}
	var state replayDeadLetterCheckpointState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("decode replay checkpoint %s: %w", path, err)
	}
	loaded := make(map[string]struct{}, len(state.ProcessedEventKeys))
	for _, key := range state.ProcessedEventKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		loaded[key] = struct{}{}
	}
	return loaded, nil
}

func saveReplayCheckpoint(path, replayPath string, seen map[string]struct{}) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create replay checkpoint directory: %w", err)
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := replayDeadLetterCheckpointState{
		Version:            1,
		Path:               strings.TrimSpace(replayPath),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
		ProcessedEventKeys: keys,
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
