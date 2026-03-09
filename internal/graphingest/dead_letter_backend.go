package graphingest

import (
	"container/heap"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteDeadLetterPrefix = "sqlite://"

type deadLetterBackend string

const (
	deadLetterBackendFile   deadLetterBackend = "file"
	deadLetterBackendSQLite deadLetterBackend = "sqlite"
)

// DeadLetterQueryOptions controls dead-letter query filtering and pagination.
type DeadLetterQueryOptions struct {
	Limit       int    `json:"limit"`
	Offset      int    `json:"offset"`
	EventType   string `json:"event_type,omitempty"`
	MappingName string `json:"mapping_name,omitempty"`
	IssueCode   string `json:"issue_code,omitempty"`
	EntityType  string `json:"entity_type,omitempty"`
	EntityKind  string `json:"entity_kind,omitempty"`
}

// DeadLetterQueryResult contains one filtered DLQ query page.
type DeadLetterQueryResult struct {
	Limit   int                `json:"limit"`
	Offset  int                `json:"offset"`
	Total   int                `json:"total"`
	Records []DeadLetterRecord `json:"records,omitempty"`
}

// NewDeadLetterSink returns the best sink implementation for a configured DLQ path.
func NewDeadLetterSink(path string) (DeadLetterSink, error) {
	backend, resolved, err := resolveDeadLetterBackend(path)
	if err != nil {
		return nil, err
	}
	switch backend {
	case deadLetterBackendSQLite:
		return NewSQLiteDeadLetterSink(resolved)
	default:
		return NewFileDeadLetterSink(resolved)
	}
}

// InspectDeadLetter returns bounded tail summary metrics for file or sqlite DLQ backends.
func InspectDeadLetter(path string, tailLimit int) (DeadLetterTailMetrics, error) {
	backend, resolved, err := resolveDeadLetterBackend(path)
	if err != nil {
		return DeadLetterTailMetrics{}, err
	}
	switch backend {
	case deadLetterBackendSQLite:
		return InspectSQLiteDeadLetter(resolved, tailLimit)
	default:
		return InspectDeadLetterFile(resolved, tailLimit)
	}
}

// StreamDeadLetterPath iterates records for file or sqlite DLQ backends.
func StreamDeadLetterPath(path string, handle func(record DeadLetterRecord) error) (DeadLetterScanStats, error) {
	backend, resolved, err := resolveDeadLetterBackend(path)
	if err != nil {
		return DeadLetterScanStats{}, err
	}
	switch backend {
	case deadLetterBackendSQLite:
		return streamSQLiteDeadLetter(resolved, handle)
	default:
		return StreamDeadLetter(resolved, handle)
	}
}

// QueryDeadLetter returns filtered DLQ records for file or sqlite backends.
func QueryDeadLetter(path string, opts DeadLetterQueryOptions) (DeadLetterQueryResult, error) {
	backend, resolved, err := resolveDeadLetterBackend(path)
	if err != nil {
		return DeadLetterQueryResult{}, err
	}
	normalized := normalizeDeadLetterQueryOptions(opts)
	switch backend {
	case deadLetterBackendSQLite:
		return queryDeadLetterSQLite(resolved, normalized)
	default:
		return queryDeadLetterFile(resolved, normalized)
	}
}

func normalizeDeadLetterQueryOptions(opts DeadLetterQueryOptions) DeadLetterQueryOptions {
	opts.Limit = maxInt(1, opts.Limit)
	if opts.Limit > 500 {
		opts.Limit = 500
	}
	if opts.Offset < 0 {
		opts.Offset = 0
	}
	opts.EventType = strings.TrimSpace(opts.EventType)
	opts.MappingName = strings.TrimSpace(opts.MappingName)
	opts.IssueCode = strings.TrimSpace(opts.IssueCode)
	opts.EntityType = strings.TrimSpace(opts.EntityType)
	opts.EntityKind = strings.TrimSpace(opts.EntityKind)
	return opts
}

func resolveDeadLetterBackend(path string) (deadLetterBackend, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", fmt.Errorf("dead-letter path is required")
	}
	if strings.HasPrefix(strings.ToLower(path), sqliteDeadLetterPrefix) {
		resolved := strings.TrimSpace(path[len(sqliteDeadLetterPrefix):])
		if resolved == "" {
			return "", "", fmt.Errorf("sqlite dead-letter path is required")
		}
		return deadLetterBackendSQLite, resolved, nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".db" || ext == ".sqlite" || ext == ".sqlite3" {
		return deadLetterBackendSQLite, path, nil
	}
	return deadLetterBackendFile, path, nil
}

// SQLiteDeadLetterSink persists dead-letter records in a queryable sqlite table.
type SQLiteDeadLetterSink struct {
	path string
	db   *sql.DB
	mu   sync.Mutex
}

func NewSQLiteDeadLetterSink(path string) (*SQLiteDeadLetterSink, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("dead-letter path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create dead-letter sqlite directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open dead-letter sqlite: %w", err)
	}
	if err := initSQLiteDeadLetterSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteDeadLetterSink{path: path, db: db}, nil
}

func (s *SQLiteDeadLetterSink) WriteDeadLetter(record DeadLetterRecord) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("dead-letter sqlite sink is nil")
	}
	record.RecordedAt = record.RecordedAt.UTC()
	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal dead-letter record: %w", err)
	}
	issueCodes := deadLetterIssueCodeSet(record)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.ExecContext(context.Background(), `
		INSERT INTO graph_dead_letters (
			recorded_at,
			event_id,
			event_type,
			mapping_name,
			entity_type,
			entity_id,
			entity_kind,
			issue_codes,
			record_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.RecordedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(record.EventID),
		strings.TrimSpace(record.EventType),
		strings.TrimSpace(record.MappingName),
		strings.TrimSpace(record.EntityType),
		strings.TrimSpace(record.EntityID),
		strings.TrimSpace(record.EntityKind),
		issueCodes,
		string(payload),
	)
	if err != nil {
		return fmt.Errorf("insert dead-letter sqlite record: %w", err)
	}
	return nil
}

func initSQLiteDeadLetterSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("dead-letter sqlite db is nil")
	}
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS graph_dead_letters (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recorded_at TEXT NOT NULL,
			event_id TEXT,
			event_type TEXT,
			mapping_name TEXT,
			entity_type TEXT,
			entity_id TEXT,
			entity_kind TEXT,
			issue_codes TEXT,
			record_json TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_graph_dead_letters_recorded_at ON graph_dead_letters(recorded_at);
		CREATE INDEX IF NOT EXISTS idx_graph_dead_letters_event_type ON graph_dead_letters(event_type);
		CREATE INDEX IF NOT EXISTS idx_graph_dead_letters_mapping_name ON graph_dead_letters(mapping_name);
		CREATE INDEX IF NOT EXISTS idx_graph_dead_letters_entity_type ON graph_dead_letters(entity_type);
		CREATE INDEX IF NOT EXISTS idx_graph_dead_letters_entity_kind ON graph_dead_letters(entity_kind);
	`)
	if err != nil {
		return fmt.Errorf("initialize dead-letter sqlite schema: %w", err)
	}
	return nil
}

func InspectSQLiteDeadLetter(path string, tailLimit int) (DeadLetterTailMetrics, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return DeadLetterTailMetrics{}, fmt.Errorf("dead-letter path is required")
	}
	if tailLimit <= 0 {
		tailLimit = 25
	}
	if tailLimit > 500 {
		tailLimit = 500
	}

	metrics := DeadLetterTailMetrics{Path: path, TailLimit: tailLimit}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return metrics, nil
		}
		return DeadLetterTailMetrics{}, fmt.Errorf("stat dead-letter sqlite file: %w", err)
	}
	if info.IsDir() {
		return DeadLetterTailMetrics{}, fmt.Errorf("dead-letter path %q is a directory", path)
	}
	metrics.Exists = true
	metrics.SizeBytes = info.Size()
	metrics.ModifiedAt = info.ModTime().UTC()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return DeadLetterTailMetrics{}, fmt.Errorf("open dead-letter sqlite: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()
	if err := initSQLiteDeadLetterSchema(db); err != nil {
		return DeadLetterTailMetrics{}, err
	}

	rows, err := db.QueryContext(context.Background(), `
		SELECT record_json
		FROM graph_dead_letters
		ORDER BY id DESC
		LIMIT ?
	`, tailLimit)
	if err != nil {
		return DeadLetterTailMetrics{}, fmt.Errorf("query dead-letter sqlite tail: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	records := make([]DeadLetterRecord, 0, tailLimit)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			metrics.ParseErrors++
			continue
		}
		var record DeadLetterRecord
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			metrics.ParseErrors++
			continue
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return DeadLetterTailMetrics{}, fmt.Errorf("scan dead-letter sqlite tail: %w", err)
	}
	for i := len(records) - 1; i >= 0; i-- {
		accumulateDeadLetterMetrics(&metrics, records[i])
	}
	metrics.TailLines = len(records)
	return metrics, nil
}

func streamSQLiteDeadLetter(path string, handle func(record DeadLetterRecord) error) (DeadLetterScanStats, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return DeadLetterScanStats{}, fmt.Errorf("dead-letter path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return DeadLetterScanStats{}, fmt.Errorf("open dead-letter sqlite: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()
	if err := initSQLiteDeadLetterSchema(db); err != nil {
		return DeadLetterScanStats{}, err
	}
	rows, err := db.QueryContext(context.Background(), `
		SELECT record_json
		FROM graph_dead_letters
		ORDER BY id ASC
	`)
	if err != nil {
		return DeadLetterScanStats{}, fmt.Errorf("query dead-letter sqlite records: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	stats := DeadLetterScanStats{}
	for rows.Next() {
		stats.LinesRead++
		var payload string
		if err := rows.Scan(&payload); err != nil {
			stats.ParseErrors++
			continue
		}
		var record DeadLetterRecord
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			stats.ParseErrors++
			continue
		}
		stats.RecordsParsed++
		if handle != nil {
			if err := handle(record); err != nil {
				return stats, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("scan dead-letter sqlite rows: %w", err)
	}
	return stats, nil
}

func queryDeadLetterSQLite(path string, opts DeadLetterQueryOptions) (DeadLetterQueryResult, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return DeadLetterQueryResult{}, fmt.Errorf("open dead-letter sqlite: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()
	if err := initSQLiteDeadLetterSchema(db); err != nil {
		return DeadLetterQueryResult{}, err
	}

	where, args := deadLetterSQLFilters(opts)
	countQuery := "SELECT COUNT(1) FROM graph_dead_letters"
	if where != "" {
		countQuery += " WHERE " + where // #nosec G202 -- `where` is built from a fixed internal clause whitelist.
	}
	var total int
	if err := db.QueryRowContext(context.Background(), countQuery, args...).Scan(&total); err != nil {
		return DeadLetterQueryResult{}, fmt.Errorf("count dead-letter sqlite rows: %w", err)
	}

	query := "SELECT record_json FROM graph_dead_letters"
	if where != "" {
		query += " WHERE " + where // #nosec G202 -- `where` is built from a fixed internal clause whitelist.
	}
	query += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, opts.Limit, opts.Offset)
	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return DeadLetterQueryResult{}, fmt.Errorf("query dead-letter sqlite rows: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	result := DeadLetterQueryResult{Limit: opts.Limit, Offset: opts.Offset, Total: total}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			continue
		}
		var record DeadLetterRecord
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			continue
		}
		result.Records = append(result.Records, record)
	}
	if err := rows.Err(); err != nil {
		return DeadLetterQueryResult{}, fmt.Errorf("scan dead-letter sqlite rows: %w", err)
	}
	return result, nil
}

func deadLetterSQLFilters(opts DeadLetterQueryOptions) (string, []any) {
	clauses := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if opts.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, opts.EventType)
	}
	if opts.MappingName != "" {
		clauses = append(clauses, "mapping_name = ?")
		args = append(args, opts.MappingName)
	}
	if opts.EntityType != "" {
		clauses = append(clauses, "entity_type = ?")
		args = append(args, opts.EntityType)
	}
	if opts.EntityKind != "" {
		clauses = append(clauses, "entity_kind = ?")
		args = append(args, opts.EntityKind)
	}
	if opts.IssueCode != "" {
		clauses = append(clauses, "issue_codes LIKE ? ESCAPE '\\'")
		args = append(args, "%,"+escapeSQLLikeLiteral(opts.IssueCode)+",%")
	}
	return strings.Join(clauses, " AND "), args
}

func escapeSQLLikeLiteral(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return replacer.Replace(value)
}

func queryDeadLetterFile(path string, opts DeadLetterQueryOptions) (DeadLetterQueryResult, error) {
	result := DeadLetterQueryResult{Limit: opts.Limit, Offset: opts.Offset}
	maxKeep := opts.Limit
	if opts.Offset > 0 {
		const maxIntValue = int(^uint(0) >> 1)
		if opts.Offset >= maxIntValue-maxKeep {
			maxKeep = maxIntValue
		} else {
			maxKeep += opts.Offset
		}
	}
	pager := &deadLetterTopKPager{maxKeep: maxKeep}
	heap.Init(pager)
	_, err := StreamDeadLetter(path, func(record DeadLetterRecord) error {
		if !deadLetterRecordMatches(record, opts) {
			return nil
		}
		result.Total++
		pager.push(record)
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return DeadLetterQueryResult{}, err
	}
	records := pager.sortedDescending()
	if opts.Offset < len(records) {
		end := opts.Offset + opts.Limit
		if end > len(records) {
			end = len(records)
		}
		result.Records = records[opts.Offset:end]
	}
	return result, nil
}

func deadLetterRecordMoreRecent(a, b DeadLetterRecord) bool {
	if a.RecordedAt.Equal(b.RecordedAt) {
		return a.EventID > b.EventID
	}
	return a.RecordedAt.After(b.RecordedAt)
}

type deadLetterTopKPager struct {
	items   []DeadLetterRecord
	maxKeep int
}

func (p deadLetterTopKPager) Len() int {
	return len(p.items)
}

func (p deadLetterTopKPager) Less(i, j int) bool {
	if p.items[i].RecordedAt.Equal(p.items[j].RecordedAt) {
		return p.items[i].EventID < p.items[j].EventID
	}
	return p.items[i].RecordedAt.Before(p.items[j].RecordedAt)
}

func (p deadLetterTopKPager) Swap(i, j int) {
	p.items[i], p.items[j] = p.items[j], p.items[i]
}

func (p *deadLetterTopKPager) Push(x any) {
	record, _ := x.(DeadLetterRecord)
	p.items = append(p.items, record)
}

func (p *deadLetterTopKPager) Pop() any {
	last := len(p.items) - 1
	if last < 0 {
		return DeadLetterRecord{}
	}
	record := p.items[last]
	p.items = p.items[:last]
	return record
}

func (p *deadLetterTopKPager) push(record DeadLetterRecord) {
	if p == nil || p.maxKeep <= 0 {
		return
	}
	if p.Len() < p.maxKeep {
		heap.Push(p, record)
		return
	}
	if p.Len() == 0 {
		return
	}
	oldest := p.items[0]
	if deadLetterRecordMoreRecent(record, oldest) {
		heap.Pop(p)
		heap.Push(p, record)
	}
}

func (p *deadLetterTopKPager) sortedDescending() []DeadLetterRecord {
	if p == nil || len(p.items) == 0 {
		return nil
	}
	records := make([]DeadLetterRecord, len(p.items))
	copy(records, p.items)
	sort.SliceStable(records, func(i, j int) bool {
		return deadLetterRecordMoreRecent(records[i], records[j])
	})
	return records
}

func deadLetterRecordMatches(record DeadLetterRecord, opts DeadLetterQueryOptions) bool {
	if opts.EventType != "" && strings.TrimSpace(record.EventType) != opts.EventType {
		return false
	}
	if opts.MappingName != "" && strings.TrimSpace(record.MappingName) != opts.MappingName {
		return false
	}
	if opts.EntityType != "" && strings.TrimSpace(record.EntityType) != opts.EntityType {
		return false
	}
	if opts.EntityKind != "" && strings.TrimSpace(record.EntityKind) != opts.EntityKind {
		return false
	}
	if opts.IssueCode != "" {
		found := false
		for _, issue := range record.Issues {
			if strings.TrimSpace(string(issue.Code)) == opts.IssueCode {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func accumulateDeadLetterMetrics(metrics *DeadLetterTailMetrics, record DeadLetterRecord) {
	if metrics == nil {
		return
	}
	metrics.RecordsParsed++
	if record.RecordedAt.After(metrics.LastRecordedAt) {
		metrics.LastRecordedAt = record.RecordedAt.UTC()
	}
	if metrics.IssueCodeCounts == nil {
		metrics.IssueCodeCounts = make(map[string]int)
	}
	if metrics.EntityTypeCounts == nil {
		metrics.EntityTypeCounts = make(map[string]int)
	}
	if metrics.EntityKindCounts == nil {
		metrics.EntityKindCounts = make(map[string]int)
	}
	if metrics.MappingNameCounts == nil {
		metrics.MappingNameCounts = make(map[string]int)
	}
	if metrics.EventTypeCounts == nil {
		metrics.EventTypeCounts = make(map[string]int)
	}

	if key := strings.TrimSpace(record.EntityType); key != "" {
		metrics.EntityTypeCounts[key]++
	}
	if key := strings.TrimSpace(record.EntityKind); key != "" {
		metrics.EntityKindCounts[key]++
	}
	if key := strings.TrimSpace(record.MappingName); key != "" {
		metrics.MappingNameCounts[key]++
	}
	if key := strings.TrimSpace(record.EventType); key != "" {
		metrics.EventTypeCounts[key]++
	}
	for _, issue := range record.Issues {
		if key := strings.TrimSpace(string(issue.Code)); key != "" {
			metrics.IssueCodeCounts[key]++
		}
	}
}

func deadLetterIssueCodeSet(record DeadLetterRecord) string {
	codes := make([]string, 0, len(record.Issues))
	seen := make(map[string]struct{})
	for _, issue := range record.Issues {
		code := strings.TrimSpace(string(issue.Code))
		if code == "" {
			continue
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	sort.Strings(codes)
	if len(codes) == 0 {
		return ""
	}
	return "," + strings.Join(codes, ",") + ","
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
