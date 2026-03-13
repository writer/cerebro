package executionstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type RunEnvelope struct {
	Namespace   string
	RunID       string
	Kind        string
	Status      string
	Stage       string
	SubmittedAt time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	UpdatedAt   time.Time
	Payload     []byte
}

type EventEnvelope struct {
	Namespace  string
	RunID      string
	Sequence   int64
	RecordedAt time.Time
	Payload    []byte
}

type RunListOptions struct {
	Namespaces         []string
	Statuses           []string
	ExcludeStatuses    []string
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("execution store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create execution store directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open execution sqlite: %w", err)
	}
	if err := initSQLiteStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func initSQLiteStore(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("execution sqlite db is nil")
	}
	schema := `
	CREATE TABLE IF NOT EXISTS execution_runs (
		namespace TEXT NOT NULL,
		run_id TEXT NOT NULL,
		kind TEXT NOT NULL,
		status TEXT NOT NULL,
		stage TEXT NOT NULL,
		submitted_at TIMESTAMP NOT NULL,
		started_at TIMESTAMP,
		completed_at TIMESTAMP,
		updated_at TIMESTAMP NOT NULL,
		payload JSON NOT NULL,
		PRIMARY KEY (namespace, run_id)
	);
	CREATE INDEX IF NOT EXISTS idx_execution_runs_namespace_status_updated
		ON execution_runs(namespace, status, updated_at DESC);
	CREATE INDEX IF NOT EXISTS idx_execution_runs_namespace_submitted
		ON execution_runs(namespace, submitted_at DESC, run_id DESC);
	CREATE TABLE IF NOT EXISTS execution_events (
		namespace TEXT NOT NULL,
		run_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		recorded_at TIMESTAMP NOT NULL,
		payload JSON NOT NULL,
		PRIMARY KEY (namespace, run_id, sequence)
	);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return fmt.Errorf("init execution sqlite schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DB() *sql.DB {
	if s == nil {
		return nil
	}
	return s.db
}

func (s *SQLiteStore) UpsertRun(ctx context.Context, env RunEnvelope) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	env.Namespace = strings.TrimSpace(env.Namespace)
	env.RunID = strings.TrimSpace(env.RunID)
	if env.Namespace == "" || env.RunID == "" {
		return fmt.Errorf("execution run namespace and id are required")
	}
	env.Kind = strings.TrimSpace(env.Kind)
	env.Status = strings.TrimSpace(env.Status)
	env.Stage = strings.TrimSpace(env.Stage)
	env.SubmittedAt = env.SubmittedAt.UTC()
	env.UpdatedAt = env.UpdatedAt.UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO execution_runs (
			namespace, run_id, kind, status, stage, submitted_at, started_at, completed_at, updated_at, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, run_id) DO UPDATE SET
			kind = excluded.kind,
			status = excluded.status,
			stage = excluded.stage,
			submitted_at = excluded.submitted_at,
			started_at = excluded.started_at,
			completed_at = excluded.completed_at,
			updated_at = excluded.updated_at,
			payload = excluded.payload
	`, env.Namespace, env.RunID, env.Kind, env.Status, env.Stage, env.SubmittedAt, nullableTime(env.StartedAt), nullableTime(env.CompletedAt), env.UpdatedAt, env.Payload)
	if err != nil {
		return fmt.Errorf("persist execution run: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ReplaceRunWithEvents(ctx context.Context, env RunEnvelope, events []EventEnvelope) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	env.Namespace = strings.TrimSpace(env.Namespace)
	env.RunID = strings.TrimSpace(env.RunID)
	if env.Namespace == "" || env.RunID == "" {
		return fmt.Errorf("execution run namespace and id are required")
	}
	env.Kind = strings.TrimSpace(env.Kind)
	env.Status = strings.TrimSpace(env.Status)
	env.Stage = strings.TrimSpace(env.Stage)
	env.SubmittedAt = env.SubmittedAt.UTC()
	env.UpdatedAt = env.UpdatedAt.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin execution run replacement tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO execution_runs (
			namespace, run_id, kind, status, stage, submitted_at, started_at, completed_at, updated_at, payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(namespace, run_id) DO UPDATE SET
			kind = excluded.kind,
			status = excluded.status,
			stage = excluded.stage,
			submitted_at = excluded.submitted_at,
			started_at = excluded.started_at,
			completed_at = excluded.completed_at,
			updated_at = excluded.updated_at,
			payload = excluded.payload
	`, env.Namespace, env.RunID, env.Kind, env.Status, env.Stage, env.SubmittedAt, nullableTime(env.StartedAt), nullableTime(env.CompletedAt), env.UpdatedAt, env.Payload); err != nil {
		return fmt.Errorf("persist execution run: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM execution_events
		WHERE namespace = ? AND run_id = ?
	`, env.Namespace, env.RunID); err != nil {
		return fmt.Errorf("delete execution events: %w", err)
	}

	for index, event := range events {
		event.Namespace = strings.TrimSpace(event.Namespace)
		if event.Namespace == "" {
			event.Namespace = env.Namespace
		}
		event.RunID = strings.TrimSpace(event.RunID)
		if event.RunID == "" {
			event.RunID = env.RunID
		}
		if event.Namespace != env.Namespace || event.RunID != env.RunID {
			return fmt.Errorf("execution event namespace/run mismatch for %s/%s", event.Namespace, event.RunID)
		}
		if event.RecordedAt.IsZero() {
			event.RecordedAt = time.Now().UTC()
		} else {
			event.RecordedAt = event.RecordedAt.UTC()
		}
		if event.Sequence <= 0 {
			event.Sequence = int64(index + 1)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO execution_events (namespace, run_id, sequence, recorded_at, payload)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(namespace, run_id, sequence) DO UPDATE SET
				recorded_at = excluded.recorded_at,
				payload = excluded.payload
		`, event.Namespace, event.RunID, event.Sequence, event.RecordedAt, event.Payload); err != nil {
			return fmt.Errorf("persist execution event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit execution run replacement: %w", err)
	}
	return nil
}

func (s *SQLiteStore) LoadRun(ctx context.Context, namespace, runID string) (*RunEnvelope, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var env RunEnvelope
	var startedAt sql.NullTime
	var completedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT namespace, run_id, kind, status, stage, submitted_at, started_at, completed_at, updated_at, payload
		FROM execution_runs
		WHERE namespace = ? AND run_id = ?
	`, strings.TrimSpace(namespace), strings.TrimSpace(runID)).
		Scan(&env.Namespace, &env.RunID, &env.Kind, &env.Status, &env.Stage, &env.SubmittedAt, &startedAt, &completedAt, &env.UpdatedAt, &env.Payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load execution run: %w", err)
	}
	env.StartedAt = nullableTimeValue(startedAt)
	env.CompletedAt = nullableTimeValue(completedAt)
	return &env, nil
}

func (s *SQLiteStore) ListRuns(ctx context.Context, namespace string, opts RunListOptions) ([]RunEnvelope, error) {
	return s.listRunsWithNamespaces(ctx, []string{namespace}, opts)
}

func (s *SQLiteStore) ListAllRuns(ctx context.Context, opts RunListOptions) ([]RunEnvelope, error) {
	return s.listRunsWithNamespaces(ctx, opts.Namespaces, opts)
}

func (s *SQLiteStore) listRunsWithNamespaces(ctx context.Context, namespaces []string, opts RunListOptions) ([]RunEnvelope, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	query := `
		SELECT namespace, run_id, kind, status, stage, submitted_at, started_at, completed_at, updated_at, payload
		FROM execution_runs
		WHERE 1 = 1
	`
	args := make([]any, 0)
	namespaces = normalizeNamespaces(namespaces, opts.Namespaces)
	if len(namespaces) > 0 {
		placeholders := make([]string, 0, len(namespaces))
		for _, namespace := range namespaces {
			placeholders = append(placeholders, "?")
			args = append(args, namespace)
		}
		query += ` AND namespace IN (` + strings.Join(placeholders, ",") + `)` // #nosec G202 -- fixed placeholders; values remain parameterized.
	}
	if len(opts.Statuses) > 0 {
		placeholders := make([]string, 0, len(opts.Statuses))
		for _, status := range opts.Statuses {
			placeholders = append(placeholders, "?")
			args = append(args, strings.TrimSpace(status))
		}
		query += ` AND status IN (` + strings.Join(placeholders, ",") + `)` // #nosec G202 -- fixed placeholders; values remain parameterized.
	}
	if len(opts.ExcludeStatuses) > 0 {
		placeholders := make([]string, 0, len(opts.ExcludeStatuses))
		for _, status := range opts.ExcludeStatuses {
			placeholders = append(placeholders, "?")
			args = append(args, strings.TrimSpace(status))
		}
		query += ` AND status NOT IN (` + strings.Join(placeholders, ",") + `)` // #nosec G202 -- fixed placeholders; values remain parameterized.
	}
	if opts.OrderBySubmittedAt {
		query += ` ORDER BY submitted_at DESC, run_id DESC`
	} else {
		query += ` ORDER BY updated_at DESC, run_id DESC`
	}
	if opts.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		if opts.Limit <= 0 {
			query += ` LIMIT -1`
		}
		query += ` OFFSET ?`
		args = append(args, opts.Offset)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query execution runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	runs := make([]RunEnvelope, 0)
	for rows.Next() {
		var env RunEnvelope
		var startedAt sql.NullTime
		var completedAt sql.NullTime
		if err := rows.Scan(&env.Namespace, &env.RunID, &env.Kind, &env.Status, &env.Stage, &env.SubmittedAt, &startedAt, &completedAt, &env.UpdatedAt, &env.Payload); err != nil {
			return nil, fmt.Errorf("scan execution run: %w", err)
		}
		env.StartedAt = nullableTimeValue(startedAt)
		env.CompletedAt = nullableTimeValue(completedAt)
		runs = append(runs, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate execution runs: %w", err)
	}
	return runs, nil
}

func (s *SQLiteStore) DeleteRun(ctx context.Context, namespace, runID string) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	runID = strings.TrimSpace(runID)
	if namespace == "" || runID == "" {
		return fmt.Errorf("execution run namespace and id are required")
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM execution_runs
		WHERE namespace = ? AND run_id = ?
	`, namespace, runID); err != nil {
		return fmt.Errorf("delete execution run: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteEvents(ctx context.Context, namespace, runID string) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	namespace = strings.TrimSpace(namespace)
	runID = strings.TrimSpace(runID)
	if namespace == "" || runID == "" {
		return fmt.Errorf("execution event namespace and run id are required")
	}
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM execution_events
		WHERE namespace = ? AND run_id = ?
	`, namespace, runID); err != nil {
		return fmt.Errorf("delete execution events: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SaveEvent(ctx context.Context, env EventEnvelope) (EventEnvelope, error) {
	if s == nil || s.db == nil {
		return env, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	env.Namespace = strings.TrimSpace(env.Namespace)
	env.RunID = strings.TrimSpace(env.RunID)
	if env.Namespace == "" || env.RunID == "" {
		return env, fmt.Errorf("execution event namespace and run id are required")
	}
	if env.RecordedAt.IsZero() {
		env.RecordedAt = time.Now().UTC()
	} else {
		env.RecordedAt = env.RecordedAt.UTC()
	}
	if env.Sequence <= 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return env, fmt.Errorf("begin execution event tx: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(sequence), 0) + 1
			FROM execution_events
			WHERE namespace = ? AND run_id = ?
		`, env.Namespace, env.RunID).Scan(&env.Sequence); err != nil {
			return env, fmt.Errorf("allocate execution event sequence: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO execution_events (namespace, run_id, sequence, recorded_at, payload)
			VALUES (?, ?, ?, ?, ?)
		`, env.Namespace, env.RunID, env.Sequence, env.RecordedAt, env.Payload); err != nil {
			return env, fmt.Errorf("persist execution event: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return env, fmt.Errorf("commit execution event: %w", err)
		}
		return env, nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO execution_events (namespace, run_id, sequence, recorded_at, payload)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(namespace, run_id, sequence) DO UPDATE SET
			recorded_at = excluded.recorded_at,
			payload = excluded.payload
	`, env.Namespace, env.RunID, env.Sequence, env.RecordedAt, env.Payload)
	if err != nil {
		return env, fmt.Errorf("persist execution event: %w", err)
	}
	return env, nil
}

func (s *SQLiteStore) LoadEvents(ctx context.Context, namespace, runID string) ([]EventEnvelope, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT namespace, run_id, sequence, recorded_at, payload
		FROM execution_events
		WHERE namespace = ? AND run_id = ?
		ORDER BY sequence ASC
	`, strings.TrimSpace(namespace), strings.TrimSpace(runID))
	if err != nil {
		return nil, fmt.Errorf("query execution events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]EventEnvelope, 0)
	for rows.Next() {
		var env EventEnvelope
		if err := rows.Scan(&env.Namespace, &env.RunID, &env.Sequence, &env.RecordedAt, &env.Payload); err != nil {
			return nil, fmt.Errorf("scan execution event: %w", err)
		}
		events = append(events, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate execution events: %w", err)
	}
	return events, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullableTimeValue(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	ts := value.Time.UTC()
	return &ts
}

func normalizeNamespaces(primary []string, secondary []string) []string {
	values := append(append([]string(nil), primary...), secondary...)
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
