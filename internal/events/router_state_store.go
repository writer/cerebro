package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/webhooks"
)

type AlertRouterStateStore interface {
	Load(ctx context.Context) (alertRouterStateSnapshot, error)
	Save(ctx context.Context, state alertRouterStateSnapshot) error
	Close() error
}

type SQLiteAlertRouterStateStore struct {
	db *sql.DB
}

type alertRouterStateSnapshot struct {
	Revision      uint64                       `json:"revision,omitempty"`
	ThrottleUntil map[string]time.Time         `json:"throttle_until,omitempty"`
	DigestBuckets map[string]digestBucketState `json:"digest_buckets,omitempty"`
	PendingAcks   map[string]pendingAckState   `json:"pending_acks,omitempty"`
}

type digestBucketState struct {
	Key       string           `json:"key"`
	RouteID   string           `json:"route_id"`
	Recipient AlertRecipient   `json:"recipient"`
	GroupKey  string           `json:"group_key"`
	FirstSeen time.Time        `json:"first_seen"`
	DueAt     time.Time        `json:"due_at"`
	Events    []webhooks.Event `json:"events"`
}

type pendingAckState struct {
	Key       string         `json:"key"`
	AlertID   string         `json:"alert_id"`
	RouteID   string         `json:"route_id"`
	Event     webhooks.Event `json:"event"`
	EntityID  string         `json:"entity_id"`
	GroupKey  string         `json:"group_key"`
	Recipient AlertRecipient `json:"recipient"`
	Deadline  time.Time      `json:"deadline"`
}

func NewSQLiteAlertRouterStateStore(path string) (*SQLiteAlertRouterStateStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("alert router state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create alert router state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open alert router state db: %w", err)
	}
	schema := `
	CREATE TABLE IF NOT EXISTS alert_router_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		revision INTEGER NOT NULL DEFAULT 0,
		payload JSON NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init alert router state schema: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), "ALTER TABLE alert_router_state ADD COLUMN revision INTEGER NOT NULL DEFAULT 0"); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("migrate alert router state schema: %w", err)
	}
	return &SQLiteAlertRouterStateStore{db: db}, nil
}

func (s *SQLiteAlertRouterStateStore) Load(ctx context.Context) (alertRouterStateSnapshot, error) {
	if s == nil || s.db == nil {
		return alertRouterStateSnapshot{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var payload []byte
	var revision uint64
	err := s.db.QueryRowContext(ctx, "SELECT revision, payload FROM alert_router_state WHERE id = 1").Scan(&revision, &payload)
	if err == sql.ErrNoRows {
		return alertRouterStateSnapshot{}, nil
	}
	if err != nil {
		return alertRouterStateSnapshot{}, fmt.Errorf("load alert router state: %w", err)
	}
	if len(payload) == 0 {
		return alertRouterStateSnapshot{}, nil
	}
	var snapshot alertRouterStateSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return alertRouterStateSnapshot{}, fmt.Errorf("decode alert router state: %w", err)
	}
	if snapshot.Revision == 0 {
		snapshot.Revision = revision
	}
	return snapshot, nil
}

func (s *SQLiteAlertRouterStateStore) Save(ctx context.Context, state alertRouterStateSnapshot) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode alert router state: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO alert_router_state (id, revision, payload, updated_at)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			revision = excluded.revision,
			payload = excluded.payload,
			updated_at = excluded.updated_at
		WHERE excluded.revision >= alert_router_state.revision
	`, state.Revision, payload, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("persist alert router state: %w", err)
	}
	return nil
}

func (s *SQLiteAlertRouterStateStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
