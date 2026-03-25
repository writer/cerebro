package agents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// PostgresSessionStore persists agent sessions to PostgreSQL.
type PostgresSessionStore struct {
	db       *sql.DB
	tableRef string
}

// NewPostgresSessionStore creates a new Postgres-backed session store.
// The schema parameter should be a simple schema name (e.g. "cerebro").
func NewPostgresSessionStore(db *sql.DB, schema string) (*PostgresSessionStore, error) {
	tableRef := "agent_sessions"
	if schema != "" {
		tableRef = schema + ".agent_sessions"
	}

	store := &PostgresSessionStore{
		db:       db,
		tableRef: tableRef,
	}

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS ` + store.tableRef + ` (
			id TEXT PRIMARY KEY,
			agent_id TEXT,
			user_id TEXT,
			status TEXT,
			messages JSONB,
			context JSONB,
			created_at TIMESTAMP,
			updated_at TIMESTAMP
		)
	`

	if _, err := store.db.ExecContext(context.Background(), createTableQuery); err != nil {
		return nil, err
	}

	return store, nil
}

// Save persists a session to Postgres using INSERT ON CONFLICT.
func (s *PostgresSessionStore) Save(ctx context.Context, session *Session) error {
	messagesJSON, err := json.Marshal(session.Messages)
	if err != nil {
		return err
	}
	if len(messagesJSON) == 0 {
		messagesJSON = []byte("[]")
	}

	contextJSON, err := json.Marshal(session.Context)
	if err != nil {
		return err
	}
	if len(contextJSON) == 0 {
		contextJSON = []byte("{}")
	}

	query := `
		INSERT INTO ` + s.tableRef + ` (
			id, agent_id, user_id, status, messages, context, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			agent_id = EXCLUDED.agent_id,
			user_id = EXCLUDED.user_id,
			status = EXCLUDED.status,
			messages = EXCLUDED.messages,
			context = EXCLUDED.context,
			updated_at = EXCLUDED.updated_at
	`

	_, err = s.db.ExecContext(ctx, query,
		session.ID,
		session.AgentID,
		session.UserID,
		session.Status,
		string(messagesJSON),
		string(contextJSON),
		session.CreatedAt.UTC(),
		session.UpdatedAt.UTC(),
	)

	return err
}

// Get retrieves a session by ID from Postgres.
func (s *PostgresSessionStore) Get(ctx context.Context, id string) (*Session, error) {
	query := `
		SELECT id, agent_id, user_id, status, messages, context, created_at, updated_at
		FROM ` + s.tableRef + `
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	var session Session
	var messagesRaw []byte
	var contextRaw []byte
	var createdAt time.Time
	var updatedAt time.Time

	err := row.Scan(
		&session.ID,
		&session.AgentID,
		&session.UserID,
		&session.Status,
		&messagesRaw,
		&contextRaw,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if len(messagesRaw) > 0 {
		if err := json.Unmarshal(messagesRaw, &session.Messages); err != nil {
			return nil, err
		}
	}
	if len(contextRaw) > 0 {
		if err := json.Unmarshal(contextRaw, &session.Context); err != nil {
			return nil, err
		}
	}

	session.CreatedAt = createdAt.UTC()
	session.UpdatedAt = updatedAt.UTC()

	return &session, nil
}
