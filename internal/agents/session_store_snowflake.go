package agents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
)

type SnowflakeSessionStore struct {
	db       *sql.DB
	tableRef string
}

func NewSnowflakeSessionStore(client *snowflake.Client) (*SnowflakeSessionStore, error) {
	tableRef, err := snowflake.SafeTableRef(client.Database(), client.AppSchema(), "agent_sessions")
	if err != nil {
		return nil, err
	}

	store := &SnowflakeSessionStore{
		db:       client.DB(),
		tableRef: tableRef,
	}

	// #nosec G202 -- store.tableRef is validated by snowflake.SafeTableRef before interpolation.
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS ` + store.tableRef + ` (
			id STRING,
			agent_id STRING,
			user_id STRING,
			status STRING,
			messages VARIANT,
			context VARIANT,
			created_at TIMESTAMP_NTZ,
			updated_at TIMESTAMP_NTZ,
			PRIMARY KEY (id)
		)
	`

	if _, err = store.db.ExecContext(context.Background(), createTableQuery); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *SnowflakeSessionStore) Save(ctx context.Context, session *Session) error {
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

	// #nosec G202 -- s.tableRef is validated by snowflake.SafeTableRef before interpolation.
	query := `
		MERGE INTO ` + s.tableRef + ` t
		USING (SELECT ? AS id) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			agent_id = ?,
			user_id = ?,
			status = ?,
			messages = PARSE_JSON(?),
			context = PARSE_JSON(?),
			updated_at = ?
		WHEN NOT MATCHED THEN INSERT (
			id, agent_id, user_id, status, messages, context, created_at, updated_at
		) VALUES (?, ?, ?, ?, PARSE_JSON(?), PARSE_JSON(?), ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		session.ID,
		session.AgentID,
		session.UserID,
		session.Status,
		string(messagesJSON),
		string(contextJSON),
		session.UpdatedAt.UTC(),
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

func (s *SnowflakeSessionStore) Get(ctx context.Context, id string) (*Session, error) {
	// #nosec G202 -- s.tableRef is validated by snowflake.SafeTableRef before interpolation.
	query := `
		SELECT id, agent_id, user_id, status, messages, context, created_at, updated_at
		FROM ` + s.tableRef + `
		WHERE id = ?
	`

	row := s.db.QueryRowContext(ctx, query, id)

	var session Session
	var messagesRaw any
	var contextRaw any
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

	if messagesJSON := normalizeVariantJSON(messagesRaw); len(messagesJSON) > 0 {
		if err := json.Unmarshal(messagesJSON, &session.Messages); err != nil {
			return nil, err
		}
	}
	if contextJSON := normalizeVariantJSON(contextRaw); len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &session.Context); err != nil {
			return nil, err
		}
	}

	session.CreatedAt = createdAt.UTC()
	session.UpdatedAt = updatedAt.UTC()

	return &session, nil
}

func normalizeVariantJSON(raw any) []byte {
	switch v := raw.(type) {
	case nil:
		return nil
	case []byte:
		trimmed := strings.TrimSpace(string(v))
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return encoded
	}
}
