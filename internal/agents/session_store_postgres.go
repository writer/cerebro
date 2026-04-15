package agents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const postgresSessionTable = "cerebro_agent_sessions"

type PostgresSessionStore struct {
	db         *sql.DB
	rewriteSQL func(string) string
}

func NewPostgresSessionStore(db *sql.DB) *PostgresSessionStore {
	return &PostgresSessionStore{db: db}
}

func (s *PostgresSessionStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres session store is not initialized")
	}
	_, err := s.db.ExecContext(ctx, s.q(`
CREATE TABLE IF NOT EXISTS `+postgresSessionTable+` (
	id TEXT PRIMARY KEY,
	agent_id TEXT NOT NULL,
	user_id TEXT NOT NULL,
	status TEXT NOT NULL,
	messages TEXT NOT NULL DEFAULT '[]',
	context TEXT NOT NULL DEFAULT '{}',
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_`+postgresSessionTable+`_updated_at ON `+postgresSessionTable+` (updated_at);
`))
	return err
}

func (s *PostgresSessionStore) Save(ctx context.Context, session *Session) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres session store is not initialized")
	}
	if session == nil {
		return fmt.Errorf("session is required")
	}
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	messagesJSON, contextJSON, createdAt, updatedAt, err := prepareSessionRow(session)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, s.q(`
INSERT INTO `+postgresSessionTable+` (
	id, agent_id, user_id, status, messages, context, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
	agent_id = EXCLUDED.agent_id,
	user_id = EXCLUDED.user_id,
	status = EXCLUDED.status,
	messages = EXCLUDED.messages,
	context = EXCLUDED.context,
	updated_at = EXCLUDED.updated_at
`),
		session.ID,
		session.AgentID,
		session.UserID,
		session.Status,
		string(messagesJSON),
		string(contextJSON),
		createdAt,
		updatedAt,
	)
	return err
}

func (s *PostgresSessionStore) ImportMissing(ctx context.Context, sessions []*Session) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres session store is not initialized")
	}
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}
	for _, session := range sessions {
		if session == nil {
			continue
		}
		messagesJSON, contextJSON, createdAt, updatedAt, err := prepareSessionRow(session)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO `+postgresSessionTable+` (
	id, agent_id, user_id, status, messages, context, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING
`),
			session.ID,
			session.AgentID,
			session.UserID,
			session.Status,
			string(messagesJSON),
			string(contextJSON),
			createdAt,
			updatedAt,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresSessionStore) Get(ctx context.Context, id string) (*Session, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres session store is not initialized")
	}
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, err
	}

	var session Session
	var messagesRaw string
	var contextRaw string

	err := s.db.QueryRowContext(ctx, s.q(`
SELECT id, agent_id, user_id, status, messages, context, created_at, updated_at
FROM `+postgresSessionTable+`
WHERE id = $1
`), id).Scan(
		&session.ID,
		&session.AgentID,
		&session.UserID,
		&session.Status,
		&messagesRaw,
		&contextRaw,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
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

	session.CreatedAt = session.CreatedAt.UTC()
	session.UpdatedAt = session.UpdatedAt.UTC()
	return &session, nil
}

func (s *PostgresSessionStore) q(query string) string {
	if s != nil && s.rewriteSQL != nil {
		return s.rewriteSQL(query)
	}
	return query
}

func prepareSessionRow(session *Session) ([]byte, []byte, time.Time, time.Time, error) {
	messagesJSON, err := json.Marshal(session.Messages)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	if len(messagesJSON) == 0 {
		messagesJSON = []byte("[]")
	}

	contextJSON, err := json.Marshal(session.Context)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	if len(contextJSON) == 0 {
		contextJSON = []byte("{}")
	}

	createdAt := session.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		session.CreatedAt = createdAt
	}
	updatedAt := session.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = createdAt
		session.UpdatedAt = updatedAt
	}

	return messagesJSON, contextJSON, createdAt, updatedAt, nil
}

var _ SessionStore = (*PostgresSessionStore)(nil)
