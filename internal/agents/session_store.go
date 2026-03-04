package agents

import "context"

// SessionStore persists agent sessions beyond process memory.
type SessionStore interface {
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}
