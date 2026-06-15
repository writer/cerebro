package ports

import (
	"context"
	"errors"
	"time"
)

// ErrConnectorCredentialNotFound indicates that a stored connector credential does not exist.
var ErrConnectorCredentialNotFound = errors.New("connector credential not found")

// ConnectorCredentialRecord stores one encrypted connector credential envelope.
type ConnectorCredentialRecord struct {
	ID        string
	TenantID  string
	SourceID  string
	RuntimeID string
	KeyID     string
	Sealed    []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ConnectorCredentialStore persists encrypted connector credentials.
type ConnectorCredentialStore interface {
	StateStore
	PutConnectorCredential(context.Context, *ConnectorCredentialRecord) error
	GetConnectorCredential(context.Context, string) (*ConnectorCredentialRecord, error)
}
