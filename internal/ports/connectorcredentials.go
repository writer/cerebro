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
	ID                   string
	TenantID             string
	SourceID             string
	RuntimeID            string
	CredentialStoreID    string
	AuthMethod           string
	Status               string
	KeyID                string
	Fields               []string
	Sealed               []byte
	CreatedBy            string
	UpdatedBy            string
	RevokedBy            string
	PreviousCredentialID string
	IdempotencyKey       string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RevokedAt            time.Time
	LastUsedAt           time.Time
	LastValidatedAt      time.Time
}

// ConnectorCredentialFilter scopes connector credential metadata queries.
type ConnectorCredentialFilter struct {
	ID             string
	TenantID       string
	SourceID       string
	RuntimeID      string
	Status         string
	IdempotencyKey string
	Limit          int
}

// ConnectorCredentialMetadataUpdate describes non-secret credential metadata updates.
type ConnectorCredentialMetadataUpdate struct {
	Status               string
	Fields               []string
	UpdatedBy            string
	RevokedBy            string
	PreviousCredentialID string
	RevokedAt            *time.Time
	LastUsedAt           *time.Time
	LastValidatedAt      *time.Time
}

// ConnectorCredentialAuditRecord records one credential broker lifecycle event.
type ConnectorCredentialAuditRecord struct {
	ID           string
	CredentialID string
	TenantID     string
	SourceID     string
	RuntimeID    string
	EventType    string
	Actor        string
	Status       string
	Detail       string
	CreatedAt    time.Time
}

// ConnectorCredentialStore persists encrypted connector credentials.
type ConnectorCredentialStore interface {
	StateStore
	PutConnectorCredential(context.Context, *ConnectorCredentialRecord) error
	GetConnectorCredential(context.Context, string) (*ConnectorCredentialRecord, error)
	ListConnectorCredentials(context.Context, ConnectorCredentialFilter) ([]*ConnectorCredentialRecord, error)
	UpdateConnectorCredentialMetadata(context.Context, string, ConnectorCredentialMetadataUpdate) (*ConnectorCredentialRecord, error)
	MarkConnectorCredentialUsed(context.Context, string, time.Time, time.Time) (*ConnectorCredentialRecord, bool, error)
	AppendConnectorCredentialAuditEvent(context.Context, *ConnectorCredentialAuditRecord) error
	ListConnectorCredentialAuditEvents(context.Context, string, int) ([]*ConnectorCredentialAuditRecord, error)
}
