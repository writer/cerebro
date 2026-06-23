package ports

import (
	"context"
	"errors"
	"time"
)

// ErrConnectorDefinitionNotFound indicates that a stored connector definition does not exist.
var ErrConnectorDefinitionNotFound = errors.New("connector definition not found")

// ConnectorDefinitionRecord stores the current version of a dynamic connector definition.
type ConnectorDefinitionRecord struct {
	ID             string
	TenantID       string
	SourceID       string
	DisplayName    string
	Runtime        string
	Stage          string
	CurrentVersion int
	DefinitionJSON []byte
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ConnectorDefinitionVersionRecord stores one immutable connector definition version.
type ConnectorDefinitionVersionRecord struct {
	DefinitionID   string
	Version        int
	TenantID       string
	SourceID       string
	Stage          string
	DefinitionJSON []byte
	CreatedAt      time.Time
}

// ConnectorDefinitionFilter scopes persisted connector definition listing.
type ConnectorDefinitionFilter struct {
	TenantID string
	Stage    string
	Limit    uint32
}

// ConnectorDefinitionStore persists dynamic connector definitions and versions.
type ConnectorDefinitionStore interface {
	StateStore
	PutConnectorDefinition(context.Context, *ConnectorDefinitionRecord) (*ConnectorDefinitionRecord, error)
	GetConnectorDefinition(context.Context, string) (*ConnectorDefinitionRecord, error)
	ListConnectorDefinitions(context.Context, ConnectorDefinitionFilter) ([]*ConnectorDefinitionRecord, error)
	ListConnectorDefinitionVersions(context.Context, string) ([]*ConnectorDefinitionVersionRecord, error)
}
