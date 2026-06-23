package connectordefinitionrecords

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

func FromRecord(record *ports.ConnectorDefinitionRecord) (connectordefinitions.Definition, error) {
	if record == nil {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: definition record is required", connectorcredentials.ErrInvalidRequest)
	}
	definition := connectordefinitions.Definition{}
	if err := json.Unmarshal(record.DefinitionJSON, &definition); err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("decode connector definition %q: %w", record.ID, err)
	}
	definition.ID = record.ID
	definition.TenantID = record.TenantID
	definition.SourceID = record.SourceID
	definition.DisplayName = record.DisplayName
	definition.Runtime = record.Runtime
	definition.Stage = record.Stage
	definition.CurrentVersion = record.CurrentVersion
	if !record.CreatedAt.IsZero() {
		definition.CreatedAt = record.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !record.UpdatedAt.IsZero() {
		definition.UpdatedAt = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("normalize connector definition %q: %w", record.ID, err)
	}
	normalized.CurrentVersion = record.CurrentVersion
	normalized.CreatedAt = definition.CreatedAt
	normalized.UpdatedAt = definition.UpdatedAt
	return normalized, nil
}

func FromVersionRecord(version *ports.ConnectorDefinitionVersionRecord) (connectordefinitions.Definition, error) {
	if version == nil {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: definition version record is required", connectorcredentials.ErrInvalidRequest)
	}
	definition := connectordefinitions.Definition{}
	if err := json.Unmarshal(version.DefinitionJSON, &definition); err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("decode connector definition version %q/%d: %w", version.DefinitionID, version.Version, err)
	}
	definition.ID = version.DefinitionID
	definition.TenantID = version.TenantID
	definition.SourceID = version.SourceID
	definition.Stage = version.Stage
	definition.CurrentVersion = version.Version
	if !version.CreatedAt.IsZero() {
		definition.CreatedAt = version.CreatedAt.UTC().Format(time.RFC3339)
	}
	normalized, err := connectordefinitions.Normalize(definition)
	if err != nil {
		return connectordefinitions.Definition{}, fmt.Errorf("normalize connector definition version %q/%d: %w", version.DefinitionID, version.Version, err)
	}
	normalized.CurrentVersion = version.Version
	normalized.CreatedAt = definition.CreatedAt
	return normalized, nil
}
