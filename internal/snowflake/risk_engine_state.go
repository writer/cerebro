package snowflake

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// RiskEngineStateRepository persists durable graph risk-engine snapshots.
type RiskEngineStateRepository struct {
	client *Client
	schema string
}

func NewRiskEngineStateRepository(client *Client) *RiskEngineStateRepository {
	return &RiskEngineStateRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

func (r *RiskEngineStateRepository) SaveSnapshot(ctx context.Context, graphID string, snapshot []byte) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return fmt.Errorf("graph id is required")
	}
	if len(snapshot) == 0 {
		snapshot = []byte("{}")
	}

	tableRef, err := r.tableRef()
	if err != nil {
		return err
	}
	if err := r.ensureTable(ctx, tableRef); err != nil {
		return err
	}

	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `
		MERGE INTO ` + tableRef + ` t
		USING (SELECT ? AS graph_id) s
		ON t.graph_id = s.graph_id
		WHEN MATCHED THEN UPDATE SET
			snapshot = PARSE_JSON(?),
			updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (
			graph_id, snapshot, updated_at
		) VALUES (?, PARSE_JSON(?), CURRENT_TIMESTAMP())
	`

	_, err = r.client.db.ExecContext(ctx, query, graphID, string(snapshot), graphID, string(snapshot))
	return err
}

func (r *RiskEngineStateRepository) LoadSnapshot(ctx context.Context, graphID string) ([]byte, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return nil, fmt.Errorf("graph id is required")
	}

	tableRef, err := r.tableRef()
	if err != nil {
		return nil, err
	}
	if err := r.ensureTable(ctx, tableRef); err != nil {
		return nil, err
	}

	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `SELECT snapshot FROM ` + tableRef + ` WHERE graph_id = ?`
	row := r.client.db.QueryRowContext(ctx, query, graphID)
	var raw any
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	normalized := normalizeVariantJSONForState(raw)
	if len(normalized) == 0 || string(normalized) == "null" {
		return nil, nil
	}
	return normalized, nil
}

func (r *RiskEngineStateRepository) tableRef() (string, error) {
	ref, err := SafeQualifiedTableRef(r.schema, "risk_engine_state")
	if err != nil {
		return "", fmt.Errorf("invalid risk_engine_state table reference: %w", err)
	}
	return ref, nil
}

func (r *RiskEngineStateRepository) ensureTable(ctx context.Context, tableRef string) error {
	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `
		CREATE TABLE IF NOT EXISTS ` + tableRef + ` (
			graph_id VARCHAR(128) PRIMARY KEY,
			snapshot VARIANT,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)
	`
	_, err := r.client.db.ExecContext(ctx, query)
	return err
}

func normalizeVariantJSONForState(raw any) []byte {
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
