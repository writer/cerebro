package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agents"
	appsubstate "github.com/writer/cerebro/internal/app/appstate"
	staterepo "github.com/writer/cerebro/internal/appstate"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/snowflake"
)

const appStateRiskEngineGraphID = "security-graph"

const (
	appStateMigrationStateTable          = "cerebro_app_state_migrations"
	legacySnowflakeAppStateMigrationName = "legacy_snowflake"
	legacySnowflakeAppStateStartedName   = "legacy_snowflake_started"
)

func (a *App) appStateMigrationSnowflake() *snowflake.Client {
	if a == nil {
		return nil
	}
	if a.LegacySnowflake != nil {
		return a.LegacySnowflake
	}
	return a.Snowflake
}

func (a *App) appStateDatabaseURL() string {
	if a == nil || a.Config == nil {
		return ""
	}
	return appsubstate.DatabaseURL(a.Config.JobDatabaseURL, a.Config.WarehouseBackend, a.Config.WarehousePostgresDSN)
}

func (a *App) appStateRuntime() *appsubstate.Runtime {
	if a == nil {
		return nil
	}
	if a.AppState == nil {
		a.AppState = appsubstate.NewRuntime()
	}
	return a.AppState
}

func (a *App) appStateDB() *sql.DB {
	if a == nil || a.AppState == nil {
		return nil
	}
	return a.AppState.DB()
}

func (a *App) setAppStateDB(db *sql.DB) {
	if a == nil {
		return
	}
	a.appStateRuntime().SetDB(db)
}

func (a *App) initAppStateDB(ctx context.Context) error {
	dsn := a.appStateDatabaseURL()
	runtime := a.appStateRuntime()
	if runtime == nil {
		return fmt.Errorf("appstate runtime is nil")
	}
	if dsn == "" {
		return nil
	}
	return runtime.Init(ctx, dsn,
		func(ctx context.Context, db *sql.DB) error { return findings.NewPostgresStore(db).EnsureSchema(ctx) },
		func(ctx context.Context, db *sql.DB) error {
			return agents.NewPostgresSessionStore(db).EnsureSchema(ctx)
		},
		func(ctx context.Context, db *sql.DB) error { return staterepo.NewAuditRepository(db).EnsureSchema(ctx) },
		func(ctx context.Context, db *sql.DB) error {
			return staterepo.NewPolicyHistoryRepository(db).EnsureSchema(ctx)
		},
		func(ctx context.Context, db *sql.DB) error {
			return staterepo.NewRiskEngineStateRepository(db).EnsureSchema(ctx)
		},
		func(ctx context.Context, db *sql.DB) error {
			return ensureAppStateMigrationStateSchema(ctx, db)
		},
	)
}

func (a *App) migrateAppState(ctx context.Context) error {
	if a == nil || a.appStateDB() == nil {
		return nil
	}
	if a.appStateMigrationSnowflake() != nil {
		if err := a.markAppStateMigrationComplete(ctx, legacySnowflakeAppStateStartedName); err != nil {
			return fmt.Errorf("mark app-state migration started: %w", err)
		}
	}
	if err := a.migrateFindings(ctx); err != nil {
		return err
	}
	if err := a.migrateAgentSessions(ctx); err != nil {
		return err
	}
	if err := a.migrateAuditLogs(ctx); err != nil {
		return err
	}
	if err := a.migratePolicyHistory(ctx); err != nil {
		return err
	}
	if err := a.migrateRiskEngineState(ctx); err != nil {
		return err
	}
	if a.appStateMigrationSnowflake() != nil {
		if err := a.markAppStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName); err != nil {
			return fmt.Errorf("mark app-state migration complete: %w", err)
		}
	}
	return nil
}

func ensureAppStateMigrationStateSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS `+appStateMigrationStateTable+` (
	migration_name TEXT PRIMARY KEY,
	completed_at TIMESTAMP NOT NULL
)`)
	return err
}

func (a *App) appStateMigrationComplete(ctx context.Context, migrationName string) (bool, error) {
	db := a.appStateDB()
	if a == nil || db == nil {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureAppStateMigrationStateSchema(ctx, db); err != nil {
		return false, err
	}

	var completedAt time.Time
	err := db.QueryRowContext(ctx, `
SELECT completed_at
FROM `+appStateMigrationStateTable+`
WHERE migration_name = $1
`, migrationName).Scan(&completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !completedAt.IsZero(), nil
}

func (a *App) markAppStateMigrationComplete(ctx context.Context, migrationName string) error {
	db := a.appStateDB()
	if a == nil || db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureAppStateMigrationStateSchema(ctx, db); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO `+appStateMigrationStateTable+` (migration_name, completed_at)
VALUES ($1, $2)
ON CONFLICT (migration_name) DO UPDATE SET
	completed_at = EXCLUDED.completed_at
`, migrationName, time.Now().UTC())
	return err
}

func (a *App) migrateFindings(ctx context.Context) error {
	store, ok := a.Findings.(*findings.PostgresStore)
	if !ok {
		return nil
	}
	if err := a.migrateLegacyPostgresFindings(ctx, store); err != nil {
		return err
	}
	source := a.appStateMigrationSnowflake()
	if source == nil {
		return nil
	}
	records, err := snowflake.NewFindingRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("migrate findings from snowflake: %w", err)
	}
	return store.ImportRecords(ctx, records)
}

func (a *App) migrateAgentSessions(ctx context.Context) error {
	sourceClient := a.appStateMigrationSnowflake()
	if a.appStateDB() == nil || sourceClient == nil {
		return nil
	}
	source, err := agents.NewSnowflakeSessionStore(sourceClient)
	if err != nil {
		return fmt.Errorf("initialize snowflake session store: %w", err)
	}
	sessions, err := source.ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeColumnErr(err, "messages") {
			sessions, err = loadLegacySnowflakeAgentSessions(ctx, sourceClient)
		}
	}
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("list snowflake agent sessions: %w", err)
	}
	destination := agents.NewPostgresSessionStore(a.appStateDB())
	if err := destination.ImportMissing(ctx, sessions); err != nil {
		return fmt.Errorf("persist postgres agent sessions: %w", err)
	}
	return nil
}

func (a *App) migrateAuditLogs(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.AuditRepo == nil || source == nil {
		return nil
	}
	entries, err := snowflake.NewAuditRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("list snowflake audit logs: %w", err)
	}
	for _, entry := range entries {
		if err := a.AuditRepo.Log(ctx, entry); err != nil {
			return fmt.Errorf("persist audit log %s: %w", entry.ID, err)
		}
	}
	return nil
}

func (a *App) migratePolicyHistory(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.PolicyHistoryRepo == nil || source == nil {
		return nil
	}
	records, err := snowflake.NewPolicyHistoryRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("list snowflake policy history: %w", err)
	}
	for _, record := range records {
		if err := a.PolicyHistoryRepo.Upsert(ctx, record); err != nil {
			return fmt.Errorf("persist policy history %s@%d: %w", record.PolicyID, record.Version, err)
		}
	}
	return nil
}

func (a *App) migrateRiskEngineState(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.RiskEngineStateRepo == nil || source == nil {
		return nil
	}
	existing, err := a.RiskEngineStateRepo.LoadSnapshot(ctx, appStateRiskEngineGraphID)
	if err != nil {
		return fmt.Errorf("load postgres risk engine state: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	payload, err := snowflake.NewRiskEngineStateRepository(source).LoadSnapshot(ctx, appStateRiskEngineGraphID)
	if err != nil {
		return fmt.Errorf("load snowflake risk engine state: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if err := a.RiskEngineStateRepo.SaveSnapshot(ctx, appStateRiskEngineGraphID, payload); err != nil {
		return fmt.Errorf("persist postgres risk engine state: %w", err)
	}
	return nil
}

func isMissingSnowflakeTableErr(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "not authorized") {
		return false
	}
	return strings.Contains(message, "does not exist") ||
		strings.Contains(message, "unknown table") ||
		strings.Contains(message, "not exist")
}

var postgresIdentifierRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (a *App) migrateLegacyPostgresFindings(ctx context.Context, store *findings.PostgresStore) error {
	if a == nil || store == nil || a.Warehouse == nil || a.Warehouse.DB() == nil || a.Config == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(a.Config.WarehouseBackend), "postgres") {
		return nil
	}
	records, err := loadLegacyPostgresFindingRecords(ctx, a.Warehouse.DB(), a.appStateFindingsSchema())
	if err != nil {
		if isMissingPostgresRelationErr(err) {
			return nil
		}
		return fmt.Errorf("migrate legacy postgres findings: %w", err)
	}
	return store.ImportRecords(ctx, records)
}

func (a *App) appStateFindingsSchema() string {
	if a == nil || a.Warehouse == nil {
		return "cerebro"
	}
	schemaName := strings.TrimSpace(a.Warehouse.AppSchema())
	if schemaName == "" {
		schemaName = "cerebro"
	}
	return schemaName
}

func loadLegacyPostgresFindingRecords(ctx context.Context, db *sql.DB, schemaName string) ([]*snowflake.FindingRecord, error) {
	if db == nil {
		return nil, nil
	}
	tableRef, err := safePostgresTableRef(schemaName, "findings")
	if err != nil {
		return nil, err
	}
	// #nosec G202 -- tableRef is built from validated identifiers via safePostgresTableRef.
	rows, err := db.QueryContext(ctx, `
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, CAST(resource_data AS TEXT), description, remediation,
	   COALESCE(CAST(metadata AS TEXT), '{}'), first_seen, last_seen, resolved_at
FROM `+tableRef+`
ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	records := make([]*snowflake.FindingRecord, 0)
	for rows.Next() {
		record, scanErr := scanLegacyPostgresFindingRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if record != nil {
			records = append(records, record)
		}
	}
	return records, rows.Err()
}

func scanLegacyPostgresFindingRecord(row interface {
	Scan(dest ...any) error
}) (*snowflake.FindingRecord, error) {
	var record snowflake.FindingRecord
	var resourceData sql.NullString
	var remediation sql.NullString
	var metadata sql.NullString
	var resolvedAt sql.NullTime
	if err := row.Scan(
		&record.ID,
		&record.PolicyID,
		&record.PolicyName,
		&record.Severity,
		&record.Status,
		&record.ResourceID,
		&record.ResourceType,
		&resourceData,
		&record.Description,
		&remediation,
		&metadata,
		&record.FirstSeen,
		&record.LastSeen,
		&resolvedAt,
	); err != nil {
		return nil, err
	}
	if resourceData.Valid && strings.TrimSpace(resourceData.String) != "" {
		if err := json.Unmarshal([]byte(resourceData.String), &record.ResourceData); err != nil {
			return nil, fmt.Errorf("parse legacy postgres finding %s resource data: %w", record.ID, err)
		}
	}
	if metadata.Valid && strings.TrimSpace(metadata.String) != "" {
		record.Metadata = json.RawMessage(metadata.String)
	}
	if remediation.Valid {
		record.Remediation = remediation.String
	}
	if resolvedAt.Valid {
		ts := resolvedAt.Time.UTC()
		record.ResolvedAt = &ts
	}
	record.FirstSeen = record.FirstSeen.UTC()
	record.LastSeen = record.LastSeen.UTC()
	return &record, nil
}

func loadLegacySnowflakeAgentSessions(ctx context.Context, client *snowflake.Client) ([]*agents.Session, error) {
	if client == nil {
		return nil, nil
	}
	sessionTableRef, err := snowflake.SafeTableRef(client.Database(), client.AppSchema(), "agent_sessions")
	if err != nil {
		return nil, err
	}
	messageTableRef, err := snowflake.SafeTableRef(client.Database(), client.AppSchema(), "agent_messages")
	if err != nil {
		return nil, err
	}

	rows, err := client.DB().QueryContext(ctx, `
SELECT id, agent_id, user_id, status, context, created_at, updated_at
FROM `+sessionTableRef+`
ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	sessionsByID := make(map[string]*agents.Session)
	sessions := make([]*agents.Session, 0)
	for rows.Next() {
		var session agents.Session
		var userID sql.NullString
		var contextRaw any
		var createdAt time.Time
		var updatedAt time.Time
		if err := rows.Scan(
			&session.ID,
			&session.AgentID,
			&userID,
			&session.Status,
			&contextRaw,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		session.UserID = strings.TrimSpace(userID.String)
		if contextJSON := normalizeVariantJSON(contextRaw); len(contextJSON) > 0 {
			if err := json.Unmarshal(contextJSON, &session.Context); err != nil {
				return nil, fmt.Errorf("parse legacy snowflake agent session %s context: %w", session.ID, err)
			}
		}
		session.CreatedAt = createdAt.UTC()
		session.UpdatedAt = updatedAt.UTC()
		sessionsByID[session.ID] = &session
		sessions = append(sessions, &session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	messageRows, err := client.DB().QueryContext(ctx, `
SELECT session_id, role, content, tool_calls, metadata
FROM `+messageTableRef+`
ORDER BY created_at ASC`)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return sessions, nil
		}
		return nil, err
	}
	defer func() { _ = messageRows.Close() }()

	for messageRows.Next() {
		var sessionID string
		var role string
		var content sql.NullString
		var toolCallsRaw any
		var metadataRaw any
		if err := messageRows.Scan(&sessionID, &role, &content, &toolCallsRaw, &metadataRaw); err != nil {
			return nil, err
		}
		session := sessionsByID[sessionID]
		if session == nil {
			continue
		}
		message := agents.Message{
			Role:    role,
			Content: content.String,
		}
		if toolCallsJSON := normalizeVariantJSON(toolCallsRaw); len(toolCallsJSON) > 0 {
			if err := json.Unmarshal(toolCallsJSON, &message.ToolCalls); err != nil {
				return nil, fmt.Errorf("parse legacy snowflake agent session %s tool calls: %w", sessionID, err)
			}
		}
		if metadataJSON := normalizeVariantJSON(metadataRaw); len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &message.Metadata); err != nil {
				return nil, fmt.Errorf("parse legacy snowflake agent session %s metadata: %w", sessionID, err)
			}
		}
		session.Messages = append(session.Messages, message)
	}
	return sessions, messageRows.Err()
}

func normalizeVariantJSON(raw any) []byte {
	switch value := raw.(type) {
	case nil:
		return nil
	case []byte:
		trimmed := strings.TrimSpace(string(value))
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		return encoded
	}
}

func safePostgresTableRef(schemaName, tableName string) (string, error) {
	schemaName = strings.TrimSpace(schemaName)
	tableName = strings.TrimSpace(tableName)
	if !postgresIdentifierRe.MatchString(schemaName) {
		return "", fmt.Errorf("invalid postgres schema %q", schemaName)
	}
	if !postgresIdentifierRe.MatchString(tableName) {
		return "", fmt.Errorf("invalid postgres table %q", tableName)
	}
	return `"` + schemaName + `"."` + tableName + `"`, nil
}

func isMissingSnowflakeColumnErr(err error, columnName string) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	columnName = strings.ToLower(strings.TrimSpace(columnName))
	if columnName == "" {
		return false
	}
	return strings.Contains(message, columnName) &&
		(strings.Contains(message, "invalid identifier") ||
			strings.Contains(message, "unknown column") ||
			(strings.Contains(message, "column") && strings.Contains(message, "does not exist")))
}

func isMissingPostgresRelationErr(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "relation") && strings.Contains(message, "does not exist")
}
