package warehouse

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"github.com/writer/cerebro/internal/snowflake"
)

type PostgresWarehouseConfig struct {
	DSN       string
	Database  string
	Schema    string
	AppSchema string
}

// PostgresWarehouse provides a DataWarehouse backend for self-hosted deployments.
type PostgresWarehouse struct {
	db        *sql.DB
	dsn       string
	database  string
	schema    string
	appSchema string

	cdcMu    sync.Mutex
	cdcReady bool
}

func NewPostgresWarehouse(config PostgresWarehouseConfig) (*PostgresWarehouse, error) {
	dsn, err := PreparePostgresDSN(config.DSN)
	if err != nil {
		return nil, fmt.Errorf("prepare postgres warehouse dsn: %w", err)
	}
	if dsn == "" {
		return nil, fmt.Errorf("postgres warehouse dsn is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres warehouse: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	ctx, cancel := context.WithTimeout(context.Background(), defaultPostgresWarehousePingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres warehouse: %w", err)
	}

	databaseName := strings.TrimSpace(config.Database)
	if databaseName == "" {
		databaseName = postgresDatabaseNameFromDSN(dsn)
	}
	if databaseName == "" {
		databaseName = "postgres"
	}

	schemaName := strings.TrimSpace(config.Schema)
	if schemaName == "" {
		schemaName = "public"
	}

	appSchemaName := strings.TrimSpace(config.AppSchema)
	if appSchemaName == "" {
		appSchemaName = "cerebro"
	}

	return &PostgresWarehouse{
		db:        db,
		dsn:       dsn,
		database:  databaseName,
		schema:    schemaName,
		appSchema: appSchemaName,
	}, nil
}

const defaultPostgresWarehousePingTimeout = 3 * time.Second

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func PreparePostgresDSN(dsn string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return "", nil
	}

	connSettings, err := parsePostgresDSNSettings(dsn)
	if err != nil {
		return "", err
	}

	envSettings := postgresEnvSettings()
	serviceSettings, err := postgresServiceSettings(envSettings, connSettings)
	if err != nil {
		return "", err
	}

	finalSettings := make(map[string]string, len(serviceSettings)+len(connSettings)+1)
	for _, settings := range []map[string]string{serviceSettings, connSettings} {
		for key, value := range settings {
			finalSettings[key] = value
		}
	}
	delete(finalSettings, "service")
	delete(finalSettings, "servicefile")

	effectiveSettings := make(map[string]string, len(envSettings)+len(serviceSettings)+len(connSettings))
	for _, settings := range []map[string]string{envSettings, serviceSettings, connSettings} {
		for key, value := range settings {
			effectiveSettings[key] = value
		}
	}

	switch {
	case strings.EqualFold(strings.TrimSpace(effectiveSettings["sslrootcert"]), "system"):
		finalSettings["sslmode"] = "verify-full"
	case strings.TrimSpace(effectiveSettings["sslmode"]) == "":
		finalSettings["sslmode"] = "prefer"
	}

	return postgresKeywordDSNFromSettings(finalSettings), nil
}

func postgresDatabaseNameFromDSN(dsn string) string {
	settings, err := parsePostgresDSNSettings(dsn)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(settings["database"])
}

func postgresEnvSettings() map[string]string {
	settings := make(map[string]string)
	nameMap := map[string]string{
		"PGSERVICE":     "service",
		"PGSERVICEFILE": "servicefile",
		"PGSSLMODE":     "sslmode",
		"PGSSLROOTCERT": "sslrootcert",
	}

	for envName, key := range nameMap {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			settings[key] = value
		}
	}

	return settings
}

func postgresServiceSettings(envSettings, connSettings map[string]string) (map[string]string, error) {
	effectiveSettings := make(map[string]string, len(envSettings)+len(connSettings))
	for _, settings := range []map[string]string{envSettings, connSettings} {
		for key, value := range settings {
			effectiveSettings[key] = value
		}
	}

	serviceName := strings.TrimSpace(effectiveSettings["service"])
	if serviceName == "" {
		return nil, nil
	}

	serviceFilePath := strings.TrimSpace(effectiveSettings["servicefile"])
	if serviceFilePath == "" {
		serviceFilePath = defaultPostgresServiceFilePath()
	}

	return readPostgresServiceSettings(serviceFilePath, serviceName)
}

func defaultPostgresServiceFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".pg_service.conf")
}

func readPostgresServiceSettings(serviceFilePath, serviceName string) (map[string]string, error) {
	file, err := os.Open(serviceFilePath) // #nosec G304 -- servicefile is an operator-supplied PostgreSQL client config path
	if err != nil {
		return nil, fmt.Errorf("failed to read service file %q: %w", serviceFilePath, err)
	}
	defer func() { _ = file.Close() }()

	var (
		settings       = map[string]string{}
		currentService string
		scanner        = bufio.NewScanner(file)
		lineNumber     int
		found          bool
	)

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "", strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			currentService = strings.TrimSpace(line[1 : len(line)-1])
			if currentService == serviceName {
				found = true
				settings = map[string]string{}
			}
			continue
		case currentService == "":
			return nil, fmt.Errorf("line %d is not in a section in %q", lineNumber, serviceFilePath)
		default:
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("unable to parse line %d in %q", lineNumber, serviceFilePath)
			}
			if currentService != serviceName {
				continue
			}

			found = true
			key := strings.TrimSpace(parts[0])
			if key == "dbname" {
				key = "database"
			}
			settings[key] = strings.TrimSpace(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read postgres service file %q: %w", serviceFilePath, err)
	}
	if !found {
		return nil, fmt.Errorf("unable to find service %q in %q", serviceName, serviceFilePath)
	}

	return settings, nil
}

func parsePostgresDSNSettings(connString string) (map[string]string, error) {
	connString = strings.TrimSpace(connString)
	if connString == "" {
		return map[string]string{}, nil
	}

	if strings.HasPrefix(connString, "postgres://") || strings.HasPrefix(connString, "postgresql://") {
		return parsePostgresURLSettings(connString)
	}
	return parsePostgresKeywordValueSettings(connString)
}

func parsePostgresURLSettings(connString string) (map[string]string, error) {
	settings := make(map[string]string)

	parsedURL, err := url.Parse(connString)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, urlErr.Err
		}
		return nil, err
	}

	if parsedURL.User != nil {
		settings["user"] = parsedURL.User.Username()
		if password, ok := parsedURL.User.Password(); ok {
			settings["password"] = password
		}
	}

	var hosts []string
	var ports []string
	for _, host := range strings.Split(parsedURL.Host, ",") {
		if host == "" {
			continue
		}
		if isIPOnly(host) {
			hosts = append(hosts, strings.Trim(host, "[]"))
			continue
		}
		splitHost, splitPort, err := net.SplitHostPort(host)
		if err != nil {
			return nil, fmt.Errorf("failed to split host:port in %q: %w", host, err)
		}
		if splitHost != "" {
			hosts = append(hosts, splitHost)
		}
		if splitPort != "" {
			ports = append(ports, splitPort)
		}
	}
	if len(hosts) > 0 {
		settings["host"] = strings.Join(hosts, ",")
	}
	if len(ports) > 0 {
		settings["port"] = strings.Join(ports, ",")
	}

	if database := strings.TrimLeft(parsedURL.Path, "/"); database != "" {
		settings["database"] = database
	}

	for key, values := range parsedURL.Query() {
		if key == "dbname" {
			key = "database"
		}
		if len(values) > 0 {
			settings[key] = values[0]
		}
	}

	return settings, nil
}

func isIPOnly(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil || !strings.Contains(host, ":")
}

func parsePostgresKeywordValueSettings(s string) (map[string]string, error) {
	settings := make(map[string]string)

	for len(s) > 0 {
		eqIdx := strings.IndexRune(s, '=')
		if eqIdx < 0 {
			return nil, errors.New("invalid keyword/value")
		}

		key := strings.Trim(s[:eqIdx], " \t\n\r\v\f")
		s = strings.TrimLeft(s[eqIdx+1:], " \t\n\r\v\f")

		var value string
		if len(s) == 0 {
			value = ""
		} else if s[0] != '\'' {
			end := 0
			for ; end < len(s); end++ {
				if asciiSpace[s[end]] == 1 {
					break
				}
				if s[end] == '\\' {
					end++
					if end == len(s) {
						return nil, errors.New("invalid backslash")
					}
				}
			}

			value = strings.ReplaceAll(strings.ReplaceAll(s[:end], `\\`, `\`), `\'`, `'`)
			if end == len(s) {
				s = ""
			} else {
				s = s[end+1:]
			}
		} else {
			s = s[1:]
			end := 0
			for ; end < len(s); end++ {
				if s[end] == '\'' {
					break
				}
				if s[end] == '\\' {
					end++
				}
			}
			if end == len(s) {
				return nil, errors.New("unterminated quoted string in connection info string")
			}

			value = strings.ReplaceAll(strings.ReplaceAll(s[:end], `\\`, `\`), `\'`, `'`)
			if end == len(s) {
				s = ""
			} else {
				s = s[end+1:]
			}
		}

		if key == "dbname" {
			key = "database"
		}
		if key == "" {
			return nil, errors.New("invalid keyword/value")
		}
		settings[key] = value
		s = strings.TrimLeft(s, " \t\n\r\v\f")
	}

	return settings, nil
}

func postgresKeywordDSNFromSettings(settings map[string]string) string {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		outputKey := key
		if outputKey == "database" {
			outputKey = "dbname"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", outputKey, postgresKeywordValue(settings[key])))
	}
	return strings.Join(parts, " ")
}

func postgresKeywordValue(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\n\r\v\f'\\") {
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `'`, `\'`)
		return "'" + value + "'"
	}
	return value
}

func (w *PostgresWarehouse) Close() error {
	if w == nil || w.db == nil {
		return nil
	}
	return w.db.Close()
}

func (w *PostgresWarehouse) Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return &snowflake.QueryResult{}, nil
	}
	query = RewriteQueryForDialect(query, DialectPostgres)
	rows, err := w.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanRows(rows)
}

func (w *PostgresWarehouse) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	query = RewriteQueryForDialect(query, DialectPostgres)
	return w.db.ExecContext(ctx, query, args...)
}

func (w *PostgresWarehouse) DB() *sql.DB {
	if w == nil {
		return nil
	}
	return w.db
}

func (w *PostgresWarehouse) Database() string {
	if w == nil {
		return ""
	}
	return w.database
}

func (w *PostgresWarehouse) Schema() string {
	if w == nil {
		return ""
	}
	return w.schema
}

func (w *PostgresWarehouse) AppSchema() string {
	if w == nil {
		return ""
	}
	return w.appSchema
}

func (w *PostgresWarehouse) ListTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *PostgresWarehouse) ListAvailableTables(ctx context.Context) ([]string, error) {
	return w.listUserTables(ctx)
}

func (w *PostgresWarehouse) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeSQLiteIdentifier(table)
	if err != nil {
		return nil, err
	}
	rows, err := w.db.QueryContext(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position
	`, w.schema, table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func (w *PostgresWarehouse) GetAssets(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}

	selectExpr := "*"
	if len(filter.Columns) > 0 {
		quoted := make([]string, 0, len(filter.Columns))
		for _, column := range filter.Columns {
			normalized, err := normalizeSQLiteIdentifier(column)
			if err != nil {
				continue
			}
			quoted = append(quoted, quoteSQLiteIdentifier(normalized))
		}
		if len(quoted) > 0 {
			selectExpr = strings.Join(quoted, ", ")
		}
	}

	query := "SELECT " + selectExpr + " FROM " + quoteSQLiteIdentifier(table)
	var (
		conditions []string
		args       []any
		argIndex   = 1
	)
	if strings.TrimSpace(filter.Account) != "" {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", quoteSQLiteIdentifier("account_id"), argIndex))
		args = append(args, filter.Account)
		argIndex++
	}
	if strings.TrimSpace(filter.Region) != "" {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", quoteSQLiteIdentifier("region"), argIndex))
		args = append(args, filter.Region)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	result, err := w.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return result.Rows, nil
}

func (w *PostgresWarehouse) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	if w == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	table, err := normalizeAssetTableName(table)
	if err != nil {
		return nil, err
	}
	result, err := w.Query(ctx, "SELECT * FROM "+quoteSQLiteIdentifier(table)+" WHERE "+quoteSQLiteIdentifier("id")+" = $1 LIMIT 1", id)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}
	return result.Rows[0], nil
}

func (w *PostgresWarehouse) InsertCDCEvents(ctx context.Context, events []snowflake.CDCEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := w.ensureCDCEventsTable(ctx); err != nil {
		return err
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cdc_events (
			event_id, table_name, resource_id, change_type, provider, region, account_id, payload, payload_hash, event_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (event_id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, event := range events {
		eventTime := event.EventTime
		if eventTime.IsZero() {
			eventTime = time.Now().UTC()
		}
		eventID := strings.TrimSpace(event.EventID)
		if eventID == "" {
			eventID = snowflake.BuildCDCEventID(event.TableName, event.ResourceID, event.ChangeType, event.PayloadHash, eventTime)
		}
		payload := []byte("{}")
		if event.Payload != nil {
			encoded, err := json.Marshal(event.Payload)
			if err != nil {
				return err
			}
			payload = encoded
		}
		if _, err := stmt.ExecContext(
			ctx,
			eventID,
			event.TableName,
			event.ResourceID,
			event.ChangeType,
			event.Provider,
			event.Region,
			event.AccountID,
			string(payload),
			event.PayloadHash,
			eventTime.UTC(),
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (w *PostgresWarehouse) ensureCDCEventsTable(ctx context.Context) error {
	w.cdcMu.Lock()
	defer w.cdcMu.Unlock()
	if w.cdcReady {
		return nil
	}
	_, err := w.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS cdc_events (
			event_id TEXT PRIMARY KEY,
			table_name TEXT,
			resource_id TEXT,
			change_type TEXT,
			provider TEXT,
			region TEXT,
			account_id TEXT,
			payload TEXT,
			payload_hash TEXT,
			event_time TIMESTAMPTZ,
			ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	w.cdcReady = true
	return nil
}

func (w *PostgresWarehouse) listUserTables(ctx context.Context) ([]string, error) {
	if w == nil || w.db == nil {
		return nil, fmt.Errorf("postgres warehouse is not initialized")
	}
	rows, err := w.db.QueryContext(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, w.schema)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}
