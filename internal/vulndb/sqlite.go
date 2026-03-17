package vulndb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type candidateRecord struct {
	Vulnerability Vulnerability
	Affected      AffectedPackage
}

type SQLiteStore struct {
	db *sql.DB
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type sqliteTxStore struct {
	tx *sql.Tx
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("vulnerability database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create vulnerability database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open vulnerability sqlite: %w", err)
	}
	if err := initSQLiteStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func initSQLiteStore(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("vulnerability sqlite db is nil")
	}
	schema := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT NOT NULL PRIMARY KEY,
		summary TEXT NOT NULL DEFAULT '',
		details TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		cvss REAL NOT NULL DEFAULT 0,
		published_at TIMESTAMP,
		modified_at TIMESTAMP,
		withdrawn_at TIMESTAMP,
		source TEXT NOT NULL DEFAULT '',
		references_json JSON NOT NULL DEFAULT '[]',
		epss_score REAL NOT NULL DEFAULT 0,
		epss_percentile REAL NOT NULL DEFAULT 0,
		in_kev INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS vulnerability_aliases (
		vulnerability_id TEXT NOT NULL,
		alias TEXT NOT NULL,
		PRIMARY KEY (vulnerability_id, alias)
	);
	CREATE INDEX IF NOT EXISTS idx_vulnerability_aliases_alias ON vulnerability_aliases(alias);
	CREATE TABLE IF NOT EXISTS package_advisories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vulnerability_id TEXT NOT NULL,
		ecosystem TEXT NOT NULL,
		package_name TEXT NOT NULL,
		range_type TEXT NOT NULL DEFAULT '',
		introduced TEXT NOT NULL DEFAULT '',
		fixed TEXT NOT NULL DEFAULT '',
		last_affected TEXT NOT NULL DEFAULT '',
		vulnerable_version TEXT NOT NULL DEFAULT '',
		distribution TEXT NOT NULL DEFAULT '',
		distribution_version TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_package_advisories_lookup ON package_advisories(ecosystem, package_name);
	CREATE INDEX IF NOT EXISTS idx_package_advisories_vuln ON package_advisories(vulnerability_id);
	CREATE TABLE IF NOT EXISTS sync_state (
		source TEXT NOT NULL PRIMARY KEY,
		etag TEXT NOT NULL DEFAULT '',
		cursor TEXT NOT NULL DEFAULT '',
		last_attempt_at TIMESTAMP,
		last_success_at TIMESTAMP,
		records_synced INTEGER NOT NULL DEFAULT 0,
		metadata_json JSON NOT NULL DEFAULT '{}'
	);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return fmt.Errorf("init vulnerability sqlite schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) WithWriteTx(ctx context.Context, fn func(advisoryWriteStore) error) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin vulnerability sqlite tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(&sqliteTxStore{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit vulnerability sqlite tx: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertAdvisory(ctx context.Context, vuln Vulnerability, affected []AffectedPackage) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin vulnerability sqlite tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := upsertAdvisoryExec(ctx, tx, vuln, affected); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit vulnerability advisory: %w", err)
	}
	return nil
}

func (s *sqliteTxStore) UpsertAdvisory(ctx context.Context, vuln Vulnerability, affected []AffectedPackage) error {
	if s == nil || s.tx == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return upsertAdvisoryExec(ctx, s.tx, vuln, affected)
}

func upsertAdvisoryExec(ctx context.Context, exec sqlExecer, vuln Vulnerability, affected []AffectedPackage) error {
	vuln.ID = strings.TrimSpace(vuln.ID)
	if vuln.ID == "" {
		return fmt.Errorf("vulnerability id is required")
	}
	refJSON, err := json.Marshal(uniqueStrings(vuln.References))
	if err != nil {
		return fmt.Errorf("marshal vulnerability references: %w", err)
	}
	vuln.Severity = normalizeSeverity(vuln.Severity)
	if vuln.ModifiedAt.IsZero() {
		vuln.ModifiedAt = time.Now().UTC()
	} else {
		vuln.ModifiedAt = vuln.ModifiedAt.UTC()
	}
	if !vuln.PublishedAt.IsZero() {
		vuln.PublishedAt = vuln.PublishedAt.UTC()
	}
	if vuln.WithdrawnAt != nil {
		withdrawn := vuln.WithdrawnAt.UTC()
		vuln.WithdrawnAt = &withdrawn
	}
	for i := range affected {
		affected[i].VulnerabilityID = vuln.ID
		affected[i].Ecosystem = strings.TrimSpace(strings.ToLower(affected[i].Ecosystem))
		affected[i].PackageName = strings.TrimSpace(strings.ToLower(affected[i].PackageName))
		affected[i].RangeType = strings.TrimSpace(strings.ToUpper(affected[i].RangeType))
		affected[i].Introduced = strings.TrimSpace(affected[i].Introduced)
		affected[i].Fixed = strings.TrimSpace(affected[i].Fixed)
		affected[i].LastAffected = strings.TrimSpace(affected[i].LastAffected)
		affected[i].VulnerableVersion = strings.TrimSpace(affected[i].VulnerableVersion)
		affected[i].Distribution = strings.TrimSpace(strings.ToLower(affected[i].Distribution))
		affected[i].DistributionVersion = strings.TrimSpace(affected[i].DistributionVersion)
	}
	_, err = exec.ExecContext(ctx, `
		INSERT INTO vulnerabilities (
			id, summary, details, severity, cvss, published_at, modified_at, withdrawn_at, source, references_json, epss_score, epss_percentile, in_kev
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			summary = excluded.summary,
			details = excluded.details,
			severity = excluded.severity,
			cvss = excluded.cvss,
			published_at = excluded.published_at,
			modified_at = excluded.modified_at,
			withdrawn_at = excluded.withdrawn_at,
			source = excluded.source,
			references_json = excluded.references_json
	`, vuln.ID, vuln.Summary, vuln.Details, vuln.Severity, vuln.CVSS, nullableTimeValueRef(vuln.PublishedAt), nullableTimeValueRef(vuln.ModifiedAt), nullableTime(vuln.WithdrawnAt), vuln.Source, refJSON, vuln.EPSSScore, vuln.EPSSPercentile, boolToInt(vuln.InKEV))
	if err != nil {
		return fmt.Errorf("upsert vulnerability advisory: %w", err)
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM vulnerability_aliases WHERE vulnerability_id = ?`, vuln.ID); err != nil {
		return fmt.Errorf("reset vulnerability aliases: %w", err)
	}
	aliases := uniqueStrings(append([]string{vuln.ID}, vuln.Aliases...))
	for _, alias := range aliases {
		alias = strings.TrimSpace(strings.ToUpper(alias))
		if alias == "" {
			continue
		}
		if _, err := exec.ExecContext(ctx, `INSERT INTO vulnerability_aliases (vulnerability_id, alias) VALUES (?, ?)`, vuln.ID, alias); err != nil {
			return fmt.Errorf("insert vulnerability alias: %w", err)
		}
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM package_advisories WHERE vulnerability_id = ?`, vuln.ID); err != nil {
		return fmt.Errorf("reset package advisories: %w", err)
	}
	for _, item := range affected {
		if item.Ecosystem == "" || item.PackageName == "" {
			continue
		}
		if _, err := exec.ExecContext(ctx, `
			INSERT INTO package_advisories (
				vulnerability_id, ecosystem, package_name, range_type, introduced, fixed, last_affected, vulnerable_version, distribution, distribution_version
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, item.VulnerabilityID, item.Ecosystem, item.PackageName, item.RangeType, item.Introduced, item.Fixed, item.LastAffected, item.VulnerableVersion, item.Distribution, item.DistributionVersion); err != nil {
			return fmt.Errorf("insert package advisory: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) LookupVulnerability(ctx context.Context, idOrAlias string) (*Vulnerability, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lookup := strings.TrimSpace(strings.ToUpper(idOrAlias))
	if lookup == "" {
		return nil, nil
	}
	var vuln Vulnerability
	var referencesJSON []byte
	var publishedAt sql.NullTime
	var modifiedAt sql.NullTime
	var withdrawnAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT v.id, v.summary, v.details, v.severity, v.cvss, v.published_at, v.modified_at, v.withdrawn_at, v.source, v.references_json, v.epss_score, v.epss_percentile, v.in_kev
		FROM vulnerabilities v
		JOIN vulnerability_aliases a ON a.vulnerability_id = v.id
		WHERE a.alias = ?
		LIMIT 1
	`, lookup).Scan(&vuln.ID, &vuln.Summary, &vuln.Details, &vuln.Severity, &vuln.CVSS, &publishedAt, &modifiedAt, &withdrawnAt, &vuln.Source, &referencesJSON, &vuln.EPSSScore, &vuln.EPSSPercentile, (*boolInt)(&vuln.InKEV))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup vulnerability: %w", err)
	}
	vuln.PublishedAt = nullableTimeValue(publishedAt)
	vuln.ModifiedAt = nullableTimeValue(modifiedAt)
	vuln.WithdrawnAt = nullableTimePointer(withdrawnAt)
	if err := json.Unmarshal(referencesJSON, &vuln.References); err != nil {
		return nil, fmt.Errorf("decode vulnerability references: %w", err)
	}
	aliases, err := s.lookupAliases(ctx, vuln.ID)
	if err != nil {
		return nil, err
	}
	vuln.Aliases = aliases
	return &vuln, nil
}

func (s *SQLiteStore) lookupAliases(ctx context.Context, vulnID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT alias FROM vulnerability_aliases WHERE vulnerability_id = ? ORDER BY alias ASC`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query vulnerability aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	aliases := make([]string, 0)
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("scan vulnerability alias: %w", err)
		}
		if strings.EqualFold(alias, vulnID) {
			continue
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vulnerability aliases: %w", err)
	}
	return aliases, nil
}

func (s *SQLiteStore) ListPackageCandidates(ctx context.Context, ecosystem, packageName string) ([]candidateRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			v.id, v.summary, v.details, v.severity, v.cvss, v.published_at, v.modified_at, v.withdrawn_at, v.source, v.references_json, v.epss_score, v.epss_percentile, v.in_kev,
			p.ecosystem, p.package_name, p.range_type, p.introduced, p.fixed, p.last_affected, p.vulnerable_version, p.distribution, p.distribution_version
		FROM package_advisories p
		JOIN vulnerabilities v ON v.id = p.vulnerability_id
		WHERE p.ecosystem = ? AND p.package_name = ? AND v.withdrawn_at IS NULL
		ORDER BY v.modified_at DESC, v.id ASC
	`, strings.TrimSpace(strings.ToLower(ecosystem)), strings.TrimSpace(strings.ToLower(packageName)))
	if err != nil {
		return nil, fmt.Errorf("query package advisories: %w", err)
	}
	defer func() { _ = rows.Close() }()
	candidates := make([]candidateRecord, 0)
	for rows.Next() {
		var rec candidateRecord
		var referencesJSON []byte
		var publishedAt sql.NullTime
		var modifiedAt sql.NullTime
		var withdrawnAt sql.NullTime
		if err := rows.Scan(
			&rec.Vulnerability.ID,
			&rec.Vulnerability.Summary,
			&rec.Vulnerability.Details,
			&rec.Vulnerability.Severity,
			&rec.Vulnerability.CVSS,
			&publishedAt,
			&modifiedAt,
			&withdrawnAt,
			&rec.Vulnerability.Source,
			&referencesJSON,
			&rec.Vulnerability.EPSSScore,
			&rec.Vulnerability.EPSSPercentile,
			(*boolInt)(&rec.Vulnerability.InKEV),
			&rec.Affected.Ecosystem,
			&rec.Affected.PackageName,
			&rec.Affected.RangeType,
			&rec.Affected.Introduced,
			&rec.Affected.Fixed,
			&rec.Affected.LastAffected,
			&rec.Affected.VulnerableVersion,
			&rec.Affected.Distribution,
			&rec.Affected.DistributionVersion,
		); err != nil {
			return nil, fmt.Errorf("scan package advisory candidate: %w", err)
		}
		rec.Vulnerability.PublishedAt = nullableTimeValue(publishedAt)
		rec.Vulnerability.ModifiedAt = nullableTimeValue(modifiedAt)
		rec.Vulnerability.WithdrawnAt = nullableTimePointer(withdrawnAt)
		if err := json.Unmarshal(referencesJSON, &rec.Vulnerability.References); err != nil {
			return nil, fmt.Errorf("decode package advisory references: %w", err)
		}
		candidates = append(candidates, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate package advisories: %w", err)
	}
	seenAliases := make(map[string][]string)
	for i := range candidates {
		id := candidates[i].Vulnerability.ID
		if _, ok := seenAliases[id]; !ok {
			aliases, err := s.lookupAliases(ctx, id)
			if err != nil {
				return nil, err
			}
			seenAliases[id] = aliases
		}
		candidates[i].Vulnerability.Aliases = seenAliases[id]
	}
	return candidates, nil
}

func (s *SQLiteStore) UpdateSyncState(ctx context.Context, state SyncState) error {
	if s == nil || s.db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return updateSyncStateExec(ctx, s.db, state)
}

func (s *sqliteTxStore) UpdateSyncState(ctx context.Context, state SyncState) error {
	if s == nil || s.tx == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return updateSyncStateExec(ctx, s.tx, state)
}

func updateSyncStateExec(ctx context.Context, exec sqlExecer, state SyncState) error {
	state.Source = strings.TrimSpace(state.Source)
	if state.Source == "" {
		return fmt.Errorf("sync state source is required")
	}
	metaJSON, err := json.Marshal(state.Metadata)
	if err != nil {
		return fmt.Errorf("marshal sync state metadata: %w", err)
	}
	_, err = exec.ExecContext(ctx, `
		INSERT INTO sync_state (source, etag, cursor, last_attempt_at, last_success_at, records_synced, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			etag = excluded.etag,
			cursor = excluded.cursor,
			last_attempt_at = excluded.last_attempt_at,
			last_success_at = excluded.last_success_at,
			records_synced = excluded.records_synced,
			metadata_json = excluded.metadata_json
	`, state.Source, state.ETag, state.Cursor, nullableTimeValueRef(state.LastAttemptAt), nullableTimeValueRef(state.LastSuccessAt), state.RecordsSynced, metaJSON)
	if err != nil {
		return fmt.Errorf("upsert sync state: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListSyncStates(ctx context.Context) ([]SyncState, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, etag, cursor, last_attempt_at, last_success_at, records_synced, metadata_json
		FROM sync_state
		ORDER BY source ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list sync states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var states []SyncState
	for rows.Next() {
		var state SyncState
		var lastAttempt sql.NullTime
		var lastSuccess sql.NullTime
		var metadataJSON []byte
		if err := rows.Scan(&state.Source, &state.ETag, &state.Cursor, &lastAttempt, &lastSuccess, &state.RecordsSynced, &metadataJSON); err != nil {
			return nil, fmt.Errorf("scan sync state: %w", err)
		}
		state.LastAttemptAt = nullableTimeValue(lastAttempt)
		state.LastSuccessAt = nullableTimeValue(lastSuccess)
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &state.Metadata); err != nil {
				return nil, fmt.Errorf("decode sync state metadata for %s: %w", state.Source, err)
			}
		}
		if state.Metadata == nil {
			state.Metadata = map[string]string{}
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sync states: %w", err)
	}
	return states, nil
}

func (s *SQLiteStore) Stats(ctx context.Context) (Stats, error) {
	if s == nil || s.db == nil {
		return Stats{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var stats Stats
	var lastUpdatedRaw sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities`).Scan(&stats.VulnerabilityCount); err != nil {
		return Stats{}, fmt.Errorf("count vulnerabilities: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_advisories`).Scan(&stats.PackageRangeCount); err != nil {
		return Stats{}, fmt.Errorf("count package advisories: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE in_kev = 1`).Scan(&stats.KEVCount); err != nil {
		return Stats{}, fmt.Errorf("count kev vulnerabilities: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(modified_at) FROM vulnerabilities`).Scan(&lastUpdatedRaw); err != nil {
		return Stats{}, fmt.Errorf("max vulnerability modified_at: %w", err)
	}
	if lastUpdatedRaw.Valid {
		parsed, err := parseStoredTime(lastUpdatedRaw.String)
		if err != nil {
			return Stats{}, fmt.Errorf("parse max vulnerability modified_at %q: %w", lastUpdatedRaw.String, err)
		}
		stats.LastUpdatedAt = parsed
	}
	return stats, nil
}

func (s *SQLiteStore) MarkKEV(ctx context.Context, cves []string) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return markKEVExec(ctx, s.db, cves)
}

func (s *sqliteTxStore) MarkKEV(ctx context.Context, cves []string) (int64, error) {
	if s == nil || s.tx == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return markKEVExec(ctx, s.tx, cves)
}

func markKEVExec(ctx context.Context, exec sqlExecer, cves []string) (int64, error) {
	var updated int64
	for _, cve := range uniqueStrings(cves) {
		alias := strings.TrimSpace(strings.ToUpper(cve))
		if alias == "" {
			continue
		}
		res, err := exec.ExecContext(ctx, `
			UPDATE vulnerabilities
			SET in_kev = 1
			WHERE id IN (SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = ?)
		`, alias)
		if err != nil {
			return updated, fmt.Errorf("mark kev vulnerability %s: %w", alias, err)
		}
		count, err := res.RowsAffected()
		if err == nil {
			updated += count
		}
	}
	return updated, nil
}

func (s *SQLiteStore) UpsertEPSS(ctx context.Context, cve string, score, percentile float64) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return upsertEPSSExec(ctx, s.db, cve, score, percentile)
}

func (s *sqliteTxStore) UpsertEPSS(ctx context.Context, cve string, score, percentile float64) (int64, error) {
	if s == nil || s.tx == nil {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return upsertEPSSExec(ctx, s.tx, cve, score, percentile)
}

func upsertEPSSExec(ctx context.Context, exec sqlExecer, cve string, score, percentile float64) (int64, error) {
	cve = strings.TrimSpace(strings.ToUpper(cve))
	if cve == "" {
		return 0, nil
	}
	res, err := exec.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET epss_score = ?, epss_percentile = ?
		WHERE id IN (SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = ?)
	`, score, percentile, cve)
	if err != nil {
		return 0, fmt.Errorf("upsert epss score %s: %w", cve, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rows, nil
}

func nullableTimeValue(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func nullableTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	timeValue := value.Time.UTC()
	return &timeValue
}

func nullableTimeValueRef(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func parseStoredTime(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format")
}

type boolInt bool

func (b *boolInt) Scan(src any) error {
	switch value := src.(type) {
	case int64:
		*b = value != 0
		return nil
	case bool:
		*b = boolInt(value)
		return nil
	case []byte:
		*b = strings.TrimSpace(string(value)) == "1"
		return nil
	case string:
		*b = strings.TrimSpace(value) == "1"
		return nil
	case nil:
		*b = false
		return nil
	default:
		return fmt.Errorf("unsupported boolInt source %T", src)
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
