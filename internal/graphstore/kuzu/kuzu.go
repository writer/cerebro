//go:build cgo

package kuzu

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	kuzudb "github.com/kuzudb/go-kuzu"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

// Store is the Kuzu-backed graph projection store implementation.
type Store struct {
	db          *sql.DB
	schemaMu    sync.Mutex
	schemaReady bool
}

// Open opens a Kuzu-backed graph projection store.
func Open(cfg config.GraphStoreConfig) (*Store, error) {
	rawPath := strings.TrimSpace(cfg.KuzuPath)
	if rawPath == "" {
		return nil, errors.New("kuzu path is required")
	}
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return nil, fmt.Errorf("resolve kuzu path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create kuzu parent directory: %w", err)
	}
	dsn := kuzuDSN(absPath)
	db, err := sql.Open(kuzudb.Name, dsn)
	if err != nil {
		return nil, fmt.Errorf("open kuzu: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping verifies that Kuzu can answer a trivial query.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	var result int64
	if err := s.db.QueryRowContext(ctx, "RETURN 1 AS ok").Scan(&result); err != nil {
		return fmt.Errorf("query kuzu: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("unexpected kuzu ping result %d", result)
	}
	return nil
}

func kuzuDSN(absPath string) string {
	return (&url.URL{
		Scheme: "kuzu",
		Path:   filepath.ToSlash(absPath),
	}).String()
}

// UpsertProjectedEntity upserts one normalized entity in the graph store.
func (s *Store) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return errors.New("projected entity is required")
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return errors.New("projected entity urn is required")
	}
	tenantID := strings.TrimSpace(entity.TenantID)
	if tenantID == "" {
		return errors.New("projected entity tenant id is required")
	}
	sourceID := strings.TrimSpace(entity.SourceID)
	if sourceID == "" {
		return errors.New("projected entity source id is required")
	}
	entityType := strings.TrimSpace(entity.EntityType)
	if entityType == "" {
		return errors.New("projected entity type is required")
	}
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	if err := s.ensureProjectionSchema(ctx); err != nil {
		return err
	}
	attributes, err := s.mergedEntityAttributes(ctx, urn, entity.Attributes)
	if err != nil {
		return err
	}
	attributesJSON, err := graphAttributesJSON(attributes)
	if err != nil {
		return fmt.Errorf("marshal projected entity attributes: %w", err)
	}
	label := strings.TrimSpace(entity.Label)
	if label == "" {
		label = urn
	}
	statement := fmt.Sprintf(
		"MERGE (e:entity {urn: %s}) SET e.tenant_id = %s, e.source_id = %s, e.entity_type = %s, e.label = %s, e.attributes_json = %s",
		cypherString(urn),
		cypherString(tenantID),
		cypherString(sourceID),
		cypherString(entityType),
		cypherString(label),
		cypherString(attributesJSON),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	return nil
}

func (s *Store) mergedEntityAttributes(ctx context.Context, urn string, attributes map[string]string) (map[string]string, error) {
	merged := make(map[string]string, len(attributes))
	var raw string
	err := s.db.QueryRowContext(ctx, fmt.Sprintf("MATCH (e:entity {urn: %s}) RETURN e.attributes_json", cypherString(urn))).Scan(&raw)
	switch {
	case err == nil:
		if strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &merged); err != nil {
				return nil, fmt.Errorf("decode existing projected entity attributes %q: %w", urn, err)
			}
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return nil, fmt.Errorf("load projected entity attributes %q: %w", urn, err)
	}
	for key, value := range attributes {
		merged[key] = value
	}
	return merged, nil
}

// UpsertProjectedLink upserts one normalized link in the graph store.
func (s *Store) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return errors.New("projected link is required")
	}
	fromURN := strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return errors.New("projected link from urn is required")
	}
	toURN := strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return errors.New("projected link to urn is required")
	}
	relation := strings.TrimSpace(link.Relation)
	if relation == "" {
		return errors.New("projected link relation is required")
	}
	tenantID := strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return errors.New("projected link tenant id is required")
	}
	sourceID := strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return errors.New("projected link source id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	if err := s.ensureProjectionSchema(ctx); err != nil {
		return err
	}
	attributesJSON, err := graphAttributesJSON(link.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected link attributes: %w", err)
	}
	statement := fmt.Sprintf(
		"MERGE (src:entity {urn: %s}) MERGE (dst:entity {urn: %s}) MERGE (src)-[r:relation {relation: %s}]->(dst) SET r.tenant_id = %s, r.source_id = %s, r.attributes_json = %s",
		cypherString(fromURN),
		cypherString(toURN),
		cypherString(relation),
		cypherString(tenantID),
		cypherString(sourceID),
		cypherString(attributesJSON),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

func (s *Store) ensureProjectionSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemaReady {
		return nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return err
	}
	if !tables["entity"] {
		if _, err := s.db.ExecContext(ctx, "CREATE NODE TABLE entity(urn STRING, tenant_id STRING, source_id STRING, entity_type STRING, label STRING, attributes_json STRING, PRIMARY KEY (urn))"); err != nil {
			return fmt.Errorf("create entity node table: %w", err)
		}
	}
	if !tables["relation"] {
		if _, err := s.db.ExecContext(ctx, "CREATE REL TABLE relation(FROM entity TO entity, relation STRING, tenant_id STRING, source_id STRING, attributes_json STRING)"); err != nil {
			return fmt.Errorf("create relation table: %w", err)
		}
	}
	s.schemaReady = true
	return nil
}

func (s *Store) graphTables(ctx context.Context) (_ map[string]bool, err error) {
	rows, err := s.db.QueryContext(ctx, "CALL show_tables() RETURN *")
	if err != nil {
		return nil, fmt.Errorf("show kuzu tables: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close kuzu tables: %w", closeErr)
		}
	}()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("list kuzu table columns: %w", err)
	}
	tables := make(map[string]bool)
	for rows.Next() {
		values := make([]any, len(columns))
		scanArgs := make([]any, len(columns))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("scan kuzu tables: %w", err)
		}
		for idx, name := range columns {
			if name != "name" {
				continue
			}
			tableName := stringColumn(values[idx])
			if tableName != "" {
				tables[tableName] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate kuzu tables: %w", err)
	}
	return tables, nil
}

func graphAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func stringColumn(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

func cypherString(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"'", "\\'",
		"\n", "\\n",
		"\r", "\\r",
	)
	return "'" + replacer.Replace(value) + "'"
}
