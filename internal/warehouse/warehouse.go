package warehouse

import (
	"context"
	"database/sql"
	"sync"

	"github.com/writer/cerebro/internal/snowflake"
)

// QueryWarehouse is the narrow query surface used by graph and scanner code.
type QueryWarehouse interface {
	Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error)
}

// ExecWarehouse is the mutation surface used by sync and warehouse table helpers.
type ExecWarehouse interface {
	Exec(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SchemaWarehouse exposes the minimum schema/connection metadata needed by sync and app wiring.
type SchemaWarehouse interface {
	DB() *sql.DB
	Database() string
	Schema() string
	AppSchema() string
}

// AssetWarehouse exposes higher-level asset retrieval helpers still used by API handlers.
type AssetWarehouse interface {
	ListTables(ctx context.Context) ([]string, error)
	GetAssets(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error)
	GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error)
}

// DiscoveryWarehouse exposes table-discovery helpers used by higher-level scans and query policy allowlisting.
type DiscoveryWarehouse interface {
	ListAvailableTables(ctx context.Context) ([]string, error)
	DescribeColumns(ctx context.Context, table string) ([]string, error)
}

// CDCWarehouse is the write surface used to persist CDC events during sync.
type CDCWarehouse interface {
	InsertCDCEvents(ctx context.Context, events []snowflake.CDCEvent) error
}

// SyncWarehouse is the concrete sync/scanner dependency slice.
type SyncWarehouse interface {
	QueryWarehouse
	ExecWarehouse
	SchemaWarehouse
	CDCWarehouse
}

// DataWarehouse is the broader application-level warehouse surface.
type DataWarehouse interface {
	SyncWarehouse
	AssetWarehouse
	DiscoveryWarehouse
}

var _ DataWarehouse = (*snowflake.Client)(nil)

// RecordedCall captures a query or exec invocation for tests.
type RecordedCall struct {
	Statement string
	Args      []any
}

// MemoryWarehouse is a test double that satisfies the warehouse interfaces without an external database.
type MemoryWarehouse struct {
	QueryFunc           func(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error)
	ExecFunc            func(ctx context.Context, query string, args ...any) (sql.Result, error)
	InsertCDCEventsFunc func(ctx context.Context, events []snowflake.CDCEvent) error
	ListTablesFunc      func(ctx context.Context) ([]string, error)
	ListAvailableFunc   func(ctx context.Context) ([]string, error)
	DescribeColumnsFunc func(ctx context.Context, table string) ([]string, error)
	GetAssetsFunc       func(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error)
	GetAssetByIDFunc    func(ctx context.Context, table, id string) (map[string]interface{}, error)
	DBFunc              func() *sql.DB
	DatabaseValue       string
	SchemaValue         string
	AppSchemaValue      string

	mu         sync.Mutex
	Queries    []RecordedCall
	Execs      []RecordedCall
	CDCBatches [][]snowflake.CDCEvent
}

func (m *MemoryWarehouse) Query(ctx context.Context, query string, args ...any) (*snowflake.QueryResult, error) {
	m.recordQuery(query, args)
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, query, args...)
	}
	return &snowflake.QueryResult{}, nil
}

func (m *MemoryWarehouse) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	m.recordExec(query, args)
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, query, args...)
	}
	return memoryResult(0), nil
}

func (m *MemoryWarehouse) InsertCDCEvents(ctx context.Context, events []snowflake.CDCEvent) error {
	m.mu.Lock()
	m.CDCBatches = append(m.CDCBatches, append([]snowflake.CDCEvent(nil), events...))
	m.mu.Unlock()
	if m.InsertCDCEventsFunc != nil {
		return m.InsertCDCEventsFunc(ctx, events)
	}
	return nil
}

func (m *MemoryWarehouse) ListTables(ctx context.Context) ([]string, error) {
	if m.ListTablesFunc != nil {
		return m.ListTablesFunc(ctx)
	}
	return []string{}, nil
}

func (m *MemoryWarehouse) ListAvailableTables(ctx context.Context) ([]string, error) {
	if m.ListAvailableFunc != nil {
		return m.ListAvailableFunc(ctx)
	}
	return []string{}, nil
}

func (m *MemoryWarehouse) DescribeColumns(ctx context.Context, table string) ([]string, error) {
	if m.DescribeColumnsFunc != nil {
		return m.DescribeColumnsFunc(ctx, table)
	}
	return []string{}, nil
}

func (m *MemoryWarehouse) GetAssets(ctx context.Context, table string, filter snowflake.AssetFilter) ([]map[string]interface{}, error) {
	if _, err := normalizeAssetTableName(table); err != nil {
		return nil, err
	}
	if m.GetAssetsFunc != nil {
		return m.GetAssetsFunc(ctx, table, filter)
	}
	return []map[string]interface{}{}, nil
}

func (m *MemoryWarehouse) GetAssetByID(ctx context.Context, table, id string) (map[string]interface{}, error) {
	if _, err := normalizeAssetTableName(table); err != nil {
		return nil, err
	}
	if m.GetAssetByIDFunc != nil {
		return m.GetAssetByIDFunc(ctx, table, id)
	}
	return nil, nil
}

func (m *MemoryWarehouse) DB() *sql.DB {
	if m.DBFunc != nil {
		return m.DBFunc()
	}
	return nil
}

func (m *MemoryWarehouse) Database() string {
	return m.DatabaseValue
}

func (m *MemoryWarehouse) Schema() string {
	return m.SchemaValue
}

func (m *MemoryWarehouse) AppSchema() string {
	return m.AppSchemaValue
}

func (m *MemoryWarehouse) recordQuery(statement string, args []any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Queries = append(m.Queries, RecordedCall{Statement: statement, Args: append([]any(nil), args...)})
}

func (m *MemoryWarehouse) recordExec(statement string, args []any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Execs = append(m.Execs, RecordedCall{Statement: statement, Args: append([]any(nil), args...)})
}

type memoryResult int64

func (m memoryResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (m memoryResult) RowsAffected() (int64, error) {
	return int64(m), nil
}
