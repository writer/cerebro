package providers

import (
	"context"
	"testing"
	"time"
)

// MockProvider implements Provider interface for testing
type MockProvider struct {
	*BaseProvider
	syncCalls int
	testCalls int
}

func NewMockProvider(name string, provType ProviderType) *MockProvider {
	return &MockProvider{
		BaseProvider: NewBaseProvider(name, provType),
	}
}

func (m *MockProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
	m.syncCalls++
	return &SyncResult{
		Provider:    m.Name(),
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		TotalRows:   100,
		Tables: []TableResult{
			{Name: "test_table", Rows: 100, Inserted: 100},
		},
	}, nil
}

func (m *MockProvider) Test(ctx context.Context) error {
	m.testCalls++
	return nil
}

func (m *MockProvider) Schema() []TableSchema {
	return []TableSchema{
		{
			Name:        "test_table",
			Description: "Test table",
			Columns: []ColumnSchema{
				{Name: "id", Type: "string", Required: true},
				{Name: "name", Type: "string"},
			},
			PrimaryKey: []string{"id"},
		},
	}
}

func TestRegistry_NewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}

	if r.providers == nil {
		t.Error("providers map should be initialized")
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	provider := NewMockProvider("test", ProviderTypeCustom)
	r.Register(provider)

	found, ok := r.Get("test")
	if !ok {
		t.Fatal("expected to find provider")
	}

	if found.Name() != "test" {
		t.Errorf("got name %s, want test", found.Name())
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	r.Register(NewMockProvider("exists", ProviderTypeCloud))

	// Existing
	p, ok := r.Get("exists")
	if !ok || p == nil {
		t.Error("expected to find existing provider")
	}

	// Non-existent
	_, ok = r.Get("not-exists")
	if ok {
		t.Error("expected not to find non-existent provider")
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()

	r.Register(NewMockProvider("provider1", ProviderTypeCloud))
	r.Register(NewMockProvider("provider2", ProviderTypeSaaS))
	r.Register(NewMockProvider("provider3", ProviderTypeIdentity))

	providers := r.List()
	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}
}

func TestRegistry_Configure(t *testing.T) {
	r := NewRegistry()

	provider := NewMockProvider("test", ProviderTypeCloud)
	r.Register(provider)

	config := map[string]interface{}{
		"api_key": "secret",
		"region":  "us-east-1",
	}

	err := r.Configure(context.Background(), "test", config)
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if !provider.IsConfigured() {
		t.Error("provider should be configured")
	}

	if provider.GetConfigString("api_key") != "secret" {
		t.Error("config should be stored")
	}
}

func TestRegistry_SyncAll(t *testing.T) {
	r := NewRegistry()

	p1 := NewMockProvider("provider1", ProviderTypeCloud)
	p2 := NewMockProvider("provider2", ProviderTypeSaaS)

	r.Register(p1)
	r.Register(p2)

	results, err := r.SyncAll(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if p1.syncCalls != 1 || p2.syncCalls != 1 {
		t.Error("both providers should be synced")
	}
}

func TestBaseProvider(t *testing.T) {
	bp := NewBaseProvider("test", ProviderTypeCloud)

	if bp.Name() != "test" {
		t.Errorf("got name %s, want test", bp.Name())
	}

	if bp.Type() != ProviderTypeCloud {
		t.Errorf("got type %s, want cloud", bp.Type())
	}

	if bp.IsConfigured() {
		t.Error("should not be configured initially")
	}
}

func TestBaseProvider_Configure(t *testing.T) {
	bp := NewBaseProvider("test", ProviderTypeCloud)

	config := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	err := bp.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if !bp.IsConfigured() {
		t.Error("should be configured")
	}

	if bp.GetConfig("key1") != "value1" {
		t.Error("GetConfig failed")
	}

	if bp.GetConfigString("key1") != "value1" {
		t.Error("GetConfigString failed")
	}

	// Non-existent key
	if bp.GetConfigString("nonexistent") != "" {
		t.Error("GetConfigString should return empty for missing key")
	}
}

func TestProviderType_Constants(t *testing.T) {
	types := []ProviderType{
		ProviderTypeCloud,
		ProviderTypeSaaS,
		ProviderTypeIdentity,
		ProviderTypeEndpoint,
		ProviderTypeNetwork,
		ProviderTypeCustom,
	}

	for _, pt := range types {
		if pt == "" {
			t.Error("provider type should not be empty")
		}
	}
}

func TestSyncOptions_Fields(t *testing.T) {
	now := time.Now()
	opts := SyncOptions{
		FullSync:    true,
		Tables:      []string{"table1", "table2"},
		Since:       &now,
		Concurrency: 4,
	}

	if !opts.FullSync {
		t.Error("FullSync field incorrect")
	}

	if len(opts.Tables) != 2 {
		t.Error("Tables field incorrect")
	}

	if opts.Concurrency != 4 {
		t.Error("Concurrency field incorrect")
	}

	if opts.Since == nil || !opts.Since.Equal(now) {
		t.Error("Since field incorrect")
	}
}

func TestSyncResult_Fields(t *testing.T) {
	now := time.Now()
	completed := now.Add(5 * time.Second)
	result := &SyncResult{ //nolint:govet // false positive - all fields are tested below
		Provider:    "test",
		StartedAt:   now,
		CompletedAt: completed,
		Duration:    5 * time.Second,
		TotalRows:   1000,
		Tables: []TableResult{
			{Name: "t1", Rows: 500},
			{Name: "t2", Rows: 500},
		},
		Errors: nil,
	}

	if result.Provider != "test" {
		t.Error("Provider field incorrect")
	}
	if result.StartedAt != now {
		t.Error("StartedAt field incorrect")
	}
	if result.CompletedAt != completed {
		t.Error("CompletedAt field incorrect")
	}
	if result.TotalRows != 1000 {
		t.Error("TotalRows field incorrect")
	}
	if result.Duration != 5*time.Second {
		t.Error("Duration field incorrect")
	}

	if len(result.Tables) != 2 {
		t.Error("Tables field incorrect")
	}

	if result.Errors != nil {
		t.Error("Errors field should be nil")
	}
}

func TestTableSchema_Fields(t *testing.T) {
	schema := TableSchema{
		Name:        "test_table",
		Description: "A test table",
		Columns: []ColumnSchema{
			{Name: "id", Type: "string", Required: true},
			{Name: "name", Type: "string", Required: false},
		},
		PrimaryKey: []string{"id"},
	}

	if schema.Name != "test_table" {
		t.Error("Name field incorrect")
	}

	if schema.Description != "A test table" {
		t.Error("Description field incorrect")
	}

	if len(schema.Columns) != 2 {
		t.Error("Columns field incorrect")
	}

	if !schema.Columns[0].Required {
		t.Error("Required field incorrect")
	}

	if len(schema.PrimaryKey) != 1 || schema.PrimaryKey[0] != "id" {
		t.Error("PrimaryKey field incorrect")
	}
}

func TestMockProvider_Schema(t *testing.T) {
	p := NewMockProvider("test", ProviderTypeCloud)
	schema := p.Schema()

	if len(schema) == 0 {
		t.Error("expected at least one table schema")
	}

	if schema[0].Name != "test_table" {
		t.Errorf("got table name %s, want test_table", schema[0].Name)
	}
}

func TestMockProvider_Test(t *testing.T) {
	p := NewMockProvider("test", ProviderTypeCloud)

	err := p.Test(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	if p.testCalls != 1 {
		t.Error("Test should have been called")
	}
}
