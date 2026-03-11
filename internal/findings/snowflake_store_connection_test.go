package findings

import "testing"

func TestSnowflakeStoreSetConnection(t *testing.T) {
	store := NewSnowflakeStore(nil, "DB1", "SCHEMA1")

	store.SetConnection(nil, "DB2", "SCHEMA2")
	if store.schema != "DB2.SCHEMA2" {
		t.Fatalf("expected schema to be updated, got %q", store.schema)
	}
	if store.db != nil {
		t.Fatal("expected db handle to be updated")
	}

	store.SetConnection(nil, "", "")
	if store.schema != "DB2.SCHEMA2" {
		t.Fatalf("expected schema to remain unchanged when database/schema are empty, got %q", store.schema)
	}
}
