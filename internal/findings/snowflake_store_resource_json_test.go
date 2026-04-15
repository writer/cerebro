package findings

import (
	"bytes"
	"context"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

func TestParseResourceDataCachesRawJSON(t *testing.T) {
	raw := []byte(`{"id":"res-1","severity":"high"}`)
	var f Finding

	if err := parseResourceData(&f, raw); err != nil {
		t.Fatalf("parseResourceData returned error: %v", err)
	}
	if f.Resource["id"] != "res-1" {
		t.Fatalf("expected parsed resource id res-1, got %v", f.Resource["id"])
	}
	if !bytes.Equal(f.resourceJSONRaw, raw) {
		t.Fatalf("expected cached raw JSON to match input")
	}

	// Ensure cached raw bytes are a defensive copy.
	raw[0] = '['
	if bytes.Equal(f.resourceJSONRaw, raw) {
		t.Fatal("expected cached raw JSON to be isolated from caller mutations")
	}
}

func TestParseResourceDataReturnsErrorOnInvalidJSON(t *testing.T) {
	var f Finding
	if err := parseResourceData(&f, []byte(`{"invalid"`)); err == nil {
		t.Fatal("expected parseResourceData to return an error for invalid JSON")
		return
	}
}

func TestResourceJSONForSyncUsesCachedRaw(t *testing.T) {
	f := &Finding{
		Resource:        map[string]interface{}{"id": "from-map"},
		resourceJSONRaw: []byte(`{"id":"from-cache"}`),
	}

	resourceJSON, err := resourceJSONForSync(f)
	if err != nil {
		t.Fatalf("resourceJSONForSync returned error: %v", err)
	}
	if string(resourceJSON) != `{"id":"from-cache"}` {
		t.Fatalf("expected cached JSON to be reused, got %s", string(resourceJSON))
	}
}

func TestResourceJSONForSyncMarshalsAndCachesWhenMissing(t *testing.T) {
	f := &Finding{
		Resource: map[string]interface{}{"id": "res-1", "enabled": true},
	}

	resourceJSON, err := resourceJSONForSync(f)
	if err != nil {
		t.Fatalf("resourceJSONForSync returned error: %v", err)
	}
	if len(f.resourceJSONRaw) == 0 {
		t.Fatal("expected marshaled JSON to be cached on finding")
	}
	if !bytes.Equal(resourceJSON, f.resourceJSONRaw) {
		t.Fatal("expected returned JSON to match cached JSON")
	}

	// Ensure returned bytes are independent from cached bytes.
	resourceJSON[0] = '['
	if bytes.Equal(resourceJSON, f.resourceJSONRaw) {
		t.Fatal("expected cached JSON to be isolated from returned slice mutations")
	}
}

func TestSnowflakeStoreUpdateInvalidatesResourceJSONCache(t *testing.T) {
	f := &Finding{
		ID:              "finding-1",
		Resource:        map[string]interface{}{"id": "res-1"},
		resourceJSONRaw: []byte(`{"id":"res-1"}`),
	}
	store := &SnowflakeStore{
		cache: map[string]*Finding{
			f.ID: f,
		},
		dirty: make(map[string]bool),
	}

	if err := store.Update(f.ID, func(existing *Finding) error {
		existing.Description = "updated"
		return nil
	}); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if len(f.resourceJSONRaw) != 0 {
		t.Fatal("expected Update to invalidate cached resource JSON")
	}
	if !store.dirty[f.ID] {
		t.Fatal("expected Update to mark finding as dirty")
	}
}

func TestSnowflakeStoreUpsertInvalidatesResourceJSONCacheOnResourceChange(t *testing.T) {
	f := &Finding{
		ID:              "finding-1",
		Status:          "OPEN",
		Resource:        map[string]interface{}{"id": "res-1"},
		resourceJSONRaw: []byte(`{"id":"res-1"}`),
	}
	store := &SnowflakeStore{
		cache: map[string]*Finding{
			f.ID: f,
		},
		dirty: make(map[string]bool),
	}

	store.Upsert(context.Background(), policy.Finding{
		ID:       f.ID,
		Resource: map[string]interface{}{"id": "res-2"},
	})
	if len(f.resourceJSONRaw) != 0 {
		t.Fatal("expected Upsert to invalidate cached resource JSON when resource changes")
	}
}
