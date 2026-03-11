package api

import (
	"context"
	"net/http"
	"testing"
)

func TestGetAssetLineage_ByBusinessEntityID(t *testing.T) {
	s := newTestServer(t)

	_, err := s.app.Lineage.MapBusinessEntity(context.Background(), map[string]interface{}{
		"entity_id":         "tenant-1",
		"lead_id":           "lead-1",
		"deal_id":           "deal-1",
		"contract_id":       "contract-1",
		"subscription_id":   "sub-1",
		"billing_entity_id": "cus-1",
	})
	if err != nil {
		t.Fatalf("MapBusinessEntity failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/lineage/sub-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["asset_id"] != "tenant-1" {
		t.Fatalf("expected asset_id tenant-1, got %v", body["asset_id"])
	}
}

func TestGetAssetLineage_ByChainEntityID(t *testing.T) {
	s := newTestServer(t)

	_, err := s.app.Lineage.MapBusinessEntity(context.Background(), map[string]interface{}{
		"entity_id":       "tenant-2",
		"lead_id":         "lead-2",
		"deal_id":         "deal-2",
		"subscription_id": "sub-2",
	})
	if err != nil {
		t.Fatalf("MapBusinessEntity failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/lineage/lead-2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if body["asset_id"] != "tenant-2" {
		t.Fatalf("expected asset_id tenant-2, got %v", body["asset_id"])
	}
}

func TestGetAssetLineage_NotFound(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/lineage/not-found", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (%s)", w.Code, w.Body.String())
	}
}
