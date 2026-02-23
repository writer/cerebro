package sync

import (
	"testing"
	"time"
)

func TestHashRowContentWithModeCanonicalizesNonJSONMaps(t *testing.T) {
	now := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	rowA := map[string]interface{}{
		"payload": map[interface{}]interface{}{
			"env":     "prod",
			"updated": &now,
		},
	}
	rowB := map[string]interface{}{
		"payload": map[interface{}]interface{}{
			"updated": now,
			"env":     "prod",
		},
	}

	if gotA, gotB := hashRowContentWithMode(rowA, false), hashRowContentWithMode(rowB, false); gotA != gotB {
		t.Fatalf("expected canonical hashes for equivalent maps, got %q and %q", gotA, gotB)
	}
}

func TestHashRowContentWithModeAvoidsNonJSONCollisions(t *testing.T) {
	rowA := map[string]interface{}{
		"payload": map[interface{}]interface{}{"a": "1"},
	}
	rowB := map[string]interface{}{
		"payload": map[interface{}]interface{}{"b": "2"},
	}

	if hashRowContent(rowA) == hashRowContent(rowB) {
		t.Fatal("expected different hashes for different non-JSON map payloads")
	}
}
