package archetypeclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVulnerabilitiesForScansDefaultsZeroFanoutConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scans/1/vulnerabilities":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":10,"scan_id":1,"severity":"high"}]`))
		case "/scans/2/vulnerabilities":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":20,"scan_id":2,"severity":"critical"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := VulnerabilitiesForScans(ctx, Settings{
		SourceID:      "archetype",
		BaseURL:       server.URL,
		AllowLoopback: true,
	}, []Scan{{ID: 1}, {ID: 2}})
	if err != nil {
		t.Fatalf("VulnerabilitiesForScans() error = %v", err)
	}
	if len(got) != 2 || len(got[0]) != 1 || got[0][0].ID != 10 || len(got[1]) != 1 || got[1][0].ID != 20 {
		t.Fatalf("VulnerabilitiesForScans() = %#v, want ordered vulnerability batches", got)
	}
}
