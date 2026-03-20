package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/lineage"
)

type stubLineageService struct {
	availableErr           error
	getLineageFunc         func(string) (*lineage.AssetLineage, bool, error)
	getLineageByCommitFunc func(string) ([]*lineage.AssetLineage, error)
	getLineageByImageFunc  func(string) ([]*lineage.AssetLineage, error)
	detectDriftFunc        func(context.Context, string, map[string]interface{}, map[string]interface{}) ([]lineage.DriftDetail, error)
}

func (s stubLineageService) Available() error {
	return s.availableErr
}

func (s stubLineageService) GetLineage(assetID string) (*lineage.AssetLineage, bool, error) {
	if s.getLineageFunc != nil {
		return s.getLineageFunc(assetID)
	}
	return nil, false, nil
}

func (s stubLineageService) GetLineageByCommit(commitSHA string) ([]*lineage.AssetLineage, error) {
	if s.getLineageByCommitFunc != nil {
		return s.getLineageByCommitFunc(commitSHA)
	}
	return nil, nil
}

func (s stubLineageService) GetLineageByImage(imageDigest string) ([]*lineage.AssetLineage, error) {
	if s.getLineageByImageFunc != nil {
		return s.getLineageByImageFunc(imageDigest)
	}
	return nil, nil
}

func (s stubLineageService) DetectDrift(ctx context.Context, assetID string, currentState map[string]interface{}, iacState map[string]interface{}) ([]lineage.DriftDetail, error) {
	if s.detectDriftFunc != nil {
		return s.detectDriftFunc(ctx, assetID, currentState, iacState)
	}
	return nil, nil
}

func TestLineageReadHandlersUseServiceInterface(t *testing.T) {
	var (
		getCalled    bool
		commitCalled bool
		imageCalled  bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		lineage: stubLineageService{
			getLineageFunc: func(assetID string) (*lineage.AssetLineage, bool, error) {
				getCalled = true
				if assetID != "asset-123" {
					t.Fatalf("expected asset-123, got %q", assetID)
				}
				return &lineage.AssetLineage{AssetID: assetID, Repository: "repo/a"}, true, nil
			},
			getLineageByCommitFunc: func(commitSHA string) ([]*lineage.AssetLineage, error) {
				commitCalled = true
				if commitSHA != "abc123" {
					t.Fatalf("expected abc123, got %q", commitSHA)
				}
				return []*lineage.AssetLineage{{AssetID: "asset-123", CommitSHA: commitSHA}}, nil
			},
			getLineageByImageFunc: func(imageDigest string) ([]*lineage.AssetLineage, error) {
				imageCalled = true
				if imageDigest != "sha256:abc" {
					t.Fatalf("expected sha256:abc, got %q", imageDigest)
				}
				return []*lineage.AssetLineage{{AssetID: "asset-123", ImageDigest: imageDigest}}, nil
			},
		},
	})
	s.app.Lineage = nil
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/lineage/asset-123", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed lineage asset lookup, got %d: %s", w.Code, w.Body.String())
	}
	if !getCalled {
		t.Fatal("expected asset lineage handler to use lineage service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/lineage/by-commit/abc123", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed commit lookup, got %d: %s", w.Code, w.Body.String())
	}
	if !commitCalled {
		t.Fatal("expected commit lineage handler to use lineage service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/lineage/by-image/sha256:abc", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed image lookup, got %d: %s", w.Code, w.Body.String())
	}
	if !imageCalled {
		t.Fatal("expected image lineage handler to use lineage service")
	}
}

func TestLineageDriftHandlerUsesServiceInterface(t *testing.T) {
	var called bool

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		lineage: stubLineageService{
			detectDriftFunc: func(_ context.Context, assetID string, currentState map[string]interface{}, iacState map[string]interface{}) ([]lineage.DriftDetail, error) {
				called = true
				if assetID != "asset-123" {
					t.Fatalf("expected asset-123, got %q", assetID)
				}
				if currentState["replicas"] != float64(3) {
					t.Fatalf("expected current replicas 3, got %#v", currentState)
				}
				if iacState["replicas"] != float64(2) {
					t.Fatalf("expected iac replicas 2, got %#v", iacState)
				}
				return []lineage.DriftDetail{{
					Field:         "replicas",
					ExpectedValue: "2",
					ActualValue:   "3",
					Source:        "iac",
				}}, nil
			},
		},
	})
	s.app.Lineage = nil
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/lineage/drift/asset-123", map[string]any{
		"current_state": map[string]any{"replicas": 3},
		"iac_state":     map[string]any{"replicas": 2},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed drift detection, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected drift handler to use lineage service")
	}

	body := decodeJSON(t, w)
	if body["drift_detected"] != true {
		t.Fatalf("expected drift_detected true, got %#v", body["drift_detected"])
	}
	drifts, ok := body["drifts"].([]any)
	if !ok || len(drifts) != 1 {
		t.Fatalf("expected one stubbed drift result, got %#v", body["drifts"])
	}
}
