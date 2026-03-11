package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/policy"
)

func TestListPolicies_SendsPaginationAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("expected limit query, got %q", got)
		}
		if got := r.URL.Query().Get("offset"); got != "5" {
			t.Fatalf("expected offset query, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"policies": []map[string]interface{}{
				{
					"id":       "policy-1",
					"name":     "Policy 1",
					"severity": "high",
					"resource": "aws::s3::bucket",
				},
			},
			"count": 1,
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	policies, err := c.ListPolicies(context.Background(), 10, 5)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(policies))
	}
	if policies[0].ID != "policy-1" {
		t.Fatalf("unexpected policy ID: %s", policies[0].ID)
	}
}

func TestGetPolicy_SendsPathAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/policies/policy-1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       "policy-1",
			"name":     "Policy 1",
			"effect":   "forbid",
			"resource": "aws::s3::bucket",
			"severity": "high",
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	p, err := c.GetPolicy(context.Background(), "policy-1")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
	if p.ID != "policy-1" {
		t.Fatalf("unexpected policy id: %s", p.ID)
	}
}

func TestDryRunPolicyChange_SendsCandidateAndAssets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/policies/policy-1/dry-run" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		payload := string(body)
		if !strings.Contains(payload, "\"policy\"") || !strings.Contains(payload, "\"assets\"") {
			t.Fatalf("expected policy/assets in request payload, got %s", payload)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"dry_run":      true,
			"policy_id":    "policy-1",
			"asset_source": "request",
			"diff": map[string]interface{}{
				"changed": true,
				"field_diffs": []map[string]interface{}{
					{"field": "conditions", "before": []string{"a"}, "after": []string{"b"}},
				},
			},
			"impact": map[string]interface{}{
				"asset_count":         1,
				"before_matches":      1,
				"after_matches":       1,
				"added_finding_ids":   []string{},
				"removed_finding_ids": []string{},
				"new_findings":        []map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.DryRunPolicyChange(context.Background(), "policy-1", policy.Policy{
		ID:         "policy-1",
		Name:       "Candidate",
		Effect:     "forbid",
		Resource:   "aws::s3::bucket",
		Conditions: []string{"public == false"},
		Severity:   "high",
	}, []map[string]interface{}{{"_cq_id": "a"}}, 0)
	if err != nil {
		t.Fatalf("dry-run policy change: %v", err)
	}
	if resp.PolicyID != "policy-1" {
		t.Fatalf("unexpected policy_id: %s", resp.PolicyID)
	}
	if !resp.Diff.Changed {
		t.Fatal("expected changed diff")
	}
	if resp.Impact == nil || resp.Impact.AssetCount != 1 {
		t.Fatalf("expected impact asset_count=1, got %+v", resp.Impact)
	}
}
