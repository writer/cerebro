package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/threatintel"
)

type stubThreatRuntimeService struct {
	listThreatFeedsFunc       func() ([]threatintel.Feed, error)
	syncThreatFeedFunc        func(context.Context, string, string) error
	threatIntelStatsFunc      func() (map[string]interface{}, error)
	lookupIPFunc              func(string) (*threatintel.Indicator, bool, error)
	lookupDomainFunc          func(string) (*threatintel.Indicator, bool, error)
	lookupCVEFunc             func(string) (*threatintel.Indicator, bool, bool, error)
	listDetectionRulesFunc    func() ([]runtime.DetectionRule, error)
	recentFindingsFunc        func(int) ([]runtime.RuntimeFinding, error)
	listResponsePoliciesFunc  func() ([]*runtime.ResponsePolicy, error)
	enableResponsePolicyFunc  func(string) error
	disableResponsePolicyFunc func(string) error
}

func (s stubThreatRuntimeService) ListThreatFeeds() ([]threatintel.Feed, error) {
	if s.listThreatFeedsFunc != nil {
		return s.listThreatFeedsFunc()
	}
	return nil, nil
}

func (s stubThreatRuntimeService) SyncThreatFeed(ctx context.Context, id, triggeredBy string) error {
	if s.syncThreatFeedFunc != nil {
		return s.syncThreatFeedFunc(ctx, id, triggeredBy)
	}
	return nil
}

func (s stubThreatRuntimeService) ThreatIntelStats() (map[string]interface{}, error) {
	if s.threatIntelStatsFunc != nil {
		return s.threatIntelStatsFunc()
	}
	return nil, nil
}

func (s stubThreatRuntimeService) LookupIP(ip string) (*threatintel.Indicator, bool, error) {
	if s.lookupIPFunc != nil {
		return s.lookupIPFunc(ip)
	}
	return nil, false, nil
}

func (s stubThreatRuntimeService) LookupDomain(domain string) (*threatintel.Indicator, bool, error) {
	if s.lookupDomainFunc != nil {
		return s.lookupDomainFunc(domain)
	}
	return nil, false, nil
}

func (s stubThreatRuntimeService) LookupCVE(cve string) (*threatintel.Indicator, bool, bool, error) {
	if s.lookupCVEFunc != nil {
		return s.lookupCVEFunc(cve)
	}
	return nil, false, false, nil
}

func (s stubThreatRuntimeService) ListDetectionRules() ([]runtime.DetectionRule, error) {
	if s.listDetectionRulesFunc != nil {
		return s.listDetectionRulesFunc()
	}
	return nil, nil
}

func (s stubThreatRuntimeService) RecentRuntimeFindings(limit int) ([]runtime.RuntimeFinding, error) {
	if s.recentFindingsFunc != nil {
		return s.recentFindingsFunc(limit)
	}
	return nil, nil
}

func (s stubThreatRuntimeService) ListResponsePolicies() ([]*runtime.ResponsePolicy, error) {
	if s.listResponsePoliciesFunc != nil {
		return s.listResponsePoliciesFunc()
	}
	return nil, nil
}

func (s stubThreatRuntimeService) EnableResponsePolicy(id string) error {
	if s.enableResponsePolicyFunc != nil {
		return s.enableResponsePolicyFunc(id)
	}
	return nil
}

func (s stubThreatRuntimeService) DisableResponsePolicy(id string) error {
	if s.disableResponsePolicyFunc != nil {
		return s.disableResponsePolicyFunc(id)
	}
	return nil
}

func TestThreatIntelHandlersUseServiceInterface(t *testing.T) {
	var (
		listCalled   bool
		syncCalled   bool
		statsCalled  bool
		ipCalled     bool
		domainCalled bool
		cveCalled    bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		threatRuntime: stubThreatRuntimeService{
			listThreatFeedsFunc: func() ([]threatintel.Feed, error) {
				listCalled = true
				return []threatintel.Feed{{ID: "kev", Name: "CISA KEV"}}, nil
			},
			syncThreatFeedFunc: func(_ context.Context, id, _ string) error {
				syncCalled = true
				if id != "kev" {
					t.Fatalf("expected feed id kev, got %q", id)
				}
				return nil
			},
			threatIntelStatsFunc: func() (map[string]interface{}, error) {
				statsCalled = true
				return map[string]interface{}{"feeds": 1}, nil
			},
			lookupIPFunc: func(ip string) (*threatintel.Indicator, bool, error) {
				ipCalled = true
				if ip != "1.2.3.4" {
					t.Fatalf("expected ip 1.2.3.4, got %q", ip)
				}
				return &threatintel.Indicator{Value: ip, Source: "kev"}, true, nil
			},
			lookupDomainFunc: func(domain string) (*threatintel.Indicator, bool, error) {
				domainCalled = true
				if domain != "evil.example.com" {
					t.Fatalf("expected domain evil.example.com, got %q", domain)
				}
				return &threatintel.Indicator{Value: domain, Source: "urlhaus"}, true, nil
			},
			lookupCVEFunc: func(cve string) (*threatintel.Indicator, bool, bool, error) {
				cveCalled = true
				if cve != "CVE-2026-0001" {
					t.Fatalf("expected cve CVE-2026-0001, got %q", cve)
				}
				return &threatintel.Indicator{Value: cve, Source: "kev"}, true, true, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/threatintel/feeds", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed feed list, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected threat feed list handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/threatintel/feeds/kev/sync", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed feed sync, got %d: %s", w.Code, w.Body.String())
	}
	if !syncCalled {
		t.Fatal("expected threat feed sync handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/threatintel/stats", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed threat stats, got %d: %s", w.Code, w.Body.String())
	}
	if !statsCalled {
		t.Fatal("expected threat stats handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/threatintel/lookup/ip/1.2.3.4", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed ip lookup, got %d: %s", w.Code, w.Body.String())
	}
	if !ipCalled {
		t.Fatal("expected ip lookup handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/threatintel/lookup/domain/evil.example.com", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed domain lookup, got %d: %s", w.Code, w.Body.String())
	}
	if !domainCalled {
		t.Fatal("expected domain lookup handler to use threat runtime service")
	}

	cveResp := do(t, s, http.MethodGet, "/api/v1/threatintel/lookup/cve/CVE-2026-0001", nil)
	if cveResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed cve lookup, got %d: %s", cveResp.Code, cveResp.Body.String())
	}
	if !cveCalled {
		t.Fatal("expected cve lookup handler to use threat runtime service")
	}
	body := decodeJSON(t, cveResp)
	if body["is_kev"] != true {
		t.Fatalf("expected stubbed kev response, got %#v", body)
	}
}

func TestRuntimeThreatHandlersUseServiceInterface(t *testing.T) {
	var (
		rulesCalled   bool
		findingsLimit int
		listCalled    bool
		enableCalled  bool
		disableCalled bool
	)

	now := time.Date(2026, 3, 19, 17, 0, 0, 0, time.UTC)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		threatRuntime: stubThreatRuntimeService{
			listDetectionRulesFunc: func() ([]runtime.DetectionRule, error) {
				rulesCalled = true
				return []runtime.DetectionRule{{ID: "rule-1", Name: "crypto miner"}}, nil
			},
			recentFindingsFunc: func(limit int) ([]runtime.RuntimeFinding, error) {
				findingsLimit = limit
				return []runtime.RuntimeFinding{{ID: "finding-1", RuleID: "rule-1", Timestamp: now}}, nil
			},
			listResponsePoliciesFunc: func() ([]*runtime.ResponsePolicy, error) {
				listCalled = true
				return []*runtime.ResponsePolicy{{ID: "policy-1", Name: "contain miner"}}, nil
			},
			enableResponsePolicyFunc: func(id string) error {
				enableCalled = true
				if id != "policy-1" {
					t.Fatalf("expected policy-1, got %q", id)
				}
				return nil
			},
			disableResponsePolicyFunc: func(id string) error {
				disableCalled = true
				if id != "policy-1" {
					t.Fatalf("expected policy-1, got %q", id)
				}
				return nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/runtime/detections", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed detections, got %d: %s", w.Code, w.Body.String())
	}
	if !rulesCalled {
		t.Fatal("expected detections handler to use threat runtime service")
	}

	findingsResp := do(t, s, http.MethodGet, "/api/v1/runtime/findings?limit=7", nil)
	if findingsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed findings, got %d: %s", findingsResp.Code, findingsResp.Body.String())
	}
	if findingsLimit != 7 {
		t.Fatalf("expected findings limit 7, got %d", findingsLimit)
	}

	if w := do(t, s, http.MethodGet, "/api/v1/runtime/responses", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed responses, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected response policy list handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/runtime/responses/policy-1/enable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed enable policy, got %d: %s", w.Code, w.Body.String())
	}
	if !enableCalled {
		t.Fatal("expected enable policy handler to use threat runtime service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/runtime/responses/policy-1/disable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed disable policy, got %d: %s", w.Code, w.Body.String())
	}
	if !disableCalled {
		t.Fatal("expected disable policy handler to use threat runtime service")
	}
}
