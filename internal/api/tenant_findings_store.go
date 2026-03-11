package api

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/policy"
)

type tenantFindingStore struct {
	tenantID string
	base     findings.FindingStore
}

func newTenantFindingStore(base findings.FindingStore, tenantID string) findings.FindingStore {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || base == nil {
		return base
	}
	return &tenantFindingStore{
		tenantID: tenantID,
		base:     base,
	}
}

func (s *tenantFindingStore) tenantMatches(f *findings.Finding) bool {
	if f == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(f.TenantID), s.tenantID)
}

func (s *tenantFindingStore) applyTenant(filter findings.FindingFilter) findings.FindingFilter {
	filter.TenantID = s.tenantID
	return filter
}

func (s *tenantFindingStore) Upsert(ctx context.Context, pf policy.Finding) *findings.Finding {
	if pf.Resource == nil {
		pf.Resource = map[string]interface{}{}
	}
	if _, ok := pf.Resource["tenant_id"]; !ok {
		pf.Resource["tenant_id"] = s.tenantID
	}
	return s.base.Upsert(ctx, pf)
}

func (s *tenantFindingStore) Get(id string) (*findings.Finding, bool) {
	f, ok := s.base.Get(id)
	if !ok || !s.tenantMatches(f) {
		return nil, false
	}
	return f, true
}

func (s *tenantFindingStore) Update(id string, mutate func(*findings.Finding) error) error {
	if _, ok := s.Get(id); !ok {
		return findings.ErrIssueNotFound
	}
	return s.base.Update(id, mutate)
}

func (s *tenantFindingStore) List(filter findings.FindingFilter) []*findings.Finding {
	return s.base.List(s.applyTenant(filter))
}

func (s *tenantFindingStore) Count(filter findings.FindingFilter) int {
	return s.base.Count(s.applyTenant(filter))
}

func (s *tenantFindingStore) Resolve(id string) bool {
	if _, ok := s.Get(id); !ok {
		return false
	}
	return s.base.Resolve(id)
}

func (s *tenantFindingStore) Suppress(id string) bool {
	if _, ok := s.Get(id); !ok {
		return false
	}
	return s.base.Suppress(id)
}

func (s *tenantFindingStore) Stats() findings.Stats {
	list := s.List(findings.FindingFilter{})
	stats := findings.Stats{
		Total:        len(list),
		BySeverity:   map[string]int{},
		ByStatus:     map[string]int{},
		ByPolicy:     map[string]int{},
		BySignalType: map[string]int{},
		ByDomain:     map[string]int{},
	}
	for _, finding := range list {
		stats.BySeverity[strings.ToLower(strings.TrimSpace(finding.Severity))]++
		stats.ByStatus[strings.ToLower(strings.TrimSpace(finding.Status))]++
		if finding.PolicyID != "" {
			stats.ByPolicy[finding.PolicyID]++
		}
		signalType := strings.ToLower(strings.TrimSpace(finding.SignalType))
		if signalType == "" {
			signalType = findings.SignalTypeSecurity
		}
		stats.BySignalType[signalType]++
		domain := strings.ToLower(strings.TrimSpace(finding.Domain))
		if domain == "" {
			domain = findings.DomainInfra
		}
		stats.ByDomain[domain]++
	}
	return stats
}

func (s *tenantFindingStore) Sync(ctx context.Context) error {
	return s.base.Sync(ctx)
}

func (s *Server) findingsStoreForRequest(ctx context.Context) findings.FindingStore {
	return newTenantFindingStore(s.app.Findings, GetTenantID(ctx))
}
