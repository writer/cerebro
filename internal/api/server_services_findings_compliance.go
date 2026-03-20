package api

import (
	"context"
	"errors"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

var errFindingsComplianceScanUnavailable = errors.New("findings scan dependencies not configured")

type findingsComplianceService interface {
	FindingsStore(ctx context.Context) findings.FindingStore
	ScanFindings(ctx context.Context, tables []string, limit int) (*scanFindingsResponse, error)
	Reporter(ctx context.Context) *findings.ComplianceReporter
	EvaluateFramework(ctx context.Context, framework *compliance.Framework, opts compliance.EvaluationOptions) compliance.ComplianceReport
	Warn(msg string, args ...any)
}

type serverFindingsComplianceService struct {
	deps *serverDependencies
}

func newFindingsComplianceService(deps *serverDependencies) findingsComplianceService {
	return serverFindingsComplianceService{deps: deps}
}

func (s serverFindingsComplianceService) FindingsStore(ctx context.Context) findings.FindingStore {
	if s.deps == nil {
		return findings.NewStore()
	}
	store := newTenantFindingStore(s.deps.Findings, GetTenantID(ctx))
	if store == nil {
		return findings.NewStore()
	}
	return store
}

func (s serverFindingsComplianceService) ScanFindings(ctx context.Context, tables []string, limit int) (*scanFindingsResponse, error) {
	if s.deps == nil || s.deps.Warehouse == nil || s.deps.Scanner == nil {
		return nil, errFindingsComplianceScanUnavailable
	}
	if limit <= 0 {
		limit = 100
	}

	store := s.FindingsStore(ctx)
	start := time.Now()
	resp := &scanFindingsResponse{
		Findings: make([]policy.Finding, 0),
		Tables:   make([]scanFindingsTableResult, 0, len(tables)),
	}
	for _, table := range tables {
		tableResult, err := s.scanTable(ctx, store, table, limit)
		if err != nil {
			return nil, err
		}
		resp.Scanned += tableResult.Scanned
		resp.Violations += tableResult.Violations
		resp.Findings = append(resp.Findings, tableResult.Findings...)
		resp.Tables = append(resp.Tables, tableResult.Summary)
	}
	resp.Duration = time.Since(start).String()
	return resp, nil
}

func (s serverFindingsComplianceService) Reporter(ctx context.Context) *findings.ComplianceReporter {
	return findings.NewComplianceReporter(s.FindingsStore(ctx), s.policyCatalog())
}

func (s serverFindingsComplianceService) EvaluateFramework(ctx context.Context, framework *compliance.Framework, opts compliance.EvaluationOptions) compliance.ComplianceReport {
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	opts.OpenFindingsByPolicy = openFindingsByPolicy(s.FindingsStore(ctx))
	return compliance.EvaluateFramework(s.currentTenantGraph(ctx), framework, opts)
}

func (s serverFindingsComplianceService) Warn(msg string, args ...any) {
	if s.deps == nil || s.deps.Logger == nil {
		return
	}
	s.deps.Logger.Warn(msg, args...)
}

func (s serverFindingsComplianceService) policyCatalog() findings.PolicyCatalog {
	if s.deps == nil {
		return nil
	}
	return s.deps.Policy
}

func (s serverFindingsComplianceService) currentTenantGraph(ctx context.Context) *graph.Graph {
	if s.deps == nil {
		return nil
	}
	tenantID := currentTenantScopeID(ctx)
	g, err := currentOrStoredGraphView(ctx, s.deps.CurrentSecurityGraphForTenant(tenantID), s.deps.CurrentSecurityGraphStoreForTenant(tenantID))
	if err != nil {
		return nil
	}
	return g
}

func (s serverFindingsComplianceService) scanTable(ctx context.Context, store findings.FindingStore, table string, limit int) (*scanFindingsTableServiceResult, error) {
	assets, err := s.deps.Warehouse.GetAssets(ctx, table, snowflake.AssetFilter{Limit: limit})
	if err != nil {
		return nil, err
	}

	result := s.deps.Scanner.ScanAssets(ctx, assets)
	for _, finding := range result.Findings {
		if store != nil {
			store.Upsert(ctx, finding)
		}
	}

	return &scanFindingsTableServiceResult{
		Findings: result.Findings,
		Summary: scanFindingsTableResult{
			Table:      table,
			Scanned:    result.Scanned,
			Violations: result.Violations,
			Duration:   result.Duration.String(),
		},
		Scanned:    result.Scanned,
		Violations: result.Violations,
	}, nil
}

type scanFindingsResponse struct {
	Scanned    int64
	Violations int64
	Duration   string
	Findings   []policy.Finding
	Tables     []scanFindingsTableResult
}

type scanFindingsTableServiceResult struct {
	Findings   []policy.Finding
	Summary    scanFindingsTableResult
	Scanned    int64
	Violations int64
}

var _ findingsComplianceService = serverFindingsComplianceService{}
