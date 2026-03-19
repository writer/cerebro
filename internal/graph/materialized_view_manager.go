package graph

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type MaterializedDetectionViewsConfig struct {
	RefreshDebounce      time.Duration `json:"refresh_debounce"`
	BlastRadiusTopNLimit int           `json:"blast_radius_top_n_limit"`
	BlastRadiusTopNDepth int           `json:"blast_radius_top_n_depth"`
}

type MaterializedToxicCombinationsView struct {
	GeneratedAt  time.Time           `json:"generated_at"`
	Version      uint64              `json:"version"`
	Combinations []*ToxicCombination `json:"combinations,omitempty"`
	TotalCount   int                 `json:"total_count"`
}

type MaterializedDetectionViewManager struct {
	graph       *Graph
	logger      *slog.Logger
	config      MaterializedDetectionViewsConfig
	toxicEngine *ToxicCombinationEngine

	mu                sync.RWMutex
	running           bool
	stopCh            chan struct{}
	wg                sync.WaitGroup
	blastRadiusTopN   *BlastRadiusTopNView
	toxicCombinations *MaterializedToxicCombinationsView

	blastRadiusRefreshHook func()
	toxicRefreshHook       func()
}

func NewMaterializedDetectionViewManager(g *Graph, config MaterializedDetectionViewsConfig, logger *slog.Logger) *MaterializedDetectionViewManager {
	if logger == nil {
		logger = slog.Default()
	}
	if config.BlastRadiusTopNLimit <= 0 {
		config.BlastRadiusTopNLimit = defaultBlastRadiusTopNLimit
	}
	if config.BlastRadiusTopNDepth <= 0 {
		config.BlastRadiusTopNDepth = defaultBlastRadiusTopNDepth
	}
	if config.RefreshDebounce <= 0 {
		config.RefreshDebounce = defaultMonitorDebounce
	}

	return &MaterializedDetectionViewManager{
		graph:       g,
		logger:      logger,
		config:      config,
		toxicEngine: NewToxicCombinationEngine(),
	}
}

func (m *MaterializedDetectionViewManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("materialized detection view manager already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	m.mu.Unlock()

	m.logger.Info("starting materialized detection view manager",
		"refresh_debounce", m.config.RefreshDebounce,
		"blast_radius_top_n_limit", m.config.BlastRadiusTopNLimit,
		"blast_radius_top_n_depth", m.config.BlastRadiusTopNDepth)

	m.wg.Add(2)
	go m.runWorker(ctx, stopCh, "blast_radius_top_n", blastRadiusTopNViewChangeFilter(), m.refreshBlastRadiusTopNView)
	go m.runWorker(ctx, stopCh, "toxic_combinations", toxicCombinationMonitorChangeFilter(), m.refreshToxicCombinationsView)
	return nil
}

func (m *MaterializedDetectionViewManager) runWorker(
	ctx context.Context,
	stopCh <-chan struct{},
	name string,
	filter GraphChangeFilter,
	refresh func(),
) {
	defer m.wg.Done()
	if err := runReactiveMonitorLoop(ctx, m.graph, stopCh, m.config.RefreshDebounce, filter, refresh); err != nil && !errors.Is(err, context.Canceled) {
		m.logger.Warn("materialized detection view worker stopped", "view", name, "error", err)
	}
}

func (m *MaterializedDetectionViewManager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	stopCh := m.stopCh
	m.running = false
	m.stopCh = nil
	m.mu.Unlock()

	close(stopCh)
	m.wg.Wait()
}

func (m *MaterializedDetectionViewManager) BlastRadiusTopNView() *BlastRadiusTopNView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneBlastRadiusTopNView(m.blastRadiusTopN)
}

func (m *MaterializedDetectionViewManager) ToxicCombinationsView() *MaterializedToxicCombinationsView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneMaterializedToxicCombinationsView(m.toxicCombinations)
}

func (m *MaterializedDetectionViewManager) refreshBlastRadiusTopNView() {
	if m.blastRadiusRefreshHook != nil {
		m.blastRadiusRefreshHook()
	}
	scanGraph := cloneGraphForMonitorScan(m.graph)
	topN := BlastRadiusTopN(scanGraph, m.config.BlastRadiusTopNLimit, m.config.BlastRadiusTopNDepth)
	m.mu.Lock()
	m.blastRadiusTopN = cloneBlastRadiusTopNView(topN)
	m.mu.Unlock()
}

func (m *MaterializedDetectionViewManager) refreshToxicCombinationsView() {
	if m.toxicRefreshHook != nil {
		m.toxicRefreshHook()
	}
	scanGraph := cloneGraphForMonitorScan(m.graph)
	version := scanGraph.currentBlastRadiusCacheVersion()
	combinations := m.toxicEngine.Analyze(scanGraph)
	materializedView := &MaterializedToxicCombinationsView{
		GeneratedAt:  temporalNowUTC(),
		Version:      version,
		Combinations: cloneToxicCombinations(combinations),
		TotalCount:   len(combinations),
	}
	m.mu.Lock()
	m.toxicCombinations = materializedView
	m.mu.Unlock()
}

func cloneMaterializedToxicCombinationsView(view *MaterializedToxicCombinationsView) *MaterializedToxicCombinationsView {
	if view == nil {
		return nil
	}
	cloned := *view
	cloned.Combinations = cloneToxicCombinations(view.Combinations)
	return &cloned
}

func cloneToxicCombinations(values []*ToxicCombination) []*ToxicCombination {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]*ToxicCombination, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		next := *value
		next.Factors = append([]*RiskFactor(nil), value.Factors...)
		next.Remediation = append([]*RemediationStep(nil), value.Remediation...)
		next.AffectedAssets = append([]string(nil), value.AffectedAssets...)
		next.Tags = append([]string(nil), value.Tags...)
		if value.AttackPath != nil {
			pathCopy := *value.AttackPath
			pathCopy.Steps = append([]*AttackStep(nil), value.AttackPath.Steps...)
			next.AttackPath = &pathCopy
		}
		cloned = append(cloned, &next)
	}
	return cloned
}

func blastRadiusTopNViewChangeFilter() GraphChangeFilter {
	return GraphChangeFilter{
		NodeKinds: []NodeKind{
			NodeKindUser,
			NodeKindPerson,
			NodeKindIdentityAlias,
			NodeKindRole,
			NodeKindGroup,
			NodeKindServiceAccount,
			NodeKindInternet,
			NodeKindService,
			NodeKindWorkload,
			NodeKindBucket,
			NodeKindInstance,
			NodeKindDatabase,
			NodeKindSecret,
			NodeKindFunction,
			NodeKindPod,
			NodeKindApplication,
			NodeKindNetwork,
		},
		EdgeKinds: []EdgeKind{
			EdgeKindCanAssume,
			EdgeKindMemberOf,
			EdgeKindResolvesTo,
			EdgeKindAliasOf,
			EdgeKindCanRead,
			EdgeKindCanWrite,
			EdgeKindCanDelete,
			EdgeKindCanAdmin,
			EdgeKindConnectsTo,
			EdgeKindCalls,
			EdgeKindRuns,
			EdgeKindDependsOn,
			EdgeKindExposedTo,
			EdgeKindContains,
			EdgeKindHasCredentialFor,
		},
	}
}
