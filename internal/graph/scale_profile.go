package graph

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultScaleProfileQueryIterations = 5
	defaultScaleProfileMutationDepth   = 3
	maxScaleProfileQueryIterations     = 20
	maxScaleProfileTierCount           = 8
	maxScaleProfileResourceCount       = 200000
)

var defaultScaleProfileTiers = []int{1000, 10000, 50000, 100000}

// ScaleProfileSpec controls one synthetic graph scaling profile run.
type ScaleProfileSpec struct {
	Tiers           []int `json:"tiers,omitempty"`
	QueryIterations int   `json:"query_iterations,omitempty"`
}

// ScaleProfileReport captures one synthetic graph scaling benchmark report.
type ScaleProfileReport struct {
	GeneratedAt     time.Time                 `json:"generated_at"`
	Workload        string                    `json:"workload"`
	QueryIterations int                       `json:"query_iterations"`
	Measurements    []ScaleProfileMeasurement `json:"measurements,omitempty"`
	RecommendedPath string                    `json:"recommended_path,omitempty"`
	Recommendation  string                    `json:"recommendation,omitempty"`
}

// ScaleProfileMeasurement captures one tier's benchmark results.
type ScaleProfileMeasurement struct {
	ResourceCount             int     `json:"resource_count"`
	AccountCount              int     `json:"account_count"`
	NodeCount                 int     `json:"node_count"`
	EdgeCount                 int     `json:"edge_count"`
	BuildDurationMS           float64 `json:"build_duration_ms"`
	IndexDurationMS           float64 `json:"index_duration_ms"`
	SnapshotDurationMS        float64 `json:"snapshot_duration_ms"`
	SnapshotCompressedBytes   int64   `json:"snapshot_compressed_bytes"`
	CloneDurationMS           float64 `json:"clone_duration_ms"`
	CopyOnWriteDurationMS     float64 `json:"copy_on_write_duration_ms"`
	DiffDurationMS            float64 `json:"diff_duration_ms"`
	SearchDurationMS          float64 `json:"search_duration_ms"`
	SearchResultCount         int     `json:"search_result_count"`
	SuggestDurationMS         float64 `json:"suggest_duration_ms"`
	SuggestResultCount        int     `json:"suggest_result_count"`
	BlastRadiusColdDurationMS float64 `json:"blast_radius_cold_duration_ms"`
	BlastRadiusWarmDurationMS float64 `json:"blast_radius_warm_duration_ms"`
	BlastRadiusReachableCount int     `json:"blast_radius_reachable_count"`
	NodesModifiedInDiff       int     `json:"nodes_modified_in_diff"`
	EdgesAddedInDiff          int     `json:"edges_added_in_diff"`
	HeapAllocBytes            uint64  `json:"heap_alloc_bytes"`
	TotalAllocBytes           uint64  `json:"total_alloc_bytes"`
	HeapObjects               uint64  `json:"heap_objects"`
}

type scaleSyntheticFixture struct {
	principalID    string
	mutationNodeID string
	searchQuery    string
	suggestPrefix  string
}

// NormalizeScaleProfileSpec fills defaults and canonicalizes the requested tiers.
func NormalizeScaleProfileSpec(spec ScaleProfileSpec) ScaleProfileSpec {
	seen := make(map[int]struct{})
	tiers := make([]int, 0, len(spec.Tiers))
	for _, tier := range spec.Tiers {
		if tier <= 0 {
			continue
		}
		if _, ok := seen[tier]; ok {
			continue
		}
		seen[tier] = struct{}{}
		tiers = append(tiers, tier)
	}
	if len(tiers) == 0 {
		tiers = append(tiers, defaultScaleProfileTiers...)
	}
	sort.Ints(tiers)
	spec.Tiers = tiers
	if spec.QueryIterations <= 0 {
		spec.QueryIterations = defaultScaleProfileQueryIterations
	}
	return spec
}

// ProfileSyntheticScale benchmarks synthetic graph tiers to guide scaling decisions.
func ProfileSyntheticScale(spec ScaleProfileSpec) (*ScaleProfileReport, error) {
	normalized := NormalizeScaleProfileSpec(spec)
	if err := validateScaleProfileSpec(normalized); err != nil {
		return nil, err
	}
	report := &ScaleProfileReport{
		GeneratedAt:     time.Now().UTC(),
		Workload:        "synthetic_estate_v1",
		QueryIterations: normalized.QueryIterations,
		Measurements:    make([]ScaleProfileMeasurement, 0, len(normalized.Tiers)),
	}
	for _, tier := range normalized.Tiers {
		measurement, err := profileSyntheticScaleTier(tier, normalized.QueryIterations)
		if err != nil {
			return nil, err
		}
		report.Measurements = append(report.Measurements, measurement)
	}
	path, recommendation := recommendScalePath(report.Measurements)
	report.RecommendedPath = path
	report.Recommendation = recommendation
	return report, nil
}

func validateScaleProfileSpec(spec ScaleProfileSpec) error {
	if len(spec.Tiers) > maxScaleProfileTierCount {
		return fmt.Errorf("at most %d tiers may be profiled in one run", maxScaleProfileTierCount)
	}
	if spec.QueryIterations <= 0 || spec.QueryIterations > maxScaleProfileQueryIterations {
		return fmt.Errorf("query iterations must be between 1 and %d", maxScaleProfileQueryIterations)
	}
	for _, tier := range spec.Tiers {
		if tier > maxScaleProfileResourceCount {
			return fmt.Errorf("resource tier %d exceeds the maximum supported tier size of %d", tier, maxScaleProfileResourceCount)
		}
	}
	return nil
}

func profileSyntheticScaleTier(resourceCount, queryIterations int) (ScaleProfileMeasurement, error) {
	runtime.GC()
	before := readScaleMemStats()

	buildStart := time.Now()
	g, fixture := buildSyntheticScaleGraph(resourceCount)
	buildDuration := time.Since(buildStart)
	if g == nil {
		return ScaleProfileMeasurement{}, fmt.Errorf("build synthetic graph: nil graph")
	}

	indexStart := time.Now()
	g.BuildIndex()
	indexDuration := time.Since(indexStart)

	runtime.GC()
	afterBuild := readScaleMemStats()

	searchDuration, searchCount := measureSearchLatency(g, fixture.searchQuery, queryIterations)
	suggestDuration, suggestCount := measureSuggestLatency(g, fixture.suggestPrefix, queryIterations)

	blastStart := time.Now()
	blastCold := BlastRadius(g, fixture.principalID, defaultScaleProfileMutationDepth)
	blastColdDuration := time.Since(blastStart)
	blastWarmStart := time.Now()
	blastWarm := BlastRadius(g, fixture.principalID, defaultScaleProfileMutationDepth)
	blastWarmDuration := time.Since(blastWarmStart)
	blastReachable := 0
	if blastWarm != nil {
		blastReachable = blastWarm.TotalCount
	} else if blastCold != nil {
		blastReachable = blastCold.TotalCount
	}

	snapshotStart := time.Now()
	snapshot := CreateSnapshot(g)
	snapshotDuration := time.Since(snapshotStart)
	snapshotCompressedBytes, err := measureCompressedSnapshotSize(snapshot)
	if err != nil {
		return ScaleProfileMeasurement{}, err
	}

	cloneStart := time.Now()
	clone := g.Clone()
	cloneDuration := time.Since(cloneStart)

	copyOnWriteStart := time.Now()
	candidate := g.Fork()
	candidate.SetNodeProperty(fixture.mutationNodeID, "profile_marker", fmt.Sprintf("tier-%d", resourceCount))
	candidate.BuildIndex()
	copyOnWriteDuration := time.Since(copyOnWriteStart)

	diffStart := time.Now()
	diff := DiffSnapshots(snapshot, CreateSnapshot(candidate))
	diffDuration := time.Since(diffStart)

	runtime.KeepAlive(g)
	runtime.KeepAlive(clone)
	runtime.KeepAlive(candidate)
	runtime.GC()
	afterOps := readScaleMemStats()

	measurement := ScaleProfileMeasurement{
		ResourceCount:             resourceCount,
		AccountCount:              syntheticAccountCount(resourceCount),
		NodeCount:                 g.NodeCount(),
		EdgeCount:                 g.EdgeCount(),
		BuildDurationMS:           durationMillis(buildDuration),
		IndexDurationMS:           durationMillis(indexDuration),
		SnapshotDurationMS:        durationMillis(snapshotDuration),
		SnapshotCompressedBytes:   snapshotCompressedBytes,
		CloneDurationMS:           durationMillis(cloneDuration),
		CopyOnWriteDurationMS:     durationMillis(copyOnWriteDuration),
		DiffDurationMS:            durationMillis(diffDuration),
		SearchDurationMS:          durationMillis(searchDuration),
		SearchResultCount:         searchCount,
		SuggestDurationMS:         durationMillis(suggestDuration),
		SuggestResultCount:        suggestCount,
		BlastRadiusColdDurationMS: durationMillis(blastColdDuration),
		BlastRadiusWarmDurationMS: durationMillis(blastWarmDuration),
		BlastRadiusReachableCount: blastReachable,
		HeapAllocBytes:            saturatingUint64Diff(afterBuild.HeapAlloc, before.HeapAlloc),
		TotalAllocBytes:           saturatingUint64Diff(afterOps.TotalAlloc, before.TotalAlloc),
		HeapObjects:               saturatingUint64Diff(afterBuild.HeapObjects, before.HeapObjects),
	}
	if diff != nil {
		measurement.NodesModifiedInDiff = len(diff.NodesModified)
		measurement.EdgesAddedInDiff = len(diff.EdgesAdded)
	}
	return measurement, nil
}

func buildSyntheticScaleGraph(resourceCount int) (*Graph, scaleSyntheticFixture) {
	g := New()
	now := time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)
	internetNode := &Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet", Risk: RiskHigh, CreatedAt: now, UpdatedAt: now, Version: 1}
	g.AddNode(internetNode)

	serviceNames := []string{"payments", "auth", "billing", "orders", "search", "analytics", "messaging", "identity"}
	fixture := scaleSyntheticFixture{searchQuery: "payments", suggestPrefix: "pay"}
	accounts := syntheticAccountCount(resourceCount)
	resourcesAssigned := 0
	for accountIdx := 0; accountIdx < accounts; accountIdx++ {
		accountID := fmt.Sprintf("acct-%03d", accountIdx+1)
		tenantID := fmt.Sprintf("tenant-%02d", accountIdx%8+1)
		provider := "aws"
		userID := fmt.Sprintf("user:%s:admin", accountID)
		user := &Node{
			ID:        userID,
			Kind:      NodeKindUser,
			Name:      fmt.Sprintf("%s admin", accountID),
			Provider:  provider,
			Account:   accountID,
			Risk:      RiskMedium,
			CreatedAt: now,
			UpdatedAt: now,
			Version:   1,
			Properties: map[string]any{
				"tenant_id":     tenantID,
				"source_system": "synthetic",
			},
		}
		g.AddNode(user)
		if fixture.principalID == "" {
			fixture.principalID = userID
		}

		accountResources := resourceCount / accounts
		if accountIdx < resourceCount%accounts {
			accountResources++
		}
		roleCount := maxInt(2, accountResources/250)
		roles := make([]string, 0, roleCount)
		for roleIdx := 0; roleIdx < roleCount; roleIdx++ {
			roleID := fmt.Sprintf("role:%s:%02d", accountID, roleIdx+1)
			role := &Node{
				ID:        roleID,
				Kind:      NodeKindRole,
				Name:      fmt.Sprintf("%s role %02d", accountID, roleIdx+1),
				Provider:  provider,
				Account:   accountID,
				Risk:      RiskMedium,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
				Properties: map[string]any{
					"tenant_id":     tenantID,
					"source_system": "synthetic",
				},
			}
			g.AddNode(role)
			roles = append(roles, roleID)
			g.AddEdge(&Edge{ID: fmt.Sprintf("edge:%s:%s:assume", userID, roleID), Source: userID, Target: roleID, Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
		}

		serviceCount := maxInt(1, accountResources/250)
		serviceIDs := make([]string, 0, serviceCount)
		for serviceIdx := 0; serviceIdx < serviceCount; serviceIdx++ {
			serviceLabel := serviceNames[(serviceIdx+accountIdx)%len(serviceNames)]
			serviceID := fmt.Sprintf("service:%s:%s:%03d", accountID, serviceLabel, serviceIdx+1)
			service := &Node{
				ID:        serviceID,
				Kind:      NodeKindService,
				Name:      fmt.Sprintf("%s-%03d", serviceLabel, serviceIdx+1),
				Provider:  provider,
				Account:   accountID,
				Risk:      RiskLow,
				CreatedAt: now,
				UpdatedAt: now,
				Version:   1,
				Properties: map[string]any{
					"tenant_id":     tenantID,
					"service_id":    serviceLabel,
					"environment":   environmentForIndex(serviceIdx),
					"source_system": "synthetic",
				},
			}
			g.AddNode(service)
			serviceIDs = append(serviceIDs, serviceID)
			roleID := roles[serviceIdx%len(roles)]
			g.AddEdge(&Edge{ID: fmt.Sprintf("edge:%s:%s:admin", roleID, serviceID), Source: roleID, Target: serviceID, Kind: EdgeKindCanAdmin, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
		}

		lastByService := make(map[string]string, len(serviceIDs))
		for resourceIdx := 0; resourceIdx < accountResources; resourceIdx++ {
			globalIdx := resourcesAssigned + resourceIdx
			serviceID := serviceIDs[resourceIdx%len(serviceIDs)]
			serviceLabel := serviceNames[(resourceIdx+accountIdx)%len(serviceNames)]
			kind, risk, props := syntheticResourceShape(globalIdx, tenantID, serviceLabel)
			resourceID := fmt.Sprintf("%s:%s:%06d", kind, accountID, globalIdx+1)
			resource := &Node{
				ID:         resourceID,
				Kind:       kind,
				Name:       fmt.Sprintf("%s-%06d", serviceLabel, globalIdx+1),
				Provider:   provider,
				Account:    accountID,
				Region:     fmt.Sprintf("us-west-%d", (accountIdx%3)+1),
				Risk:       risk,
				CreatedAt:  now,
				UpdatedAt:  now,
				Version:    1,
				Properties: props,
				Tags: map[string]string{
					"team":        serviceLabel,
					"tenant_id":   tenantID,
					"environment": environmentForIndex(resourceIdx),
				},
			}
			g.AddNode(resource)
			if fixture.mutationNodeID == "" {
				fixture.mutationNodeID = resourceID
			}

			roleID := roles[resourceIdx%len(roles)]
			permissionKind := []EdgeKind{EdgeKindCanRead, EdgeKindCanWrite, EdgeKindCanAdmin}[resourceIdx%3]
			g.AddEdge(&Edge{ID: fmt.Sprintf("edge:%s:%s:perm", roleID, resourceID), Source: roleID, Target: resourceID, Kind: permissionKind, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
			g.AddEdge(&Edge{ID: fmt.Sprintf("edge:%s:%s:service", serviceID, resourceID), Source: serviceID, Target: resourceID, Kind: EdgeKindRuns, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
			if previous := lastByService[serviceID]; previous != "" {
				g.AddEdge(&Edge{ID: fmt.Sprintf("edge:%s:%s:dep", resourceID, previous), Source: resourceID, Target: previous, Kind: EdgeKindDependsOn, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
			}
			lastByService[serviceID] = resourceID
			if publicFacing(kind, props) {
				g.AddEdge(&Edge{ID: fmt.Sprintf("edge:internet:%s:exposed", resourceID), Source: "internet", Target: resourceID, Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow, Priority: 50, CreatedAt: now, Version: 1})
			}
		}
		resourcesAssigned += accountResources
	}

	g.SetMetadata(Metadata{
		BuiltAt:       now,
		NodeCount:     g.NodeCount(),
		EdgeCount:     g.EdgeCount(),
		Providers:     []string{"aws"},
		Accounts:      syntheticAccounts(accounts),
		BuildDuration: 0,
	})
	return g, fixture
}

func syntheticResourceShape(globalIdx int, tenantID, serviceLabel string) (NodeKind, RiskLevel, map[string]any) {
	props := map[string]any{
		"tenant_id":     tenantID,
		"service_id":    serviceLabel,
		"source_system": "synthetic",
		"environment":   environmentForIndex(globalIdx),
	}
	switch globalIdx % 4 {
	case 0:
		internetExposed := globalIdx%7 == 0
		props["internet_exposed"] = internetExposed
		if internetExposed {
			props["public_ip"] = fmt.Sprintf("203.0.113.%d", (globalIdx%200)+1)
		}
		return NodeKindWorkload, syntheticRisk(globalIdx, 7, 13), props
	case 1:
		props["public"] = globalIdx%9 == 0
		props["bucket_versioning"] = globalIdx%5 != 0
		return NodeKindBucket, syntheticRisk(globalIdx, 9, 17), props
	case 2:
		props["data_classification"] = "restricted"
		props["contains_pii"] = globalIdx%3 == 0
		return NodeKindDatabase, syntheticRisk(globalIdx, 11, 19), props
	default:
		if globalIdx%5 == 0 {
			props["function_url"] = fmt.Sprintf("https://%s-%06d.example.com", serviceLabel, globalIdx+1)
		}
		props["runtime"] = []string{"go1.x", "python3.12", "nodejs20.x"}[globalIdx%3]
		return NodeKindFunction, syntheticRisk(globalIdx, 8, 23), props
	}
}

func syntheticRisk(index, highMod, criticalMod int) RiskLevel {
	switch {
	case index%criticalMod == 0:
		return RiskCritical
	case index%highMod == 0:
		return RiskHigh
	case index%5 == 0:
		return RiskMedium
	default:
		return RiskLow
	}
}

func publicFacing(kind NodeKind, props map[string]any) bool {
	if exposed, ok := props["internet_exposed"].(bool); ok && exposed {
		return true
	}
	if public, ok := props["public"].(bool); ok && public {
		return true
	}
	if publicIP, ok := props["public_ip"].(string); ok && strings.TrimSpace(publicIP) != "" {
		return true
	}
	if !NodeKindHasCapability(kind, NodeCapabilityInternetExposable) {
		return false
	}
	if url, ok := props["function_url"].(string); ok && strings.TrimSpace(url) != "" {
		return true
	}
	return false
}

func environmentForIndex(index int) string {
	switch index % 3 {
	case 0:
		return "production"
	case 1:
		return "staging"
	default:
		return "development"
	}
}

func syntheticAccountCount(resourceCount int) int {
	switch {
	case resourceCount >= 100000:
		return 16
	case resourceCount >= 50000:
		return 8
	case resourceCount >= 10000:
		return 4
	case resourceCount >= 1000:
		return 2
	default:
		return 1
	}
}

func syntheticAccounts(count int) []string {
	accounts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		accounts = append(accounts, fmt.Sprintf("acct-%03d", i+1))
	}
	return accounts
}

func measureSearchLatency(g *Graph, query string, iterations int) (time.Duration, int) {
	var total time.Duration
	resultCount := 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		result := SearchEntities(g, EntitySearchOptions{Query: query, Limit: 20, Fuzzy: true})
		total += time.Since(start)
		if i == 0 {
			resultCount = result.Count
		}
	}
	return averageDuration(total, iterations), resultCount
}

func measureSuggestLatency(g *Graph, prefix string, iterations int) (time.Duration, int) {
	var total time.Duration
	resultCount := 0
	for i := 0; i < iterations; i++ {
		start := time.Now()
		result := SuggestEntities(g, EntitySuggestOptions{Prefix: prefix, Limit: 10})
		total += time.Since(start)
		if i == 0 {
			resultCount = result.Count
		}
	}
	return averageDuration(total, iterations), resultCount
}

func measureCompressedSnapshotSize(snapshot *Snapshot) (int64, error) {
	if snapshot == nil {
		return 0, fmt.Errorf("snapshot is required")
	}
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gzipWriter).Encode(snapshot); err != nil {
		_ = gzipWriter.Close()
		return 0, fmt.Errorf("encode compressed snapshot: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return 0, fmt.Errorf("close compressed snapshot writer: %w", err)
	}
	return int64(buf.Len()), nil
}

func recommendScalePath(measurements []ScaleProfileMeasurement) (string, string) {
	if len(measurements) == 0 {
		return "unknown", "No measurements collected"
	}
	maxMeasurement := measurements[len(measurements)-1]
	switch {
	case maxMeasurement.HeapAllocBytes >= 1536*1024*1024 || maxMeasurement.CopyOnWriteDurationMS >= 1500:
		return "hybrid_persistent_graph", "The hot in-memory graph is approaching an unsafe single-process budget. Keep hot indexes in memory, move snapshots and historical graph state to durable backing storage, and avoid deepening SQLite-only execution paths."
	case maxMeasurement.HeapAllocBytes >= 512*1024*1024 || maxMeasurement.CopyOnWriteDurationMS >= 250:
		return "tenant_sharded_hot_graph", "Single-node in-memory remains viable for smaller tenants, but large tenants need tenant/account partitioning plus read replicas and object-backed snapshots before pushing further scale."
	default:
		return "single_node_with_replicated_snapshots", "The graph still fits single-node memory budgets at the tested tiers. Keep the hot graph in memory, but pair it with replicated snapshots and a higher-scale execution-store backend before introducing multi-worker graph writers."
	}
}

func readScaleMemStats() runtime.MemStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats
}

func averageDuration(total time.Duration, count int) time.Duration {
	if count <= 0 {
		return 0
	}
	return time.Duration(int64(total) / int64(count))
}

func durationMillis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func saturatingUint64Diff(after, before uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}
