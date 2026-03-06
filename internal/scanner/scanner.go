package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/cache"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

// Scanner performs parallel policy evaluation across assets
type Scanner struct {
	engine           *policy.Engine
	toxicDetector    *attackpath.ToxicCombinationDetector
	graphToxicEngine *graph.ToxicCombinationEngine
	workers          int
	batchSize        int
	logger           *slog.Logger
	evalCache        *cache.PolicyCache // optional: caches asset hash -> skip
}

type ScanConfig struct {
	Workers   int
	BatchSize int
}

func NewScanner(engine *policy.Engine, cfg ScanConfig, logger *slog.Logger) *Scanner {
	if cfg.Workers == 0 {
		cfg.Workers = 10
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	return &Scanner{
		engine:           engine,
		toxicDetector:    attackpath.NewToxicCombinationDetector(),
		graphToxicEngine: graph.NewToxicCombinationEngine(),
		workers:          cfg.Workers,
		batchSize:        cfg.BatchSize,
		logger:           logger,
	}
}

// SetCache enables evaluation caching. Cached assets whose content hash
// hasn't changed will skip policy evaluation on subsequent scans.
func (s *Scanner) SetCache(c *cache.PolicyCache) {
	s.evalCache = c
}

// hashAsset produces a deterministic content hash of the asset properties,
// excluding volatile metadata fields (_cq_sync_time, _cq_id, _cq_table).
func hashAsset(asset map[string]interface{}) string {
	keys := make([]string, 0, len(asset))
	for k := range asset {
		if k == "_cq_sync_time" || k == "_cq_id" || k == "_cq_table" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		v, _ := json.Marshal(asset[k])
		h.Write([]byte(k))
		h.Write(v)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type ScanResult struct {
	Findings   []policy.Finding
	Scanned    int64
	Violations int64
	Skipped    int64 // assets skipped via cache
	Duration   time.Duration
	Errors     []string
}

// ScanAssets evaluates policies against assets using a worker pool
func (s *Scanner) ScanAssets(ctx context.Context, assets []map[string]interface{}) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Findings: make([]policy.Finding, 0),
	}

	if len(assets) == 0 {
		return result
	}

	// Channel for assets to scan
	assetCh := make(chan map[string]interface{}, s.batchSize)

	// Channel for results
	resultCh := make(chan []policy.Finding, s.workers)

	// Error channel
	errCh := make(chan string, s.workers)

	var scanned int64
	var violations int64
	var skipped int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range assetCh {
				// Check context before processing
				select {
				case <-ctx.Done():
					return
				default:
				}

				assetID := ""
				if id, ok := asset["_cq_id"].(string); ok {
					assetID = id
				}

				// Compute content hash once for both cache lookup and store
				var contentHash string
				if s.evalCache != nil && assetID != "" {
					contentHash = hashAsset(asset)
					if cached, hit := s.evalCache.GetEvaluation(contentHash, assetID); hit {
						atomic.AddInt64(&scanned, 1)
						atomic.AddInt64(&skipped, 1)
						if cachedFindings, ok := cached.([]policy.Finding); ok && len(cachedFindings) > 0 {
							atomic.AddInt64(&violations, int64(len(cachedFindings)))
							select {
							case resultCh <- cachedFindings:
							case <-ctx.Done():
								return
							}
						}
						continue
					}
				}

				findings, err := s.engine.EvaluateAsset(ctx, asset)
				atomic.AddInt64(&scanned, 1)

				if err != nil {
					select {
					case errCh <- err.Error():
					default:
					}
					continue
				}

				if s.evalCache != nil && assetID != "" {
					s.evalCache.SetEvaluation(contentHash, assetID, findings)
				}

				if len(findings) > 0 {
					atomic.AddInt64(&violations, int64(len(findings)))
					select {
					case resultCh <- findings:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Feed assets to workers
	go func() {
		defer close(assetCh) // Always close channel when done
		for _, asset := range assets {
			select {
			case assetCh <- asset:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	// Aggregate findings
	for findings := range resultCh {
		result.Findings = append(result.Findings, findings...)
	}

	// Collect errors
	for err := range errCh {
		result.Errors = append(result.Errors, err)
	}

	result.Scanned = atomic.LoadInt64(&scanned)
	result.Violations = atomic.LoadInt64(&violations)
	result.Skipped = atomic.LoadInt64(&skipped)
	result.Duration = time.Since(start)

	s.logger.Info("scan complete",
		"scanned", result.Scanned,
		"violations", result.Violations,
		"cache_skipped", result.Skipped,
		"duration_ms", result.Duration.Milliseconds(),
	)

	return result
}

// ScanWithToxicCombinations runs policy evaluation AND toxic combination detection
func (s *Scanner) ScanWithToxicCombinations(ctx context.Context, assets []map[string]interface{}) *EnhancedScanResult {
	// First run standard policy scan
	policyResult := s.ScanAssets(ctx, assets)

	toxicFindings := s.DetectToxicCombinations(ctx, assets)

	return &EnhancedScanResult{
		ScanResult:        policyResult,
		ToxicCombinations: toxicFindings,
	}
}

// EnhancedScanResult includes both policy findings and toxic combinations
type EnhancedScanResult struct {
	*ScanResult
	ToxicCombinations []policy.Finding
}

// AttackPathSummary is a simplified attack path for findings output
type AttackPathSummary struct {
	ID             string   `json:"id"`
	EntryPoint     string   `json:"entry_point"`
	Target         string   `json:"target"`
	Steps          []string `json:"steps"`
	Length         int      `json:"length"`
	RiskScore      float64  `json:"risk_score"`
	Exploitability float64  `json:"exploitability"`
	Impact         float64  `json:"impact"`
}

// AttackPathStats summarizes attack path analysis.
type AttackPathStats struct {
	TotalPaths      int         `json:"total_paths"`
	CriticalPaths   int         `json:"critical_paths"`
	EntryPointCount int         `json:"entry_point_count"`
	CrownJewelCount int         `json:"crown_jewel_count"`
	MeanPathLength  float64     `json:"mean_path_length"`
	ShortestPath    int         `json:"shortest_path"`
	LengthCounts    map[int]int `json:"length_counts"`
}

// AttackPathChokepointSummary summarizes chokepoint impact for reporting.
type AttackPathChokepointSummary struct {
	NodeID             string  `json:"node_id"`
	NodeName           string  `json:"node_name"`
	PathsThrough       int     `json:"paths_through"`
	BlockedPaths       int     `json:"blocked_paths"`
	RemediationImpact  float64 `json:"remediation_impact"`
	UpstreamEntryCount int     `json:"upstream_entry_count"`
	DownstreamCount    int     `json:"downstream_target_count"`
}

// GraphAnalysisResult contains graph-based toxic combinations and attack paths
type GraphAnalysisResult struct {
	ToxicCombinations []policy.Finding
	AttackPaths       []AttackPathSummary
	AttackPathStats   AttackPathStats
	Chokepoints       []AttackPathChokepointSummary
}

// AllFindings returns combined policy and toxic combination findings
func (r *EnhancedScanResult) AllFindings() []policy.Finding {
	all := make([]policy.Finding, 0, len(r.Findings)+len(r.ToxicCombinations))
	all = append(all, r.Findings...)
	all = append(all, r.ToxicCombinations...)
	return all
}

// DetectToxicCombinations runs risk-profile based toxic combination detection
func (s *Scanner) DetectToxicCombinations(ctx context.Context, assets []map[string]interface{}) []policy.Finding {
	// Build risk profiles from assets
	profiles := make([]attackpath.ResourceRiskProfile, 0, len(assets))
	for _, asset := range assets {
		profile := s.buildRiskProfile(asset)
		if len(profile.RiskFactors) > 0 {
			profiles = append(profiles, profile)
		}
	}

	// Detect toxic combinations
	toxicCombos := s.toxicDetector.Detect(ctx, profiles)

	// Convert toxic combinations to findings
	toxicFindings := make([]policy.Finding, 0, len(toxicCombos))
	for _, combo := range toxicCombos {
		finding := policy.Finding{
			ID:           combo.ID,
			PolicyID:     "toxic-combination",
			PolicyName:   "Toxic Combination Detection",
			Title:        combo.Title,
			Severity:     string(combo.Severity),
			Resource:     map[string]interface{}{"id": combo.ResourceID, "name": combo.ResourceName, "type": combo.ResourceType},
			Description:  combo.Description,
			Remediation:  combo.Remediation,
			ControlID:    combo.ControlID,
			ResourceType: combo.ResourceType,
			ResourceID:   combo.ResourceID,
			ResourceName: combo.ResourceName,
		}

		// Add risk categories from factors
		for _, f := range combo.RiskFactors {
			finding.RiskCategories = append(finding.RiskCategories, string(f.Type))
		}

		// Add MITRE ATT&CK
		for _, m := range combo.MitreAttack {
			finding.MitreAttack = append(finding.MitreAttack, policy.MitreMapping{
				Technique: m,
			})
		}

		toxicFindings = append(toxicFindings, finding)
	}

	s.logger.Info("toxic combination scan complete",
		"profiles_analyzed", len(profiles),
		"toxic_combinations", len(toxicCombos),
	)

	return toxicFindings
}

// AnalyzeGraph runs graph-based toxic combination detection and attack path simulation
func (s *Scanner) AnalyzeGraph(ctx context.Context, g *graph.Graph) *GraphAnalysisResult {
	if g == nil || g.NodeCount() == 0 {
		s.logger.Warn("no security graph available for analysis")
		return nil
	}

	result := &GraphAnalysisResult{
		ToxicCombinations: make([]policy.Finding, 0),
		AttackPaths:       make([]AttackPathSummary, 0),
	}

	graphToxics := s.graphToxicEngine.Analyze(g)
	s.logger.Info("graph toxic combination analysis complete",
		"combinations_found", len(graphToxics))

	for _, tc := range graphToxics {
		finding := policy.Finding{
			ID:          tc.ID,
			PolicyID:    "toxic-combination-graph",
			PolicyName:  "Graph-Based Toxic Combination",
			Title:       tc.Name,
			Severity:    string(tc.Severity),
			Description: tc.Description,
		}

		if len(tc.AffectedAssets) > 0 {
			finding.ResourceID = tc.AffectedAssets[0]
			finding.Resource = map[string]interface{}{
				"affected_count": len(tc.AffectedAssets),
				"affected_ids":   tc.AffectedAssets,
			}
			if node, ok := g.GetNode(finding.ResourceID); ok {
				finding.ResourceName = node.Name
			}
		} else if tc.AttackPath != nil && tc.AttackPath.Target != nil {
			finding.ResourceID = tc.AttackPath.Target.ID
			finding.ResourceName = tc.AttackPath.Target.Name
		}

		for _, rf := range tc.Factors {
			finding.RiskCategories = append(finding.RiskCategories, string(rf.Type))
		}

		if tc.AttackPath != nil {
			finding.Description = fmt.Sprintf("%s\n\nAttack Path: %s (Exploitability: %.1f, Impact: %.1f, Likelihood: %.1f)",
				finding.Description,
				tc.AttackPath.ID,
				tc.AttackPath.Exploitability,
				tc.AttackPath.Impact,
				tc.AttackPath.Likelihood)
		}

		if len(tc.Remediation) > 0 {
			remediationStrs := make([]string, 0, len(tc.Remediation))
			for _, r := range tc.Remediation {
				remediationStrs = append(remediationStrs, fmt.Sprintf("%d. %s", r.Priority, r.Action))
			}
			finding.Remediation = fmt.Sprintf("Recommended actions:\n%s",
				strings.Join(remediationStrs, "\n"))
		}

		result.ToxicCombinations = append(result.ToxicCombinations, finding)
	}

	sim := graph.NewAttackPathSimulator(g)
	simResult := sim.Simulate(10)
	s.logger.Info("attack path simulation complete",
		"paths_found", simResult.TotalPaths,
		"critical_paths", simResult.CriticalPaths,
		"chokepoints", len(simResult.Chokepoints))

	lengthCounts := make(map[int]int)
	for _, path := range simResult.Paths {
		lengthCounts[path.Length]++
	}

	result.AttackPathStats = AttackPathStats{
		TotalPaths:      simResult.TotalPaths,
		CriticalPaths:   simResult.CriticalPaths,
		EntryPointCount: simResult.EntryPointCount,
		CrownJewelCount: simResult.CrownJewelCount,
		MeanPathLength:  simResult.MeanPathLength,
		ShortestPath:    simResult.ShortestPath,
		LengthCounts:    lengthCounts,
	}

	const maxChokepoints = 5
	for i, cp := range simResult.Chokepoints {
		if i >= maxChokepoints {
			break
		}
		nodeID := ""
		name := ""
		if cp.Node != nil {
			nodeID = cp.Node.ID
			name = cp.Node.Name
		}
		result.Chokepoints = append(result.Chokepoints, AttackPathChokepointSummary{
			NodeID:             nodeID,
			NodeName:           name,
			PathsThrough:       cp.PathsThrough,
			BlockedPaths:       cp.BlockedPaths,
			RemediationImpact:  cp.RemediationImpact,
			UpstreamEntryCount: len(cp.UpstreamEntries),
			DownstreamCount:    len(cp.DownstreamTargets),
		})
	}

	for _, path := range simResult.Paths {
		if path.Priority > 10 {
			continue
		}
		steps := make([]string, 0, len(path.Steps))
		for _, step := range path.Steps {
			steps = append(steps, step.Description)
		}

		entryName := ""
		targetName := ""
		if path.EntryPoint != nil {
			entryName = path.EntryPoint.Name
		}
		if path.Target != nil {
			targetName = path.Target.Name
		}

		result.AttackPaths = append(result.AttackPaths, AttackPathSummary{
			ID:             path.ID,
			EntryPoint:     entryName,
			Target:         targetName,
			Steps:          steps,
			Length:         len(path.Steps),
			RiskScore:      path.TotalScore,
			Exploitability: path.Exploitability,
			Impact:         path.Impact,
		})
	}

	s.logger.Info("graph analysis complete",
		"toxic_combinations", len(result.ToxicCombinations),
		"attack_paths", len(result.AttackPaths))

	return result
}

// buildRiskProfile extracts a risk profile from an asset's properties
func (s *Scanner) buildRiskProfile(asset map[string]interface{}) attackpath.ResourceRiskProfile {
	// Extract resource identifiers
	resourceID := getStringField(asset, "_cq_id", "arn", "id", "resource_id")
	resourceName := getStringField(asset, "name", "resource_name", "title")
	resourceType := getStringField(asset, "_cq_table", "resource_type", "type")
	provider := inferProvider(resourceType)
	region := getStringField(asset, "region", "location")

	// Build properties map for risk factor detection
	props := make(map[string]interface{})

	// Network exposure detection
	if isPublic, ok := asset["public"].(bool); ok {
		props["public"] = isPublic
	}
	if scheme, ok := asset["scheme"].(string); ok && scheme == "internet-facing" {
		props["internet_facing"] = true
	}
	if publiclyAccessible, ok := asset["publicly_accessible"].(bool); ok {
		props["public"] = publiclyAccessible
	}

	// Public access for storage (S3, etc.)
	if blockPublicAcls, ok := asset["block_public_acls"].(bool); ok && !blockPublicAcls {
		props["public_access"] = true
	}

	// High privilege detection
	if adminAccess, ok := asset["administrator_access"].(bool); ok {
		props["admin"] = adminAccess
	}
	if permissionBoundary, ok := asset["permissions_boundary"].(string); ok && permissionBoundary == "" {
		// No permission boundary on admin role is a risk
		if isAdmin, _ := asset["is_admin"].(bool); isAdmin {
			props["high_privilege"] = true
		}
	}
	// Check for wildcards in policy statements
	if policies := asset["attached_policies"]; policies != nil {
		props["high_privilege"] = hasHighPrivilege(policies)
	}

	// Data access
	if dataClassification, ok := asset["data_classification"].(string); ok && dataClassification != "" {
		props["sensitive_data"] = true
		props["data_access"] = true
	}
	// S3/storage with sensitive patterns in name
	if name, ok := asset["name"].(string); ok {
		if containsSensitivePattern(name) {
			props["sensitive_data"] = true
		}
	}

	// Container-specific
	if containerDefs, ok := asset["container_definitions"].([]interface{}); ok {
		for _, cd := range containerDefs {
			if def, ok := cd.(map[string]interface{}); ok {
				if priv, ok := def["privileged"].(bool); ok && priv {
					props["privileged"] = true
				}
				if user, ok := def["user"].(string); ok && (user == "" || user == "root" || user == "0") {
					props["root_user"] = true
				}
				// Check for secrets in env vars
				if envVars, ok := def["environment"].([]interface{}); ok {
					for _, env := range envVars {
						if e, ok := env.(map[string]interface{}); ok {
							if name, ok := e["name"].(string); ok {
								if containsSecretPattern(name) {
									props["secrets_in_env"] = true
								}
							}
						}
					}
				}
			}
		}
	}

	// Secrets/credentials
	if accessKeyLastRotated, ok := asset["access_key_1_last_rotated"].(string); ok {
		if isKeyOld(accessKeyLastRotated) {
			props["keys_unrotated"] = true
		}
	}

	// Logging
	if loggingEnabled, ok := asset["logging_enabled"].(bool); ok && !loggingEnabled {
		props["logging_disabled"] = true
	}
	if logConfiguration, ok := asset["log_configuration"]; ok && logConfiguration == nil {
		props["logging_disabled"] = true
	}

	// Authentication
	if authType, ok := asset["authentication_type"].(string); ok && authType == "NONE" {
		props["authentication_disabled"] = true
	}

	return attackpath.BuildRiskProfile(resourceID, resourceName, resourceType, provider, region, props)
}

func getStringField(asset map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := asset[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func inferProvider(resourceType string) string {
	switch {
	case len(resourceType) >= 3 && resourceType[:3] == "aws":
		return "aws"
	case len(resourceType) >= 3 && resourceType[:3] == "gcp":
		return "gcp"
	case len(resourceType) >= 5 && resourceType[:5] == "azure":
		return "azure"
	case len(resourceType) >= 2 && resourceType[:2] == "k8":
		return "kubernetes"
	default:
		return "unknown"
	}
}

func hasHighPrivilege(policies interface{}) bool {
	// Check if any attached policies indicate high privilege
	// This is a simplified check - in production, you'd analyze the policy documents
	if plist, ok := policies.([]interface{}); ok {
		for _, p := range plist {
			if ps, ok := p.(string); ok {
				if containsAdminPattern(ps) {
					return true
				}
			}
			if pm, ok := p.(map[string]interface{}); ok {
				if name, ok := pm["policy_name"].(string); ok {
					if containsAdminPattern(name) {
						return true
					}
				}
			}
		}
	}
	return false
}

func containsAdminPattern(s string) bool {
	patterns := []string{"Admin", "admin", "PowerUser", "FullAccess", "*"}
	for _, p := range patterns {
		if len(s) >= len(p) {
			for i := 0; i <= len(s)-len(p); i++ {
				if s[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}

func containsSensitivePattern(s string) bool {
	patterns := []string{"pii", "pci", "phi", "sensitive", "confidential", "secret", "password", "credential"}
	lower := ""
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			lower += string(c + 32)
		} else {
			lower += string(c)
		}
	}
	for _, p := range patterns {
		if len(lower) >= len(p) {
			for i := 0; i <= len(lower)-len(p); i++ {
				if lower[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}

func containsSecretPattern(s string) bool {
	patterns := []string{"password", "passwd", "secret", "api_key", "apikey", "access_key", "token", "credential", "aws_"}
	lower := ""
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			lower += string(c + 32)
		} else {
			lower += string(c)
		}
	}
	for _, p := range patterns {
		if len(lower) >= len(p) {
			for i := 0; i <= len(lower)-len(p); i++ {
				if lower[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}

func isKeyOld(lastRotated string) bool {
	rotatedAt, ok := parseRotationTime(lastRotated)
	if !ok {
		return true
	}

	const maxKeyAge = 90 * 24 * time.Hour
	return time.Since(rotatedAt.UTC()) > maxKeyAge
}

func parseRotationTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "N/A") {
		return time.Time{}, false
	}

	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		if unix > 1_000_000_000_000 {
			unix = unix / 1000
		}
		if unix > 0 {
			return time.Unix(unix, 0).UTC(), true
		}
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02T15:04:05.000Z07:00",
		"2006-01-02T15:04:05Z07:00",
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}

	return time.Time{}, false
}

// StreamScan scans assets as they're received (for large datasets)
func (s *Scanner) StreamScan(ctx context.Context, assetStream <-chan map[string]interface{}, resultStream chan<- policy.Finding) *ScanResult {
	start := time.Now()
	result := &ScanResult{}

	var scanned int64
	var violations int64

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.workers)

	for asset := range assetStream {
		select {
		case <-ctx.Done():
			result.Scanned = atomic.LoadInt64(&scanned)
			result.Duration = time.Since(start)
			return result
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(a map[string]interface{}) {
			defer wg.Done()
			defer func() { <-sem }()

			findings, err := s.engine.EvaluateAsset(ctx, a)
			atomic.AddInt64(&scanned, 1)

			if err != nil {
				return
			}

			for _, f := range findings {
				atomic.AddInt64(&violations, 1)
				select {
				case resultStream <- f:
				case <-ctx.Done():
					return
				}
			}
		}(asset)
	}

	wg.Wait()

	result.Scanned = atomic.LoadInt64(&scanned)
	result.Violations = atomic.LoadInt64(&violations)
	result.Duration = time.Since(start)

	return result
}
