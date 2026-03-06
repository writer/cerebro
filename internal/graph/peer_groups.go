package graph

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"sync"
)

const (
	// MinHash parameters for ~0.7 similarity threshold with high accuracy
	numHashFunctions = 128
	numBands         = 16
	rowsPerBand      = 8 // numHashFunctions / numBands
)

// PeerGroup represents a group of principals with similar access patterns
type PeerGroup struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Members         []string `json:"members"`
	MemberCount     int      `json:"member_count"`
	CommonResources []string `json:"common_resources"`
	Similarity      float64  `json:"similarity"`
	Account         string   `json:"account,omitempty"`
}

// PeerGroupAnalysis contains the results of peer group analysis
type PeerGroupAnalysis struct {
	Groups          []*PeerGroup   `json:"groups"`
	Outliers        []*OutlierNode `json:"outliers"`
	TotalPrincipals int            `json:"total_principals"`
	Ungrouped       int            `json:"ungrouped"`
}

// OutlierNode represents a principal with unusual access patterns
type OutlierNode struct {
	PrincipalID    string   `json:"principal_id"`
	PrincipalName  string   `json:"principal_name"`
	ExpectedGroup  string   `json:"expected_group,omitempty"`
	UnusualAccess  []string `json:"unusual_access,omitempty"`
	MissingAccess  []string `json:"missing_access,omitempty"`
	OutlierScore   float64  `json:"outlier_score"`
	Recommendation string   `json:"recommendation"`
}

// AccessFingerprint represents a principal's access pattern
type AccessFingerprint struct {
	PrincipalID   string
	Resources     map[string]bool
	WeightedSet   map[string]float64 // resource -> weight (based on risk)
	EdgeKinds     map[EdgeKind]int
	Account       string
	MinHashSig    []uint64
	ResourceCount int
}

// MinHashIndex provides O(1) approximate similarity lookups using LSH
type MinHashIndex struct {
	mu           sync.RWMutex
	bands        []map[uint64][]string // band -> bucket hash -> principal IDs
	signatures   map[string][]uint64   // principal ID -> minhash signature
	fingerprints map[string]*AccessFingerprint
	hashSeeds    []uint64
}

// NewMinHashIndex creates a new LSH index
func NewMinHashIndex() *MinHashIndex {
	idx := &MinHashIndex{
		bands:        make([]map[uint64][]string, numBands),
		signatures:   make(map[string][]uint64),
		fingerprints: make(map[string]*AccessFingerprint),
		hashSeeds:    make([]uint64, numHashFunctions),
	}

	// Generate deterministic hash seeds using golden ratio constant
	const goldenRatio uint64 = 0x9E3779B97F4A7C15
	const initSeed uint64 = 0x6A09E667BB67AE85
	for i := range idx.hashSeeds {
		idx.hashSeeds[i] = uint64(i)*goldenRatio + initSeed // #nosec G115 -- i is bounded by numHashFunctions (128).
	}

	for i := range idx.bands {
		idx.bands[i] = make(map[uint64][]string)
	}

	return idx
}

// computeMinHash generates a MinHash signature for a set of elements
func (idx *MinHashIndex) computeMinHash(elements map[string]bool) []uint64 {
	sig := make([]uint64, numHashFunctions)
	for i := range sig {
		sig[i] = math.MaxUint64
	}

	if len(elements) == 0 {
		return sig
	}

	for elem := range elements {
		elemHash := hashString(elem)
		for i, seed := range idx.hashSeeds {
			h := elemHash ^ seed
			h = h * 0x9E3779B97F4A7C15
			h = h ^ (h >> 33)
			if h < sig[i] {
				sig[i] = h
			}
		}
	}

	return sig
}

// computeBandHash computes a hash for a band (subset of signature)
func computeBandHash(sig []uint64, bandIdx int) uint64 {
	start := bandIdx * rowsPerBand
	end := start + rowsPerBand

	h := fnv.New64a()
	buf := make([]byte, 8)
	for i := start; i < end && i < len(sig); i++ {
		binary.LittleEndian.PutUint64(buf, sig[i])
		h.Write(buf)
	}
	return h.Sum64()
}

// Add indexes a principal's access fingerprint
func (idx *MinHashIndex) Add(fp *AccessFingerprint) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	sig := idx.computeMinHash(fp.Resources)
	fp.MinHashSig = sig
	idx.signatures[fp.PrincipalID] = sig
	idx.fingerprints[fp.PrincipalID] = fp

	// Insert into LSH bands
	for b := 0; b < numBands; b++ {
		bandHash := computeBandHash(sig, b)
		idx.bands[b][bandHash] = append(idx.bands[b][bandHash], fp.PrincipalID)
	}
}

// FindCandidates returns candidate similar principals using LSH
func (idx *MinHashIndex) FindCandidates(principalID string) []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	sig, ok := idx.signatures[principalID]
	if !ok {
		return nil
	}

	candidateSet := make(map[string]bool)
	for b := 0; b < numBands; b++ {
		bandHash := computeBandHash(sig, b)
		for _, cid := range idx.bands[b][bandHash] {
			if cid != principalID {
				candidateSet[cid] = true
			}
		}
	}

	candidates := make([]string, 0, len(candidateSet))
	for c := range candidateSet {
		candidates = append(candidates, c)
	}
	return candidates
}

// EstimateSimilarity estimates Jaccard similarity from MinHash signatures
func EstimateSimilarity(sig1, sig2 []uint64) float64 {
	if len(sig1) != len(sig2) || len(sig1) == 0 {
		return 0.0
	}

	matches := 0
	for i := range sig1 {
		if sig1[i] == sig2[i] {
			matches++
		}
	}
	return float64(matches) / float64(len(sig1))
}

func hashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// AnalyzePeerGroups identifies groups of principals with similar access patterns
// Uses MinHash/LSH for O(n) time complexity instead of O(n^2)
func AnalyzePeerGroups(g *Graph, minSimilarity float64, minGroupSize int) *PeerGroupAnalysis {
	if minSimilarity <= 0 {
		minSimilarity = 0.7
	}
	if minGroupSize <= 0 {
		minGroupSize = 2
	}

	// Build access fingerprints and index
	fingerprints, index := buildFingerprintsWithIndex(g)
	if len(fingerprints) == 0 {
		return &PeerGroupAnalysis{}
	}

	// Cluster using LSH candidates
	groups := clusterWithLSH(g, fingerprints, index, minSimilarity, minGroupSize)

	// Identify outliers
	outliers := identifyOutliersLSH(g, fingerprints, index, groups, minSimilarity)

	// Count ungrouped
	grouped := make(map[string]bool)
	for _, grp := range groups {
		for _, m := range grp.Members {
			grouped[m] = true
		}
	}

	return &PeerGroupAnalysis{
		Groups:          groups,
		Outliers:        outliers,
		TotalPrincipals: len(fingerprints),
		Ungrouped:       len(fingerprints) - len(grouped),
	}
}

func buildFingerprintsWithIndex(g *Graph) (map[string]*AccessFingerprint, *MinHashIndex) {
	fingerprints := make(map[string]*AccessFingerprint)
	index := NewMinHashIndex()

	nodes := g.GetAllNodes()

	// Parallel fingerprint building for large graphs
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32) // Limit concurrency

	for _, node := range nodes {
		if !node.IsIdentity() {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(n *Node) {
			defer wg.Done()
			defer func() { <-sem }()

			fp := &AccessFingerprint{
				PrincipalID: n.ID,
				Resources:   make(map[string]bool),
				WeightedSet: make(map[string]float64),
				EdgeKinds:   make(map[EdgeKind]int),
				Account:     n.Account,
			}

			// Get reachable resources with risk weighting
			result := BlastRadius(g, n.ID, 3)
			for _, rn := range result.ReachableNodes {
				fp.Resources[rn.Node.ID] = true
				fp.EdgeKinds[rn.EdgeKind]++

				// Weight by risk level
				weight := 1.0
				switch rn.Node.Risk {
				case RiskCritical:
					weight = 4.0
				case RiskHigh:
					weight = 2.0
				case RiskMedium:
					weight = 1.5
				}
				// Weight by edge type
				switch rn.EdgeKind {
				case EdgeKindCanAdmin:
					weight *= 2.0
				case EdgeKindCanWrite, EdgeKindCanDelete:
					weight *= 1.5
				}
				fp.WeightedSet[rn.Node.ID] = weight
			}
			fp.ResourceCount = len(fp.Resources)

			mu.Lock()
			fingerprints[n.ID] = fp
			index.Add(fp)
			mu.Unlock()
		}(node)
	}

	wg.Wait()
	return fingerprints, index
}

func clusterWithLSH(g *Graph, fingerprints map[string]*AccessFingerprint, index *MinHashIndex, minSimilarity float64, minGroupSize int) []*PeerGroup {
	assigned := make(map[string]bool)
	var groups []*PeerGroup
	groupID := 0

	// Sort for deterministic ordering
	principals := make([]string, 0, len(fingerprints))
	for id := range fingerprints {
		principals = append(principals, id)
	}
	sort.Strings(principals)

	for _, pid := range principals {
		if assigned[pid] {
			continue
		}

		fp := fingerprints[pid]
		if fp.ResourceCount == 0 {
			continue
		}

		group := &PeerGroup{
			ID:      fmt.Sprintf("pg-%d", groupID),
			Members: []string{pid},
			Account: fp.Account,
		}
		assigned[pid] = true

		// Use LSH to find candidates (O(1) per principal)
		candidates := index.FindCandidates(pid)

		for _, cid := range candidates {
			if assigned[cid] {
				continue
			}

			cfp := fingerprints[cid]
			if cfp == nil || cfp.Account != fp.Account {
				continue
			}

			// Verify similarity with exact Jaccard (only for candidates)
			similarity := EstimateSimilarity(fp.MinHashSig, cfp.MinHashSig)
			if similarity >= minSimilarity {
				// Double-check with exact calculation for borderline cases
				exactSim := jaccardSimilarity(fp.Resources, cfp.Resources)
				if exactSim >= minSimilarity*0.95 { // 5% tolerance
					group.Members = append(group.Members, cid)
					assigned[cid] = true
				}
			}
		}

		if len(group.Members) >= minGroupSize {
			group.MemberCount = len(group.Members)
			group.CommonResources = findCommonResourcesWeighted(fingerprints, group.Members)
			group.Similarity = calculateGroupSimilarityFast(fingerprints, group.Members)
			group.Name = generateGroupName(g, group)
			groups = append(groups, group)
			groupID++
		} else {
			// Unassign if group too small
			for _, m := range group.Members {
				assigned[m] = false
			}
		}
	}

	// Sort groups by size
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].MemberCount > groups[j].MemberCount
	})

	return groups
}

func findCommonResourcesWeighted(fingerprints map[string]*AccessFingerprint, members []string) []string {
	if len(members) == 0 {
		return nil
	}

	resourceCount := make(map[string]int)
	resourceWeight := make(map[string]float64)

	for _, mid := range members {
		fp := fingerprints[mid]
		for r := range fp.Resources {
			resourceCount[r]++
			resourceWeight[r] += fp.WeightedSet[r]
		}
	}

	// Keep resources that majority of members have
	threshold := (len(members) + 1) / 2
	var result []string
	for r, count := range resourceCount {
		if count >= threshold {
			result = append(result, r)
		}
	}

	// Sort by weight (most important first)
	sort.Slice(result, func(i, j int) bool {
		return resourceWeight[result[i]] > resourceWeight[result[j]]
	})

	// Limit to top 100 for readability
	if len(result) > 100 {
		result = result[:100]
	}

	return result
}

func calculateGroupSimilarityFast(fingerprints map[string]*AccessFingerprint, members []string) float64 {
	if len(members) < 2 {
		return 1.0
	}

	// Sample-based similarity for large groups
	sampleSize := 10
	if len(members) < sampleSize*2 {
		sampleSize = len(members)
	}

	var totalSim float64
	var count int

	for i := 0; i < sampleSize && i < len(members); i++ {
		for j := i + 1; j < sampleSize && j < len(members); j++ {
			fp1 := fingerprints[members[i]]
			fp2 := fingerprints[members[j]]
			if fp1 != nil && fp2 != nil && len(fp1.MinHashSig) > 0 && len(fp2.MinHashSig) > 0 {
				totalSim += EstimateSimilarity(fp1.MinHashSig, fp2.MinHashSig)
				count++
			}
		}
	}

	if count == 0 {
		return 0.0
	}
	return totalSim / float64(count)
}

func generateGroupName(g *Graph, group *PeerGroup) string {
	if len(group.Members) == 0 {
		return "Empty Group"
	}

	// Try to find a common naming pattern
	if len(group.Members) > 0 {
		node, _ := g.GetNode(group.Members[0])
		if node != nil && node.Kind != "" {
			return fmt.Sprintf("%s Group %s (%d members)", node.Kind, group.ID, group.MemberCount)
		}
	}

	return fmt.Sprintf("Peer Group %s (%d members)", group.ID, group.MemberCount)
}

func identifyOutliersLSH(g *Graph, fingerprints map[string]*AccessFingerprint, index *MinHashIndex, groups []*PeerGroup, minSimilarity float64) []*OutlierNode {
	var outliers []*OutlierNode

	// Build membership map
	memberToGroup := make(map[string]*PeerGroup)
	groupProfiles := make(map[string]map[string]bool)

	for _, group := range groups {
		profile := make(map[string]bool)
		for _, r := range group.CommonResources {
			profile[r] = true
		}
		groupProfiles[group.ID] = profile
		for _, m := range group.Members {
			memberToGroup[m] = group
		}
	}

	for pid, fp := range fingerprints {
		group := memberToGroup[pid]

		if group == nil {
			// Not in a group - check if close to any group
			candidates := index.FindCandidates(pid)
			var bestMatch *PeerGroup
			var bestSim float64

			for _, cid := range candidates {
				if cg := memberToGroup[cid]; cg != nil {
					cfp := fingerprints[cid]
					if cfp != nil && len(fp.MinHashSig) > 0 && len(cfp.MinHashSig) > 0 {
						sim := EstimateSimilarity(fp.MinHashSig, cfp.MinHashSig)
						if sim > bestSim && sim >= minSimilarity*0.5 {
							bestSim = sim
							bestMatch = cg
						}
					}
				}
			}

			if bestMatch != nil && bestSim < minSimilarity {
				node, _ := g.GetNode(pid)
				name := pid
				if node != nil {
					name = node.Name
				}
				outliers = append(outliers, &OutlierNode{
					PrincipalID:    pid,
					PrincipalName:  name,
					ExpectedGroup:  bestMatch.ID,
					OutlierScore:   1.0 - bestSim,
					Recommendation: "Review access - partially matches peer group but doesn't qualify",
				})
			}
			continue
		}

		// In a group - check for unusual access
		profile := groupProfiles[group.ID]
		var unusualAccess []string
		var missingAccess []string

		for r := range fp.Resources {
			if !profile[r] {
				unusualAccess = append(unusualAccess, r)
			}
		}

		for r := range profile {
			if !fp.Resources[r] {
				missingAccess = append(missingAccess, r)
			}
		}

		// Calculate outlier score with weighting
		var unusualWeight float64
		for _, r := range unusualAccess {
			unusualWeight += fp.WeightedSet[r]
		}

		totalWeight := 0.0
		for _, w := range fp.WeightedSet {
			totalWeight += w
		}

		if totalWeight > 0 {
			outlierScore := unusualWeight / totalWeight
			if outlierScore > 0.2 { // 20% weighted deviation
				node, _ := g.GetNode(pid)
				name := pid
				if node != nil {
					name = node.Name
				}

				// Limit unusual access list
				if len(unusualAccess) > 20 {
					unusualAccess = unusualAccess[:20]
				}
				if len(missingAccess) > 20 {
					missingAccess = missingAccess[:20]
				}

				outliers = append(outliers, &OutlierNode{
					PrincipalID:    pid,
					PrincipalName:  name,
					ExpectedGroup:  group.ID,
					UnusualAccess:  unusualAccess,
					MissingAccess:  missingAccess,
					OutlierScore:   outlierScore,
					Recommendation: generateRecommendation(unusualAccess, missingAccess),
				})
			}
		}
	}

	// Sort by outlier score descending
	sort.Slice(outliers, func(i, j int) bool {
		return outliers[i].OutlierScore > outliers[j].OutlierScore
	})

	// Limit outliers for large graphs
	if len(outliers) > 1000 {
		outliers = outliers[:1000]
	}

	return outliers
}

func generateRecommendation(unusualAccess, missingAccess []string) string {
	if len(unusualAccess) > 0 && len(missingAccess) > 0 {
		return "Review access - has unusual permissions and missing expected access"
	}
	if len(unusualAccess) > 0 {
		return "Review access - has permissions beyond peer group"
	}
	if len(missingAccess) > 0 {
		return "Review access - missing expected permissions for role"
	}
	return "Review access pattern"
}

// jaccardSimilarity calculates exact Jaccard similarity between two sets
func jaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	intersection := 0
	for k := range a {
		if b[k] {
			intersection++
		}
	}

	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// FindPrivilegeCreep identifies principals whose access has grown beyond their peers
func FindPrivilegeCreep(g *Graph, threshold float64) []*OutlierNode {
	if threshold <= 0 {
		threshold = 1.5 // 50% more access than peers
	}

	analysis := AnalyzePeerGroups(g, 0.6, 2)
	var creepCases []*OutlierNode

	fingerprints, _ := buildFingerprintsWithIndex(g)
	memberToGroup := make(map[string]*PeerGroup)
	for _, group := range analysis.Groups {
		for _, m := range group.Members {
			memberToGroup[m] = group
		}
	}

	// Calculate group statistics
	groupStats := make(map[string]struct {
		avgResources float64
		avgWeight    float64
		memberCount  int
	})

	for _, group := range analysis.Groups {
		var totalResources int
		var totalWeight float64
		for _, m := range group.Members {
			if fp := fingerprints[m]; fp != nil {
				totalResources += fp.ResourceCount
				for _, w := range fp.WeightedSet {
					totalWeight += w
				}
			}
		}
		if len(group.Members) > 0 {
			groupStats[group.ID] = struct {
				avgResources float64
				avgWeight    float64
				memberCount  int
			}{
				avgResources: float64(totalResources) / float64(len(group.Members)),
				avgWeight:    totalWeight / float64(len(group.Members)),
				memberCount:  len(group.Members),
			}
		}
	}

	for pid, fp := range fingerprints {
		group := memberToGroup[pid]
		if group == nil {
			continue
		}

		stats := groupStats[group.ID]
		if stats.avgResources == 0 {
			continue
		}

		// Check weighted access (accounts for high-risk resources)
		var weight float64
		for _, w := range fp.WeightedSet {
			weight += w
		}

		weightRatio := weight / stats.avgWeight
		resourceRatio := float64(fp.ResourceCount) / stats.avgResources

		// Use the higher of the two ratios
		ratio := weightRatio
		if resourceRatio > ratio {
			ratio = resourceRatio
		}

		if ratio >= threshold {
			node, _ := g.GetNode(pid)
			name := pid
			if node != nil {
				name = node.Name
			}
			creepCases = append(creepCases, &OutlierNode{
				PrincipalID:    pid,
				PrincipalName:  name,
				ExpectedGroup:  group.ID,
				OutlierScore:   ratio,
				Recommendation: fmt.Sprintf("Potential privilege creep - %.1fx peer group average access", ratio),
			})
		}
	}

	sort.Slice(creepCases, func(i, j int) bool {
		return creepCases[i].OutlierScore > creepCases[j].OutlierScore
	})

	return creepCases
}

// CompareAccess compares access between two principals
func CompareAccess(g *Graph, principalA, principalB string) *AccessComparison {
	fpA := &AccessFingerprint{
		Resources:   make(map[string]bool),
		WeightedSet: make(map[string]float64),
	}
	fpB := &AccessFingerprint{
		Resources:   make(map[string]bool),
		WeightedSet: make(map[string]float64),
	}

	resultA := BlastRadius(g, principalA, 3)
	for _, rn := range resultA.ReachableNodes {
		fpA.Resources[rn.Node.ID] = true
		fpA.WeightedSet[rn.Node.ID] = riskWeight(rn.Node.Risk)
	}

	resultB := BlastRadius(g, principalB, 3)
	for _, rn := range resultB.ReachableNodes {
		fpB.Resources[rn.Node.ID] = true
		fpB.WeightedSet[rn.Node.ID] = riskWeight(rn.Node.Risk)
	}

	var onlyA, onlyB, both []string
	for r := range fpA.Resources {
		if fpB.Resources[r] {
			both = append(both, r)
		} else {
			onlyA = append(onlyA, r)
		}
	}
	for r := range fpB.Resources {
		if !fpA.Resources[r] {
			onlyB = append(onlyB, r)
		}
	}

	// Sort by weight (most important first)
	sortByWeight := func(items []string, weights map[string]float64) {
		sort.Slice(items, func(i, j int) bool {
			return weights[items[i]] > weights[items[j]]
		})
	}

	sortByWeight(onlyA, fpA.WeightedSet)
	sortByWeight(onlyB, fpB.WeightedSet)
	combinedWeights := make(map[string]float64)
	for r, w := range fpA.WeightedSet {
		combinedWeights[r] = w
	}
	for r, w := range fpB.WeightedSet {
		if combinedWeights[r] < w {
			combinedWeights[r] = w
		}
	}
	sortByWeight(both, combinedWeights)

	return &AccessComparison{
		PrincipalA:  principalA,
		PrincipalB:  principalB,
		OnlyA:       onlyA,
		OnlyB:       onlyB,
		Shared:      both,
		Similarity:  jaccardSimilarity(fpA.Resources, fpB.Resources),
		ACount:      len(fpA.Resources),
		BCount:      len(fpB.Resources),
		SharedCount: len(both),
	}
}

func riskWeight(risk RiskLevel) float64 {
	switch risk {
	case RiskCritical:
		return 4.0
	case RiskHigh:
		return 2.0
	case RiskMedium:
		return 1.5
	default:
		return 1.0
	}
}

// AccessComparison shows the difference in access between two principals
type AccessComparison struct {
	PrincipalA  string   `json:"principal_a"`
	PrincipalB  string   `json:"principal_b"`
	OnlyA       []string `json:"only_a"`
	OnlyB       []string `json:"only_b"`
	Shared      []string `json:"shared"`
	Similarity  float64  `json:"similarity"`
	ACount      int      `json:"a_count"`
	BCount      int      `json:"b_count"`
	SharedCount int      `json:"shared_count"`
}

// PeerGroupIndex is a persistent index for incremental updates
type PeerGroupIndex struct {
	mu           sync.RWMutex
	index        *MinHashIndex
	fingerprints map[string]*AccessFingerprint
	groups       []*PeerGroup
}

// NewPeerGroupIndex creates a reusable peer group index
func NewPeerGroupIndex() *PeerGroupIndex {
	return &PeerGroupIndex{
		index:        NewMinHashIndex(),
		fingerprints: make(map[string]*AccessFingerprint),
	}
}

// Update incrementally updates the index with changed principals
func (p *PeerGroupIndex) Update(g *Graph, changedPrincipals []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pid := range changedPrincipals {
		node, ok := g.GetNode(pid)
		if !ok || !node.IsIdentity() {
			// Removed - delete from index
			delete(p.fingerprints, pid)
			continue
		}

		// Rebuild fingerprint for this principal
		fp := &AccessFingerprint{
			PrincipalID: pid,
			Resources:   make(map[string]bool),
			WeightedSet: make(map[string]float64),
			EdgeKinds:   make(map[EdgeKind]int),
			Account:     node.Account,
		}

		result := BlastRadius(g, pid, 3)
		for _, rn := range result.ReachableNodes {
			fp.Resources[rn.Node.ID] = true
			fp.EdgeKinds[rn.EdgeKind]++
			fp.WeightedSet[rn.Node.ID] = riskWeight(rn.Node.Risk)
		}
		fp.ResourceCount = len(fp.Resources)

		p.fingerprints[pid] = fp
		p.index.Add(fp)
	}
}

// GetGroups returns cached groups or rebuilds if needed
func (p *PeerGroupIndex) GetGroups(g *Graph, minSimilarity float64, minGroupSize int) []*PeerGroup {
	p.mu.RLock()
	if len(p.groups) > 0 {
		groups := p.groups
		p.mu.RUnlock()
		return groups
	}
	p.mu.RUnlock()

	// Full rebuild needed
	analysis := AnalyzePeerGroups(g, minSimilarity, minGroupSize)

	p.mu.Lock()
	p.groups = analysis.Groups
	p.mu.Unlock()

	return analysis.Groups
}
