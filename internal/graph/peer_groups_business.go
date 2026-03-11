package graph

import (
	"fmt"
	"sort"
	"strings"
)

// EntityFingerprint is a MinHash representation of a business entity profile.
type EntityFingerprint struct {
	EntityID   string             `json:"entity_id"`
	EntityKind NodeKind           `json:"entity_kind"`
	Features   map[string]float64 `json:"features"`
	MinHashSig []uint64           `json:"minhash_sig,omitempty"`
}

// EntityPeerGroup groups similar business entities.
type EntityPeerGroup struct {
	ID             string   `json:"id"`
	EntityKind     NodeKind `json:"entity_kind"`
	Members        []string `json:"members"`
	MemberCount    int      `json:"member_count"`
	CommonFeatures []string `json:"common_features,omitempty"`
	Similarity     float64  `json:"similarity"`
}

// EntityOutlierScore captures profile distance from a detected cohort.
type EntityOutlierScore struct {
	EntityID       string             `json:"entity_id"`
	ExpectedGroup  string             `json:"expected_group,omitempty"`
	OutlierScore   float64            `json:"outlier_score"`
	Recommendation string             `json:"recommendation"`
	FeatureDelta   map[string]float64 `json:"feature_delta,omitempty"`
}

// EntityPeerGroupAnalysis summarizes cohort analysis for business entities.
type EntityPeerGroupAnalysis struct {
	Groups        []*EntityPeerGroup    `json:"groups"`
	Outliers      []*EntityOutlierScore `json:"outliers"`
	TotalEntities int                   `json:"total_entities"`
	Ungrouped     int                   `json:"ungrouped"`
}

// EntityCohort provides cohort-level comparison data for one entity.
type EntityCohort struct {
	EntityID       string             `json:"entity_id"`
	GroupID        string             `json:"group_id"`
	Members        []string           `json:"members"`
	EntityMetrics  map[string]float64 `json:"entity_metrics"`
	CohortAverages map[string]float64 `json:"cohort_averages"`
	Delta          map[string]float64 `json:"delta"`
}

// AnalyzeEntityPeerGroups applies MinHash LSH clustering to business entities.
func AnalyzeEntityPeerGroups(g *Graph, minSimilarity float64, minGroupSize int) *EntityPeerGroupAnalysis {
	if minSimilarity <= 0 {
		minSimilarity = 0.7
	}
	if minGroupSize <= 1 {
		minGroupSize = 2
	}

	fingerprints, index := buildEntityFingerprints(g)
	if len(fingerprints) == 0 {
		return &EntityPeerGroupAnalysis{}
	}

	groups := clusterEntityFingerprints(fingerprints, index, minSimilarity, minGroupSize)
	outliers := identifyEntityOutliers(fingerprints, index, groups, minSimilarity)

	grouped := make(map[string]bool)
	for _, group := range groups {
		for _, member := range group.Members {
			grouped[member] = true
		}
	}

	return &EntityPeerGroupAnalysis{
		Groups:        groups,
		Outliers:      outliers,
		TotalEntities: len(fingerprints),
		Ungrouped:     len(fingerprints) - len(grouped),
	}
}

// GetEntityCohort returns cohort members and metrics for a specific entity.
func GetEntityCohort(g *Graph, entityID string) (*EntityCohort, bool) {
	analysis := AnalyzeEntityPeerGroups(g, 0.7, 2)
	var targetGroup *EntityPeerGroup
	for _, group := range analysis.Groups {
		for _, member := range group.Members {
			if member == entityID {
				targetGroup = group
				break
			}
		}
		if targetGroup != nil {
			break
		}
	}
	if targetGroup == nil {
		return nil, false
	}

	entityNode, ok := g.GetNode(entityID)
	if !ok {
		return nil, false
	}

	entityMetrics := entityBusinessMetrics(entityNode)
	averages := make(map[string]float64)
	for _, member := range targetGroup.Members {
		node, exists := g.GetNode(member)
		if !exists {
			continue
		}
		for key, value := range entityBusinessMetrics(node) {
			averages[key] += value
		}
	}
	memberCount := float64(len(targetGroup.Members))
	if memberCount <= 0 {
		memberCount = 1
	}
	for key := range averages {
		averages[key] /= memberCount
	}

	delta := make(map[string]float64)
	for key, value := range entityMetrics {
		delta[key] = value - averages[key]
	}

	return &EntityCohort{
		EntityID:       entityID,
		GroupID:        targetGroup.ID,
		Members:        append([]string(nil), targetGroup.Members...),
		EntityMetrics:  entityMetrics,
		CohortAverages: averages,
		Delta:          delta,
	}, true
}

// GetEntityOutlierScore returns outlier analysis for a single entity.
func GetEntityOutlierScore(g *Graph, entityID string) (*EntityOutlierScore, bool) {
	analysis := AnalyzeEntityPeerGroups(g, 0.7, 2)
	for _, outlier := range analysis.Outliers {
		if outlier.EntityID == entityID {
			copy := *outlier
			return &copy, true
		}
	}

	cohort, ok := GetEntityCohort(g, entityID)
	if !ok {
		return nil, false
	}

	featureDelta := make(map[string]float64)
	totalDeviation := 0.0
	for key, delta := range cohort.Delta {
		abs := delta
		if abs < 0 {
			abs = -abs
		}
		totalDeviation += abs
		featureDelta[key] = delta
	}
	score := totalDeviation / float64(len(cohort.Delta)+1)

	return &EntityOutlierScore{
		EntityID:       entityID,
		ExpectedGroup:  cohort.GroupID,
		OutlierScore:   score,
		Recommendation: "Investigate deviation from cohort baseline",
		FeatureDelta:   featureDelta,
	}, true
}

func buildEntityFingerprints(g *Graph) (map[string]*EntityFingerprint, *MinHashIndex) {
	fingerprints := make(map[string]*EntityFingerprint)
	index := NewMinHashIndex()

	for _, node := range g.GetAllNodes() {
		if !node.IsBusinessEntity() {
			continue
		}
		features := extractEntityFeatures(node)
		if len(features) == 0 {
			continue
		}

		featureSet := make(map[string]bool, len(features))
		for feature := range features {
			featureSet[feature] = true
		}

		fp := &EntityFingerprint{
			EntityID:   node.ID,
			EntityKind: node.Kind,
			Features:   features,
		}
		fp.MinHashSig = index.computeMinHash(featureSet)
		fingerprints[node.ID] = fp

		index.Add(&AccessFingerprint{
			PrincipalID: node.ID,
			Resources:   featureSet,
		})
	}

	return fingerprints, index
}

func extractEntityFeatures(node *Node) map[string]float64 {
	features := make(map[string]float64)
	if node == nil {
		return features
	}

	addToken := func(key, value string, weight float64) {
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(strings.ToLower(value))
		if key == "" || value == "" {
			return
		}
		features[key+"="+value] = weight
	}

	addBand := func(key string, value float64, bounds []float64, labels []string, weight float64) {
		if len(labels) == 0 {
			return
		}
		idx := len(labels) - 1
		for i := 0; i < len(bounds) && i < len(labels)-1; i++ {
			if value < bounds[i] {
				idx = i
				break
			}
		}
		addToken(key, labels[idx], weight)
	}

	for key, value := range node.Properties {
		switch key {
		case "product_tier", "industry", "region", "support_plan", "plan_type", "billing_interval", "stage", "lead_source":
			addToken(key, fmt.Sprintf("%v", value), 1)
		case "arr", "employee_count", "usage", "deal_size", "discount", "stage_velocity", "sales_cycle_length", "addon_count":
			f := readFloat(node.Properties, key)
			addBand(key+"_band", f, []float64{10, 100, 1000, 10000, 100000, 1000000}, []string{"xs", "s", "m", "l", "xl", "xxl", "mega"}, 1.2)
		}
	}

	switch node.Kind {
	case NodeKindCustomer:
		addToken("kind", "customer", 1)
	case NodeKindSubscription:
		addToken("kind", "subscription", 1)
	case NodeKindDeal, NodeKindOpportunity:
		addToken("kind", "deal", 1)
	}

	return features
}

func clusterEntityFingerprints(fingerprints map[string]*EntityFingerprint, index *MinHashIndex, minSimilarity float64, minGroupSize int) []*EntityPeerGroup {
	assigned := make(map[string]bool)
	groups := make([]*EntityPeerGroup, 0)

	ids := make([]string, 0, len(fingerprints))
	for id := range fingerprints {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	groupNum := 0
	for _, id := range ids {
		if assigned[id] {
			continue
		}

		base := fingerprints[id]
		group := &EntityPeerGroup{
			ID:         fmt.Sprintf("cohort-%d", groupNum),
			EntityKind: base.EntityKind,
			Members:    []string{id},
		}
		assigned[id] = true

		candidates := index.FindCandidates(id)
		for _, cid := range candidates {
			if assigned[cid] {
				continue
			}
			candidate := fingerprints[cid]
			if candidate == nil || candidate.EntityKind != base.EntityKind {
				continue
			}
			sim := EstimateSimilarity(base.MinHashSig, candidate.MinHashSig)
			if sim >= minSimilarity {
				group.Members = append(group.Members, cid)
				assigned[cid] = true
			}
		}

		if len(group.Members) < minGroupSize {
			for _, member := range group.Members {
				assigned[member] = false
			}
			continue
		}

		group.MemberCount = len(group.Members)
		group.Similarity = groupSimilarity(fingerprints, group.Members)
		group.CommonFeatures = commonEntityFeatures(fingerprints, group.Members)
		groups = append(groups, group)
		groupNum++
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].MemberCount > groups[j].MemberCount
	})

	return groups
}

func identifyEntityOutliers(fingerprints map[string]*EntityFingerprint, index *MinHashIndex, groups []*EntityPeerGroup, minSimilarity float64) []*EntityOutlierScore {
	memberToGroup := make(map[string]*EntityPeerGroup)
	for _, group := range groups {
		for _, member := range group.Members {
			memberToGroup[member] = group
		}
	}

	outliers := make([]*EntityOutlierScore, 0)
	for id, fp := range fingerprints {
		if memberToGroup[id] == nil {
			candidates := index.FindCandidates(id)
			best := 0.0
			bestGroup := ""
			for _, candidate := range candidates {
				group := memberToGroup[candidate]
				if group == nil {
					continue
				}
				candidateFP := fingerprints[candidate]
				sim := EstimateSimilarity(fp.MinHashSig, candidateFP.MinHashSig)
				if sim > best {
					best = sim
					bestGroup = group.ID
				}
			}
			if best > 0 && best < minSimilarity {
				outliers = append(outliers, &EntityOutlierScore{
					EntityID:       id,
					ExpectedGroup:  bestGroup,
					OutlierScore:   1 - best,
					Recommendation: "Entity partially matches a cohort but remains outside group threshold",
				})
			}
		}
	}

	sort.Slice(outliers, func(i, j int) bool {
		return outliers[i].OutlierScore > outliers[j].OutlierScore
	})
	return outliers
}

func commonEntityFeatures(fingerprints map[string]*EntityFingerprint, members []string) []string {
	if len(members) == 0 {
		return nil
	}
	featureCount := make(map[string]int)
	for _, member := range members {
		for feature := range fingerprints[member].Features {
			featureCount[feature]++
		}
	}
	threshold := (len(members) + 1) / 2
	common := make([]string, 0)
	for feature, count := range featureCount {
		if count >= threshold {
			common = append(common, feature)
		}
	}
	sort.Strings(common)
	if len(common) > 20 {
		common = common[:20]
	}
	return common
}

func groupSimilarity(fingerprints map[string]*EntityFingerprint, members []string) float64 {
	if len(members) < 2 {
		return 1
	}
	total := 0.0
	pairs := 0
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			left := fingerprints[members[i]]
			right := fingerprints[members[j]]
			total += EstimateSimilarity(left.MinHashSig, right.MinHashSig)
			pairs++
		}
	}
	if pairs == 0 {
		return 0
	}
	return total / float64(pairs)
}

func entityBusinessMetrics(node *Node) map[string]float64 {
	metrics := map[string]float64{
		"arr":                  readFloat(node.Properties, "arr", "contract_value", "deal_value"),
		"open_p1_tickets":      float64(readInt(node.Properties, "open_p1_tickets", "p1_ticket_count")),
		"failed_payment_count": float64(readInt(node.Properties, "failed_payment_count", "payment_failed_count")),
		"usage_delta_pct":      readFloat(node.Properties, "usage_delta_pct", "usage_change_pct"),
		"days_since_activity":  float64(readInt(node.Properties, "days_since_last_activity", "days_since_last_modified")),
	}
	for key, value := range metrics {
		if value != value {
			metrics[key] = 0
		}
	}
	return metrics
}
