package app

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/policy"
)

const (
	orgTopologySystemsTable               = "org_topology_systems"
	orgTopologyTeamPairsTable             = "org_topology_team_pairs"
	orgTopologyCustomerRelationshipsTable = "org_topology_customer_relationships"
	orgTopologyPeopleTable                = "org_topology_people"
)

// OrgTopologyPolicyScanResult captures policy findings derived from graph org-topology metrics.
type OrgTopologyPolicyScanResult struct {
	Assets   int
	Findings []policy.Finding
	Errors   []string
}

// ScanOrgTopologyPolicies evaluates policy rules against graph-derived organizational topology assets.
func (a *App) ScanOrgTopologyPolicies(ctx context.Context) OrgTopologyPolicyScanResult {
	result := OrgTopologyPolicyScanResult{Findings: make([]policy.Finding, 0)}
	if a == nil || a.Policy == nil {
		return result
	}

	securityGraph, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	if securityGraph == nil {
		return result
	}

	orgHealth := graph.ComputeOrgHealthScore(securityGraph)
	assets := buildOrgTopologyPolicyAssets(securityGraph, orgHealth)
	result.Assets = len(assets)
	if len(assets) == 0 {
		return result
	}

	seen := make(map[string]struct{})
	for _, asset := range assets {
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, err.Error())
			break
		}

		findingsForAsset, err := a.Policy.EvaluateAsset(ctx, asset)
		if err != nil {
			tableName := strings.TrimSpace(valueAsString(asset["_cq_table"]))
			assetID := strings.TrimSpace(valueAsString(asset["_cq_id"]))
			result.Errors = append(result.Errors, fmt.Sprintf("org topology policy evaluation failed for %s/%s: %v", tableName, assetID, err))
			continue
		}

		for _, finding := range findingsForAsset {
			if _, exists := seen[finding.ID]; exists {
				continue
			}
			seen[finding.ID] = struct{}{}
			result.Findings = append(result.Findings, finding)
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].ID < result.Findings[j].ID
	})
	return result
}

func buildOrgTopologyPolicyAssets(g *graph.Graph, orgHealth graph.OrgHealthScore) []map[string]interface{} {
	assets := make([]map[string]interface{}, 0)
	now := time.Now().UTC()

	busFactorOneByPerson := make(map[string]int)
	for _, bus := range orgHealth.BusFactors {
		targetName := bus.TargetID
		targetCriticality := "medium"
		if target, ok := g.GetNode(bus.TargetID); ok && target != nil {
			if strings.TrimSpace(target.Name) != "" {
				targetName = target.Name
			}
			targetCriticality = criticalityForNode(target)
		}

		assets = append(assets, map[string]interface{}{
			"_cq_table":     orgTopologySystemsTable,
			"_cq_id":        fmt.Sprintf("org-system:%s", bus.TargetID),
			"resource_id":   bus.TargetID,
			"resource_name": targetName,
			"criticality":   targetCriticality,
			"bus_factor":    bus.BusFactor,
			"active_people": bus.Active,
			"total_people":  bus.Total,
		})

		if bus.BusFactor <= 1 {
			for _, personID := range bus.ActivePersonIDs {
				busFactorOneByPerson[personID]++
			}
		}
	}

	for _, silo := range orgHealth.Silos {
		assets = append(assets, map[string]interface{}{
			"_cq_table":           orgTopologyTeamPairsTable,
			"_cq_id":              fmt.Sprintf("org-team-pair:%s|%s", silo.TeamAID, silo.TeamBID),
			"resource_id":         fmt.Sprintf("%s|%s", silo.TeamAID, silo.TeamBID),
			"resource_name":       fmt.Sprintf("%s <-> %s", firstNonEmptyTrim(silo.TeamAName, silo.TeamAID), firstNonEmptyTrim(silo.TeamBName, silo.TeamBID)),
			"team_a_id":           silo.TeamAID,
			"team_b_id":           silo.TeamBID,
			"shared_dependencies": len(silo.SharedDependencies),
			"interaction_edges":   silo.InteractionEdgeCount,
		})
	}

	customerHealth := graph.ComputeCustomerRelationshipHealth(g)
	for _, health := range customerHealth {
		customerID := strings.TrimSpace(health.CustomerID)
		if customerID == "" {
			continue
		}

		customerName := customerID
		if customer, ok := g.GetNode(customerID); ok && customer != nil && strings.TrimSpace(customer.Name) != "" {
			customerName = customer.Name
		}

		assets = append(assets, map[string]interface{}{
			"_cq_table":             orgTopologyCustomerRelationshipsTable,
			"_cq_id":                fmt.Sprintf("org-customer-health:%s", customerID),
			"resource_id":           customerID,
			"resource_name":         customerName,
			"customer_id":           customerID,
			"touchpoint_count":      health.TouchpointCount,
			"role_diversity":        health.RoleDiversity,
			"interaction_frequency": health.InteractionFrequency,
			"internal_cohesion":     health.InternalCohesion,
			"recency_score":         health.RecencyScore,
			"touchpoint_trend":      health.TouchpointTrend,
			"frequency_trend":       health.FrequencyTrend,
			"cohort_percentile":     health.CohortPercentile,
			"ideal_gap":             health.IdealGap,
			"health_score":          health.HealthScore,
			"churn_risk":            graph.ChurnRiskFromTopology(g, customerID),
			"renewal_days":          customerRenewalDays(g, customerID),
		})
	}

	decayByPerson := make(map[string]int)
	for _, alert := range orgHealth.DecayAlerts {
		source, sourceOK := g.GetNode(alert.SourceID)
		target, targetOK := g.GetNode(alert.TargetID)
		if !sourceOK || !targetOK || source == nil || target == nil {
			continue
		}

		// Build customer relationship assets from person<->customer decay alerts.
		customerID := ""
		customerName := ""
		personID := ""
		switch {
		case source.Kind == graph.NodeKindPerson && target.Kind == graph.NodeKindCustomer:
			personID = source.ID
			customerID = target.ID
			customerName = target.Name
		case source.Kind == graph.NodeKindCustomer && target.Kind == graph.NodeKindPerson:
			personID = target.ID
			customerID = source.ID
			customerName = source.Name
		}
		if customerID == "" || personID == "" {
			continue
		}

		decayByPerson[personID]++
		renewalDays := customerRenewalDays(g, customerID)
		assets = append(assets, map[string]interface{}{
			"_cq_table":             orgTopologyCustomerRelationshipsTable,
			"_cq_id":                fmt.Sprintf("org-customer-relationship:%s", firstNonEmptyTrim(alert.EdgeID, customerID+"|"+personID)),
			"resource_id":           customerID,
			"resource_name":         firstNonEmptyTrim(customerName, customerID),
			"customer_id":           customerID,
			"person_id":             personID,
			"relationship_strength": alert.CurrentStrength,
			"previous_strength":     alert.PreviousStrength,
			"renewal_days":          renewalDays,
			"trend":                 alert.Trend,
		})
	}

	bottleneckByPerson := make(map[string]graph.BottleneckResult)
	for _, bottleneck := range orgHealth.Bottlenecks {
		bottleneckByPerson[bottleneck.PersonID] = bottleneck
	}

	people := make(map[string]struct{})
	for _, person := range g.GetNodesByKind(graph.NodeKindPerson) {
		people[person.ID] = struct{}{}
	}
	for personID := range busFactorOneByPerson {
		people[personID] = struct{}{}
	}
	for personID := range bottleneckByPerson {
		people[personID] = struct{}{}
	}
	for personID := range decayByPerson {
		people[personID] = struct{}{}
	}

	personIDs := make([]string, 0, len(people))
	for personID := range people {
		personIDs = append(personIDs, personID)
	}
	sort.Strings(personIDs)

	for _, personID := range personIDs {
		personName := personID
		activityTrend := "stable"
		tenureYears := 0.0

		person, ok := g.GetNode(personID)
		if ok && person != nil {
			if strings.TrimSpace(person.Name) != "" {
				personName = person.Name
			}
			activityTrend = deriveActivityTrend(person.Properties, decayByPerson[personID])
			tenureYears = tenureYearsFromProperties(now, person.Properties)
		} else if decayByPerson[personID] > 0 {
			activityTrend = "declining"
		}

		bottleneck := bottleneckByPerson[personID]
		assets = append(assets, map[string]interface{}{
			"_cq_table":              orgTopologyPeopleTable,
			"_cq_id":                 personID,
			"resource_id":            personID,
			"resource_name":          personName,
			"person_id":              personID,
			"betweenness_centrality": bottleneck.BetweennessCentrality,
			"bridged_teams":          bottleneck.BridgedTeams,
			"bus_factor_1_systems":   busFactorOneByPerson[personID],
			"activity_trend":         activityTrend,
			"tenure_years":           tenureYears,
		})
	}

	sort.Slice(assets, func(i, j int) bool {
		tableI := valueAsString(assets[i]["_cq_table"])
		tableJ := valueAsString(assets[j]["_cq_table"])
		if tableI == tableJ {
			return valueAsString(assets[i]["_cq_id"]) < valueAsString(assets[j]["_cq_id"])
		}
		return tableI < tableJ
	})
	return assets
}

func criticalityForNode(node *graph.Node) string {
	if node == nil {
		return "medium"
	}

	raw := strings.ToLower(strings.TrimSpace(
		firstNonEmptyTrim(
			valueAsString(node.Properties["criticality"]),
			valueAsString(node.Properties["business_criticality"]),
			valueAsString(node.Properties["tier"]),
			valueAsString(node.Properties["priority"]),
		),
	))
	switch raw {
	case "critical", "high", "p0", "tier0", "tier-0", "sev0", "sev1":
		return "high"
	case "medium", "moderate", "p1", "tier1", "tier-1", "sev2":
		return "medium"
	case "low", "p2", "p3", "tier2", "tier-2", "sev3":
		return "low"
	}
	if valueAsBool(node.Properties["critical"]) || valueAsBool(node.Properties["is_critical"]) {
		return "high"
	}
	return "medium"
}

func customerRenewalDays(g *graph.Graph, customerID string) int {
	customer, ok := g.GetNode(customerID)
	if !ok || customer == nil {
		return 365
	}
	days := valueAsInt(
		customer.Properties["renewal_days"],
		customer.Properties["days_to_renewal"],
		customer.Properties["renewal_in_days"],
	)
	if days < 0 {
		return 0
	}
	if days == 0 {
		return 365
	}
	return days
}

func deriveActivityTrend(properties map[string]any, decayCount int) string {
	raw := strings.ToLower(strings.TrimSpace(valueAsString(properties["activity_trend"])))
	switch raw {
	case "declining", "stable", "improving":
		return raw
	}
	if decayCount > 0 {
		return "declining"
	}
	return "stable"
}

func tenureYearsFromProperties(now time.Time, properties map[string]any) float64 {
	startDateRaw := strings.TrimSpace(valueAsString(properties["start_date"]))
	if startDateRaw == "" {
		return 0
	}

	candidates := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
		"2006-01-02 15:04:05",
	}
	var start time.Time
	for _, layout := range candidates {
		parsed, err := time.Parse(layout, startDateRaw)
		if err != nil {
			continue
		}
		start = parsed.UTC()
		break
	}
	if start.IsZero() || start.After(now) {
		return 0
	}
	return now.Sub(start).Hours() / (24 * 365)
}

func valueAsString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func valueAsInt(values ...any) int {
	for _, value := range values {
		switch typed := value.(type) {
		case nil:
			continue
		case int:
			return typed
		case int64:
			return int(typed)
		case int32:
			return int(typed)
		case float64:
			return int(typed)
		case float32:
			return int(typed)
		case string:
			trimmed := strings.TrimSpace(typed)
			if trimmed == "" {
				continue
			}
			if parsed, err := strconv.Atoi(trimmed); err == nil {
				return parsed
			}
			if parsed, err := strconv.ParseFloat(trimmed, 64); err == nil {
				return int(parsed)
			}
		}
	}
	return 0
}

func valueAsBool(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	}
	return false
}

func firstNonEmptyTrim(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
