package graph

import (
	"fmt"
	"strings"
	"time"
)

const businessNeighborTraversalDepth = 2

const (
	businessTrajectoryWindow   = 30 * 24 * time.Hour
	businessHealthStreakWindow = 60 * 24 * time.Hour
)

func (e *ToxicCombinationEngine) ruleChurnCompoundSignal() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-001",
		Name:        "Churn Compound Signal",
		Description: "Multiple customer-health signals indicate acute churn risk",
		Severity:    SeverityCritical,
		Tags:        []string{"business", "churn", "cross-system"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindCustomer && node.Kind != NodeKindCompany {
				return nil
			}

			p1Tickets := readInt(node.Properties, "open_p1_tickets", "p1_ticket_count")
			paymentFailure := readInt(node.Properties, "failed_payment_count") > 0
			renewalSoon := readInt(node.Properties, "days_until_renewal")
			championDeparted := readBool(node.Properties, "champion_departed")

			affected := []string{node.ID}
			for _, neighbor := range businessNeighbors(g, node.ID, businessNeighborTraversalDepth) {
				affected = append(affected, neighbor.ID)
				switch neighbor.Kind {
				case NodeKindTicket:
					priority := strings.ToLower(readString(neighbor.Properties, "priority", "severity"))
					status := strings.ToLower(readString(neighbor.Properties, "status"))
					if (priority == "p1" || priority == "critical" || priority == "sev1") && status != "resolved" && status != "closed" {
						p1Tickets++
					}
				case NodeKindSubscription, NodeKindInvoice:
					if readInt(neighbor.Properties, "failed_payment_count", "payment_failed_count") > 0 {
						paymentFailure = true
					}
					status := strings.ToLower(readString(neighbor.Properties, "status", "collection_status"))
					if status == "past_due" || status == "unpaid" {
						paymentFailure = true
					}
				case NodeKindDeal, NodeKindOpportunity:
					if d := readInt(neighbor.Properties, "days_until_renewal", "days_until_trial_end"); d > 0 && (renewalSoon == 0 || d < renewalSoon) {
						renewalSoon = d
					}
				case NodeKindContact:
					if readBool(neighbor.Properties, "champion_departed", "is_champion_departed") {
						championDeparted = true
					}
				}
			}

			if p1Tickets < 2 || !paymentFailure || renewalSoon <= 0 || renewalSoon >= 30 || !championDeparted {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-001-%s", node.ID),
				Name:        "Churn Compound Signal",
				Description: fmt.Sprintf("%s has support pressure, billing failure, near-term renewal, and champion departure", node.Name),
				Severity:    SeverityCritical,
				Score:       93,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: fmt.Sprintf("%d open P1 tickets", p1Tickets), Severity: SeverityHigh},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Billing failure on active account", Severity: SeverityCritical},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: fmt.Sprintf("Renewal in %d days", renewalSoon), Severity: SeverityHigh},
				},
				AffectedAssets: dedupeStrings(affected),
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Escalate customer health review", Resource: node.ID, Impact: "Coordinates support, sales, and finance intervention", Effort: "low"},
					{Priority: 2, Action: "Resolve payment blockers and executive outreach", Resource: node.ID, Impact: "Reduces immediate churn probability", Effort: "medium"},
				},
				Tags: []string{"churn", "support", "billing", "renewal"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleTrajectoryDeterioration() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-006",
		Name:        "Trajectory Deterioration",
		Description: "Customer trajectory is deteriorating across health and support load",
		Severity:    SeverityHigh,
		Tags:        []string{"business", "trajectory", "churn"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindCustomer && node.Kind != NodeKindCompany {
				return nil
			}

			healthDelta, healthDeltaOK := g.TemporalDelta(node.ID, "health_score", businessTrajectoryWindow)
			healthTrend, healthTrendOK := g.TemporalTrend(node.ID, "health_score", businessTrajectoryWindow)
			ticketTrend, ticketTrendOK := g.TemporalTrend(node.ID, "open_tickets", businessTrajectoryWindow)
			ticketDelta, ticketDeltaOK := g.TemporalDelta(node.ID, "open_tickets", businessTrajectoryWindow)
			lowHealthStreak, lowHealthStreakOK := g.TemporalStreak(node.ID, "health_score", "<=", 80, businessHealthStreakWindow)

			deterioratingHealth := healthDeltaOK && healthDelta <= -20
			if healthTrendOK && healthTrend == "decreasing" && healthDeltaOK && healthDelta <= -10 {
				deterioratingHealth = true
			}
			risingTickets := (ticketTrendOK && ticketTrend == "increasing") || (ticketDeltaOK && ticketDelta >= 3)
			sustainedLowHealth := lowHealthStreakOK && lowHealthStreak >= 2
			if !deterioratingHealth || !risingTickets || !sustainedLowHealth {
				return nil
			}

			name := strings.TrimSpace(node.Name)
			if name == "" {
				name = node.ID
			}

			score := 86.0
			if healthDelta <= -30 && ticketDeltaOK && ticketDelta >= 5 {
				score = 92
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-006-%s", node.ID),
				Name:        "Trajectory Deterioration",
				Description: fmt.Sprintf("%s shows sustained health decline with rising support pressure", name),
				Severity:    SeverityHigh,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: fmt.Sprintf("Health score delta %.1f over %d days", healthDelta, int(businessTrajectoryWindow.Hours()/24)), Severity: SeverityHigh},
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Open tickets trend is increasing", Severity: SeverityHigh},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: fmt.Sprintf("Low-health streak: %d snapshots <= 80", lowHealthStreak), Severity: SeverityMedium},
				},
				AffectedAssets: []string{node.ID},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Launch proactive customer recovery plan", Resource: node.ID, Impact: "Stabilizes health score before renewal risk compounds", Effort: "medium"},
					{Priority: 2, Action: "Escalate support backlog burn-down", Resource: node.ID, Impact: "Reverses ticket growth trajectory", Effort: "medium"},
				},
				Tags: []string{"trajectory", "health-score", "support"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleRevenueAtRisk() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-002",
		Name:        "Revenue-at-Risk",
		Description: "Large stale revenue opportunity with competitive and usage pressure",
		Severity:    SeverityHigh,
		Tags:        []string{"business", "revenue", "pipeline"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindDeal && node.Kind != NodeKindOpportunity {
				return nil
			}

			amount := readFloat(node.Properties, "amount", "arr", "deal_value")
			staleDays := readInt(node.Properties, "days_since_last_activity", "days_since_last_modified")
			if amount < 100000 || staleDays <= 21 {
				return nil
			}

			competitorMentioned := readBool(node.Properties, "competitor_mentioned")
			usageDeclining := readBool(node.Properties, "usage_declining", "usage_downtrend")
			affected := []string{node.ID}

			for _, neighbor := range businessNeighbors(g, node.ID, businessNeighborTraversalDepth) {
				affected = append(affected, neighbor.ID)
				switch neighbor.Kind {
				case NodeKindTicket:
					if readBool(neighbor.Properties, "competitor_mentioned") {
						competitorMentioned = true
					}
				case NodeKindCustomer, NodeKindCompany:
					if readBool(neighbor.Properties, "usage_declining", "usage_downtrend") || readFloat(neighbor.Properties, "usage_delta_pct") < -20 {
						usageDeclining = true
					}
				}
			}

			if !competitorMentioned || !usageDeclining {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-002-%s", node.ID),
				Name:        "Revenue-at-Risk",
				Description: fmt.Sprintf("%s is a stale high-value opportunity with competitive pressure", node.Name),
				Severity:    SeverityHigh,
				Score:       84,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: fmt.Sprintf("$%.0f stale %d days", amount, staleDays), Severity: SeverityHigh},
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Competitor mentioned in customer support context", Severity: SeverityMedium},
				},
				AffectedAssets: dedupeStrings(affected),
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Run pipeline rescue plan", Resource: node.ID, Impact: "Restores deal momentum and next-step cadence", Effort: "medium"},
					{Priority: 2, Action: "Launch executive product adoption intervention", Resource: node.ID, Impact: "Counteracts usage decline and competitive threat", Effort: "medium"},
				},
				Tags: []string{"revenue", "pipeline", "competition"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleSecurityMeetsBusiness() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-003",
		Name:        "Security-Meets-Business",
		Description: "Security posture gaps now directly threaten in-flight commercial outcomes",
		Severity:    SeverityCritical,
		Tags:        []string{"business", "security", "compliance"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindCustomer && node.Kind != NodeKindCompany {
				return nil
			}

			hasCriticalSecurity := readInt(node.Properties, "critical_findings") > 0
			complianceAsk := readBool(node.Properties, "compliance_request_open")
			renewalDays := readInt(node.Properties, "days_until_renewal")
			affected := []string{node.ID}

			for _, neighbor := range businessNeighbors(g, node.ID, businessNeighborTraversalDepth) {
				affected = append(affected, neighbor.ID)
				if neighbor.IsResource() && (neighbor.Risk == RiskCritical || neighbor.Risk == RiskHigh) {
					hasCriticalSecurity = true
				}
				if neighbor.Kind == NodeKindTicket {
					if readBool(neighbor.Properties, "compliance_request", "soc2_requested") {
						complianceAsk = true
					}
					if text := strings.ToLower(readString(neighbor.Properties, "subject", "title", "description")); strings.Contains(text, "soc2") || strings.Contains(text, "compliance") {
						complianceAsk = true
					}
				}
				if neighbor.Kind == NodeKindDeal || neighbor.Kind == NodeKindOpportunity {
					if d := readInt(neighbor.Properties, "days_until_renewal", "days_until_close"); d > 0 && (renewalDays == 0 || d < renewalDays) {
						renewalDays = d
					}
				}
			}

			if !hasCriticalSecurity || !complianceAsk || renewalDays <= 0 || renewalDays >= 60 {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-003-%s", node.ID),
				Name:        "Security-Meets-Business",
				Description: fmt.Sprintf("%s has critical security risk while facing compliance-sensitive renewal", node.Name),
				Severity:    SeverityCritical,
				Score:       90,
				Factors: []*RiskFactor{
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Critical security findings near renewal", Severity: SeverityCritical},
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Active compliance assurance request", Severity: SeverityHigh},
				},
				AffectedAssets: dedupeStrings(affected),
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Prioritize compliance remediation sprint", Resource: node.ID, Impact: "Reduces deal-loss risk tied to security posture", Effort: "high"},
					{Priority: 2, Action: "Create executive renewal risk briefing", Resource: node.ID, Impact: "Aligns security and revenue leadership response", Effort: "low"},
				},
				Tags: []string{"security", "renewal", "compliance"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleOperationalBlastRadius() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-004",
		Name:        "Operational Blast Radius",
		Description: "An active outage is attached to many high-value customer outcomes",
		Severity:    SeverityCritical,
		Tags:        []string{"business", "operations", "incident"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindApplication && node.Kind != NodeKindInstance && node.Kind != NodeKindFunction {
				return nil
			}
			if !readBool(node.Properties, "outage_detected", "incident_open") {
				return nil
			}

			affectedCustomers := 0
			combinedARR := 0.0
			affected := []string{node.ID}
			for _, neighbor := range businessNeighbors(g, node.ID, businessNeighborTraversalDepth) {
				affected = append(affected, neighbor.ID)
				if neighbor.Kind == NodeKindCustomer || neighbor.Kind == NodeKindCompany {
					affectedCustomers++
					combinedARR += readFloat(neighbor.Properties, "arr", "contract_value", "revenue")
				}
			}

			if affectedCustomers < 2 {
				return nil
			}

			score := 82.0
			if combinedARR >= 1000000 {
				score = 94
			} else if combinedARR >= 500000 {
				score = 90
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-004-%s", node.ID),
				Name:        "Operational Blast Radius",
				Description: fmt.Sprintf("Outage on %s affects %d customers and %.0f ARR", node.Name, affectedCustomers, combinedARR),
				Severity:    SeverityCritical,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Service outage on shared dependency", Severity: SeverityCritical},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: fmt.Sprintf("%d customers affected", affectedCustomers), Severity: SeverityHigh},
				},
				AffectedAssets: dedupeStrings(affected),
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Activate enterprise incident escalation", Resource: node.ID, Impact: "Limits churn and SLA impact during outage", Effort: "high"},
					{Priority: 2, Action: "Isolate failing dependency path", Resource: node.ID, Impact: "Reduces blast radius for unaffected tenants", Effort: "medium"},
				},
				Tags: []string{"incident", "blast-radius", "arr"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleFinancialGuardrail() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-BIZ-005",
		Name:        "Financial Guardrail",
		Description: "Large refund without approval on account with recent chargeback",
		Severity:    SeverityHigh,
		Tags:        []string{"business", "finance", "fraud"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindInvoice && node.Kind != NodeKindSubscription && node.Kind != NodeKindCustomer {
				return nil
			}

			refundAmount := readFloat(node.Properties, "refund_amount", "refund_total")
			approvalRecorded := readBool(node.Properties, "approval_recorded", "approval_exists") || readString(node.Properties, "approval_id") != ""
			hasChargeback := readInt(node.Properties, "chargeback_count") > 0 || readInt(node.Properties, "days_since_last_chargeback") <= 90
			affected := []string{node.ID}

			for _, neighbor := range businessNeighbors(g, node.ID, businessNeighborTraversalDepth) {
				affected = append(affected, neighbor.ID)
				if amount := readFloat(neighbor.Properties, "refund_amount", "refund_total"); amount > refundAmount {
					refundAmount = amount
				}
				if readBool(neighbor.Properties, "approval_recorded", "approval_exists") || readString(neighbor.Properties, "approval_id") != "" {
					approvalRecorded = true
				}
				if readInt(neighbor.Properties, "chargeback_count") > 0 || readInt(neighbor.Properties, "days_since_last_chargeback") <= 90 {
					hasChargeback = true
				}
			}

			if refundAmount <= 5000 || approvalRecorded || !hasChargeback {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-BIZ-005-%s", node.ID),
				Name:        "Financial Guardrail",
				Description: fmt.Sprintf("%.0f refund without approval on account with recent chargeback", refundAmount),
				Severity:    SeverityHigh,
				Score:       83,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Approval bypass on large refund", Severity: SeverityHigh},
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Chargeback history in last 90 days", Severity: SeverityMedium},
				},
				AffectedAssets: dedupeStrings(affected),
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Require human approval for high-value refunds", Resource: node.ID, Impact: "Restores financial approval control", Effort: "low"},
					{Priority: 2, Action: "Run fraud/compliance review on account", Resource: node.ID, Impact: "Reduces repeated financial leakage", Effort: "medium"},
				},
				Tags: []string{"financial-controls", "refund", "approval"},
			}
		},
	}
}

func businessNeighbors(g *Graph, nodeID string, maxDepth int) []*Node {
	if maxDepth <= 0 {
		return nil
	}

	type visit struct {
		id    string
		depth int
	}
	seen := map[string]bool{nodeID: true}
	neighbors := make([]*Node, 0)
	queue := []visit{{id: nodeID, depth: 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= maxDepth {
			continue
		}

		nextIDs := make([]string, 0)
		for _, edge := range g.GetOutEdges(current.id) {
			nextIDs = append(nextIDs, edge.Target)
		}
		for _, edge := range g.GetInEdges(current.id) {
			nextIDs = append(nextIDs, edge.Source)
		}

		for _, adjacentID := range nextIDs {
			if seen[adjacentID] {
				continue
			}
			node, ok := g.GetNode(adjacentID)
			if !ok {
				continue
			}
			seen[adjacentID] = true
			neighbors = append(neighbors, node)
			queue = append(queue, visit{id: adjacentID, depth: current.depth + 1})
		}
	}

	return neighbors
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
