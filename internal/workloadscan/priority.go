package workloadscan

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

const (
	prioritySourceGraph          = "graph"
	prioritySourceGraphOverride  = "graph_override"
	prioritySourceManualOverride = "manual_override"
)

type PrioritizationOptions struct {
	Providers       []ProviderKind
	IncludeDeferred bool
	Limit           int
	Now             func() time.Time
}

func NormalizeScanPriority(raw string) (ScanPriority, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "urgent", "highest", "now", "force":
		return ScanPriorityCritical, true
	case "high":
		return ScanPriorityHigh, true
	case "medium", "normal":
		return ScanPriorityMedium, true
	case "low":
		return ScanPriorityLow, true
	default:
		return "", false
	}
}

func ManualPriorityAssessment(level ScanPriority, reason string) *PriorityAssessment {
	if !isValidScanPriority(level) {
		return nil
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "manual priority override"
	}
	return &PriorityAssessment{
		Score:    priorityOverrideScore(level),
		Priority: level,
		Eligible: true,
		Source:   prioritySourceManualOverride,
		Reasons:  []string{reason},
		Signals: []PrioritySignal{{
			Category: "override",
			Weight:   priorityOverrideScore(level),
			Summary:  reason,
		}},
	}
}

func ClonePriorityAssessment(in *PriorityAssessment) *PriorityAssessment {
	if in == nil {
		return nil
	}
	out := *in
	out.Reasons = append([]string(nil), in.Reasons...)
	out.ComplianceScopes = append([]string(nil), in.ComplianceScopes...)
	out.Signals = append([]PrioritySignal(nil), in.Signals...)
	if in.LastScannedAt != nil {
		copy := in.LastScannedAt.UTC()
		out.LastScannedAt = &copy
	}
	return &out
}

func PrioritizeTargets(ctx context.Context, g *graph.Graph, store RunStore, opts PrioritizationOptions) ([]TargetPriority, error) {
	if g == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	lastScanned, err := loadLatestSuccessfulScans(ctx, store)
	if err != nil {
		return nil, err
	}
	internetFacing := nodeSet(g.GetInternetFacingNodes())
	crownJewels := nodeSet(g.GetCrownJewels())
	allowedProviders := providerSet(opts.Providers)

	targets := make([]TargetPriority, 0)
	for _, node := range g.GetNodesByKind(graph.NodeKindInstance) {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		target, ok := vmTargetFromNode(node)
		if !ok {
			continue
		}
		if len(allowedProviders) > 0 {
			if _, ok := allowedProviders[target.Provider]; !ok {
				continue
			}
		}
		assessment := assessTargetPriority(g, node, internetFacing, crownJewels, lastScanned[target.Identity()], now)
		if !opts.IncludeDeferred && !assessment.Eligible {
			continue
		}
		targets = append(targets, TargetPriority{
			NodeID:      node.ID,
			DisplayName: firstNonEmpty(strings.TrimSpace(node.Name), target.Identity()),
			Provider:    target.Provider,
			Target:      target,
			Assessment:  assessment,
		})
	}

	sort.Slice(targets, func(i, j int) bool {
		left := targets[i].Assessment
		right := targets[j].Assessment
		if left.Eligible != right.Eligible {
			return left.Eligible
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.LastScannedAt == nil && right.LastScannedAt != nil {
			return true
		}
		if left.LastScannedAt != nil && right.LastScannedAt == nil {
			return false
		}
		if left.LastScannedAt != nil && right.LastScannedAt != nil && !left.LastScannedAt.Equal(*right.LastScannedAt) {
			return left.LastScannedAt.Before(*right.LastScannedAt)
		}
		if targets[i].Provider != targets[j].Provider {
			return targets[i].Provider < targets[j].Provider
		}
		return targets[i].Target.Identity() < targets[j].Target.Identity()
	})

	if opts.Limit > 0 && len(targets) > opts.Limit {
		targets = targets[:opts.Limit]
	}
	return targets, nil
}

func assessTargetPriority(g *graph.Graph, node *graph.Node, internetFacing, crownJewels map[string]struct{}, lastScannedAt *time.Time, now time.Time) PriorityAssessment {
	if override := nodePriorityOverride(node); override != "" {
		assessment := ManualPriorityAssessment(override, "graph priority override")
		if assessment != nil {
			assessment.Source = prioritySourceGraphOverride
			assessment.LastScannedAt = cloneTime(lastScannedAt)
			assessment.Staleness = stalenessBucket(lastScannedAt, now)
			return *assessment
		}
	}

	signals := make([]PrioritySignal, 0, 6)
	addSignal := func(category string, weight int, summary string) {
		if strings.TrimSpace(summary) == "" || weight == 0 {
			return
		}
		signals = append(signals, PrioritySignal{
			Category: category,
			Weight:   weight,
			Summary:  summary,
		})
	}

	score := 0
	exposureWeight, exposure, exposureReason := exposureSignal(g, node, internetFacing)
	score += exposureWeight
	addSignal("exposure", exposureWeight, exposureReason)

	privilegeWeight, privilege, privilegeReason := privilegeSignal(g, node, crownJewels)
	score += privilegeWeight
	addSignal("privilege", privilegeWeight, privilegeReason)

	criticalityWeight, criticality, scopes, criticalityReason := criticalitySignal(g, node)
	score += criticalityWeight
	addSignal("criticality", criticalityWeight, criticalityReason)

	stalenessWeight, eligible, staleness, stalenessReason := stalenessSignal(lastScannedAt, now)
	score += stalenessWeight
	addSignal("staleness", stalenessWeight, stalenessReason)

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	reasons := make([]string, 0, len(signals))
	for _, signal := range signals {
		reasons = append(reasons, signal.Summary)
	}

	return PriorityAssessment{
		Score:            score,
		Priority:         priorityForScore(score),
		Eligible:         eligible,
		Source:           prioritySourceGraph,
		Reasons:          reasons,
		Exposure:         exposure,
		Privilege:        privilege,
		Criticality:      criticality,
		ComplianceScopes: scopes,
		Staleness:        staleness,
		LastScannedAt:    cloneTime(lastScannedAt),
		Signals:          signals,
	}
}

func loadLatestSuccessfulScans(ctx context.Context, store RunStore) (map[string]*time.Time, error) {
	if store == nil {
		return map[string]*time.Time{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	const pageSize = 200
	latest := make(map[string]*time.Time)
	for offset := 0; ; offset += pageSize {
		runs, err := store.ListRuns(ctx, RunListOptions{
			Statuses:           []RunStatus{RunStatusSucceeded},
			Limit:              pageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return nil, err
		}
		for _, run := range runs {
			targetID := strings.TrimSpace(run.Target.Identity())
			if targetID == "" {
				continue
			}
			completedAt := runCompletedAt(run)
			if completedAt == nil {
				continue
			}
			current, ok := latest[targetID]
			if !ok || (current != nil && completedAt.After(*current)) {
				copy := completedAt.UTC()
				latest[targetID] = &copy
			}
		}
		if len(runs) < pageSize {
			break
		}
	}
	return latest, nil
}

func runCompletedAt(run RunRecord) *time.Time {
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt
	}
	if !run.UpdatedAt.IsZero() {
		return &run.UpdatedAt
	}
	if !run.SubmittedAt.IsZero() {
		return &run.SubmittedAt
	}
	return nil
}

func nodeSet(nodes []*graph.Node) map[string]struct{} {
	out := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if node == nil || node.DeletedAt != nil {
			continue
		}
		out[node.ID] = struct{}{}
	}
	return out
}

func providerSet(values []ProviderKind) map[ProviderKind]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[ProviderKind]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func vmTargetFromNode(node *graph.Node) (VMTarget, bool) {
	if node == nil {
		return VMTarget{}, false
	}
	switch strings.ToLower(strings.TrimSpace(node.Provider)) {
	case string(ProviderAWS):
		instanceID := firstNonEmpty(
			readString(node.Properties, "instance_id"),
			strings.TrimSpace(node.Name),
		)
		if instanceID == "" || strings.HasPrefix(strings.ToLower(instanceID), "arn:") {
			instanceID = lastPathSegment(node.ID)
		}
		if instanceID == "" {
			return VMTarget{}, false
		}
		return VMTarget{
			Provider:     ProviderAWS,
			AccountID:    strings.TrimSpace(node.Account),
			Region:       strings.TrimSpace(node.Region),
			InstanceID:   instanceID,
			InstanceName: strings.TrimSpace(node.Name),
		}, true
	case string(ProviderGCP):
		instanceName := firstNonEmpty(strings.TrimSpace(node.Name), readString(node.Properties, "instance_name"))
		zone := firstNonEmpty(readString(node.Properties, "zone"), strings.TrimSpace(node.Region))
		if instanceName == "" || zone == "" {
			return VMTarget{}, false
		}
		return VMTarget{
			Provider:     ProviderGCP,
			ProjectID:    strings.TrimSpace(node.Account),
			Region:       strings.TrimSpace(node.Region),
			Zone:         zone,
			InstanceName: instanceName,
		}, true
	case string(ProviderAzure):
		instanceName := firstNonEmpty(strings.TrimSpace(node.Name), readString(node.Properties, "vm_name"), readString(node.Properties, "instance_name"))
		if instanceName == "" {
			return VMTarget{}, false
		}
		return VMTarget{
			Provider:       ProviderAzure,
			SubscriptionID: strings.TrimSpace(node.Account),
			ResourceGroup:  readString(node.Properties, "resource_group"),
			Region:         strings.TrimSpace(node.Region),
			InstanceName:   instanceName,
		}, true
	default:
		return VMTarget{}, false
	}
}

func exposureSignal(g *graph.Graph, node *graph.Node, internetFacing map[string]struct{}) (int, string, string) {
	if node == nil {
		return 0, "", ""
	}
	if _, ok := internetFacing[node.ID]; ok {
		return 50, "internet_facing", "workload is directly internet-facing"
	}
	if isPublicNode(node) {
		return 35, "public_addressable", "workload exposes a public address or public access property"
	}
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil || edge.IsDeny() {
			continue
		}
		if edge.Kind == graph.EdgeKindExposedTo {
			if source, ok := g.GetNode(edge.Source); ok && source != nil && source.Kind == graph.NodeKindInternet {
				return 50, "internet_facing", "internet entry point reaches workload"
			}
		}
		if _, ok := internetFacing[edge.Source]; ok {
			return 20, "indirect_exposure", "workload sits behind an internet-facing hop"
		}
	}
	return 0, "private", ""
}

func privilegeSignal(g *graph.Graph, node *graph.Node, crownJewels map[string]struct{}) (int, string, string) {
	if node == nil {
		return 0, "", ""
	}
	high := false
	medium := false
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil || edge.IsDeny() {
			continue
		}
		target, _ := g.GetNode(edge.Target)
		switch edge.Kind {
		case graph.EdgeKindCanAdmin:
			return 30, "admin_access", "workload has direct administrative permissions"
		case graph.EdgeKindCanRead, graph.EdgeKindCanWrite:
			if isSensitiveTarget(target, crownJewels) {
				high = true
			} else if target != nil {
				medium = true
			}
		case graph.EdgeKindCanAssume:
			if isPrivilegedIdentity(target) || roleReachesSensitiveTargets(g, target, crownJewels) {
				high = true
			} else if target != nil {
				medium = true
			}
		}
	}
	if high {
		return 25, "privileged", "workload can reach privileged identities or sensitive resources"
	}
	if medium {
		return 12, "elevated", "workload has non-trivial identity or data-plane access"
	}
	return 0, "minimal", ""
}

func roleReachesSensitiveTargets(g *graph.Graph, identity *graph.Node, crownJewels map[string]struct{}) bool {
	if identity == nil {
		return false
	}
	for _, edge := range g.GetOutEdges(identity.ID) {
		if edge == nil || edge.DeletedAt != nil || edge.IsDeny() {
			continue
		}
		target, _ := g.GetNode(edge.Target)
		switch edge.Kind {
		case graph.EdgeKindCanAdmin:
			return true
		case graph.EdgeKindCanRead, graph.EdgeKindCanWrite:
			if isSensitiveTarget(target, crownJewels) {
				return true
			}
		}
	}
	return false
}

func criticalitySignal(g *graph.Graph, node *graph.Node) (int, string, []string, string) {
	level := "low"
	if raw := highestCriticality(g, node); raw != "" {
		level = raw
	}
	scopes := complianceScopes(g, node)
	weight := 0
	reasons := make([]string, 0, 2)
	switch level {
	case "high":
		weight += 20
		reasons = append(reasons, "workload is tagged or connected as business-critical")
	case "medium":
		weight += 10
		reasons = append(reasons, "workload has medium business criticality")
	}
	if len(scopes) > 0 {
		weight += 10
		reasons = append(reasons, "workload is in compliance-sensitive scope")
	}
	return weight, level, scopes, strings.Join(reasons, "; ")
}

func stalenessSignal(lastScannedAt *time.Time, now time.Time) (int, bool, string, string) {
	if lastScannedAt == nil || lastScannedAt.IsZero() {
		return 25, true, "never_scanned", "workload has never been scanned"
	}
	age := now.Sub(lastScannedAt.UTC())
	switch {
	case age > 7*24*time.Hour:
		return 15, true, "stale", "last successful scan is older than seven days"
	case age > 24*time.Hour:
		return 5, true, "aging", "last successful scan is older than one day"
	default:
		return -25, false, "fresh", "last successful scan is within the last 24 hours"
	}
}

func highestCriticality(g *graph.Graph, node *graph.Node) string {
	best := criticalityRank(nodeCriticality(node))
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		neighbor, _ := g.GetNode(edge.Source)
		if rank := criticalityRank(nodeCriticality(neighbor)); rank > best {
			best = rank
		}
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		neighbor, _ := g.GetNode(edge.Target)
		if rank := criticalityRank(nodeCriticality(neighbor)); rank > best {
			best = rank
		}
	}
	return criticalityFromRank(best)
}

func nodeCriticality(node *graph.Node) string {
	if node == nil {
		return ""
	}
	if hasTrueProperty(node.Properties, "critical", "is_critical") {
		return "high"
	}
	if env := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		readString(node.Properties, "environment"),
		readString(node.Properties, "env"),
		valueFromTags(node.Tags, "environment"),
		valueFromTags(node.Tags, "env"),
	))); env == "prod" || env == "production" {
		return "high"
	}
	raw := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		readString(node.Properties, "criticality"),
		readString(node.Properties, "business_criticality"),
		readString(node.Properties, "tier"),
		readString(node.Properties, "priority"),
		valueFromTags(node.Tags, "criticality"),
		valueFromTags(node.Tags, "business_criticality"),
		valueFromTags(node.Tags, "tier"),
	)))
	switch raw {
	case "critical", "high", "p0", "tier0", "tier-0", "sev0", "sev1":
		return "high"
	case "medium", "moderate", "p1", "tier1", "tier-1", "sev2":
		return "medium"
	case "low", "p2", "p3", "tier2", "tier-2", "sev3":
		return "low"
	default:
		return ""
	}
}

func complianceScopes(g *graph.Graph, node *graph.Node) []string {
	scopes := make(map[string]struct{})
	collectComplianceScopes(node, scopes)
	for _, edge := range g.GetInEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		neighbor, _ := g.GetNode(edge.Source)
		collectComplianceScopes(neighbor, scopes)
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.DeletedAt != nil {
			continue
		}
		neighbor, _ := g.GetNode(edge.Target)
		collectComplianceScopes(neighbor, scopes)
	}
	if len(scopes) == 0 {
		return nil
	}
	out := make([]string, 0, len(scopes))
	for scope := range scopes {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func collectComplianceScopes(node *graph.Node, scopes map[string]struct{}) {
	if node == nil {
		return
	}
	for _, raw := range []string{
		readString(node.Properties, "compliance_scope"),
		readString(node.Properties, "compliance_scopes"),
		readString(node.Properties, "regulatory_scope"),
		readString(node.Properties, "frameworks"),
		valueFromTags(node.Tags, "compliance"),
		valueFromTags(node.Tags, "compliance_scope"),
	} {
		for _, part := range strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '|'
		}) {
			part = strings.TrimSpace(part)
			switch part {
			case "pci", "pci-dss", "hipaa", "soc2", "sox", "gdpr":
				scopes[part] = struct{}{}
			}
		}
	}
}

func isPublicNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	if hasTrueProperty(node.Properties, "public", "internet_exposed", "publicly_accessible") {
		return true
	}
	for _, key := range []string{"public_ip", "public_ip_address", "function_url"} {
		if value := strings.TrimSpace(readString(node.Properties, key)); value != "" && !strings.EqualFold(value, "n/a") {
			return true
		}
	}
	if ingress := strings.ToLower(strings.TrimSpace(readString(node.Properties, "ingress"))); strings.Contains(ingress, "all") {
		return true
	}
	return false
}

func isSensitiveTarget(node *graph.Node, crownJewels map[string]struct{}) bool {
	if node == nil {
		return false
	}
	if _, ok := crownJewels[node.ID]; ok {
		return true
	}
	switch node.Kind {
	case graph.NodeKindSecret, graph.NodeKindDatabase, graph.NodeKindBucket:
		return true
	}
	if hasTrueProperty(node.Properties, "contains_pii", "sensitive", "restricted") {
		return true
	}
	if classification := strings.ToLower(strings.TrimSpace(readString(node.Properties, "data_classification"))); classification == "confidential" || classification == "restricted" || classification == "sensitive" {
		return true
	}
	text := strings.ToLower(strings.Join([]string{node.ID, node.Name, readString(node.Properties, "service"), readString(node.Properties, "resource_type")}, " "))
	return strings.Contains(text, "kms") || strings.Contains(text, "key")
}

func isPrivilegedIdentity(node *graph.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case graph.NodeKindRole, graph.NodeKindServiceAccount, graph.NodeKindGroup:
	default:
		return false
	}
	if node.Risk == graph.RiskCritical || node.Risk == graph.RiskHigh {
		return true
	}
	if hasTrueProperty(node.Properties, "is_admin", "admin", "privileged") {
		return true
	}
	text := strings.ToLower(strings.Join([]string{node.ID, node.Name}, " "))
	return strings.Contains(text, "admin") || strings.Contains(text, "owner") || strings.Contains(text, "power")
}

func nodePriorityOverride(node *graph.Node) ScanPriority {
	if node == nil {
		return ""
	}
	for _, raw := range []string{
		readString(node.Properties, "scan_priority_override"),
		readString(node.Properties, "workload_scan_priority"),
		valueFromTags(node.Tags, "cerebro_scan_priority"),
		valueFromTags(node.Tags, "scan_priority"),
	} {
		if priority, ok := NormalizeScanPriority(raw); ok {
			return priority
		}
	}
	return ""
}

func priorityForScore(score int) ScanPriority {
	switch {
	case score >= 80:
		return ScanPriorityCritical
	case score >= 55:
		return ScanPriorityHigh
	case score >= 30:
		return ScanPriorityMedium
	default:
		return ScanPriorityLow
	}
}

func priorityOverrideScore(level ScanPriority) int {
	switch level {
	case ScanPriorityCritical:
		return 100
	case ScanPriorityHigh:
		return 80
	case ScanPriorityMedium:
		return 50
	default:
		return 20
	}
}

func isValidScanPriority(level ScanPriority) bool {
	switch level {
	case ScanPriorityCritical, ScanPriorityHigh, ScanPriorityMedium, ScanPriorityLow:
		return true
	default:
		return false
	}
}

func criticalityRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func criticalityFromRank(rank int) string {
	switch rank {
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "low"
	}
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func stalenessBucket(lastScannedAt *time.Time, now time.Time) string {
	_, _, bucket, _ := stalenessSignal(lastScannedAt, now)
	return bucket
}

func hasTrueProperty(values map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch value := values[key].(type) {
		case bool:
			if value {
				return true
			}
		case string:
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "1", "true", "yes", "y", "public", "enabled":
				return true
			}
		}
	}
	return false
}

func valueFromTags(values map[string]string, key string) string {
	if values == nil {
		return ""
	}
	return strings.TrimSpace(values[key])
}

func lastPathSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.LastIndexByte(value, '/'); idx >= 0 && idx+1 < len(value) {
		return value[idx+1:]
	}
	return value
}
