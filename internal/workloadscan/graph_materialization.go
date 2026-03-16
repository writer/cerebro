package workloadscan

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/evalops/cerebro/internal/filesystemanalyzer"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/scanner"
)

const graphMaterializationSourceSystem = "cerebro_workload_scan"

// GraphMaterializationResult summarizes one batch of graph writes derived from workload scans.
type GraphMaterializationResult struct {
	RunsConsidered           int `json:"runs_considered"`
	RunsMaterialized         int `json:"runs_materialized"`
	RunsSkipped              int `json:"runs_skipped"`
	TargetLinksCreated       int `json:"target_links_created"`
	ScanNodesUpserted        int `json:"scan_nodes_upserted"`
	ObservationNodesUpserted int `json:"observation_nodes_upserted"`
	SecretNodesUpserted      int `json:"secret_nodes_upserted"`
	PackageNodesUpserted     int `json:"package_nodes_upserted"`
	TechnologyNodesUpserted  int `json:"technology_nodes_upserted"`
	VulnNodesUpserted        int `json:"vulnerability_nodes_upserted"`
	ScanObservationEdges     int `json:"scan_observation_edges"`
	ScanSecretEdges          int `json:"scan_secret_edges"`
	SecretTargetEdges        int `json:"secret_target_edges"`
	CredentialPivotEdges     int `json:"credential_pivot_edges"`
	ScanPackageEdges         int `json:"scan_package_edges"`
	PackageDependencyEdges   int `json:"package_dependency_edges"`
	WorkloadTechnologyEdges  int `json:"workload_technology_edges"`
	ScanVulnEdges            int `json:"scan_vulnerability_edges"`
	PackageVulnEdges         int `json:"package_vulnerability_edges"`
	SkippedUnresolvedRuns    int `json:"skipped_unresolved_runs"`
	SkippedIncompleteRuns    int `json:"skipped_incomplete_runs"`
	SkippedUnsupportedRuns   int `json:"skipped_unsupported_runs"`
}

type resolvedRun struct {
	target *graph.Node
	run    RunRecord
}

type packageAggregate struct {
	record filesystemanalyzer.PackageRecord
}

type packageDependencyAggregate struct {
	parent filesystemanalyzer.PackageRecord
	child  filesystemanalyzer.PackageRecord
}

type technologyAggregate struct {
	record filesystemanalyzer.TechnologyRecord
}

type secretAggregate struct {
	record filesystemanalyzer.SecretFinding
}

type malwareAggregate struct {
	record filesystemanalyzer.MalwareFinding
}

type vulnerabilityAggregate struct {
	record scanner.ImageVulnerability
}

type vulnerabilityUsageContext struct {
	bestPackage                filesystemanalyzer.PackageRecord
	hasBestPackage             bool
	affectedPackageKeys        map[string]struct{}
	reachablePackageKeys       map[string]struct{}
	directReachablePackageKeys map[string]struct{}
}

type configAggregate struct {
	record filesystemanalyzer.ConfigFinding
}

type packageVulnerabilityAggregate struct {
	pkg     filesystemanalyzer.PackageRecord
	vulnKey string
}

type scanSummary struct {
	PackageCount                        int
	VulnerabilityCount                  int
	CriticalVulnerabilityCount          int
	HighVulnerabilityCount              int
	MediumVulnerabilityCount            int
	LowVulnerabilityCount               int
	UnknownVulnerabilityCount           int
	KnownExploitedCount                 int
	ExploitableCount                    int
	FixableCount                        int
	ReachableVulnerabilityCount         int
	ReachableCriticalVulnerabilityCount int
	ReachableHighVulnerabilityCount     int
	ReachableKnownExploitedCount        int
	DirectReachableVulnerabilityCount   int
	SecretCount                         int
	MisconfigurationCount               int
	IaCArtifactCount                    int
	MalwareCount                        int
	TechnologyCount                     int
	FindingCount                        int64
	OSName                              string
	OSVersion                           string
	OSArchitecture                      string
	SBOMRef                             string
	Risk                                graph.RiskLevel
}

// MaterializeRunsIntoGraph writes successful workload scan runs into the graph.
// Older scans for the same asset are closed with valid_to when a newer successful scan exists.
func MaterializeRunsIntoGraph(g *graph.Graph, runs []RunRecord, now time.Time) GraphMaterializationResult {
	result := GraphMaterializationResult{}
	if g == nil || len(runs) == 0 {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	grouped := make(map[string][]resolvedRun)
	for i := range runs {
		run := runs[i]
		result.RunsConsidered++
		if run.Status != RunStatusSucceeded {
			result.RunsSkipped++
			result.SkippedIncompleteRuns++
			continue
		}
		if observedAt(run).IsZero() {
			result.RunsSkipped++
			result.SkippedIncompleteRuns++
			continue
		}
		target, ok := resolveTargetNode(g, run)
		if !ok || target == nil {
			result.RunsSkipped++
			result.SkippedUnresolvedRuns++
			continue
		}
		grouped[target.ID] = append(grouped[target.ID], resolvedRun{target: target, run: run})
	}

	for _, runsForTarget := range grouped {
		sort.Slice(runsForTarget, func(i, j int) bool {
			left := observedAt(runsForTarget[i].run)
			right := observedAt(runsForTarget[j].run)
			if !left.Equal(right) {
				return left.Before(right)
			}
			return runsForTarget[i].run.ID < runsForTarget[j].run.ID
		})
		for i := range runsForTarget {
			var validTo *time.Time
			if i+1 < len(runsForTarget) {
				next := observedAt(runsForTarget[i+1].run)
				if !next.IsZero() {
					copy := next.UTC()
					validTo = &copy
				}
			}
			batch := materializeOneRun(g, runsForTarget[i].target, runsForTarget[i].run, validTo, now)
			result.RunsMaterialized += batch.RunsMaterialized
			result.RunsSkipped += batch.RunsSkipped
			result.TargetLinksCreated += batch.TargetLinksCreated
			result.ScanNodesUpserted += batch.ScanNodesUpserted
			result.ObservationNodesUpserted += batch.ObservationNodesUpserted
			result.SecretNodesUpserted += batch.SecretNodesUpserted
			result.PackageNodesUpserted += batch.PackageNodesUpserted
			result.TechnologyNodesUpserted += batch.TechnologyNodesUpserted
			result.VulnNodesUpserted += batch.VulnNodesUpserted
			result.ScanObservationEdges += batch.ScanObservationEdges
			result.ScanSecretEdges += batch.ScanSecretEdges
			result.SecretTargetEdges += batch.SecretTargetEdges
			result.CredentialPivotEdges += batch.CredentialPivotEdges
			result.ScanPackageEdges += batch.ScanPackageEdges
			result.PackageDependencyEdges += batch.PackageDependencyEdges
			result.WorkloadTechnologyEdges += batch.WorkloadTechnologyEdges
			result.ScanVulnEdges += batch.ScanVulnEdges
			result.PackageVulnEdges += batch.PackageVulnEdges
		}
	}

	g.BuildIndex()
	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		meta.BuiltAt = now.UTC()
	}
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
	return result
}

func materializeOneRun(g *graph.Graph, target *graph.Node, run RunRecord, validTo *time.Time, now time.Time) GraphMaterializationResult {
	result := GraphMaterializationResult{}
	if g == nil || target == nil {
		result.RunsSkipped = 1
		return result
	}

	seenAt := observedAt(run)
	if seenAt.IsZero() {
		result.RunsSkipped = 1
		return result
	}
	validFrom := runValidFrom(run, seenAt)
	summary, findings, secrets, malware, packages, packageDeps, technologies, vulns, relations, vulnUsage := summarizeRun(run)
	sourceEventID := fmt.Sprintf("workload_scan:%s", firstNonEmpty(strings.TrimSpace(run.ID), syntheticRunKey(run)))
	writeMeta := graph.NormalizeWriteMetadata(
		seenAt,
		validFrom,
		validTo,
		graphMaterializationSourceSystem,
		sourceEventID,
		1.0,
		graph.WriteMetadataDefaults{
			Now:             now,
			RecordedAt:      seenAt,
			TransactionFrom: seenAt,
			SourceSystem:    graphMaterializationSourceSystem,
			SourceEventID:   sourceEventID,
		},
	)

	scanNode := &graph.Node{
		ID:       nodeID(run),
		Kind:     graph.NodeKindWorkloadScan,
		Name:     nodeName(target, seenAt),
		Provider: target.Provider,
		Account:  target.Account,
		Region:   target.Region,
		Risk:     summary.Risk,
		Properties: map[string]any{
			"scan_id":                                firstNonEmpty(strings.TrimSpace(run.ID), syntheticRunKey(run)),
			"target_id":                              target.ID,
			"target_kind":                            string(target.Kind),
			"provider":                               string(run.Provider),
			"status":                                 string(run.Status),
			"stage":                                  string(run.Stage),
			"submitted_at":                           formatTime(run.SubmittedAt),
			"started_at":                             formatTimePtr(run.StartedAt),
			"completed_at":                           formatTimePtr(run.CompletedAt),
			"os_name":                                summary.OSName,
			"os_version":                             summary.OSVersion,
			"os_architecture":                        summary.OSArchitecture,
			"package_count":                          summary.PackageCount,
			"vulnerability_count":                    summary.VulnerabilityCount,
			"critical_vulnerability_count":           summary.CriticalVulnerabilityCount,
			"high_vulnerability_count":               summary.HighVulnerabilityCount,
			"medium_vulnerability_count":             summary.MediumVulnerabilityCount,
			"low_vulnerability_count":                summary.LowVulnerabilityCount,
			"unknown_vulnerability_count":            summary.UnknownVulnerabilityCount,
			"reachable_vulnerability_count":          summary.ReachableVulnerabilityCount,
			"reachable_critical_vulnerability_count": summary.ReachableCriticalVulnerabilityCount,
			"reachable_high_vulnerability_count":     summary.ReachableHighVulnerabilityCount,
			"reachable_known_exploited_count":        summary.ReachableKnownExploitedCount,
			"direct_reachable_vulnerability_count":   summary.DirectReachableVulnerabilityCount,
			"known_exploited_count":                  summary.KnownExploitedCount,
			"exploitable_vulnerability_count":        summary.ExploitableCount,
			"fixable_vulnerability_count":            summary.FixableCount,
			"secret_count":                           summary.SecretCount,
			"misconfiguration_count":                 summary.MisconfigurationCount,
			"iac_artifact_count":                     summary.IaCArtifactCount,
			"malware_count":                          summary.MalwareCount,
			"technology_count":                       summary.TechnologyCount,
			"finding_count":                          summary.FindingCount,
			"sbom_ref":                               summary.SBOMRef,
		},
	}
	applyPriorityProperties(scanNode.Properties, run.Priority)
	writeMeta.ApplyTo(scanNode.Properties)
	g.AddNode(scanNode)
	result.ScanNodesUpserted++

	if graph.AddEdgeIfMissing(g, &graph.Edge{
		ID:         edgeID(target.ID, scanNode.ID, graph.EdgeKindHasScan),
		Source:     target.ID,
		Target:     scanNode.ID,
		Kind:       graph.EdgeKindHasScan,
		Effect:     graph.EdgeEffectAllow,
		Properties: cloneWorkloadAnyMap(writeMeta.PropertyMap()),
		Risk:       scanNode.Risk,
	}) {
		result.TargetLinksCreated++
	}

	for _, pkgAgg := range packages {
		pkgMeta := graph.NormalizeWriteMetadata(
			seenAt,
			validFrom,
			nil,
			graphMaterializationSourceSystem,
			fmt.Sprintf("%s:package:%s", sourceEventID, packageKey(pkgAgg.record)),
			1.0,
			graph.WriteMetadataDefaults{
				Now:             now,
				RecordedAt:      seenAt,
				TransactionFrom: seenAt,
				SourceSystem:    graphMaterializationSourceSystem,
			},
		)
		pkgNode := buildPackageNode(pkgAgg.record, target, pkgMeta)
		g.AddNode(pkgNode)
		result.PackageNodesUpserted++
		edgeProps := cloneWorkloadAnyMap(writeMeta.PropertyMap())
		edgeProps["direct_dependency"] = pkgAgg.record.DirectDependency
		edgeProps["reachable"] = pkgAgg.record.Reachable
		edgeProps["dependency_depth"] = pkgAgg.record.DependencyDepth
		edgeProps["import_file_count"] = pkgAgg.record.ImportFileCount
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(scanNode.ID, pkgNode.ID, graph.EdgeKindContainsPkg),
			Source:     scanNode.ID,
			Target:     pkgNode.ID,
			Kind:       graph.EdgeKindContainsPkg,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeProps,
			Risk:       graph.RiskLow,
		}) {
			result.ScanPackageEdges++
		}
	}

	for _, depAgg := range packageDeps {
		parentID := packageNodeID(depAgg.parent)
		childID := packageNodeID(depAgg.child)
		if parentID == "" || childID == "" {
			continue
		}
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:     edgeID(parentID, childID, graph.EdgeKindDependsOn),
			Source: parentID,
			Target: childID,
			Kind:   graph.EdgeKindDependsOn,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"source_system":    graphMaterializationSourceSystem,
				"source_event_id":  fmt.Sprintf("%s:package_dependency:%s", sourceEventID, packageDependencyKey(depAgg.parent, depAgg.child)),
				"observed_at":      seenAt.UTC().Format(time.RFC3339),
				"valid_from":       validFrom.UTC().Format(time.RFC3339),
				"recorded_at":      seenAt.UTC().Format(time.RFC3339),
				"transaction_from": seenAt.UTC().Format(time.RFC3339),
				"confidence":       1.0,
			},
			Risk: graph.RiskLow,
		}) {
			result.PackageDependencyEdges++
		}
	}

	for _, techAgg := range technologies {
		techMeta := graph.NormalizeWriteMetadata(
			seenAt,
			validFrom,
			nil,
			graphMaterializationSourceSystem,
			fmt.Sprintf("%s:technology:%s", sourceEventID, technologyKey(techAgg.record)),
			1.0,
			graph.WriteMetadataDefaults{
				Now:             now,
				RecordedAt:      seenAt,
				TransactionFrom: seenAt,
				SourceSystem:    graphMaterializationSourceSystem,
			},
		)
		existingTechNode, _ := g.GetNode(technologyNodeID(techAgg.record))
		techNode := buildTechnologyNode(techAgg.record, techMeta, existingTechNode)
		g.AddNode(techNode)
		result.TechnologyNodesUpserted++
		techEdgeProperties := cloneWorkloadAnyMap(techMeta.PropertyMap())
		techEdgeProperties["technology_name"] = techAgg.record.Name
		techEdgeProperties["category"] = techAgg.record.Category
		techEdgeProperties["version"] = strings.TrimSpace(techAgg.record.Version)
		techEdgeProperties["file_path"] = strings.TrimSpace(techAgg.record.Path)
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(target.ID, techNode.ID, graph.EdgeKindRuns),
			Source:     target.ID,
			Target:     techNode.ID,
			Kind:       graph.EdgeKindRuns,
			Effect:     graph.EdgeEffectAllow,
			Properties: techEdgeProperties,
			Risk:       graph.RiskNone,
		}) {
			result.WorkloadTechnologyEdges++
		}
	}

	for vulnKey, vulnAgg := range vulns {
		vulnMeta := graph.NormalizeWriteMetadata(
			seenAt,
			validFrom,
			nil,
			graphMaterializationSourceSystem,
			fmt.Sprintf("%s:vulnerability:%s", sourceEventID, vulnerabilityKey(vulnAgg.record)),
			1.0,
			graph.WriteMetadataDefaults{
				Now:             now,
				RecordedAt:      seenAt,
				TransactionFrom: seenAt,
				SourceSystem:    graphMaterializationSourceSystem,
			},
		)
		vulnNode := buildVulnerabilityNode(vulnAgg.record, target, vulnMeta)
		g.AddNode(vulnNode)
		result.VulnNodesUpserted++
		usage := vulnUsage[vulnKey]
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(scanNode.ID, vulnNode.ID, graph.EdgeKindFoundVuln),
			Source:     scanNode.ID,
			Target:     vulnNode.ID,
			Kind:       graph.EdgeKindFoundVuln,
			Effect:     graph.EdgeEffectAllow,
			Properties: applyVulnerabilityUsageSummaryProperties(cloneWorkloadAnyMap(writeMeta.PropertyMap()), usage),
			Risk:       prioritizeVulnerabilityUsageRisk(vulnAgg.record, usage),
		}) {
			result.ScanVulnEdges++
		}
	}

	for _, relation := range relations {
		vulnAgg, ok := vulns[relation.vulnKey]
		if !ok {
			continue
		}
		vuln := vulnAgg.record
		pkgID := packageNodeID(relation.pkg)
		vulnID := vulnerabilityNodeID(vuln)
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:     packageVulnerabilityEdgeID(pkgID, vulnID),
			Source: pkgID,
			Target: vulnID,
			Kind:   graph.EdgeKindAffectedBy,
			Effect: graph.EdgeEffectAllow,
			Properties: applyPackageVulnerabilityPriorityProperties(map[string]any{
				"package_name":      relation.pkg.Name,
				"installed_version": relation.pkg.Version,
				"fixed_version":     strings.TrimSpace(vuln.FixedVersion),
				"severity":          normalizeSeverity(vuln.Severity),
				"source_system":     graphMaterializationSourceSystem,
				"source_event_id":   fmt.Sprintf("%s:package_vulnerability:%s", sourceEventID, packageVulnerabilityKey(relation.pkg, vuln)),
				"observed_at":       seenAt.UTC().Format(time.RFC3339),
				"valid_from":        validFrom.UTC().Format(time.RFC3339),
				"recorded_at":       seenAt.UTC().Format(time.RFC3339),
				"transaction_from":  seenAt.UTC().Format(time.RFC3339),
				"confidence":        1.0,
			}, relation.pkg),
			Risk: prioritizePackageVulnerabilityRisk(vuln, relation.pkg),
		}) {
			result.PackageVulnEdges++
		}
	}

	for _, findingAgg := range findings {
		observationMeta := graph.NormalizeWriteMetadata(
			seenAt,
			validFrom,
			nil,
			graphMaterializationSourceSystem,
			fmt.Sprintf("%s:iac_finding:%s", sourceEventID, slugify(findingAgg.record.ID)),
			1.0,
			graph.WriteMetadataDefaults{
				Now:             now,
				RecordedAt:      seenAt,
				TransactionFrom: seenAt,
				SourceSystem:    graphMaterializationSourceSystem,
			},
		)
		observationNode := buildIaCFindingObservationNode(scanNode, target, findingAgg.record, observationMeta)
		g.AddNode(observationNode)
		result.ObservationNodesUpserted++
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(observationNode.ID, scanNode.ID, graph.EdgeKindTargets),
			Source:     observationNode.ID,
			Target:     scanNode.ID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneWorkloadAnyMap(observationMeta.PropertyMap()),
			Risk:       observationNode.Risk,
		}) {
			result.ScanObservationEdges++
		}
	}

	for _, malwareAgg := range malware {
		observationMeta := graph.NormalizeWriteMetadata(
			seenAt,
			validFrom,
			nil,
			graphMaterializationSourceSystem,
			fmt.Sprintf("%s:malware:%s", sourceEventID, malwareKey(malwareAgg.record)),
			1.0,
			graph.WriteMetadataDefaults{
				Now:             now,
				RecordedAt:      seenAt,
				TransactionFrom: seenAt,
				SourceSystem:    graphMaterializationSourceSystem,
			},
		)
		observationNode := buildMalwareObservationNode(scanNode, target, malwareAgg.record, observationMeta)
		g.AddNode(observationNode)
		result.ObservationNodesUpserted++
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(observationNode.ID, scanNode.ID, graph.EdgeKindTargets),
			Source:     observationNode.ID,
			Target:     scanNode.ID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneWorkloadAnyMap(observationMeta.PropertyMap()),
			Risk:       observationNode.Risk,
		}) {
			result.ScanObservationEdges++
		}
	}

	secretResult := materializeSecretPivots(g, target, scanNode, secrets, writeMeta, now)
	result.SecretNodesUpserted += secretResult.SecretNodesUpserted
	result.ScanSecretEdges += secretResult.ScanSecretEdges
	result.SecretTargetEdges += secretResult.SecretTargetEdges
	result.CredentialPivotEdges += secretResult.CredentialPivotEdges

	result.RunsMaterialized = 1
	return result
}

func applyPriorityProperties(properties map[string]any, assessment *PriorityAssessment) {
	if properties == nil || assessment == nil {
		return
	}
	if assessment.Score > 0 {
		properties["priority_score"] = assessment.Score
	}
	if assessment.Priority != "" {
		properties["priority"] = string(assessment.Priority)
	}
	if strings.TrimSpace(assessment.Source) != "" {
		properties["priority_source"] = strings.TrimSpace(assessment.Source)
	}
	properties["priority_eligible"] = assessment.Eligible
	if assessment.LastScannedAt != nil && !assessment.LastScannedAt.IsZero() {
		properties["priority_last_scanned_at"] = formatTimePtr(assessment.LastScannedAt)
	}
	if len(assessment.Reasons) > 0 {
		properties["priority_reasons"] = append([]string(nil), assessment.Reasons...)
	}
	if assessment.Exposure != "" {
		properties["priority_exposure"] = assessment.Exposure
	}
	if assessment.Privilege != "" {
		properties["priority_privilege"] = assessment.Privilege
	}
	if assessment.Criticality != "" {
		properties["priority_criticality"] = assessment.Criticality
	}
	if assessment.Staleness != "" {
		properties["priority_staleness"] = assessment.Staleness
	}
	if len(assessment.ComplianceScopes) > 0 {
		properties["priority_compliance_scopes"] = append([]string(nil), assessment.ComplianceScopes...)
	}
}

func resolveTargetNode(g *graph.Graph, run RunRecord) (*graph.Node, bool) {
	switch run.Provider {
	case ProviderAWS:
		instanceID := strings.TrimSpace(run.Target.InstanceID)
		for _, node := range g.GetNodesByKind(graph.NodeKindInstance) {
			if node == nil || node.Provider != "aws" {
				continue
			}
			if node.Account != "" && strings.TrimSpace(run.Target.AccountID) != "" && node.Account != strings.TrimSpace(run.Target.AccountID) {
				continue
			}
			if node.Region != "" && strings.TrimSpace(run.Target.Region) != "" && node.Region != strings.TrimSpace(run.Target.Region) {
				continue
			}
			if strings.TrimSpace(node.Name) == instanceID || strings.TrimSpace(readString(node.Properties, "instance_id")) == instanceID {
				return node, true
			}
		}
	case ProviderGCP:
		instanceName := strings.TrimSpace(run.Target.InstanceName)
		for _, node := range g.GetNodesByKind(graph.NodeKindInstance) {
			if node == nil || node.Provider != "gcp" {
				continue
			}
			if node.Account != "" && strings.TrimSpace(run.Target.ProjectID) != "" && node.Account != strings.TrimSpace(run.Target.ProjectID) {
				continue
			}
			if node.Region != "" && strings.TrimSpace(run.Target.Zone) != "" && node.Region != strings.TrimSpace(run.Target.Zone) {
				continue
			}
			if strings.TrimSpace(node.Name) == instanceName {
				return node, true
			}
		}
	case ProviderAzure:
		instanceName := strings.TrimSpace(run.Target.InstanceName)
		for _, node := range g.GetNodesByKind(graph.NodeKindInstance) {
			if node == nil || node.Provider != "azure" {
				continue
			}
			if node.Account != "" && strings.TrimSpace(run.Target.SubscriptionID) != "" && node.Account != strings.TrimSpace(run.Target.SubscriptionID) {
				continue
			}
			if node.Region != "" && strings.TrimSpace(run.Target.Region) != "" && node.Region != strings.TrimSpace(run.Target.Region) {
				continue
			}
			if strings.TrimSpace(node.Name) == instanceName && strings.TrimSpace(readString(node.Properties, "resource_group")) == strings.TrimSpace(run.Target.ResourceGroup) {
				return node, true
			}
		}
	}
	return nil, false
}

func summarizeRun(run RunRecord) (scanSummary, map[string]configAggregate, map[string]secretAggregate, map[string]malwareAggregate, map[string]packageAggregate, map[string]packageDependencyAggregate, map[string]technologyAggregate, map[string]vulnerabilityAggregate, map[string]packageVulnerabilityAggregate, map[string]vulnerabilityUsageContext) {
	summary := scanSummary{
		FindingCount: run.Summary.Findings,
		Risk:         graph.RiskNone,
	}
	findings := make(map[string]configAggregate)
	secrets := make(map[string]secretAggregate)
	malware := make(map[string]malwareAggregate)
	packages := make(map[string]packageAggregate)
	packageDeps := make(map[string]packageDependencyAggregate)
	technologies := make(map[string]technologyAggregate)
	vulns := make(map[string]vulnerabilityAggregate)
	relations := make(map[string]packageVulnerabilityAggregate)
	vulnUsage := make(map[string]vulnerabilityUsageContext)
	vulnAliases := make(map[string]string)
	iacArtifacts := make(map[string]filesystemanalyzer.IaCArtifact)

	for _, volume := range run.Volumes {
		if volume.Analysis == nil || volume.Analysis.Catalog == nil {
			continue
		}
		catalog := volume.Analysis.Catalog
		if summary.OSName == "" {
			summary.OSName = strings.TrimSpace(firstNonEmpty(catalog.OS.PrettyName, catalog.OS.Name, catalog.OS.ID))
			summary.OSVersion = strings.TrimSpace(firstNonEmpty(catalog.OS.Version, catalog.OS.VersionID))
			summary.OSArchitecture = strings.TrimSpace(catalog.OS.Architecture)
		}
		if summary.SBOMRef == "" {
			summary.SBOMRef = strings.TrimSpace(volume.Analysis.SBOMRef)
		}
		summary.SecretCount += len(catalog.Secrets)
		summary.MisconfigurationCount += len(catalog.Misconfigurations)
		summary.MalwareCount += len(catalog.Malware)
		for _, tech := range catalog.Technologies {
			id := technologyNodeID(tech)
			if id == "" {
				continue
			}
			if _, exists := technologies[id]; !exists {
				technologies[id] = technologyAggregate{record: tech}
			}
		}
		for _, artifact := range catalog.IaCArtifacts {
			artifactID := strings.TrimSpace(artifact.ID)
			if artifactID == "" {
				continue
			}
			if _, exists := iacArtifacts[artifactID]; !exists {
				iacArtifacts[artifactID] = artifact
			}
		}
		for _, secret := range catalog.Secrets {
			secretID := strings.TrimSpace(secret.ID)
			if secretID == "" {
				continue
			}
			if _, exists := secrets[secretID]; !exists {
				secrets[secretID] = secretAggregate{record: secret}
			}
			summary.Risk = maxRiskLevel(summary.Risk, severityToRisk(secret.Severity, false))
		}
		for _, finding := range catalog.Misconfigurations {
			summary.Risk = maxRiskLevel(summary.Risk, severityToRisk(finding.Severity, false))
			if strings.TrimSpace(finding.ID) == "" || strings.TrimSpace(finding.ArtifactType) == "" {
				continue
			}
			if _, exists := findings[finding.ID]; !exists {
				findings[finding.ID] = configAggregate{record: finding}
			}
		}
		for _, malwareFinding := range catalog.Malware {
			summary.Risk = maxRiskLevel(summary.Risk, severityToRisk(malwareFinding.Severity, false))
			key := malwareKey(malwareFinding)
			if _, exists := malware[key]; !exists {
				malware[key] = malwareAggregate{record: malwareFinding}
			}
		}

		for _, pkg := range catalog.Packages {
			id := packageNodeID(pkg)
			if id == "" {
				continue
			}
			if existing, exists := packages[id]; exists {
				packages[id] = packageAggregate{record: filesystemanalyzer.MergePackageRecord(existing.record, pkg)}
			} else {
				packages[id] = packageAggregate{record: pkg}
			}
		}
		componentByRef := make(map[string]filesystemanalyzer.PackageRecord, len(catalog.SBOM.Components))
		for _, component := range catalog.SBOM.Components {
			pkg := packageFromSBOMComponent(component)
			if packageNodeID(pkg) == "" {
				continue
			}
			componentByRef[component.BOMRef] = pkg
		}
		for _, dep := range catalog.SBOM.Dependencies {
			parent, ok := componentByRef[strings.TrimSpace(dep.Ref)]
			if !ok {
				continue
			}
			for _, childRef := range dep.DependsOn {
				child, ok := componentByRef[strings.TrimSpace(childRef)]
				if !ok {
					continue
				}
				key := packageDependencyKey(parent, child)
				if _, exists := packageDeps[key]; !exists {
					packageDeps[key] = packageDependencyAggregate{parent: parent, child: child}
				}
			}
		}
		for _, vuln := range catalog.Vulnerabilities {
			vulnKey := vulnerabilityAggregateKey(vuln, vulnAliases)
			if vulnKey == "" {
				continue
			}
			merged := vuln
			if existing, exists := vulns[vulnKey]; exists {
				merged = mergeVulnerabilityRecord(existing.record, vuln)
			}
			vulns[vulnKey] = vulnerabilityAggregate{record: merged}
			indexVulnerabilityAliases(vulnAliases, vulnKey, merged)
			for _, pkg := range catalog.Packages {
				if !strings.EqualFold(strings.TrimSpace(pkg.Name), strings.TrimSpace(vuln.Package)) {
					continue
				}
				ctx := vulnUsage[vulnKey]
				ctx.observePackage(pkg)
				vulnUsage[vulnKey] = ctx
				key := packageVulnerabilityAggregateKey(pkg, vulnKey)
				if _, exists := relations[key]; !exists {
					relations[key] = packageVulnerabilityAggregate{
						pkg:     pkg,
						vulnKey: vulnKey,
					}
				}
			}
		}
	}

	summary.IaCArtifactCount = len(iacArtifacts)
	summary.PackageCount = len(packages)
	summary.TechnologyCount = len(technologies)
	summary.VulnerabilityCount = len(vulns)
	for vulnKey, vulnAgg := range vulns {
		ctx := vulnUsage[vulnKey]
		switch normalizeSeverity(vulnAgg.record.Severity) {
		case "critical":
			summary.CriticalVulnerabilityCount++
			if ctx.hasBestPackage && ctx.bestPackage.Reachable {
				summary.ReachableCriticalVulnerabilityCount++
			}
		case "high":
			summary.HighVulnerabilityCount++
			if ctx.hasBestPackage && ctx.bestPackage.Reachable {
				summary.ReachableHighVulnerabilityCount++
			}
		case "medium":
			summary.MediumVulnerabilityCount++
		case "low":
			summary.LowVulnerabilityCount++
		default:
			summary.UnknownVulnerabilityCount++
		}
		if vulnAgg.record.InKEV {
			summary.KnownExploitedCount++
			if ctx.hasBestPackage && ctx.bestPackage.Reachable {
				summary.ReachableKnownExploitedCount++
			}
		}
		if vulnAgg.record.Exploitable {
			summary.ExploitableCount++
		}
		if strings.TrimSpace(vulnAgg.record.FixedVersion) != "" {
			summary.FixableCount++
		}
		if ctx.hasBestPackage && ctx.bestPackage.Reachable {
			summary.ReachableVulnerabilityCount++
			if ctx.bestPackage.DirectDependency {
				summary.DirectReachableVulnerabilityCount++
			}
		}
	}
	summary.Risk = maxRiskLevel(summary.Risk, summaryRisk(summary))
	return summary, findings, secrets, malware, packages, packageDeps, technologies, vulns, relations, vulnUsage
}

func packageFromSBOMComponent(component filesystemanalyzer.SBOMComponent) filesystemanalyzer.PackageRecord {
	if componentType := strings.TrimSpace(component.Type); componentType != "" && !strings.EqualFold(componentType, "library") {
		return filesystemanalyzer.PackageRecord{}
	}
	ecosystem := strings.TrimSpace(component.Ecosystem)
	return filesystemanalyzer.PackageRecord{
		Ecosystem:        ecosystem,
		Manager:          defaultPackageManagerForEcosystem(ecosystem),
		Name:             strings.TrimSpace(component.Name),
		Version:          strings.TrimSpace(component.Version),
		PURL:             strings.TrimSpace(component.PURL),
		Location:         strings.TrimSpace(component.Location),
		DirectDependency: component.DirectDependency,
		Reachable:        component.Reachable,
		DependencyDepth:  component.DependencyDepth,
		ImportFileCount:  component.ImportFileCount,
	}
}

func mergeVulnerabilityRecord(existing, incoming scanner.ImageVulnerability) scanner.ImageVulnerability {
	merged := existing
	if strings.TrimSpace(merged.CVE) == "" {
		merged.CVE = incoming.CVE
	}
	if strings.TrimSpace(merged.ID) == "" {
		merged.ID = incoming.ID
	}
	if vulnerabilitySeverityRank(incoming.Severity) > vulnerabilitySeverityRank(merged.Severity) {
		merged.Severity = incoming.Severity
	}
	if strings.TrimSpace(merged.Package) == "" {
		merged.Package = incoming.Package
	}
	if strings.TrimSpace(merged.InstalledVersion) == "" {
		merged.InstalledVersion = incoming.InstalledVersion
	}
	if strings.TrimSpace(merged.FixedVersion) == "" {
		merged.FixedVersion = incoming.FixedVersion
	}
	if incoming.CVSS > merged.CVSS {
		merged.CVSS = incoming.CVSS
	}
	merged.InKEV = merged.InKEV || incoming.InKEV
	merged.Exploitable = merged.Exploitable || incoming.Exploitable
	if merged.Published.IsZero() && !incoming.Published.IsZero() {
		merged.Published = incoming.Published
	}
	return merged
}

func buildPackageNode(pkg filesystemanalyzer.PackageRecord, target *graph.Node, metadata graph.WriteMetadata) *graph.Node {
	properties := map[string]any{
		"package_name": pkg.Name,
		"version":      pkg.Version,
		"ecosystem":    firstNonEmpty(pkg.Ecosystem, "unknown"),
		"manager":      firstNonEmpty(strings.TrimSpace(pkg.Manager), defaultPackageManagerForEcosystem(pkg.Ecosystem)),
		"purl":         strings.TrimSpace(pkg.PURL),
	}
	metadata.ApplyTo(properties)
	return &graph.Node{
		ID:         packageNodeID(pkg),
		Kind:       graph.NodeKindPackage,
		Name:       firstNonEmpty(strings.TrimSpace(pkg.Name), packageNodeID(pkg)),
		Provider:   target.Provider,
		Account:    target.Account,
		Region:     target.Region,
		Risk:       graph.RiskNone,
		Properties: properties,
	}
}

func defaultPackageManagerForEcosystem(ecosystem string) string {
	switch strings.TrimSpace(ecosystem) {
	case "golang":
		return "go"
	case "pypi":
		return "pip"
	case "deb":
		return "dpkg"
	default:
		return strings.TrimSpace(ecosystem)
	}
}

func buildTechnologyNode(tech filesystemanalyzer.TechnologyRecord, metadata graph.WriteMetadata, existing *graph.Node) *graph.Node {
	properties := map[string]any{
		"technology_id":   technologyNodeID(tech),
		"technology_name": strings.TrimSpace(tech.Name),
		"category":        strings.TrimSpace(tech.Category),
		"version":         strings.TrimSpace(tech.Version),
	}
	applyCanonicalTechnologyMetadata(properties, metadata, existing)
	return &graph.Node{
		ID:         technologyNodeID(tech),
		Kind:       graph.NodeKindTechnology,
		Name:       firstNonEmpty(strings.TrimSpace(tech.Name), technologyNodeID(tech)),
		Risk:       graph.RiskNone,
		Properties: properties,
	}
}

func applyCanonicalTechnologyMetadata(properties map[string]any, metadata graph.WriteMetadata, existing *graph.Node) {
	if properties == nil {
		return
	}
	if sourceSystem := strings.TrimSpace(metadata.SourceSystem); sourceSystem != "" {
		properties["source_system"] = sourceSystem
	}
	properties["observed_at"] = earliestMetadataTimestamp(existing, "observed_at", metadata.ObservedAt)
	properties["valid_from"] = earliestMetadataTimestamp(existing, "valid_from", metadata.ValidFrom)
	properties["recorded_at"] = earliestMetadataTimestamp(existing, "recorded_at", metadata.RecordedAt)
	properties["transaction_from"] = earliestMetadataTimestamp(existing, "transaction_from", metadata.TransactionFrom)
	properties["confidence"] = highestMetadataConfidence(existing, metadata.Confidence)
}

func earliestMetadataTimestamp(existing *graph.Node, key string, incoming time.Time) string {
	best := incoming.UTC()
	if existingTime, ok := existingNodePropertyTime(existing, key); ok && (best.IsZero() || existingTime.Before(best)) {
		best = existingTime
	}
	return formatTime(best)
}

func highestMetadataConfidence(existing *graph.Node, incoming float64) float64 {
	best := incoming
	if existing == nil || existing.Properties == nil {
		return best
	}
	raw, ok := existing.Properties["confidence"]
	if !ok || raw == nil {
		return best
	}
	switch value := raw.(type) {
	case float64:
		if value > best {
			return value
		}
	case float32:
		if float64(value) > best {
			return float64(value)
		}
	case int:
		if float64(value) > best {
			return float64(value)
		}
	case int64:
		if float64(value) > best {
			return float64(value)
		}
	}
	return best
}

func existingNodePropertyTime(node *graph.Node, key string) (time.Time, bool) {
	if node == nil || node.Properties == nil {
		return time.Time{}, false
	}
	raw, ok := node.Properties[key]
	if !ok || raw == nil {
		return time.Time{}, false
	}
	text, ok := raw.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(text))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func buildVulnerabilityNode(vuln scanner.ImageVulnerability, target *graph.Node, metadata graph.WriteMetadata) *graph.Node {
	properties := map[string]any{
		"vulnerability_id": firstNonEmpty(strings.TrimSpace(vuln.CVE), strings.TrimSpace(vuln.ID)),
		"cve_id":           strings.TrimSpace(vuln.CVE),
		"severity":         normalizeSeverity(vuln.Severity),
		"cvss":             vuln.CVSS,
		"known_exploited":  vuln.InKEV,
		"exploitable":      vuln.Exploitable,
		"fixed_version":    strings.TrimSpace(vuln.FixedVersion),
	}
	if !vuln.Published.IsZero() {
		properties["published_at"] = vuln.Published.UTC().Format(time.RFC3339)
	}
	metadata.ApplyTo(properties)
	return &graph.Node{
		ID:         vulnerabilityNodeID(vuln),
		Kind:       graph.NodeKindVulnerability,
		Name:       firstNonEmpty(strings.TrimSpace(vuln.CVE), strings.TrimSpace(vuln.ID), strings.TrimSpace(vuln.Package)),
		Provider:   target.Provider,
		Account:    target.Account,
		Region:     target.Region,
		Risk:       severityToRisk(vuln.Severity, vuln.InKEV),
		Properties: properties,
	}
}

func buildIaCFindingObservationNode(scanNode, target *graph.Node, finding filesystemanalyzer.ConfigFinding, metadata graph.WriteMetadata) *graph.Node {
	properties := map[string]any{
		"observation_type": "workload_iac_finding",
		"subject_id":       scanNode.ID,
		"detail":           finding.Title,
		"finding_id":       strings.TrimSpace(finding.ID),
		"finding_type":     strings.TrimSpace(finding.Type),
		"severity":         normalizeSeverity(finding.Severity),
		"file_path":        strings.TrimSpace(finding.Path),
		"description":      strings.TrimSpace(finding.Description),
		"remediation":      strings.TrimSpace(finding.Remediation),
		"resource_type":    strings.TrimSpace(finding.ResourceType),
		"artifact_type":    strings.TrimSpace(finding.ArtifactType),
		"format":           strings.TrimSpace(finding.Format),
	}
	metadata.ApplyTo(properties)
	return &graph.Node{
		ID:         iacFindingObservationNodeID(scanNode.ID, finding),
		Kind:       graph.NodeKindObservation,
		Name:       firstNonEmpty(strings.TrimSpace(finding.Title), strings.TrimSpace(finding.Type), "workload iac finding"),
		Provider:   target.Provider,
		Account:    target.Account,
		Region:     target.Region,
		Risk:       severityToRisk(finding.Severity, false),
		Properties: properties,
	}
}

func buildMalwareObservationNode(scanNode, target *graph.Node, finding filesystemanalyzer.MalwareFinding, metadata graph.WriteMetadata) *graph.Node {
	properties := map[string]any{
		"observation_type": "workload_malware_finding",
		"subject_id":       scanNode.ID,
		"detail":           firstNonEmpty(strings.TrimSpace(finding.MalwareName), strings.TrimSpace(finding.MalwareType), "malware signature detected"),
		"finding_id":       strings.TrimSpace(finding.ID),
		"malware_type":     strings.TrimSpace(finding.MalwareType),
		"malware_name":     strings.TrimSpace(finding.MalwareName),
		"severity":         normalizeSeverity(finding.Severity),
		"file_path":        strings.TrimSpace(finding.Path),
		"hash":             strings.TrimSpace(finding.Hash),
		"engine":           strings.TrimSpace(finding.Engine),
		"confidence":       finding.Confidence,
	}
	metadata.ApplyTo(properties)
	return &graph.Node{
		ID:         malwareObservationNodeID(scanNode.ID, finding),
		Kind:       graph.NodeKindObservation,
		Name:       firstNonEmpty(strings.TrimSpace(finding.MalwareName), strings.TrimSpace(finding.MalwareType), "workload malware finding"),
		Provider:   target.Provider,
		Account:    target.Account,
		Region:     target.Region,
		Risk:       severityToRisk(finding.Severity, false),
		Properties: properties,
	}
}

func nodeID(run RunRecord) string {
	if id := strings.TrimSpace(run.ID); id != "" {
		return id
	}
	return "workload_scan:" + syntheticRunKey(run)
}

func iacFindingObservationNodeID(scanNodeID string, finding filesystemanalyzer.ConfigFinding) string {
	return fmt.Sprintf("observation:iac:%s:%s", slugify(scanNodeID), slugify(firstNonEmpty(strings.TrimSpace(finding.ID), strings.TrimSpace(finding.Path), strings.TrimSpace(finding.Title))))
}

func malwareObservationNodeID(scanNodeID string, finding filesystemanalyzer.MalwareFinding) string {
	return fmt.Sprintf("observation:malware:%s:%s", slugify(scanNodeID), slugify(malwareKey(finding)))
}

func packageNodeID(pkg filesystemanalyzer.PackageRecord) string {
	if strings.TrimSpace(pkg.PURL) != "" {
		return "package:purl:" + slugify(strings.TrimSpace(pkg.PURL))
	}
	if strings.TrimSpace(pkg.Name) == "" {
		return ""
	}
	return fmt.Sprintf("package:%s:%s:%s", slugify(firstNonEmpty(pkg.Ecosystem, "unknown")), slugify(pkg.Name), slugify(firstNonEmpty(pkg.Version, "unknown")))
}

func technologyNodeID(tech filesystemanalyzer.TechnologyRecord) string {
	name := strings.TrimSpace(tech.Name)
	category := strings.TrimSpace(tech.Category)
	if name == "" || category == "" {
		return ""
	}
	return fmt.Sprintf("technology:%s:%s:%s", slugify(category), slugify(name), slugify(firstNonEmpty(strings.TrimSpace(tech.Version), "unknown")))
}

func vulnerabilityNodeID(vuln scanner.ImageVulnerability) string {
	identifier := firstNonEmpty(strings.TrimSpace(vuln.CVE), strings.TrimSpace(vuln.ID))
	if identifier == "" {
		identifier = fmt.Sprintf("%s:%s", strings.TrimSpace(vuln.Package), strings.TrimSpace(vuln.FixedVersion))
	}
	if identifier == "" {
		return ""
	}
	return "vulnerability:" + slugify(identifier)
}

func nodeName(target *graph.Node, seenAt time.Time) string {
	name := firstNonEmpty(strings.TrimSpace(target.Name), strings.TrimSpace(target.ID))
	if seenAt.IsZero() {
		return name + " workload scan"
	}
	return fmt.Sprintf("%s workload scan %s", name, seenAt.UTC().Format("2006-01-02 15:04:05"))
}

func runValidFrom(run RunRecord, seenAt time.Time) time.Time {
	if run.StartedAt != nil && !run.StartedAt.IsZero() {
		return run.StartedAt.UTC()
	}
	if !run.SubmittedAt.IsZero() {
		return run.SubmittedAt.UTC()
	}
	return seenAt.UTC()
}

func observedAt(run RunRecord) time.Time {
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt.UTC()
	}
	if !run.UpdatedAt.IsZero() {
		return run.UpdatedAt.UTC()
	}
	if run.StartedAt != nil && !run.StartedAt.IsZero() {
		return run.StartedAt.UTC()
	}
	if !run.SubmittedAt.IsZero() {
		return run.SubmittedAt.UTC()
	}
	return time.Time{}
}

func edgeID(source, target string, kind graph.EdgeKind) string {
	return fmt.Sprintf("edge:%s:%s:%s", slugify(source), slugify(string(kind)), slugify(target))
}

func packageVulnerabilityEdgeID(pkgID, vulnID string) string {
	return fmt.Sprintf("edge:%s:%s:%s", slugify(pkgID), slugify(string(graph.EdgeKindAffectedBy)), slugify(vulnID))
}

func packageKey(pkg filesystemanalyzer.PackageRecord) string {
	return slugify(firstNonEmpty(pkg.PURL, fmt.Sprintf("%s:%s:%s", pkg.Ecosystem, pkg.Name, pkg.Version)))
}

func technologyKey(tech filesystemanalyzer.TechnologyRecord) string {
	return slugify(firstNonEmpty(technologyNodeID(tech), fmt.Sprintf("%s:%s:%s", tech.Category, tech.Name, firstNonEmpty(tech.Version, "unknown"))))
}

func vulnerabilityKey(vuln scanner.ImageVulnerability) string {
	return slugify(firstNonEmpty(vuln.CVE, vuln.ID, fmt.Sprintf("%s:%s", vuln.Package, vuln.FixedVersion)))
}

func packageVulnerabilityKey(pkg filesystemanalyzer.PackageRecord, vuln scanner.ImageVulnerability) string {
	return slugify(fmt.Sprintf("%s|%s|%s", packageNodeID(pkg), vulnerabilityNodeID(vuln), firstNonEmpty(vuln.FixedVersion, "none")))
}

func packageVulnerabilityAggregateKey(pkg filesystemanalyzer.PackageRecord, vulnKey string) string {
	return slugify(fmt.Sprintf("%s|%s", packageNodeID(pkg), strings.TrimSpace(vulnKey)))
}

func vulnerabilityAggregateKey(vuln scanner.ImageVulnerability, aliasIndex map[string]string) string {
	aliases := vulnerabilityAliases(vuln)
	for _, alias := range aliases {
		if key, ok := aliasIndex[alias]; ok {
			return key
		}
	}
	if len(aliases) == 0 {
		return ""
	}
	return aliases[0]
}

func indexVulnerabilityAliases(aliasIndex map[string]string, vulnKey string, vuln scanner.ImageVulnerability) {
	for _, alias := range vulnerabilityAliases(vuln) {
		aliasIndex[alias] = vulnKey
	}
}

func vulnerabilityAliases(vuln scanner.ImageVulnerability) []string {
	aliases := make([]string, 0, 3)
	if alias := vulnerabilityAlias("id", vuln.ID); alias != "" {
		aliases = append(aliases, alias)
	}
	if alias := vulnerabilityAlias("cve", vuln.CVE); alias != "" {
		aliases = append(aliases, alias)
	}
	if len(aliases) == 0 {
		if alias := vulnerabilityAlias("fallback", fmt.Sprintf("%s:%s", vuln.Package, vuln.FixedVersion)); alias != "" {
			aliases = append(aliases, alias)
		}
	}
	return aliases
}

func vulnerabilityAlias(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return kind + ":" + slugify(value)
}

func packageDependencyKey(parent, child filesystemanalyzer.PackageRecord) string {
	return slugify(fmt.Sprintf("%s|%s", packageNodeID(parent), packageNodeID(child)))
}

func malwareKey(finding filesystemanalyzer.MalwareFinding) string {
	return firstNonEmpty(
		strings.TrimSpace(finding.ID),
		fmt.Sprintf("%s|%s|%s|%s", strings.TrimSpace(finding.Path), strings.TrimSpace(finding.Hash), strings.TrimSpace(finding.MalwareName), strings.TrimSpace(finding.MalwareType)),
	)
}

func syntheticRunKey(run RunRecord) string {
	return slugify(strings.Join([]string{string(run.Provider), run.Target.Identity(), formatTime(observedAt(run))}, ":"))
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func formatTimePtr(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "unknown"
	}
}

func vulnerabilitySeverityRank(value string) int {
	switch normalizeSeverity(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func severityToRisk(severity string, knownExploited bool) graph.RiskLevel {
	if knownExploited {
		return graph.RiskCritical
	}
	switch normalizeSeverity(severity) {
	case "critical":
		return graph.RiskCritical
	case "high":
		return graph.RiskHigh
	case "medium":
		return graph.RiskMedium
	case "low":
		return graph.RiskLow
	default:
		return graph.RiskNone
	}
}

func summaryRisk(summary scanSummary) graph.RiskLevel {
	if summary.KnownExploitedCount > 0 || summary.ReachableCriticalVulnerabilityCount > 0 {
		return graph.RiskCritical
	}
	if summary.CriticalVulnerabilityCount > 0 || summary.ReachableHighVulnerabilityCount > 0 {
		return graph.RiskHigh
	}
	if summary.HighVulnerabilityCount > 0 || summary.MediumVulnerabilityCount > 0 {
		return graph.RiskMedium
	}
	if summary.LowVulnerabilityCount > 0 || summary.VulnerabilityCount > 0 {
		return graph.RiskLow
	}
	return graph.RiskNone
}

func prioritizePackageVulnerabilityRisk(vuln scanner.ImageVulnerability, pkg filesystemanalyzer.PackageRecord) graph.RiskLevel {
	risk := severityToRisk(vuln.Severity, vuln.InKEV)
	if vuln.InKEV {
		return graph.RiskCritical
	}
	if pkg.Reachable {
		return risk
	}
	switch risk {
	case graph.RiskCritical:
		return graph.RiskHigh
	case graph.RiskHigh:
		return graph.RiskMedium
	case graph.RiskMedium:
		return graph.RiskLow
	default:
		return risk
	}
}

func prioritizeVulnerabilityUsageRisk(vuln scanner.ImageVulnerability, ctx vulnerabilityUsageContext) graph.RiskLevel {
	if !ctx.hasBestPackage {
		return severityToRisk(vuln.Severity, vuln.InKEV)
	}
	return prioritizePackageVulnerabilityRisk(vuln, ctx.bestPackage)
}

func (ctx *vulnerabilityUsageContext) observePackage(pkg filesystemanalyzer.PackageRecord) {
	key := packageNodeID(pkg)
	if key == "" {
		return
	}
	if ctx.affectedPackageKeys == nil {
		ctx.affectedPackageKeys = make(map[string]struct{})
	}
	ctx.affectedPackageKeys[key] = struct{}{}
	if !ctx.hasBestPackage || packageVulnerabilityPriorityBetter(pkg, ctx.bestPackage) {
		ctx.bestPackage = pkg
		ctx.hasBestPackage = true
	}
	if pkg.Reachable {
		if ctx.reachablePackageKeys == nil {
			ctx.reachablePackageKeys = make(map[string]struct{})
		}
		ctx.reachablePackageKeys[key] = struct{}{}
		if pkg.DirectDependency {
			if ctx.directReachablePackageKeys == nil {
				ctx.directReachablePackageKeys = make(map[string]struct{})
			}
			ctx.directReachablePackageKeys[key] = struct{}{}
		}
	}
}

func packageVulnerabilityPriorityBetter(left, right filesystemanalyzer.PackageRecord) bool {
	if left.Reachable != right.Reachable {
		return left.Reachable
	}
	if left.DirectDependency != right.DirectDependency {
		return left.DirectDependency
	}
	leftDepth := packageVulnerabilityPriorityDepth(left.DependencyDepth)
	rightDepth := packageVulnerabilityPriorityDepth(right.DependencyDepth)
	if leftDepth != rightDepth {
		return leftDepth < rightDepth
	}
	if left.ImportFileCount != right.ImportFileCount {
		return left.ImportFileCount > right.ImportFileCount
	}
	return packageNodeID(left) < packageNodeID(right)
}

func packageVulnerabilityPriorityDepth(depth int) int {
	if depth <= 0 {
		return int(^uint(0) >> 1)
	}
	return depth
}

func packageVulnerabilityPriorityHint(pkg filesystemanalyzer.PackageRecord) string {
	switch {
	case pkg.Reachable && pkg.DirectDependency:
		return "reachable_direct"
	case pkg.Reachable:
		return "reachable_transitive"
	case pkg.DirectDependency:
		return "unreachable_direct"
	default:
		return "unreachable_transitive"
	}
}

func applyPackageVulnerabilityPriorityProperties(properties map[string]any, pkg filesystemanalyzer.PackageRecord) map[string]any {
	if properties == nil {
		properties = make(map[string]any)
	}
	properties["direct_dependency"] = pkg.DirectDependency
	properties["reachable"] = pkg.Reachable
	properties["dependency_depth"] = pkg.DependencyDepth
	properties["import_file_count"] = pkg.ImportFileCount
	properties["priority_hint"] = packageVulnerabilityPriorityHint(pkg)
	return properties
}

func applyVulnerabilityUsageSummaryProperties(properties map[string]any, ctx vulnerabilityUsageContext) map[string]any {
	if properties == nil {
		properties = make(map[string]any)
	}
	if !ctx.hasBestPackage {
		return properties
	}
	properties = applyPackageVulnerabilityPriorityProperties(properties, ctx.bestPackage)
	properties["affected_package_count"] = len(ctx.affectedPackageKeys)
	properties["reachable_package_count"] = len(ctx.reachablePackageKeys)
	properties["direct_reachable_package_count"] = len(ctx.directReachablePackageKeys)
	return properties
}

func cloneWorkloadAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func readString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return ""
	}
	switch typed := raw.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}
