package workloadscan

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/scanner"
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
	VulnNodesUpserted        int `json:"vulnerability_nodes_upserted"`
	ScanObservationEdges     int `json:"scan_observation_edges"`
	ScanSecretEdges          int `json:"scan_secret_edges"`
	SecretTargetEdges        int `json:"secret_target_edges"`
	CredentialPivotEdges     int `json:"credential_pivot_edges"`
	ScanPackageEdges         int `json:"scan_package_edges"`
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

type secretAggregate struct {
	record filesystemanalyzer.SecretFinding
}

type vulnerabilityAggregate struct {
	record scanner.ImageVulnerability
}

type configAggregate struct {
	record filesystemanalyzer.ConfigFinding
}

type packageVulnerabilityAggregate struct {
	pkg  filesystemanalyzer.PackageRecord
	vuln scanner.ImageVulnerability
	risk graph.RiskLevel
}

type scanSummary struct {
	PackageCount               int
	VulnerabilityCount         int
	CriticalVulnerabilityCount int
	HighVulnerabilityCount     int
	MediumVulnerabilityCount   int
	LowVulnerabilityCount      int
	UnknownVulnerabilityCount  int
	KnownExploitedCount        int
	ExploitableCount           int
	FixableCount               int
	SecretCount                int
	MisconfigurationCount      int
	IaCArtifactCount           int
	MalwareCount               int
	FindingCount               int64
	OSName                     string
	OSVersion                  string
	OSArchitecture             string
	SBOMRef                    string
	Risk                       graph.RiskLevel
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
			result.VulnNodesUpserted += batch.VulnNodesUpserted
			result.ScanObservationEdges += batch.ScanObservationEdges
			result.ScanSecretEdges += batch.ScanSecretEdges
			result.SecretTargetEdges += batch.SecretTargetEdges
			result.CredentialPivotEdges += batch.CredentialPivotEdges
			result.ScanPackageEdges += batch.ScanPackageEdges
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
	summary, findings, secrets, packages, vulns, relations := summarizeRun(run)
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
			"scan_id":                         firstNonEmpty(strings.TrimSpace(run.ID), syntheticRunKey(run)),
			"target_id":                       target.ID,
			"target_kind":                     string(target.Kind),
			"provider":                        string(run.Provider),
			"status":                          string(run.Status),
			"stage":                           string(run.Stage),
			"submitted_at":                    formatTime(run.SubmittedAt),
			"started_at":                      formatTimePtr(run.StartedAt),
			"completed_at":                    formatTimePtr(run.CompletedAt),
			"os_name":                         summary.OSName,
			"os_version":                      summary.OSVersion,
			"os_architecture":                 summary.OSArchitecture,
			"package_count":                   summary.PackageCount,
			"vulnerability_count":             summary.VulnerabilityCount,
			"critical_vulnerability_count":    summary.CriticalVulnerabilityCount,
			"high_vulnerability_count":        summary.HighVulnerabilityCount,
			"medium_vulnerability_count":      summary.MediumVulnerabilityCount,
			"low_vulnerability_count":         summary.LowVulnerabilityCount,
			"unknown_vulnerability_count":     summary.UnknownVulnerabilityCount,
			"known_exploited_count":           summary.KnownExploitedCount,
			"exploitable_vulnerability_count": summary.ExploitableCount,
			"fixable_vulnerability_count":     summary.FixableCount,
			"secret_count":                    summary.SecretCount,
			"misconfiguration_count":          summary.MisconfigurationCount,
			"iac_artifact_count":              summary.IaCArtifactCount,
			"malware_count":                   summary.MalwareCount,
			"finding_count":                   summary.FindingCount,
			"sbom_ref":                        summary.SBOMRef,
		},
	}
	applyPriorityProperties(scanNode.Properties, run.Priority)
	writeMeta.ApplyTo(scanNode.Properties)
	g.AddNode(scanNode)
	result.ScanNodesUpserted++

	if addEdgeIfMissing(g, &graph.Edge{
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
		if addEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(scanNode.ID, pkgNode.ID, graph.EdgeKindContainsPkg),
			Source:     scanNode.ID,
			Target:     pkgNode.ID,
			Kind:       graph.EdgeKindContainsPkg,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneWorkloadAnyMap(writeMeta.PropertyMap()),
			Risk:       graph.RiskLow,
		}) {
			result.ScanPackageEdges++
		}
	}

	for _, vulnAgg := range vulns {
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
		if addEdgeIfMissing(g, &graph.Edge{
			ID:         edgeID(scanNode.ID, vulnNode.ID, graph.EdgeKindFoundVuln),
			Source:     scanNode.ID,
			Target:     vulnNode.ID,
			Kind:       graph.EdgeKindFoundVuln,
			Effect:     graph.EdgeEffectAllow,
			Properties: cloneWorkloadAnyMap(writeMeta.PropertyMap()),
			Risk:       vulnNode.Risk,
		}) {
			result.ScanVulnEdges++
		}
	}

	for _, relation := range relations {
		pkgID := packageNodeID(relation.pkg)
		vulnID := vulnerabilityNodeID(relation.vuln)
		if addEdgeIfMissing(g, &graph.Edge{
			ID:     packageVulnerabilityEdgeID(pkgID, vulnID),
			Source: pkgID,
			Target: vulnID,
			Kind:   graph.EdgeKindAffectedBy,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"package_name":      relation.pkg.Name,
				"installed_version": relation.pkg.Version,
				"fixed_version":     strings.TrimSpace(relation.vuln.FixedVersion),
				"severity":          normalizeSeverity(relation.vuln.Severity),
				"source_system":     graphMaterializationSourceSystem,
				"source_event_id":   fmt.Sprintf("%s:package_vulnerability:%s", sourceEventID, packageVulnerabilityKey(relation.pkg, relation.vuln)),
				"observed_at":       seenAt.UTC().Format(time.RFC3339),
				"valid_from":        validFrom.UTC().Format(time.RFC3339),
				"recorded_at":       seenAt.UTC().Format(time.RFC3339),
				"transaction_from":  seenAt.UTC().Format(time.RFC3339),
				"confidence":        1.0,
			},
			Risk: relation.risk,
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
		if addEdgeIfMissing(g, &graph.Edge{
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

func summarizeRun(run RunRecord) (scanSummary, map[string]configAggregate, map[string]secretAggregate, map[string]packageAggregate, map[string]vulnerabilityAggregate, map[string]packageVulnerabilityAggregate) {
	summary := scanSummary{
		FindingCount: run.Summary.Findings,
		Risk:         graph.RiskNone,
	}
	findings := make(map[string]configAggregate)
	secrets := make(map[string]secretAggregate)
	packages := make(map[string]packageAggregate)
	vulns := make(map[string]vulnerabilityAggregate)
	relations := make(map[string]packageVulnerabilityAggregate)
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
		for _, malware := range catalog.Malware {
			summary.Risk = maxRiskLevel(summary.Risk, severityToRisk(malware.Severity, false))
		}

		for _, pkg := range catalog.Packages {
			id := packageNodeID(pkg)
			if id == "" {
				continue
			}
			if _, exists := packages[id]; !exists {
				packages[id] = packageAggregate{record: pkg}
			}
		}
		for _, vuln := range catalog.Vulnerabilities {
			id := vulnerabilityNodeID(vuln)
			if id == "" {
				continue
			}
			if existing, exists := vulns[id]; exists {
				vulns[id] = vulnerabilityAggregate{record: mergeVulnerabilityRecord(existing.record, vuln)}
			} else {
				vulns[id] = vulnerabilityAggregate{record: vuln}
			}
			for _, pkg := range catalog.Packages {
				if !strings.EqualFold(strings.TrimSpace(pkg.Name), strings.TrimSpace(vuln.Package)) {
					continue
				}
				key := packageVulnerabilityKey(pkg, vuln)
				if _, exists := relations[key]; !exists {
					relations[key] = packageVulnerabilityAggregate{
						pkg:  pkg,
						vuln: vuln,
						risk: severityToRisk(vuln.Severity, vuln.InKEV),
					}
				}
			}
		}
	}

	summary.IaCArtifactCount = len(iacArtifacts)
	summary.PackageCount = len(packages)
	summary.VulnerabilityCount = len(vulns)
	for _, vulnAgg := range vulns {
		switch normalizeSeverity(vulnAgg.record.Severity) {
		case "critical":
			summary.CriticalVulnerabilityCount++
		case "high":
			summary.HighVulnerabilityCount++
		case "medium":
			summary.MediumVulnerabilityCount++
		case "low":
			summary.LowVulnerabilityCount++
		default:
			summary.UnknownVulnerabilityCount++
		}
		if vulnAgg.record.InKEV {
			summary.KnownExploitedCount++
		}
		if vulnAgg.record.Exploitable {
			summary.ExploitableCount++
		}
		if strings.TrimSpace(vulnAgg.record.FixedVersion) != "" {
			summary.FixableCount++
		}
	}
	summary.Risk = maxRiskLevel(summary.Risk, summaryRisk(summary))
	return summary, findings, secrets, packages, vulns, relations
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
		"manager":      strings.TrimSpace(pkg.Manager),
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

func nodeID(run RunRecord) string {
	if id := strings.TrimSpace(run.ID); id != "" {
		return id
	}
	return "workload_scan:" + syntheticRunKey(run)
}

func iacFindingObservationNodeID(scanNodeID string, finding filesystemanalyzer.ConfigFinding) string {
	return fmt.Sprintf("observation:iac:%s:%s", slugify(scanNodeID), slugify(firstNonEmpty(strings.TrimSpace(finding.ID), strings.TrimSpace(finding.Path), strings.TrimSpace(finding.Title))))
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

func vulnerabilityKey(vuln scanner.ImageVulnerability) string {
	return slugify(firstNonEmpty(vuln.CVE, vuln.ID, fmt.Sprintf("%s:%s", vuln.Package, vuln.FixedVersion)))
}

func packageVulnerabilityKey(pkg filesystemanalyzer.PackageRecord, vuln scanner.ImageVulnerability) string {
	return slugify(fmt.Sprintf("%s|%s|%s", packageNodeID(pkg), vulnerabilityNodeID(vuln), firstNonEmpty(vuln.FixedVersion, "none")))
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
	if summary.KnownExploitedCount > 0 || summary.CriticalVulnerabilityCount > 0 {
		return graph.RiskCritical
	}
	if summary.HighVulnerabilityCount > 0 {
		return graph.RiskHigh
	}
	if summary.MediumVulnerabilityCount > 0 {
		return graph.RiskMedium
	}
	if summary.LowVulnerabilityCount > 0 {
		return graph.RiskLow
	}
	return graph.RiskNone
}

func addEdgeIfMissing(g *graph.Graph, edge *graph.Edge) bool {
	if g == nil || edge == nil {
		return false
	}
	for _, existing := range g.GetOutEdges(edge.Source) {
		if existing == nil {
			continue
		}
		if existing.ID == edge.ID || (existing.Target == edge.Target && existing.Kind == edge.Kind) {
			return false
		}
	}
	g.AddEdge(edge)
	return true
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
