package runtimegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

const runtimeFindingEvidenceSourceSystem = "cerebro_runtime_detection"

var ErrInvalidFindingEvidence = errors.New("invalid runtime finding evidence")

// EvidenceMaterializationResult summarizes one batch of runtime finding evidence writes.
type EvidenceMaterializationResult struct {
	FindingsConsidered    int   `json:"findings_considered"`
	EvidenceNodesUpserted int   `json:"evidence_nodes_upserted"`
	FindingsSkipped       int   `json:"findings_skipped"`
	InvalidFindings       int   `json:"invalid_findings"`
	LastError             error `json:"-"`
}

// BuildFindingEvidenceNode converts one runtime finding into a graph evidence node.
func BuildFindingEvidenceNode(finding *runtime.RuntimeFinding) (*graph.Node, error) {
	if finding == nil {
		return nil, fmt.Errorf("%w: finding is required", ErrInvalidFindingEvidence)
	}

	observedAt := findingObservedAt(finding)
	if observedAt.IsZero() {
		return nil, fmt.Errorf("%w: missing observed_at", ErrInvalidFindingEvidence)
	}
	observedAt = observedAt.UTC()

	sourceEventID := strings.TrimSpace(finding.ID)
	metadata := graph.NormalizeWriteMetadata(
		observedAt,
		observedAt,
		nil,
		runtimeFindingEvidenceSourceSystem,
		sourceEventID,
		0.90,
		graph.WriteMetadataDefaults{
			Now:               observedAt,
			RecordedAt:        observedAt,
			TransactionFrom:   observedAt,
			SourceSystem:      runtimeFindingEvidenceSourceSystem,
			SourceEventID:     sourceEventID,
			SourceEventPrefix: "runtime_finding",
			DefaultConfidence: 0.90,
		},
	)

	properties := metadata.PropertyMap()
	properties["evidence_type"] = "runtime_finding"
	properties["detail"] = firstNonEmpty(
		strings.TrimSpace(finding.Description),
		strings.TrimSpace(finding.RuleName),
		string(finding.Category),
	)
	addMetadataString(properties, "rule_id", finding.RuleID)
	addMetadataString(properties, "rule_name", finding.RuleName)
	addMetadataString(properties, "category", string(finding.Category))
	addMetadataString(properties, "severity", finding.Severity)
	addMetadataString(properties, "resource_id", finding.ResourceID)
	addMetadataString(properties, "resource_type", finding.ResourceType)
	addMetadataString(properties, "remediation", finding.Remediation)
	if finding.Suppressed {
		properties["suppressed"] = true
	}
	if len(finding.MITRE) > 0 {
		properties["mitre_attack"] = append([]string(nil), finding.MITRE...)
	}
	if finding.Observation != nil {
		addMetadataString(properties, "observation_id", strings.TrimSpace(finding.Observation.ID))
		addMetadataString(properties, "observation_kind", string(finding.Observation.Kind))
		addMetadataString(properties, "runtime_source", strings.TrimSpace(finding.Observation.Source))
	} else if finding.Event != nil {
		addMetadataString(properties, "runtime_source", strings.TrimSpace(finding.Event.Source))
	}

	return &graph.Node{
		ID:         findingEvidenceNodeID(finding, sourceEventID, observedAt),
		Kind:       graph.NodeKindEvidence,
		Name:       firstNonEmpty(strings.TrimSpace(finding.RuleName), strings.TrimSpace(finding.Description), "runtime finding"),
		Provider:   runtimeFindingEvidenceSourceSystem,
		Properties: properties,
		Risk:       graph.RiskNone,
	}, nil
}

// MaterializeFindingEvidenceIntoGraph projects runtime findings into graph evidence nodes.
func MaterializeFindingEvidenceIntoGraph(g *graph.Graph, findings []*runtime.RuntimeFinding, now time.Time) EvidenceMaterializationResult {
	result := EvidenceMaterializationResult{}
	if g == nil || len(findings) == 0 {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, finding := range findings {
		result.FindingsConsidered++
		node, err := BuildFindingEvidenceNode(finding)
		if err != nil {
			result.FindingsSkipped++
			result.InvalidFindings++
			result.LastError = err
			continue
		}
		g.AddNode(node)
		result.EvidenceNodesUpserted++
	}

	g.BuildIndex()
	meta := g.Metadata()
	meta.BuiltAt = now.UTC()
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
	return result
}

func findingObservedAt(finding *runtime.RuntimeFinding) time.Time {
	if finding == nil {
		return time.Time{}
	}
	if !finding.Timestamp.IsZero() {
		return finding.Timestamp
	}
	if finding.Observation != nil && !finding.Observation.ObservedAt.IsZero() {
		return finding.Observation.ObservedAt
	}
	if finding.Event != nil && !finding.Event.Timestamp.IsZero() {
		return finding.Event.Timestamp
	}
	return time.Time{}
}

func findingEvidenceNodeID(finding *runtime.RuntimeFinding, sourceEventID string, observedAt time.Time) string {
	if trimmed := strings.TrimSpace(sourceEventID); trimmed != "" {
		return "evidence:runtime_finding:" + trimmed
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.ResourceID),
		observedAt.UTC().Format(time.RFC3339Nano),
	}, "|")))
	return "evidence:runtime_finding:" + hex.EncodeToString(digest[:8])
}
