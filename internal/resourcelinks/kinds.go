package resourcelinks

import "strings"

// Kind identifies one canonical resource family.
type Kind string

const (
	KindFinding                   Kind = "finding"
	KindFindingInvestigation      Kind = "finding_investigation"
	KindFindingEvidenceCollection Kind = "finding_evidence_collection"
	KindSourceRuntime             Kind = "source_runtime"
	KindGraphEntity               Kind = "graph_entity"
)

var kindSet = map[Kind]struct{}{
	KindFinding:                   {},
	KindFindingInvestigation:      {},
	KindFindingEvidenceCollection: {},
	KindSourceRuntime:             {},
	KindGraphEntity:               {},
}

// IsKind reports whether value is a registered resource kind.
func IsKind(value Kind) bool {
	_, ok := kindSet[Kind(strings.TrimSpace(string(value)))]
	return ok
}
