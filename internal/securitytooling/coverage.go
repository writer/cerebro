package securitytooling

import "strings"

// CoverageStatus classifies a control-mapping coverage value into a normalized
// posture of "covered" or "gap". Empty or unrecognized values stay unclassified
// so downstream projections and rules do not infer a gap from unknown input.
func CoverageStatus(coverage string) string {
	switch strings.ToLower(strings.TrimSpace(coverage)) {
	case "":
		return ""
	case "full", "covered", "complete", "implemented", "operating", "met", "yes", "true":
		return "covered"
	case "none", "gap", "missing", "partial", "planned", "not_covered", "uncovered", "in_progress", "todo", "unmet", "no", "false":
		return "gap"
	default:
		return ""
	}
}
