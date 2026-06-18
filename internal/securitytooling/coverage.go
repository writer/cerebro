package securitytooling

import (
	"fmt"
	"net/url"
	"strings"
)

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

func ControlCoverageURN(tenantID string, toolID string, framework string, controlID string) string {
	tenantID = strings.TrimSpace(tenantID)
	toolID = strings.TrimSpace(toolID)
	controlID = strings.TrimSpace(controlID)
	framework = strings.TrimSpace(framework)
	if framework == "" {
		framework = "security"
	}
	if tenantID == "" || toolID == "" || controlID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:security_tool_control_coverage:%s:%s:%s", urnToken(tenantID), urnToken(toolID), urnToken(framework), urnToken(controlID))
}

func urnToken(value string) string {
	return url.QueryEscape(strings.TrimSpace(value))
}
