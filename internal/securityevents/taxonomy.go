package securityevents

import "strings"

const (
	SubjectPrefix = "sec"

	FindingsV1Prefix     = "sec.findings.v1"
	AuditV1Prefix        = "sec.audit.v1"
	ToolsV1Prefix        = "sec.tools.v1"
	ServicesV1Prefix     = "sec.services.v1"
	ObservationsV1Prefix = "sec.observations.v1"
	WorkflowsV1Prefix    = "sec.workflows.v1"
)

const (
	FindingRecorded          = FindingsV1Prefix + ".recorded"
	FindingStatusChanged     = FindingsV1Prefix + ".status_changed"
	FindingNoteAdded         = FindingsV1Prefix + ".note_added"
	FindingTicketLinked      = FindingsV1Prefix + ".ticket_linked"
	FindingExternalRefLinked = FindingsV1Prefix + ".external_ref_linked"

	APIAccessAudit = AuditV1Prefix + ".api_access"

	ToolRegistered = ToolsV1Prefix + ".registered"
	ToolHealth     = ToolsV1Prefix + ".health"
)

// IsCanonicalKind reports whether an event kind already names a security-platform subject.
func IsCanonicalKind(kind string) bool {
	return strings.HasPrefix(strings.TrimSpace(kind), SubjectPrefix+".")
}
