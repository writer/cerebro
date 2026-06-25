package projectionmeta

import "strings"

const (
	AttributeProjectionClass  = "projection_class"
	AttributeProjectionReason = "projection_reason"

	ClassDurableState   = "durable_state"
	ClassEvidence       = "evidence"
	ClassLifecycleState = "lifecycle_state"
	ClassEphemeralEvent = "ephemeral_event"
)

// Typed node properties promoted from attributes_json so hot graph-rule
// predicates can seek a range index instead of substring-scanning the JSON blob
// on every candidate row. Each derivation mirrors the exact equality semantics
// of the rule Cypher predicate it replaces (NOT the broader Go re-validation
// helpers), because the effective detection set is bounded by the narrower
// Cypher pre-filter.
const (
	// PropertyInternetExposed mirrors the case-sensitive `"<key>":"true"`
	// substring checks in the cloud public-exposure rule, which has no Go
	// post-filter, so the comparison must be byte-exact.
	PropertyInternetExposed = "internet_exposed"
	// PropertyPrivilegedIdentity mirrors the lower-cased is_admin /
	// is_delegated_admin checks in the privileged-no-MFA identity rule.
	PropertyPrivilegedIdentity = "is_privileged_identity"
	// PropertyMFADisabled mirrors the lower-cased mfa_* / *_2sv "false" checks
	// in the privileged-no-MFA identity rule.
	PropertyMFADisabled = "mfa_disabled"
)

// EntityTypedProperties holds the typed boolean properties promoted from an
// entity's attributes_json. The store maps these onto the node properties named
// by PropertyInternetExposed/PropertyPrivilegedIdentity/PropertyMFADisabled.
type EntityTypedProperties struct {
	InternetExposed    bool
	PrivilegedIdentity bool
	MFADisabled        bool
}

// DerivedEntityProperties returns the typed boolean properties promoted from an
// entity's merged attributes. Every entity gets a concrete true/false for each
// property so the promoted columns are fully populated after re-projection and
// the backing range index covers them; a NULL property therefore only means the
// entity has not been re-projected since the promotion shipped, which the rule
// predicates handle with an explicit IS NULL fallback to the legacy JSON scan.
func DerivedEntityProperties(attributes map[string]string) EntityTypedProperties {
	return EntityTypedProperties{
		// Case-sensitive to match the rule's `CONTAINS '"<key>":"true"'`.
		InternetExposed: attributeValueEquals(attributes, false, "true",
			"internet_exposed", "external_exposure", "public"),
		// Lower-cased to match the rule's `toLower(user_attrs) CONTAINS ...`.
		PrivilegedIdentity: attributeValueEquals(attributes, true, "true",
			"is_admin", "is_delegated_admin"),
		MFADisabled: attributeValueEquals(attributes, true, "false",
			"mfa_enrolled", "mfa_enforced", "is_enrolled_in_2sv", "is_enforced_in_2sv"),
	}
}

// attributeValueEquals reports whether any named key holds exactly want. It does
// not trim, because the Cypher predicates it mirrors match the verbatim JSON
// substring `"<key>":"<value>"`; a stored value with surrounding whitespace is
// not matched by those predicates either. When caseInsensitive is set the stored
// value is lower-cased first, mirroring a toLower(...) Cypher predicate.
func attributeValueEquals(attributes map[string]string, caseInsensitive bool, want string, keys ...string) bool {
	for _, key := range keys {
		value := attributes[key]
		if caseInsensitive {
			value = strings.ToLower(value)
		}
		if value == want {
			return true
		}
	}
	return false
}

type Classification struct {
	Class  string
	Reason string
}

func ClassifyEntity(entityType string, attributes map[string]string) Classification {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	switch entityType {
	case "sentinelone.activity":
		return Classification{Class: ClassEphemeralEvent, Reason: "source_activity_event"}
	case "runtime.evidence", "evidence":
		return Classification{Class: ClassEvidence, Reason: "evidence_reference"}
	case "finding", "ticket", "external_ref", "decision", "action", "outcome", "annotation":
		return Classification{Class: ClassLifecycleState, Reason: "workflow_lifecycle_state"}
	}
	if entityType == "github.runner" && strings.HasPrefix(strings.TrimSpace(attributes["action"]), "workflows.") {
		return Classification{Class: ClassEphemeralEvent, Reason: "hosted_workflow_job_runner_event"}
	}
	if strings.Contains(entityType, "evidence") || strings.HasSuffix(entityType, ".scan") || strings.HasSuffix(entityType, ".verdict") {
		return Classification{Class: ClassEvidence, Reason: "evidence_shaped_entity"}
	}
	return Classification{Class: ClassDurableState, Reason: "projected_current_state"}
}

func ApplyEntityMetadata(entityType string, attributes map[string]string) map[string]string {
	classification := ClassifyEntity(entityType, attributes)
	next := make(map[string]string, len(attributes)+2)
	for key, value := range attributes {
		next[key] = value
	}
	if strings.TrimSpace(next[AttributeProjectionClass]) == "" {
		next[AttributeProjectionClass] = classification.Class
	}
	if strings.TrimSpace(next[AttributeProjectionReason]) == "" {
		next[AttributeProjectionReason] = classification.Reason
	}
	return next
}
