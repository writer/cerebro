package main

import "strings"

type findingRuleIR struct {
	IRVersion       string                     `json:"ir_version"`
	Rule            findingRuleIdentity        `json:"rule"`
	Scope           scopeContract              `json:"scope"`
	Matcher         findingMatcherContract     `json:"matcher"`
	Fingerprint     findingFingerprintContract `json:"fingerprint"`
	Lifecycle       findingLifecycleContract   `json:"lifecycle"`
	GraphAnchors    []findingGraphAnchor       `json:"graph_anchors"`
	Expiry          findingExpiryContract      `json:"expiry"`
	Output          findingOutputContract      `json:"output"`
	ReplayCorpus    []artifactRequest          `json:"replay_corpus"`
	Counterexamples []artifactRequest          `json:"counterexamples"`
	Authority       findingAuthorityContract   `json:"authority"`
	Deletion        deletionRequest            `json:"deletion"`
}

type findingRuleIdentity struct {
	RuleID          string `json:"rule_id"`
	Family          string `json:"family"`
	CatalogRevision string `json:"catalog_revision"`
}

type findingMatcherContract struct {
	InputFields        []findingTypedField `json:"input_fields"`
	Predicates         []findingPredicate  `json:"predicates"`
	RequiredAttributes []findingAttribute  `json:"required_attributes"`
}

type findingTypedField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type findingPredicate struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Input  string `json:"input"`
}

type findingAttribute struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	MissingBehavior string `json:"missing_behavior"`
}

type findingFingerprintContract struct {
	DomainSeparator string   `json:"domain_separator"`
	Fields          []string `json:"fields"`
	Normalization   string   `json:"normalization"`
	Hash            string   `json:"hash"`
}

type findingLifecycleContract struct {
	States           []string                     `json:"states"`
	Transitions      []findingLifecycleTransition `json:"transitions"`
	CloseCondition   string                       `json:"close_condition"`
	ObservedAtSource string                       `json:"observed_at_source"`
}

type findingLifecycleTransition struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Condition string `json:"condition"`
}

type findingGraphAnchor struct {
	EntityKind       string `json:"entity_kind"`
	IDField          string `json:"id_field"`
	TenantBinding    string `json:"tenant_binding"`
	WorkspaceBinding string `json:"workspace_binding"`
	RelationshipRole string `json:"relationship_role"`
}

type findingExpiryContract struct {
	Mode         string `json:"mode"`
	TTLSeconds   int64  `json:"ttl_seconds"`
	Clock        string `json:"clock"`
	ExpirySource string `json:"expiry_source"`
}

type findingOutputContract struct {
	SchemaVersion string              `json:"schema_version"`
	Fields        []findingTypedField `json:"fields"`
}

type findingAuthorityContract struct {
	RequiredAuthority string `json:"required_authority"`
	FailClosed        bool   `json:"fail_closed"`
	ReplayParity      string `json:"replay_parity"`
}

func validateFindingRule(value *findingRuleIR, requestScope scopeContract) []reasonCode {
	if value == nil {
		return []reasonCode{reasonUnsupportedPredicate}
	}
	reasons := make([]reasonCode, 0)
	if value.IRVersion != findingRuleIRVersion || strings.TrimSpace(value.Rule.RuleID) == "" || strings.TrimSpace(value.Rule.Family) == "" || strings.TrimSpace(value.Rule.CatalogRevision) == "" {
		reasons = append(reasons, reasonAmbiguousGoOwner)
	}
	if len(reasonsForScope(value.Scope)) != 0 || !sameScope(value.Scope, requestScope) {
		reasons = append(reasons, reasonWrongScope)
	}
	if len(value.Matcher.InputFields) == 0 || len(value.Matcher.Predicates) == 0 || len(value.Matcher.RequiredAttributes) == 0 {
		reasons = append(reasons, reasonUnsupportedPredicate)
	}
	for _, predicate := range value.Matcher.Predicates {
		if predicate.Target == "" || predicate.Input == "" || !stringSetOf("equals", "in_set", "present", "absent", "bool_is")[predicate.Kind] {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
	}
	for _, attribute := range value.Matcher.RequiredAttributes {
		if attribute.Name == "" || !validScalarType(attribute.Type) || !stringSetOf("reject", "no_match", "default_false")[attribute.MissingBehavior] {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
	}
	if value.Fingerprint.DomainSeparator == "" || len(value.Fingerprint.Fields) == 0 || !stringSetOf("utf8_nfc_lowercase_trim", "utf8_trim")[value.Fingerprint.Normalization] || value.Fingerprint.Hash != "sha256" {
		reasons = append(reasons, reasonUnstableFingerprint)
	}
	if !validateLifecycle(value.Lifecycle) {
		reasons = append(reasons, reasonUnsupportedLifecycle)
	}
	if len(value.GraphAnchors) == 0 {
		reasons = append(reasons, reasonUnsupportedGraphAnchor)
	}
	for _, anchor := range value.GraphAnchors {
		if anchor.EntityKind == "" || anchor.IDField == "" || anchor.TenantBinding != "tenant_id" || anchor.RelationshipRole == "" {
			reasons = append(reasons, reasonUnsupportedGraphAnchor)
		}
		if value.Scope.WorkspacePolicy == "forbidden" && anchor.WorkspaceBinding != "forbidden" {
			reasons = append(reasons, reasonUnboundWorkspaceScope)
		}
	}
	if !validateExpiry(value.Expiry) {
		reasons = append(reasons, reasonUnsupportedTTL)
	}
	if value.Output.SchemaVersion == "" || len(value.Output.Fields) == 0 {
		reasons = append(reasons, reasonResponseShapeMismatch)
	}
	if len(value.ReplayCorpus) == 0 || value.Authority.ReplayParity != "exact" {
		reasons = append(reasons, reasonMissingReplayCorpus)
	}
	if !value.Authority.FailClosed || value.Authority.RequiredAuthority == "" {
		reasons = append(reasons, reasonUnsupportedLifecycle)
	}
	return uniqueReasons(reasons)
}

func validateLifecycle(value findingLifecycleContract) bool {
	allowed := stringSetOf("open", "update", "close", "reopen")
	if len(value.States) < 3 || value.CloseCondition == "" || value.ObservedAtSource == "" {
		return false
	}
	for _, state := range value.States {
		if !allowed[state] {
			return false
		}
	}
	for _, transition := range value.Transitions {
		if !allowed[transition.From] || !allowed[transition.To] || transition.Condition == "" {
			return false
		}
	}
	return true
}

func validateExpiry(value findingExpiryContract) bool {
	switch value.Mode {
	case "none":
		return value.TTLSeconds == 0 && value.Clock == "observed_at"
	case "ttl":
		return value.TTLSeconds > 0 && value.TTLSeconds <= 31_536_000 && value.Clock == "observed_at" && value.ExpirySource != ""
	default:
		return false
	}
}

func validScalarType(value string) bool {
	return stringSetOf("boolean", "integer", "number", "string", "timestamp", "urn")[value]
}
