package main

import "sort"

const schemaContractV1 = "cerebro.rustcarve.closed-schema/v2"

type closedSchemaContract struct {
	SchemaVersion        string                      `json:"schema_version"`
	ToolRevision         string                      `json:"tool_revision"`
	RequestSchemaVersion string                      `json:"request_schema_version"`
	EnvelopeVersion      string                      `json:"migration_ir_schema_version"`
	UnknownFields        string                      `json:"unknown_fields"`
	Scope                closedScopeSchema           `json:"scope"`
	Variants             []closedVariantSchema       `json:"variants"`
	SourceAuthority      closedSourceAuthoritySchema `json:"source_authority"`
	GraphQuery           closedGraphQuerySchema      `json:"graph_query"`
	FindingRule          closedFindingRuleSchema     `json:"finding_rule"`
	DifferentialReceipt  closedReceiptSchema         `json:"differential_receipt"`
	DeletionManifest     closedDeletionSchema        `json:"deletion_manifest"`
	ReasonCodes          []reasonCode                `json:"reason_codes"`
}

type closedScopeSchema struct {
	TenantInput     typedInput `json:"tenant_input"`
	WorkspacePolicy []string   `json:"workspace_policy"`
	WorkspaceInput  typedInput `json:"workspace_input"`
}

type closedVariantSchema struct {
	BehaviorKind         behaviorKind `json:"behavior_kind"`
	IRVersion            string       `json:"ir_version"`
	RequiredReceiptModes []string     `json:"required_receipt_modes"`
	CanonicalGoType      string       `json:"canonical_go_type"`
}

type closedGraphQuerySchema struct {
	CanonicalGoType          string   `json:"canonical_go_type"`
	AllowedNodeKinds         []string `json:"allowed_node_kinds"`
	AllowedRelationshipKinds []string `json:"allowed_relationship_kinds"`
	AllowedOperations        []string `json:"allowed_operations"`
	AllowedPredicates        []string `json:"allowed_predicates"`
	AllowedDirections        []string `json:"allowed_directions"`
	AllowedCursorKinds       []string `json:"allowed_cursor_kinds"`
	AllowedLimitExpressions  []string `json:"allowed_limit_expressions"`
	ScopeBindingRule         string   `json:"scope_binding_rule"`
	UnionOutputRule          string   `json:"union_output_rule"`
	PublicResponseRule       string   `json:"public_response_rule"`
	TraversalRule            string   `json:"traversal_rule"`
	DynamicQueryRule         string   `json:"dynamic_query_rule"`
}

type closedSourceAuthoritySchema struct {
	CanonicalRequestType     string   `json:"canonical_request_type"`
	CanonicalIRType          string   `json:"canonical_ir_type"`
	RequiredGates            []string `json:"required_gates"`
	ProjectionPath           string   `json:"projection_path"`
	ProjectionRegisterSymbol string   `json:"projection_register_symbol"`
	DynamicProjectorSymbol   string   `json:"dynamic_projector_symbol"`
	RuntimeFencePath         string   `json:"runtime_fence_path"`
	RuntimeFenceSymbol       string   `json:"runtime_fence_symbol"`
	ProjectionRule           string   `json:"projection_rule"`
	RuntimeFenceRule         string   `json:"runtime_fence_rule"`
}

type closedFindingRuleSchema struct {
	CanonicalGoType          string   `json:"canonical_go_type"`
	AllowedPredicates        []string `json:"allowed_predicates"`
	AllowedMissingBehavior   []string `json:"allowed_missing_behavior"`
	AllowedLifecycleStates   []string `json:"allowed_lifecycle_states"`
	AllowedExpiryModes       []string `json:"allowed_expiry_modes"`
	FingerprintNormalization []string `json:"fingerprint_normalization"`
	ReplayRule               string   `json:"replay_rule"`
}

type closedReceiptSchema struct {
	SchemaVersion  string   `json:"schema_version"`
	RequiredFields []string `json:"required_fields"`
	MismatchRule   string   `json:"mismatch_rule"`
}

type closedDeletionSchema struct {
	SchemaVersion  string   `json:"schema_version"`
	ExactTargets   []string `json:"exact_targets"`
	AuthorityGates []string `json:"authority_gates"`
	Eligibility    string   `json:"eligibility"`
}

func buildClosedSchemaContract() closedSchemaContract {
	reasons := append([]reasonCode(nil), allReasonCodes...)
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	return closedSchemaContract{
		SchemaVersion:        schemaContractV1,
		ToolRevision:         rustcarveToolRevision,
		RequestSchemaVersion: requestSchemaVersion,
		EnvelopeVersion:      migrationIRSchemaVersion,
		UnknownFields:        "reject",
		Scope: closedScopeSchema{
			TenantInput:     typedInput{Name: "tenant_id", Type: "tenant_id", Required: true},
			WorkspacePolicy: []string{"forbidden", "optional", "required"},
			WorkspaceInput:  typedInput{Name: "workspace_id", Type: "workspace_id"},
		},
		Variants: []closedVariantSchema{
			{BehaviorKind: behaviorStandardSource, IRVersion: standardSourceIRVersion, RequiredReceiptModes: requiredReceiptModes(behaviorStandardSource), CanonicalGoType: "tools/rustcarve.standardSourceIR"},
			{BehaviorKind: behaviorProviderSource, IRVersion: providerSourceIRVersion, RequiredReceiptModes: requiredReceiptModes(behaviorProviderSource), CanonicalGoType: "tools/rustcarve.standardSourceIR"},
			{BehaviorKind: behaviorGraphQuery, IRVersion: graphQueryIRVersion, RequiredReceiptModes: requiredReceiptModes(behaviorGraphQuery), CanonicalGoType: "tools/rustcarve.graphQueryIR"},
			{BehaviorKind: behaviorFindingRule, IRVersion: findingRuleIRVersion, RequiredReceiptModes: requiredReceiptModes(behaviorFindingRule), CanonicalGoType: "tools/rustcarve.findingRuleIR"},
		},
		SourceAuthority: closedSourceAuthoritySchema{
			CanonicalRequestType:     "tools/rustcarve.sourceAuthorityRequest",
			CanonicalIRType:          "tools/rustcarve.sourceAuthorityIR",
			RequiredGates:            []string{"projection_dispatch", "runtime_fence"},
			ProjectionPath:           sourceProjectionRegistryPath,
			ProjectionRegisterSymbol: sourceProjectionRegisterSymbol,
			DynamicProjectorSymbol:   sourceDynamicProjectorSymbol,
			RuntimeFencePath:         sourceRuntimeFencePath,
			RuntimeFenceSymbol:       sourceRuntimeFenceSymbol,
			ProjectionRule:           "the named registration function must not call the named dynamic Go projector constructor",
			RuntimeFenceRule:         "the named closed Rust authority function must unconditionally authorize every catalog runtime family for the exact source",
		},
		GraphQuery: closedGraphQuerySchema{
			CanonicalGoType:          "tools/rustcarve.graphQueryIR",
			AllowedNodeKinds:         sortedBoolKeys(allowedGraphNodeKinds),
			AllowedRelationshipKinds: sortedBoolKeys(allowedGraphRelationshipKinds),
			AllowedOperations:        sortedBoolKeys(allowedGraphOperations),
			AllowedPredicates:        []string{"bounded_substring", "exact", "exact_set", "fixed_relation", "keyset_gt"},
			AllowedDirections:        []string{"inbound", "outbound"},
			AllowedCursorKinds:       []string{"keyset", "none"},
			AllowedLimitExpressions:  []string{"exact", "fixed", "prior_exact_count", "request_plus_one"},
			ScopeBindingRule:         "every node and relationship names the typed tenant input and, when present, the typed workspace input",
			UnionOutputRule:          "every typed branch must equal one normalized output field sequence; dedupe and final order are explicit",
			PublicResponseRule:       "every operation names an exact normalized public response shape",
			TraversalRule:            "direction and finite positive minimum and maximum hops are required; effective_access requires exact one-hop segments",
			DynamicQueryRule:         "raw, interpolated, dynamic, or unbounded Cypher is not representable and is rejected",
		},
		FindingRule: closedFindingRuleSchema{
			CanonicalGoType:          "tools/rustcarve.findingRuleIR",
			AllowedPredicates:        []string{"absent", "bool_is", "equals", "in_set", "present"},
			AllowedMissingBehavior:   []string{"default_false", "no_match", "reject"},
			AllowedLifecycleStates:   []string{"close", "open", "reopen", "update"},
			AllowedExpiryModes:       []string{"none", "ttl"},
			FingerprintNormalization: []string{"utf8_nfc_lowercase_trim", "utf8_trim"},
			ReplayRule:               "exact replay parity bound to the same IR, corpus, tool, and Rust revisions",
		},
		DifferentialReceipt: closedReceiptSchema{
			SchemaVersion:  differentialReceiptV1,
			RequiredFields: []string{"tool_revision", "behavior_kind", "subject_id", "go_facts_digest_sha256", "ir_version", "ir_digest_sha256", "rust_implementation_revision", "evidence_digests_sha256", "input_digest_sha256", "fixture_or_graph_revision", "normalized_rows_digest_sha256", "order_cursor_digest_sha256", "mismatch_count"},
			MismatchRule:   "mismatch_count must be zero and every digest/revision must match the generated IR",
		},
		DeletionManifest: closedDeletionSchema{
			SchemaVersion:  deletionManifestV1,
			ExactTargets:   []string{"paths", "imports", "symbols"},
			AuthorityGates: []string{"projection_dispatch", "runtime_fence"},
			Eligibility:    "false unless Rust-only fail-closed authority, every source authority gate, and every required bound receipt pass",
		},
		ReasonCodes: reasons,
	}
}

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
