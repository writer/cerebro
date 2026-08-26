package main

type reasonCode string

const (
	reasonActiveGoRegistryPath     reasonCode = "active_go_registry_path"
	reasonActiveGoExecutionPath    reasonCode = "active_go_execution_path"
	reasonActiveGoProjectionPath   reasonCode = "active_go_projection_path"
	reasonAmbiguousGoOwner         reasonCode = "ambiguous_go_owner"
	reasonDynamicGoCallback        reasonCode = "dynamic_go_callback"
	reasonDynamicQuery             reasonCode = "dynamic_query"
	reasonInterpolatedCypher       reasonCode = "interpolated_cypher"
	reasonInvalidCursor            reasonCode = "invalid_cursor"
	reasonInvalidLimit             reasonCode = "invalid_limit"
	reasonMalformedJSON            reasonCode = "malformed_json"
	reasonMissingParityReceipt     reasonCode = "missing_parity_receipt"
	reasonMissingAuthorityEvidence reasonCode = "missing_authority_evidence"
	reasonMissingRustRuntimeFence  reasonCode = "missing_rust_runtime_fence"
	reasonNoDeletionTargets        reasonCode = "no_deletion_targets"
	reasonMissingReplayCorpus      reasonCode = "missing_replay_corpus"
	reasonNonDeterministicTime     reasonCode = "nondeterministic_time"
	reasonReceiptBindingMismatch   reasonCode = "receipt_binding_mismatch"
	reasonReplayMismatch           reasonCode = "replay_mismatch"
	reasonResponseShapeMismatch    reasonCode = "response_shape_mismatch"
	reasonSecretMaterial           reasonCode = "secret_material"
	reasonSideEffectingMatcher     reasonCode = "side_effecting_matcher"
	reasonUnboundTenantScope       reasonCode = "unbound_tenant_scope"
	reasonUnboundWorkspaceScope    reasonCode = "unbound_workspace_scope"
	reasonUnboundedResultLimit     reasonCode = "unbounded_result_limit"
	reasonUnboundedScan            reasonCode = "unbounded_scan"
	reasonUnboundedShape           reasonCode = "unbounded_shape"
	reasonUnboundedTraversal       reasonCode = "unbounded_traversal"
	reasonUnionShapeMismatch       reasonCode = "union_shape_mismatch"
	reasonUnknownBehaviorKind      reasonCode = "unknown_behavior_kind"
	reasonUnsupportedAggregate     reasonCode = "unsupported_aggregate"
	reasonUnsupportedGraphAnchor   reasonCode = "unsupported_graph_anchor"
	reasonUnsupportedLifecycle     reasonCode = "unsupported_lifecycle"
	reasonUnsupportedPredicate     reasonCode = "unsupported_predicate"
	reasonUnsupportedRelation      reasonCode = "unsupported_relation"
	reasonUnsupportedRegistration  reasonCode = "unsupported_registration_shape"
	reasonUnsupportedTTL           reasonCode = "unsupported_ttl"
	reasonUnstableFingerprint      reasonCode = "unstable_fingerprint"
	reasonWrongScope               reasonCode = "wrong_scope"
)

var allReasonCodes = []reasonCode{
	reasonActiveGoExecutionPath,
	reasonActiveGoProjectionPath,
	reasonActiveGoRegistryPath,
	reasonAmbiguousGoOwner,
	reasonDynamicGoCallback,
	reasonDynamicQuery,
	reasonInterpolatedCypher,
	reasonInvalidCursor,
	reasonInvalidLimit,
	reasonMalformedJSON,
	reasonMissingAuthorityEvidence,
	reasonMissingParityReceipt,
	reasonMissingRustRuntimeFence,
	reasonNoDeletionTargets,
	reasonMissingReplayCorpus,
	reasonNonDeterministicTime,
	reasonReceiptBindingMismatch,
	reasonReplayMismatch,
	reasonResponseShapeMismatch,
	reasonSecretMaterial,
	reasonSideEffectingMatcher,
	reasonUnboundTenantScope,
	reasonUnboundWorkspaceScope,
	reasonUnboundedResultLimit,
	reasonUnboundedScan,
	reasonUnboundedShape,
	reasonUnboundedTraversal,
	reasonUnionShapeMismatch,
	reasonUnknownBehaviorKind,
	reasonUnsupportedAggregate,
	reasonUnsupportedGraphAnchor,
	reasonUnsupportedLifecycle,
	reasonUnsupportedPredicate,
	reasonUnsupportedRelation,
	reasonUnsupportedRegistration,
	reasonUnsupportedTTL,
	reasonUnstableFingerprint,
	reasonWrongScope,
}
