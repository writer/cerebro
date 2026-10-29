// Package requirements is the pure, I/O-free deterministic core behind the
// cloud-identity requirement investigator. It never calls a model, a cloud
// provider, or a repository: callers hand it a pinned Repository already
// fetched by an adapter, a candidate set of model-proposed ModelClaims, and
// the live Definitions vocabulary, and it returns a ci.Investigation whose
// Requirements and Validation were derived entirely by deterministic rules.
//
// # Trust model
//
// A model may only *propose* claims. Nothing it emits is trusted directly:
//
//   - A claim is promoted into a ci.Requirement only when a static,
//     independently-extracted finding from ExtractStatic already proves the
//     operation exists in the pinned source at that exact location, the
//     claimed Operation maps through Definitions to a known
//     OperationDefinition, and every citation's quoted text is byte-exact
//     against the pinned file content at the cited lines.
//   - A static finding that maps through Definitions is promoted on its own
//     (with a conservative Resources=["*"] placeholder and an explicit
//     resource_scope_unresolved gap) even if no model claim corroborates it,
//     so under-reporting by the model can never hide a real excess.
//   - Anything that fails validation (bad citation, unknown operation,
//     uncorroborated claim, model response rejected outright) is preserved
//     as a Gap for inspection, never silently dropped and never promoted.
//
// # Static coverage
//
// ExtractStatic recognizes a documented, closed subset of direct cloud SDK
// call patterns: Go source parsed with go/parser, resolving local variables
// assigned from a recognized AWS SDK v2 / GCP client constructor within a
// single function body, plus explicit reflect.MethodByName detection as an
// unsupported dynamic-dispatch signal; Python source using a direct
// `x = boto3.client("service")` binding followed by `x.method(...)` calls on
// the same line; and JavaScript/TypeScript source using the AWS SDK v3
// `new XCommand(...)` literal pattern bound to an `@aws-sdk/client-*` import.
// Any other language, any computed/dynamic call, and any file outside this
// subset is an explicit scope gap, never silently assumed complete.
// ScopeComplete is computed file-by-file from these gaps; it is never a
// hard-coded constant.
package requirements

// Gap codes emitted by this package. They are stable identifiers consumers
// (native findings, UI) can match on.
const (
	GapUnreviewedPath                  = "cloud_identity.unreviewed_path"
	GapGoParseError                    = "cloud_identity.go_parse_error"
	GapUnsupportedDynamicCall          = "cloud_identity.unsupported_dynamic_call"
	GapUnsupportedPattern              = "cloud_identity.unsupported_pattern"
	GapUnknownOperation                = "cloud_identity.unknown_operation"
	GapCitationMismatch                = "cloud_identity.citation_mismatch"
	GapUncorroboratedClaim             = "cloud_identity.uncorroborated_claim"
	GapResourceScopeUnresolved         = "cloud_identity.resource_scope_unresolved"
	GapModelResponseRejected           = "cloud_identity.model_response_rejected"
	GapSourceMappingMismatch           = "cloud_identity.source_mapping_mismatch"
	GapConditionalPermission           = "cloud_identity.conditional_permission_unresolved"
	GapUnapprovedDependency            = "cloud_identity.unapproved_dependency"
	GapSourceRevisionNotImmutable      = "cloud_identity.source_revision_not_immutable"
	GapSourceDigestMismatch            = "cloud_identity.source_digest_mismatch"
	GapUnreviewablePackageInit         = "cloud_identity.unreviewable_package_init"
	GapOperationDependenciesIncomplete = "cloud_identity.operation_dependencies_incomplete"
	GapAmbiguousGCPOperation           = "cloud_identity.ambiguous_gcp_operation"
	GapUnresolvedChainMethod           = "cloud_identity.unresolved_chain_method"
	GapBuildProfileExcluded            = "cloud_identity.build_profile_excluded"

	// Analyzer is the Validation.Analyzer identifier for investigations
	// produced by Validate.
	Analyzer = "cloud-identity-requirements/v1"
)
