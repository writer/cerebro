package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDeepSeekDistillationIsDeterministicAndDeletionFailsClosed(t *testing.T) {
	request, err := loadCarveRequest("testdata/deepseek.request.json")
	if err != nil {
		t.Fatalf("load request: %v", err)
	}
	first, err := distill(repositoryRoot(t), request)
	if err != nil {
		t.Fatalf("distill: %v", err)
	}
	second, err := distill(repositoryRoot(t), request)
	if err != nil {
		t.Fatalf("distill repeat: %v", err)
	}
	if first.Unsupported != nil {
		t.Fatalf("unsupported: %#v", first.Unsupported)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("distillation is not deterministic")
	}
	if first.IR.Provider == nil || first.IR.Provider.Registration != "generic_catalog_runtime" {
		t.Fatalf("provider IR = %#v", first.IR.Provider)
	}
	if got := first.IR.Provider.RuntimeFamilies; !reflect.DeepEqual(got, []string{"account_balances", "model_catalog"}) {
		t.Fatalf("runtime families = %v", got)
	}
	if first.Manifest.Eligible {
		t.Fatal("DeepSeek deletion became eligible while the generic Go registry path is active")
	}
	wantReasons := []reasonCode{reasonActiveGoProjectionPath, reasonActiveGoRegistryPath, reasonMissingParityReceipt}
	if !reflect.DeepEqual(first.Manifest.ReasonCodes, wantReasons) {
		t.Fatalf("manifest reasons = %v, want %v", first.Manifest.ReasonCodes, wantReasons)
	}
	if len(first.Manifest.AuthorityGates) != 2 || first.Manifest.AuthorityGates[0].Satisfied || !first.Manifest.AuthorityGates[1].Satisfied {
		t.Fatalf("authority gates = %#v", first.Manifest.AuthorityGates)
	}
	for _, path := range []string{"migration-ir.json", "deletion-manifest.json", "rust/scaffold.rs", "rust/contracts.rs", "rust/parity_test.rs", "registry/standard_source_plan_index.txt"} {
		if len(first.Artifacts[path]) == 0 {
			t.Fatalf("missing generated artifact %s", path)
		}
	}
}

func TestGraphQueryAcceptsClosedComplianceImpactShape(t *testing.T) {
	value := validComplianceImpactGraphIR()
	if reasons := validateGraphQuery(&value, value.Scope); len(reasons) != 0 {
		t.Fatalf("graph reasons = %v", reasons)
	}
	value.Dynamic = true
	value.Operations[0].Limit.RequestMax = 0
	reasons := validateGraphQuery(&value, value.Scope)
	assertReason(t, reasons, reasonDynamicQuery)
	assertReason(t, reasons, reasonUnboundedResultLimit)
}

func TestGraphQueryRejectsUnboundedTraversalAndUnionShapeDrift(t *testing.T) {
	value := validComplianceImpactGraphIR()
	operation := &value.Operations[2]
	operation.Traversals = []graphTraversal{{RelationshipRole: "dependency_edge", Direction: "outbound", MinHops: 1, MaxHops: 0}}
	operation.UnionBranches = []graphUnionBranch{{
		Name:         "drift",
		OutputFields: []graphOutputField{{Name: "wrong", Type: "string", Required: true}},
	}}
	reasons := validateGraphQuery(&value, value.Scope)
	assertReason(t, reasons, reasonUnboundedTraversal)
	assertReason(t, reasons, reasonUnionShapeMismatch)
}

func TestEffectiveAccessContractIsFixedDepthTenantScopedAndFailClosed(t *testing.T) {
	request, err := loadCarveRequest("testdata/effective-access.request.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := distill(repositoryRoot(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported != nil {
		t.Fatalf("effective access unsupported: %#v", result.Unsupported)
	}
	graph := result.IR.GraphQuery
	if graph == nil || graph.Dynamic || graph.Scope.WorkspacePolicy != "forbidden" || graph.Scope.Workspace != nil {
		t.Fatalf("graph scope or dynamic contract = %#v", graph)
	}
	if len(graph.Operations) != 1 || graph.Operations[0].Name != "effective_access" {
		t.Fatalf("operations = %#v", graph.Operations)
	}
	operation := graph.Operations[0]
	if len(operation.UnionBranches) != 8 {
		t.Fatalf("union branches = %d, want five identity plus three access", len(operation.UnionBranches))
	}
	phaseCounts := map[string]int{}
	for _, branch := range operation.UnionBranches {
		phaseCounts[branch.Phase]++
		for _, traversal := range branch.Traversals {
			if traversal.MinHops != 1 || traversal.MaxHops != 1 {
				t.Fatalf("branch %s traversal = %#v, want fixed one hop", branch.Name, traversal)
			}
		}
	}
	if !reflect.DeepEqual(phaseCounts, map[string]int{"access": 3, "identity": 5}) {
		t.Fatalf("union phases = %v", phaseCounts)
	}
	relationKinds := map[string]bool{}
	for _, relation := range graph.Relationships {
		if relation.TenantInput != "tenant_id" || relation.WorkspaceInput != "" {
			t.Fatalf("relation scope = %#v", relation)
		}
		if relation.Kind != "" {
			relationKinds[relation.Kind] = true
		}
		for _, kind := range relation.AllowedKinds {
			relationKinds[kind] = true
		}
	}
	wantRelations := []string{"assigned_to", "can_admin", "confers_capability", "grants_entitlement", "member_of", "represents_identity", "same_actor"}
	if got := sortedKeys(relationKinds); !reflect.DeepEqual(got, wantRelations) {
		t.Fatalf("relationship whitelist = %v, want %v", got, wantRelations)
	}
	for _, node := range graph.NodeRoles {
		if node.TenantInput != "tenant_id" || node.WorkspaceInput != "" {
			t.Fatalf("node scope = %#v", node)
		}
	}
	needleTargets := map[string]bool{}
	for _, predicate := range operation.Predicates {
		if predicate.Kind == "bounded_substring" {
			if predicate.MaxNeedleBytes != 512 || predicate.CaseBehavior != "unicode_casefold" {
				t.Fatalf("substring predicate = %#v", predicate)
			}
			needleTargets[predicate.Target] = true
		}
	}
	if got := sortedKeys(needleTargets); !reflect.DeepEqual(got, []string{"subject.attributes_json", "subject.label", "subject.urn"}) {
		t.Fatalf("substring targets = %v", got)
	}
	if operation.Limit.RequestMin != 1 || operation.Limit.RequestMax != 100 || operation.Cursor.Kind != "none" || operation.Cursor.Input != "" || operation.Cursor.Output != "" || operation.PublicResponseShapeRef != "effective_access_response" {
		t.Fatalf("limit/cursor/response = %#v", operation)
	}
	if operation.SubjectPreLimit == nil || operation.SubjectPreLimit.RequestMax != 100 || len(operation.SubjectPreOrder) != 2 || operation.SubjectPreOrder[0].Target != "subject.label" || operation.SubjectPreOrder[1].Target != "subject.urn" {
		t.Fatalf("subject pre-limit contract = %#v", operation)
	}
	if result.Manifest.Eligible {
		t.Fatal("effective-access deletion became eligible without fixed and live-safe receipts")
	}
	assertReason(t, result.Manifest.ReasonCodes, reasonMissingParityReceipt)
	assertReason(t, result.Manifest.ReasonCodes, reasonNoDeletionTargets)

	graph.NodeRoles[0].TenantInput = ""
	assertReason(t, validateGraphQuery(graph, graph.Scope), reasonWrongScope)
}

func TestFindingRuleRejectsMissingReplayAndUnstableFingerprint(t *testing.T) {
	value := validFindingRuleIR()
	value.Fingerprint.Fields = nil
	value.ReplayCorpus = nil
	reasons := validateFindingRule(&value, value.Scope)
	assertReason(t, reasons, reasonUnstableFingerprint)
	assertReason(t, reasons, reasonMissingReplayCorpus)
}

func TestSecretMaterialAndUnknownRequestFieldsFailClosed(t *testing.T) {
	if got := detectSecretMaterial([]byte(`{"api_key":"not-a-fixture"}`)); got != "$.api_key" {
		t.Fatalf("secret path = %q", got)
	}
	temp := t.TempDir()
	path := filepath.Join(temp, "request.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"cerebro.rustcarve.request/v2","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCarveRequest(path); err == nil {
		t.Fatal("unknown request field was accepted")
	} else {
		var inputErr typedInputError
		if !errors.As(err, &inputErr) || inputErr.Reason != reasonMalformedJSON {
			t.Fatalf("request error = %T %v", err, err)
		}
	}
}

func TestGeneratedJSONIsCanonicalAndClosed(t *testing.T) {
	request, err := loadCarveRequest("testdata/acunetix.request.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := distill(repositoryRoot(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported != nil {
		t.Fatalf("unexpected unsupported result: %#v", result.Unsupported)
	}
	if result.IR.Standard == nil || result.IR.Standard.Registration != "compiled_plan_fail_closed_metadata" || !validSHA256Digest(result.IR.Standard.PlanIndexDigestSHA256) {
		t.Fatalf("Acunetix compiled plan = %#v", result.IR.Standard)
	}
	assertReason(t, result.Manifest.ReasonCodes, reasonActiveGoProjectionPath)
	assertReason(t, result.Manifest.ReasonCodes, reasonMissingRustRuntimeFence)
	assertReason(t, result.Manifest.ReasonCodes, reasonNoDeletionTargets)
	for _, path := range []string{"migration-ir.json", "deletion-manifest.json"} {
		var decoded any
		if path == "migration-ir.json" {
			decoded = &migrationIR{}
		} else {
			decoded = &deletionManifest{}
		}
		if err := json.Unmarshal(result.Artifacts[path], decoded); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		payload, err := marshalJSON(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != string(result.Artifacts[path]) {
			t.Fatalf("%s is not canonical JSON", path)
		}
	}
}

func TestDeletionEligibilityRequiresAnExactlyBoundReceipt(t *testing.T) {
	root, request := minimalSourceRepository(t)
	first, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Unsupported != nil {
		t.Fatalf("unexpected unsupported result: %#v", first.Unsupported)
	}
	if first.Manifest.Eligible || !reflect.DeepEqual(first.Manifest.ReasonCodes, []reasonCode{reasonMissingParityReceipt}) {
		t.Fatalf("initial manifest = %#v", first.Manifest)
	}
	evidence := make([]string, 0, len(first.IR.Evidence.Fixtures)+len(first.IR.Evidence.Traces))
	for _, artifact := range append(append([]artifactDigest(nil), first.IR.Evidence.Fixtures...), first.IR.Evidence.Traces...) {
		evidence = append(evidence, artifact.DigestSHA256)
	}
	receipt := differentialReceipt{
		SchemaVersion:              differentialReceiptV1,
		ToolRevision:               rustcarveToolRevision,
		Mode:                       "fixed_fixture",
		BehaviorKind:               request.BehaviorKind,
		SubjectID:                  request.Subject.ID,
		GoFactsDigestSHA256:        first.IR.GoFacts.DigestSHA256,
		IRVersion:                  first.IR.IRVersion,
		IRDigestSHA256:             first.IR.DigestSHA256,
		RustImplementationRevision: request.Subject.RustImplementationRevision,
		EvidenceDigestsSHA256:      evidence,
		InputDigestSHA256:          digestBytes([]byte("input")),
		FixtureOrGraphRevision:     "fixture-revision-1",
		NormalizedRowsDigestSHA256: digestBytes([]byte("rows")),
		OrderCursorDigestSHA256:    digestBytes([]byte("order-cursor")),
	}
	payload, err := marshalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "receipt.json", payload)
	request.Receipts = []artifactRequest{{Path: "receipt.json", Role: "fixed_fixture"}}
	second, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if second.IR.DigestSHA256 != first.IR.DigestSHA256 {
		t.Fatal("receipt path changed the migration IR digest")
	}
	if !second.Manifest.Eligible || len(second.Manifest.ReasonCodes) != 0 || len(second.Manifest.AcceptedReceipts) != 1 {
		t.Fatalf("eligible manifest = %#v", second.Manifest)
	}

	receipt.MismatchCount = 1
	payload, err = marshalJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "receipt.json", payload)
	third, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	assertReason(t, third.Manifest.ReasonCodes, reasonReceiptBindingMismatch)
}

func TestSourceAuthorityGatesRejectDynamicProjectionAndMissingRuntimeFence(t *testing.T) {
	root, request := minimalSourceRepository(t)
	writeTestFile(t, root, sourceProjectionRegistryPath, []byte("package projection\nfunc RegisterConnectorDefinitions() { installDynamicProjector() }\nfunc installDynamicProjector() { catalogRuntimeDefinitionProjectors() }\n"))
	writeTestFile(t, root, sourceRuntimeFencePath, []byte("package sourceworker\nfunc RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {\n\tswitch sourceID {\n\tcase \"test_source\":\n\t\tif familyID == \"other\" { return familyID, true }\n\t\treturn familyID, false\n\t}\n\treturn familyID, false\n}\n"))
	result, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported != nil {
		t.Fatalf("unexpected unsupported result: %#v", result.Unsupported)
	}
	assertReason(t, result.Manifest.ReasonCodes, reasonActiveGoProjectionPath)
	assertReason(t, result.Manifest.ReasonCodes, reasonMissingRustRuntimeFence)
	if result.Manifest.Eligible {
		t.Fatal("shared authority gaps became deletion eligible")
	}
	if got := result.IR.Standard.Authority.RuntimeFence.MissingRuntimeFamilies; !reflect.DeepEqual(got, []string{"records"}) {
		t.Fatalf("missing runtime families = %v", got)
	}
}

func TestSourceAuthorityEvidencePathsAreClosed(t *testing.T) {
	root, request := minimalSourceRepository(t)
	request.SourceAuthority.ProjectionDispatch.Path = "alternate/projection.go"
	result, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported == nil {
		t.Fatal("alternate authority evidence path was accepted")
	}
	assertReason(t, result.Unsupported.ReasonCodes, reasonMissingAuthorityEvidence)
}

func TestGoCallbackIsRejectedWithTypedReason(t *testing.T) {
	root, request := minimalSourceRepository(t)
	writeTestFile(t, root, "registry/registry.go", []byte("package registry\nfunc Builtin() { register(func() {}) }\n"))
	result, err := distill(root, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsupported == nil {
		t.Fatal("dynamic callback was accepted")
	}
	assertReason(t, result.Unsupported.ReasonCodes, reasonDynamicGoCallback)
}

func minimalSourceRepository(t *testing.T) (string, carveRequest) {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "registry/registry.go", []byte("package registry\nfunc Builtin() { catalogruntimesource.New(entry) }\n"))
	writeTestFile(t, root, sourceProjectionRegistryPath, []byte("package sourceprojection\nfunc RegisterConnectorDefinitions() {}\n"))
	writeTestFile(t, root, sourceRuntimeFencePath, []byte("package sourceworker\nfunc RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {\n\tswitch sourceID {\n\tcase \"test_source\":\n\t\treturn familyID, true\n\t}\n\treturn \"\", false\n}\n"))
	writeTestFile(t, root, "source/catalog.yaml", []byte("id: test_source\nruntime_families: [records]\nevent_contracts:\n  - kind: test.records\n    schema_ref: test/records/v1\n    required_attributes: [tenant_id]\n    required_payload_fields: [id]\n"))
	writeTestFile(t, root, "fixture.json", []byte("{\"records\":[{\"id\":\"one\"}]}\n"))
	return root, carveRequest{
		SchemaVersion: requestSchemaVersion,
		BehaviorKind:  behaviorStandardSource,
		Subject: subjectRequest{
			ID:                         "test_source",
			PackageDir:                 "registry",
			CatalogPath:                "source/catalog.yaml",
			GoFiles:                    []string{"registry/registry.go"},
			OwnerSymbols:               []string{"Builtin"},
			RustImplementationRevision: "rust-revision-1",
			AuthorityState:             "rust_only_fail_closed",
		},
		Scope:         tenantOnlyScope(),
		FixtureCorpus: []artifactRequest{{Path: "fixture.json", Role: "fixed_fixture"}},
		Deletion:      deletionRequest{Paths: []string{"registry/registry.go"}, Symbols: []string{"catalogruntimesource.New(entry)"}},
		SourceAuthority: &sourceAuthorityRequest{
			ProjectionDispatch: projectionDispatchRequest{Path: sourceProjectionRegistryPath, RegisterSymbol: sourceProjectionRegisterSymbol, DynamicProjectorSymbol: sourceDynamicProjectorSymbol},
			RuntimeFence:       runtimeFenceRequest{Path: sourceRuntimeFencePath, Symbol: sourceRuntimeFenceSymbol},
		},
		Options: distillationOptions{ExpectedRegistrationShape: "generic_catalog_runtime", MaxInputBytes: defaultMaxInputBytes},
	}
}

func writeTestFile(t *testing.T, root, relative string, payload []byte) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertReason(t *testing.T, reasons []reasonCode, expected reasonCode) {
	t.Helper()
	for _, reason := range reasons {
		if reason == expected {
			return
		}
	}
	t.Fatalf("reasons %v do not include %s", reasons, expected)
}

func tenantOnlyScope() scopeContract {
	return scopeContract{
		Tenant:          typedInput{Name: "tenant_id", Type: "tenant_id", Required: true},
		WorkspacePolicy: "forbidden",
	}
}

func validComplianceImpactGraphIR() graphQueryIR {
	entityFields := []graphOutputField{
		{Name: "agent_key", Type: "urn", Required: true},
		{Name: "tenant_id", Type: "tenant_id", Required: true},
		{Name: "domain", Type: "string", Required: true},
		{Name: "fact_kind", Type: "string", Required: true},
		{Name: "stable_id", Type: "string", Required: true},
		{Name: "revision_id", Type: "string", Required: true},
		{Name: "revision_version", Type: "integer", Required: true},
		{Name: "content_digest", Type: "string", Required: true},
		{Name: "last_modified", Type: "timestamp", Required: true},
		{Name: "kind", Type: "string", Required: true},
	}
	dependencyFields := append(append([]graphOutputField(nil), entityFields...), graphOutputField{Name: "dependency_relation", Type: "string", Required: true})
	return graphQueryIR{
		Family:    "graph_query",
		IRVersion: graphQueryIRVersion,
		Caller:    "internal/complianceimpact.ProjectedGraph",
		Scope:     tenantOnlyScope(),
		NodeRoles: []graphNodeRole{
			{Role: "fact", Kind: "compliance.impact_revision", TenantInput: "tenant_id"},
			{Role: "dependency", Kind: "compliance.impact_revision", TenantInput: "tenant_id"},
			{Role: "dependent", Kind: "compliance.impact_revision", TenantInput: "tenant_id"},
		},
		Relationships: []graphRelationship{{Role: "dependency_edge", Kind: "compliance_depends_on", Direction: "outbound", FromRole: "fact", ToRole: "dependency", TenantInput: "tenant_id", DomainEdgeTarget: "dependency_relation"}},
		EntityShapes:  []graphEntityShape{{Name: "compliance_impact_entity", Fields: entityFields}},
		NormalizedOutputs: []graphResponseShape{
			{Name: "fact", Fields: entityFields, Cardinality: "zero_or_one", Truncation: "duplicate_is_error"},
			{Name: "dependency_count", Fields: []graphOutputField{{Name: "count", Type: "integer", Required: true}}, Cardinality: "exactly_one_scalar", Truncation: "out_of_range_is_error"},
			{Name: "dependencies", Fields: dependencyFields, Cardinality: "bounded_list", Truncation: "count_mismatch_is_error"},
			{Name: "dependents", Fields: entityFields, Cardinality: "paged_list", Truncation: "limit_plus_one"},
		},
		Operations: []graphOperation{
			closedGraphOperation("get_fact", 2, "fact"),
			closedGraphOperation("count_dependencies", 1, "dependency_count"),
			closedGraphOperation("list_dependencies", 2999, "dependencies"),
			closedGraphOperation("list_dependents", 2999, "dependents"),
		},
		FixtureCases: []graphFixtureCase{
			{Name: "zero_dependencies", ProductionHelpers: []string{"projectedImpactEntity", "impactRevisionURN"}},
			{Name: "multiple_dependencies", ProductionHelpers: []string{"projectedImpactEntity", "impactRevisionURN"}, ExpectedRows: 2},
			{Name: "multi_page_dependents", ProductionHelpers: []string{"projectedImpactEntity", "impactRevisionURN"}, ExpectedRows: 2, ExpectedCursor: "last_returned_agent_key"},
		},
		Deletion: graphDeletionContract{
			Paths:     []string{"internal/complianceimpact/projected_graph.go"},
			Constants: []string{"getImpactFactQuery", "countImpactDependenciesQuery", "listImpactDependenciesQuery", "listImpactDependentsQuery"},
			Helpers:   []string{"impactRevisionFromRow", "decodeGraphAttributes", "nonnegativeInt"},
		},
	}
}

func closedGraphOperation(name string, max int, shape string) graphOperation {
	operation := graphOperation{
		Name: name,
		Predicates: []graphPredicate{
			{Kind: "exact", Target: "tenant_id", ValueInput: "tenant_id"},
			{Kind: "exact", Target: "kind", ValueInput: "compliance.impact_revision"},
		},
		Limit:                  graphResultLimit{RequestMin: 1, RequestMax: max, InternalExpression: "exact"},
		Cursor:                 graphCursorContract{Kind: "none", GraphRevisionInput: "graph_revision", ForeignRejected: true},
		Order:                  []graphOrderField{{Target: "agent_key", Direction: "ascending", Canonical: true}},
		Dedupe:                 "none",
		ResponseShapeRef:       shape,
		PublicResponseShapeRef: shape,
	}
	switch name {
	case "count_dependencies":
		operation.Aggregate = &graphAggregate{Kind: "count_edge", Target: "dependency_edge", Min: 0, Max: 2999}
	case "list_dependencies":
		operation.Limit.InternalExpression = "prior_exact_count"
		operation.CountBinding = &graphCountBinding{PriorOperation: "count_dependencies", ExecuteWhenNonzero: true, ExactRowCount: true}
	case "list_dependents":
		operation.Limit.InternalExpression = "request_plus_one"
		operation.Cursor = graphCursorContract{Kind: "keyset", Input: "after_agent_key", Output: "next_after_agent_key", GraphRevisionInput: "graph_revision", ForeignRejected: true}
		operation.Dedupe = "distinct_normalized_rows"
	}
	return operation
}

func validFindingRuleIR() findingRuleIR {
	return findingRuleIR{
		IRVersion: findingRuleIRVersion,
		Rule:      findingRuleIdentity{RuleID: "rule-1", Family: "test", CatalogRevision: "sha256:catalog"},
		Scope:     tenantOnlyScope(),
		Matcher: findingMatcherContract{
			InputFields:        []findingTypedField{{Name: "enabled", Type: "boolean"}},
			Predicates:         []findingPredicate{{Kind: "bool_is", Target: "enabled", Input: "false"}},
			RequiredAttributes: []findingAttribute{{Name: "enabled", Type: "boolean", MissingBehavior: "reject"}},
		},
		Fingerprint: findingFingerprintContract{DomainSeparator: "cerebro.finding/v1", Fields: []string{"tenant_id", "rule_id", "entity_urn"}, Normalization: "utf8_nfc_lowercase_trim", Hash: "sha256"},
		Lifecycle: findingLifecycleContract{
			States:           []string{"open", "update", "close"},
			Transitions:      []findingLifecycleTransition{{From: "open", To: "update", Condition: "matched"}, {From: "update", To: "close", Condition: "not_matched"}},
			CloseCondition:   "not_matched",
			ObservedAtSource: "event.observed_at",
		},
		GraphAnchors: []findingGraphAnchor{{EntityKind: "asset", IDField: "entity_urn", TenantBinding: "tenant_id", WorkspaceBinding: "forbidden", RelationshipRole: "finding_subject"}},
		Expiry:       findingExpiryContract{Mode: "none", Clock: "observed_at"},
		Output:       findingOutputContract{SchemaVersion: "cerebro.public-finding/v1", Fields: []findingTypedField{{Name: "finding_id", Type: "string"}}},
		ReplayCorpus: []artifactRequest{{Path: "fixture.json", Role: "replay"}},
		Authority:    findingAuthorityContract{RequiredAuthority: "rust", FailClosed: true, ReplayParity: "exact"},
	}
}
