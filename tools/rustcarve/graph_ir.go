package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

type graphQueryIR struct {
	Family            string                  `json:"family"`
	IRVersion         string                  `json:"ir_version"`
	Caller            string                  `json:"caller"`
	Dynamic           bool                    `json:"dynamic"`
	Scope             scopeContract           `json:"scope"`
	NodeRoles         []graphNodeRole         `json:"node_roles"`
	Relationships     []graphRelationship     `json:"relationships"`
	Operations        []graphOperation        `json:"operations"`
	EntityShapes      []graphEntityShape      `json:"entity_shapes"`
	NormalizedOutputs []graphResponseShape    `json:"normalized_outputs"`
	FixtureCases      []graphFixtureCase      `json:"fixture_cases"`
	UnsupportedShapes []graphUnsupportedShape `json:"unsupported_shapes"`
	Deletion          graphDeletionContract   `json:"deletion"`
}

type graphNodeRole struct {
	Role           string `json:"role"`
	Kind           string `json:"kind"`
	TenantInput    string `json:"tenant_input"`
	WorkspaceInput string `json:"workspace_input,omitempty"`
}

type graphRelationship struct {
	Role             string   `json:"role"`
	Kind             string   `json:"kind"`
	AllowedKinds     []string `json:"allowed_kinds"`
	Direction        string   `json:"direction"`
	FromRole         string   `json:"from_role"`
	ToRole           string   `json:"to_role"`
	TenantInput      string   `json:"tenant_input"`
	WorkspaceInput   string   `json:"workspace_input,omitempty"`
	DomainEdgeTarget string   `json:"domain_edge_property,omitempty"`
}

type graphOperation struct {
	Name                   string              `json:"name"`
	Predicates             []graphPredicate    `json:"predicates"`
	Traversals             []graphTraversal    `json:"traversals"`
	UnionBranches          []graphUnionBranch  `json:"union_branches"`
	Aggregate              *graphAggregate     `json:"aggregate,omitempty"`
	Limit                  graphResultLimit    `json:"limit"`
	Cursor                 graphCursorContract `json:"cursor"`
	Order                  []graphOrderField   `json:"order"`
	Dedupe                 string              `json:"dedupe"`
	ResponseShapeRef       string              `json:"response_shape_ref"`
	PublicResponseShapeRef string              `json:"public_response_shape_ref"`
	CountBinding           *graphCountBinding  `json:"count_binding,omitempty"`
	SubjectPreLimit        *graphResultLimit   `json:"subject_pre_limit,omitempty"`
	SubjectPreOrder        []graphOrderField   `json:"subject_pre_order"`
}

type graphPredicate struct {
	Kind             string `json:"kind"`
	Target           string `json:"target"`
	ValueInput       string `json:"value_input"`
	CaseBehavior     string `json:"case_behavior,omitempty"`
	MaxNeedleBytes   int    `json:"max_needle_bytes,omitempty"`
	MaxFieldBytes    int    `json:"max_field_bytes,omitempty"`
	MaxScannedValues int    `json:"max_scanned_values,omitempty"`
	BooleanGroup     string `json:"boolean_group,omitempty"`
	GroupOperator    string `json:"group_operator,omitempty"`
}

type graphTraversal struct {
	RelationshipRole string `json:"relationship_role"`
	Direction        string `json:"direction"`
	MinHops          int    `json:"min_hops"`
	MaxHops          int    `json:"max_hops"`
}

type graphUnionBranch struct {
	Name         string             `json:"name"`
	Phase        string             `json:"phase"`
	Predicates   []graphPredicate   `json:"predicates"`
	Traversals   []graphTraversal   `json:"traversals"`
	OutputFields []graphOutputField `json:"output_fields"`
}

type graphAggregate struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Min    int    `json:"min"`
	Max    int    `json:"max"`
}

type graphResultLimit struct {
	RequestMin         int    `json:"request_min"`
	RequestMax         int    `json:"request_max"`
	InternalExpression string `json:"internal_expression"`
	InternalMax        int    `json:"internal_max,omitempty"`
}

type graphCursorContract struct {
	Kind               string `json:"kind"`
	Input              string `json:"input,omitempty"`
	Output             string `json:"output,omitempty"`
	GraphRevisionInput string `json:"graph_revision_input,omitempty"`
	ForeignRejected    bool   `json:"foreign_rejected"`
}

type graphOrderField struct {
	Target    string `json:"target"`
	Direction string `json:"direction"`
	Canonical bool   `json:"canonical"`
}

type graphCountBinding struct {
	PriorOperation     string `json:"prior_operation"`
	ExecuteWhenNonzero bool   `json:"execute_when_nonzero"`
	ExactRowCount      bool   `json:"exact_row_count"`
}

type graphResponseShape struct {
	Name        string             `json:"name"`
	Fields      []graphOutputField `json:"fields"`
	Cardinality string             `json:"cardinality"`
	Truncation  string             `json:"truncation"`
}

type graphEntityShape struct {
	Name   string             `json:"name"`
	Fields []graphOutputField `json:"fields"`
}

type graphOutputField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type graphFixtureCase struct {
	Name              string   `json:"name"`
	ProductionHelpers []string `json:"production_helpers"`
	ExpectedRows      int      `json:"expected_rows"`
	ExpectedCursor    string   `json:"expected_cursor"`
}

type graphUnsupportedShape struct {
	Caller     string     `json:"caller"`
	ReasonCode reasonCode `json:"reason_code"`
}

type graphDeletionContract struct {
	Paths     []string `json:"paths"`
	Constants []string `json:"constants"`
	Helpers   []string `json:"helpers"`
}

var allowedGraphNodeKinds = stringSetOf(
	"application", "asset", "capability", "compliance.impact_revision", "control", "entitlement", "evidence", "evidence_declared_node",
	"finding", "group", "identity", "person", "policy", "principal", "resource", "role", "workspace",
)

var allowedGraphRelationshipKinds = stringSetOf(
	"assigned_to", "can_admin", "compliance_depends_on", "confers_capability", "depends_on", "evidence_declared_relation", "evidence_for",
	"grants_entitlement", "has_access", "member_of", "owns", "represents_identity", "same_actor", "supports",
)

var allowedGraphOperations = stringSetOf(
	"count_dependencies", "effective_access", "get_fact", "grounding_nodes", "grounding_relations", "list_dependencies", "list_dependents",
)

func validateGraphQuery(value *graphQueryIR, requestScope scopeContract) []reasonCode {
	if value == nil {
		return []reasonCode{reasonUnsupportedPredicate}
	}
	reasons := make([]reasonCode, 0)
	if value.IRVersion != graphQueryIRVersion || value.Family != "graph_query" {
		reasons = append(reasons, reasonUnsupportedPredicate)
	}
	if value.Dynamic {
		reasons = append(reasons, reasonDynamicQuery)
	}
	if len(reasonsForScope(value.Scope)) != 0 || !sameScope(value.Scope, requestScope) {
		reasons = append(reasons, reasonWrongScope)
	}
	roleKinds := map[string]string{}
	for _, node := range value.NodeRoles {
		if strings.TrimSpace(node.Role) == "" || !allowedGraphNodeKinds[node.Kind] {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
		if !graphScopeBindingMatches(node.TenantInput, node.WorkspaceInput, value.Scope) {
			reasons = append(reasons, reasonWrongScope)
		}
		if _, exists := roleKinds[node.Role]; exists {
			reasons = append(reasons, reasonResponseShapeMismatch)
		}
		roleKinds[node.Role] = node.Kind
	}
	relations := map[string]graphRelationship{}
	for _, relation := range value.Relationships {
		validKinds := relation.Kind != "" && allowedGraphRelationshipKinds[relation.Kind]
		if len(relation.AllowedKinds) != 0 {
			validKinds = relation.Kind == ""
			for _, kind := range relation.AllowedKinds {
				validKinds = validKinds && allowedGraphRelationshipKinds[kind]
			}
		}
		if !validKinds || !validDirection(relation.Direction) {
			reasons = append(reasons, reasonUnsupportedRelation)
		}
		if !graphScopeBindingMatches(relation.TenantInput, relation.WorkspaceInput, value.Scope) {
			reasons = append(reasons, reasonWrongScope)
		}
		if _, ok := roleKinds[relation.FromRole]; !ok {
			reasons = append(reasons, reasonUnsupportedRelation)
		}
		if _, ok := roleKinds[relation.ToRole]; !ok {
			reasons = append(reasons, reasonUnsupportedRelation)
		}
		if _, exists := relations[relation.Role]; exists || relation.Role == "" {
			reasons = append(reasons, reasonUnsupportedRelation)
		}
		relations[relation.Role] = relation
	}
	shapes := map[string][]graphOutputField{}
	entityShapes := map[string]bool{}
	for _, shape := range value.EntityShapes {
		if shape.Name == "" || len(shape.Fields) == 0 || entityShapes[shape.Name] {
			reasons = append(reasons, reasonResponseShapeMismatch)
		}
		entityShapes[shape.Name] = true
	}
	for _, shape := range value.EntityShapes {
		for _, field := range shape.Fields {
			if !validGraphOutputType(field.Type, entityShapes) {
				reasons = append(reasons, reasonResponseShapeMismatch)
			}
		}
	}
	for _, shape := range value.NormalizedOutputs {
		if shape.Name == "" || len(shape.Fields) == 0 || !validCardinality(shape.Cardinality) || shapes[shape.Name] != nil {
			reasons = append(reasons, reasonResponseShapeMismatch)
		}
		for _, field := range shape.Fields {
			if !validGraphOutputType(field.Type, entityShapes) {
				reasons = append(reasons, reasonResponseShapeMismatch)
			}
		}
		shapes[shape.Name] = shape.Fields
	}
	seenOperations := map[string]bool{}
	for _, operation := range value.Operations {
		if !allowedGraphOperations[operation.Name] || seenOperations[operation.Name] {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
		seenOperations[operation.Name] = true
		reasons = append(reasons, validateGraphOperation(operation, relations, shapes)...)
		if operation.Name == "effective_access" {
			reasons = append(reasons, validateEffectiveAccessShape(value, operation)...)
		}
	}
	if len(value.Operations) == 0 || len(value.FixtureCases) == 0 {
		reasons = append(reasons, reasonMissingParityReceipt)
	}
	for _, unsupported := range value.UnsupportedShapes {
		if unsupported.Caller == "" || (unsupported.ReasonCode != reasonDynamicQuery && unsupported.ReasonCode != reasonInterpolatedCypher && unsupported.ReasonCode != reasonUnboundedShape) {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
	}
	return uniqueReasons(reasons)
}

type effectiveAccessBranchSpec struct {
	Phase      string
	Traversals []graphTraversal
	Predicates map[string]string
}

func validateEffectiveAccessShape(value *graphQueryIR, operation graphOperation) []reasonCode {
	reasons := make([]reasonCode, 0)
	if value.Scope.WorkspacePolicy != "forbidden" || value.Scope.Workspace != nil {
		reasons = append(reasons, reasonWrongScope)
	}
	wantNodes := map[string]string{"subject": "identity", "identity": "identity", "principal": "principal", "group": "group", "application": "application", "role": "role", "entitlement": "entitlement", "capability": "capability"}
	if len(value.NodeRoles) != len(wantNodes) {
		reasons = append(reasons, reasonUnsupportedPredicate)
	}
	for _, node := range value.NodeRoles {
		if wantNodes[node.Role] != node.Kind || node.TenantInput != "tenant_id" || node.WorkspaceInput != "" {
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
	}
	wantRelations := map[string]graphRelationship{
		"incoming_identity":      {Role: "incoming_identity", AllowedKinds: []string{"represents_identity", "same_actor"}, Direction: "inbound", FromRole: "principal", ToRole: "subject", TenantInput: "tenant_id"},
		"outgoing_same_actor":    {Role: "outgoing_same_actor", Kind: "same_actor", Direction: "outbound", FromRole: "subject", ToRole: "principal", TenantInput: "tenant_id"},
		"subject_represents":     {Role: "subject_represents", Kind: "represents_identity", Direction: "outbound", FromRole: "subject", ToRole: "identity", TenantInput: "tenant_id"},
		"principal_represents":   {Role: "principal_represents", Kind: "represents_identity", Direction: "outbound", FromRole: "principal", ToRole: "identity", TenantInput: "tenant_id"},
		"subject_same_actor":     {Role: "subject_same_actor", Kind: "same_actor", Direction: "outbound", FromRole: "subject", ToRole: "identity", TenantInput: "tenant_id"},
		"direct_assignment":      {Role: "direct_assignment", Kind: "assigned_to", Direction: "outbound", FromRole: "principal", ToRole: "application", TenantInput: "tenant_id"},
		"group_membership":       {Role: "group_membership", Kind: "member_of", Direction: "outbound", FromRole: "principal", ToRole: "group", TenantInput: "tenant_id"},
		"group_assignment":       {Role: "group_assignment", Kind: "assigned_to", Direction: "outbound", FromRole: "group", ToRole: "application", TenantInput: "tenant_id"},
		"role_assignment":        {Role: "role_assignment", AllowedKinds: []string{"assigned_to", "can_admin"}, Direction: "outbound", FromRole: "principal", ToRole: "role", TenantInput: "tenant_id"},
		"application_grant":      {Role: "application_grant", Kind: "grants_entitlement", Direction: "outbound", FromRole: "application", ToRole: "entitlement", TenantInput: "tenant_id"},
		"role_grant":             {Role: "role_grant", Kind: "grants_entitlement", Direction: "outbound", FromRole: "role", ToRole: "entitlement", TenantInput: "tenant_id"},
		"entitlement_capability": {Role: "entitlement_capability", Kind: "confers_capability", Direction: "outbound", FromRole: "entitlement", ToRole: "capability", TenantInput: "tenant_id"},
	}
	if len(value.Relationships) != len(wantRelations) {
		reasons = append(reasons, reasonUnsupportedRelation)
	}
	for _, relation := range value.Relationships {
		want, ok := wantRelations[relation.Role]
		if !ok || relation.Kind != want.Kind || !equalStrings(relation.AllowedKinds, want.AllowedKinds) || relation.Direction != want.Direction || relation.FromRole != want.FromRole || relation.ToRole != want.ToRole || relation.TenantInput != want.TenantInput || relation.WorkspaceInput != "" || relation.DomainEdgeTarget != "" {
			reasons = append(reasons, reasonUnsupportedRelation)
		}
	}

	wantBranches := map[string]effectiveAccessBranchSpec{
		"identity_self": {Phase: "identity", Predicates: map[string]string{"subject.tenant_id": "tenant_id"}},
		"identity_incoming_represents_or_same_actor":    {Phase: "identity", Traversals: []graphTraversal{{RelationshipRole: "incoming_identity", Direction: "inbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"incoming_identity.kind": "represents_identity|same_actor"}},
		"identity_outgoing_same_actor":                  {Phase: "identity", Traversals: []graphTraversal{{RelationshipRole: "outgoing_same_actor", Direction: "outbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"outgoing_same_actor.kind": "same_actor"}},
		"identity_two_hop_represents_bridge":            {Phase: "identity", Traversals: []graphTraversal{{RelationshipRole: "subject_represents", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "principal_represents", Direction: "inbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"principal_represents.kind": "represents_identity", "subject_represents.kind": "represents_identity"}},
		"identity_two_hop_same_actor_represents_bridge": {Phase: "identity", Traversals: []graphTraversal{{RelationshipRole: "subject_same_actor", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "principal_represents", Direction: "inbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"principal_represents.kind": "represents_identity", "subject_same_actor.kind": "same_actor"}},
		"access_direct_application":                     {Phase: "access", Traversals: []graphTraversal{{RelationshipRole: "direct_assignment", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "application_grant", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "entitlement_capability", Direction: "outbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"direct_assignment.kind": "assigned_to"}},
		"access_group_mediated_application":             {Phase: "access", Traversals: []graphTraversal{{RelationshipRole: "group_membership", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "group_assignment", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "application_grant", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "entitlement_capability", Direction: "outbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"group_assignment.kind": "assigned_to", "group_membership.kind": "member_of"}},
		"access_role_or_admin":                          {Phase: "access", Traversals: []graphTraversal{{RelationshipRole: "role_assignment", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "role_grant", Direction: "outbound", MinHops: 1, MaxHops: 1}, {RelationshipRole: "entitlement_capability", Direction: "outbound", MinHops: 1, MaxHops: 1}}, Predicates: map[string]string{"role_assignment.kind": "assigned_to|can_admin"}},
	}
	if len(operation.UnionBranches) != len(wantBranches) {
		reasons = append(reasons, reasonUnionShapeMismatch)
	}
	seenBranches := map[string]bool{}
	for _, branch := range operation.UnionBranches {
		want, ok := wantBranches[branch.Name]
		if !ok || seenBranches[branch.Name] || branch.Phase != want.Phase || !equalGraphTraversals(branch.Traversals, want.Traversals) || !equalEffectiveAccessPredicates(branch.Predicates, want.Predicates) {
			reasons = append(reasons, reasonUnionShapeMismatch)
		}
		seenBranches[branch.Name] = true
	}

	wantNeedles := map[string]bool{"subject.attributes_json": true, "subject.label": true, "subject.urn": true}
	seenNeedles := map[string]bool{}
	seenTenant := false
	for _, predicate := range operation.Predicates {
		switch predicate.Kind {
		case "exact":
			seenTenant = predicate.Target == "subject.tenant_id" && predicate.ValueInput == "tenant_id"
		case "bounded_substring":
			if !wantNeedles[predicate.Target] || predicate.ValueInput != "identity_query" || predicate.CaseBehavior != "unicode_casefold" || predicate.MaxNeedleBytes != 512 || predicate.MaxFieldBytes <= 0 || predicate.MaxScannedValues <= 0 || predicate.BooleanGroup != "identity_search" || predicate.GroupOperator != "any" {
				reasons = append(reasons, reasonUnsupportedPredicate)
			}
			seenNeedles[predicate.Target] = true
		default:
			reasons = append(reasons, reasonUnsupportedPredicate)
		}
	}
	if !seenTenant || !reflect.DeepEqual(seenNeedles, wantNeedles) || len(operation.Predicates) != 4 {
		reasons = append(reasons, reasonUnsupportedPredicate)
	}
	if operation.Limit != (graphResultLimit{RequestMin: 1, RequestMax: 100, InternalExpression: "exact"}) || operation.Cursor.Kind != "none" || operation.Cursor.Input != "" || operation.Cursor.Output != "" || operation.Cursor.GraphRevisionInput != "graph_revision" || operation.Cursor.ForeignRejected {
		reasons = append(reasons, reasonInvalidLimit, reasonInvalidCursor)
	}
	wantPreOrder := []graphOrderField{{Target: "subject.label", Direction: "ascending", Canonical: true}, {Target: "subject.urn", Direction: "ascending", Canonical: true}}
	if operation.SubjectPreLimit == nil || *operation.SubjectPreLimit != (graphResultLimit{RequestMin: 1, RequestMax: 100, InternalExpression: "exact"}) || !reflect.DeepEqual(operation.SubjectPreOrder, wantPreOrder) {
		reasons = append(reasons, reasonInvalidLimit)
	}
	wantOrder := []graphOrderField{{Target: "identity.label", Direction: "ascending", Canonical: true}, {Target: "principal.label", Direction: "ascending", Canonical: true}, {Target: "assignment_kind", Direction: "ascending", Canonical: true}, {Target: "application.label", Direction: "ascending", Canonical: true}, {Target: "entitlement.label", Direction: "ascending", Canonical: true}, {Target: "capability.label", Direction: "ascending", Canonical: true}}
	if operation.Dedupe != "distinct_normalized_rows" || !reflect.DeepEqual(operation.Order, wantOrder) || operation.ResponseShapeRef != "effective_access_paths" || operation.PublicResponseShapeRef != "effective_access_response" {
		reasons = append(reasons, reasonResponseShapeMismatch)
	}
	wantFixtures := stringSetOf("six_node_five_edge_group_mediated", "direct_application", "role_and_admin_variants", "cross_tenant_rejected", "malformed_chain_rejected", "raw_only_go_store_fails_closed")
	seenFixtures := map[string]bool{}
	for _, fixture := range value.FixtureCases {
		seenFixtures[fixture.Name] = true
	}
	if len(value.FixtureCases) != len(wantFixtures) || !reflect.DeepEqual(seenFixtures, wantFixtures) {
		reasons = append(reasons, reasonMissingParityReceipt)
	}
	return uniqueReasons(reasons)
}

func equalEffectiveAccessPredicates(predicates []graphPredicate, expected map[string]string) bool {
	if len(predicates) != len(expected) {
		return false
	}
	for _, predicate := range predicates {
		if expected[predicate.Target] != predicate.ValueInput {
			return false
		}
		if predicate.Kind != "exact" && predicate.Kind != "fixed_relation" {
			return false
		}
	}
	return true
}

func equalGraphTraversals(left, right []graphTraversal) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateGraphOperation(operation graphOperation, relations map[string]graphRelationship, shapes map[string][]graphOutputField) []reasonCode {
	reasons := make([]reasonCode, 0)
	for _, predicate := range operation.Predicates {
		reasons = append(reasons, validateGraphPredicate(predicate)...)
	}
	for _, traversal := range operation.Traversals {
		if _, ok := relations[traversal.RelationshipRole]; !ok || !validDirection(traversal.Direction) || traversal.MinHops < 0 || traversal.MaxHops < traversal.MinHops || traversal.MaxHops == 0 {
			reasons = append(reasons, reasonUnboundedTraversal)
		}
	}
	if operation.Limit.RequestMin <= 0 || operation.Limit.RequestMax < operation.Limit.RequestMin || operation.Limit.RequestMax > 10_000 {
		reasons = append(reasons, reasonUnboundedResultLimit)
	}
	if operation.Limit.InternalExpression != "exact" && operation.Limit.InternalExpression != "request_plus_one" && operation.Limit.InternalExpression != "prior_exact_count" && operation.Limit.InternalExpression != "fixed" {
		reasons = append(reasons, reasonInvalidLimit)
	}
	if operation.Limit.InternalExpression == "fixed" && (operation.Limit.InternalMax <= 0 || operation.Limit.InternalMax > 10_000) {
		reasons = append(reasons, reasonInvalidLimit)
	}
	if operation.Cursor.Kind != "none" && operation.Cursor.Kind != "keyset" {
		reasons = append(reasons, reasonInvalidCursor)
	}
	if operation.Cursor.GraphRevisionInput == "" {
		reasons = append(reasons, reasonInvalidCursor)
	}
	if operation.Cursor.Kind == "keyset" && (operation.Cursor.Input == "" || operation.Cursor.Output == "" || operation.Cursor.GraphRevisionInput == "" || !operation.Cursor.ForeignRejected) {
		reasons = append(reasons, reasonInvalidCursor)
	}
	if operation.Cursor.Kind == "none" && (operation.Cursor.Input != "" || operation.Cursor.Output != "") {
		reasons = append(reasons, reasonInvalidCursor)
	}
	if operation.SubjectPreLimit != nil {
		if operation.SubjectPreLimit.RequestMin <= 0 || operation.SubjectPreLimit.RequestMax < operation.SubjectPreLimit.RequestMin || operation.SubjectPreLimit.InternalExpression != "exact" || len(operation.SubjectPreOrder) == 0 {
			reasons = append(reasons, reasonInvalidLimit)
		}
	}
	if _, ok := shapes[operation.ResponseShapeRef]; !ok {
		reasons = append(reasons, reasonResponseShapeMismatch)
	}
	if _, ok := shapes[operation.PublicResponseShapeRef]; !ok {
		reasons = append(reasons, reasonResponseShapeMismatch)
	}
	if operation.Dedupe != "none" && operation.Dedupe != "distinct_normalized_rows" {
		reasons = append(reasons, reasonResponseShapeMismatch)
	}
	for _, branch := range operation.UnionBranches {
		if branch.Phase != "" && branch.Phase != "identity" && branch.Phase != "access" {
			reasons = append(reasons, reasonUnionShapeMismatch)
		}
		if !sameOutputFields(branch.OutputFields, shapes[operation.ResponseShapeRef]) {
			reasons = append(reasons, reasonUnionShapeMismatch)
		}
		for _, predicate := range branch.Predicates {
			reasons = append(reasons, validateGraphPredicate(predicate)...)
		}
		for _, traversal := range branch.Traversals {
			if _, ok := relations[traversal.RelationshipRole]; !ok || !validDirection(traversal.Direction) || traversal.MinHops < 0 || traversal.MaxHops < traversal.MinHops || traversal.MaxHops == 0 {
				reasons = append(reasons, reasonUnboundedTraversal)
			}
		}
	}
	if operation.Aggregate != nil {
		if operation.Aggregate.Kind != "count_edge" || operation.Aggregate.Min < 0 || operation.Aggregate.Max < operation.Aggregate.Min || operation.Aggregate.Max > 10_000 {
			reasons = append(reasons, reasonUnsupportedAggregate)
		}
	}
	return reasons
}

func validateGraphPredicate(predicate graphPredicate) []reasonCode {
	if predicate.BooleanGroup != "" && predicate.GroupOperator != "any" && predicate.GroupOperator != "all" {
		return []reasonCode{reasonUnsupportedPredicate}
	}
	switch predicate.Kind {
	case "bounded_substring":
		if predicate.Target == "" || predicate.ValueInput == "" || (predicate.CaseBehavior != "sensitive" && predicate.CaseBehavior != "unicode_casefold") {
			return []reasonCode{reasonUnsupportedPredicate}
		}
		if predicate.MaxNeedleBytes <= 0 || predicate.MaxFieldBytes <= 0 || predicate.MaxScannedValues <= 0 {
			return []reasonCode{reasonUnboundedScan}
		}
	case "exact", "exact_set", "fixed_relation", "keyset_gt":
		if predicate.Target == "" || predicate.ValueInput == "" {
			return []reasonCode{reasonUnsupportedPredicate}
		}
	default:
		return []reasonCode{reasonUnsupportedPredicate}
	}
	return nil
}

func validDirection(value string) bool { return value == "outbound" || value == "inbound" }

func validCardinality(value string) bool {
	return value == "zero_or_one" || value == "exactly_one" || value == "exactly_one_scalar" || value == "bounded_list" || value == "paged_list"
}

func sameOutputFields(left, right []graphOutputField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validGraphOutputType(value string, entities map[string]bool) bool {
	if stringSetOf("boolean", "integer", "number", "string", "tenant_id", "timestamp", "urn")[value] || entities[value] {
		return true
	}
	if strings.HasPrefix(value, "array<") && strings.HasSuffix(value, ">") {
		item := strings.TrimSuffix(strings.TrimPrefix(value, "array<"), ">")
		return entities[item] || stringSetOf("boolean", "integer", "number", "string", "tenant_id", "timestamp", "urn")[item]
	}
	return false
}

func sameScope(left, right scopeContract) bool {
	return left.Tenant == right.Tenant && left.WorkspacePolicy == right.WorkspacePolicy && equalTypedInput(left.Workspace, right.Workspace)
}

func equalTypedInput(left, right *typedInput) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func graphScopeBindingMatches(tenantInput, workspaceInput string, scope scopeContract) bool {
	if tenantInput != scope.Tenant.Name {
		return false
	}
	if scope.Workspace == nil {
		return workspaceInput == ""
	}
	return workspaceInput == scope.Workspace.Name
}

func stringSetOf(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func uniqueReasons(values []reasonCode) []reasonCode {
	seen := map[reasonCode]bool{}
	result := make([]reasonCode, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func graphValidationError(reasons []reasonCode) error {
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("graph query rejected: %s", joinReasons(reasons))
}

func joinReasons(reasons []reasonCode) string {
	values := make([]string, len(reasons))
	for index, reason := range reasons {
		values[index] = string(reason)
	}
	return strings.Join(values, ",")
}
