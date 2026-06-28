package grcpolicylifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/fabriccontract"
	"github.com/writer/cerebro/internal/ports"
)

const (
	grcPolicyLifecycleDefaultLimit         = 100
	grcPolicyLifecycleDefaultRelationLimit = 2000
	grcPolicyLifecycleExceptionWindow      = 30 * 24 * time.Hour
)

type Scope struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	Limit     uint32
}

var grcPolicyLifecycleEntityTypes = []string{
	"policy",
	"policy.template",
	"policy.version",
	"policy.approval",
	"policy.acceptance",
	"policy.review",
	"policy.exception",
	"policy.reminder",
}

const grcPolicyLifecycleEntitiesQuery = `UNWIND $entity_types AS entity_type
CALL {
  WITH entity_type
  MATCH (e:Entity)
  WHERE ($tenant_id = '' OR e.tenant_id = $tenant_id)
    AND ($source_id = '' OR e.source_id = $source_id)
    AND ($runtime_id = '' OR coalesce(e.runtime_id, '') = $runtime_id)
    AND e.entity_type = entity_type
  RETURN e
  ORDER BY coalesce(e.label, e.urn), e.urn
  LIMIT $type_limit
}
RETURN e.urn AS urn,
       e.tenant_id AS tenant_id,
       e.source_id AS source_id,
       coalesce(e.runtime_id, '') AS runtime_id,
       e.entity_type AS entity_type,
       coalesce(e.label, e.urn) AS label,
       coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY e.entity_type, e.label, e.urn`

const grcPolicyLifecycleRelationsQuery = `MATCH (left:Entity)-[r:RELATION]->(right:Entity)
WHERE ($tenant_id = '' OR left.tenant_id = $tenant_id)
  AND ($tenant_id = '' OR right.tenant_id = $tenant_id)
  AND (
    $source_id = '' OR
    (left.entity_type IN $entity_types AND left.source_id = $source_id) OR
    (right.entity_type IN $entity_types AND right.source_id = $source_id)
  )
  AND (
    $runtime_id = '' OR
    (left.entity_type IN $entity_types AND coalesce(left.runtime_id, '') = $runtime_id) OR
    (right.entity_type IN $entity_types AND coalesce(right.runtime_id, '') = $runtime_id)
  )
  AND (left.entity_type IN $entity_types OR right.entity_type IN $entity_types)
RETURN left.urn AS left_urn,
       left.tenant_id AS left_tenant_id,
       left.source_id AS left_source_id,
       coalesce(left.runtime_id, '') AS left_runtime_id,
       left.entity_type AS left_entity_type,
       coalesce(left.label, left.urn) AS left_label,
       coalesce(left.attributes_json, '{}') AS left_attributes_json,
       r.relation AS relation,
       coalesce(r.attributes_json, '{}') AS relation_attributes_json,
       right.urn AS right_urn,
       right.tenant_id AS right_tenant_id,
       right.source_id AS right_source_id,
       coalesce(right.runtime_id, '') AS right_runtime_id,
       right.entity_type AS right_entity_type,
       coalesce(right.label, right.urn) AS right_label,
       coalesce(right.attributes_json, '{}') AS right_attributes_json
ORDER BY left.urn, r.relation, right.urn
LIMIT $limit`

type Response struct {
	Summary     grcPolicyLifecycleSummary   `json:"summary"`
	Templates   []grcPolicyTemplateItem     `json:"templates"`
	Policies    []grcPolicyLifecyclePolicy  `json:"policies"`
	WorkQueue   []grcPolicyLifecycleWork    `json:"work_queue"`
	Reminders   []grcPolicyReminderItem     `json:"reminders"`
	Mappings    []grcPolicyLifecycleMapping `json:"mappings"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type grcPolicyLifecycleSummary struct {
	Policies               int `json:"policies"`
	Templates              int `json:"templates"`
	DraftVersions          int `json:"draft_versions"`
	PendingApprovals       int `json:"pending_approvals"`
	OverdueReviews         int `json:"overdue_reviews"`
	OpenExceptions         int `json:"open_exceptions"`
	ExpiringExceptions     int `json:"expiring_exceptions"`
	AttestationCoveragePct int `json:"attestation_coverage_pct"`
	OverdueAttestations    int `json:"overdue_attestations"`
	MappedControls         int `json:"mapped_controls"`
	EvidenceItems          int `json:"evidence_items"`
}

type grcPolicyTemplateItem struct {
	ID         string                 `json:"id"`
	URN        string                 `json:"urn"`
	Title      string                 `json:"title"`
	Status     string                 `json:"status,omitempty"`
	Category   string                 `json:"category,omitempty"`
	Frameworks []string               `json:"frameworks,omitempty"`
	Owner      string                 `json:"owner,omitempty"`
	Controls   []grcPolicyControlRef  `json:"controls,omitempty"`
	Evidence   []grcPolicyEvidenceRef `json:"evidence,omitempty"`
	Attributes map[string]string      `json:"attributes,omitempty"`
}

type grcPolicyLifecyclePolicy struct {
	ID                string                     `json:"id"`
	URN               string                     `json:"urn"`
	Title             string                     `json:"title"`
	Status            string                     `json:"status,omitempty"`
	Owner             string                     `json:"owner,omitempty"`
	Reviewer          string                     `json:"reviewer,omitempty"`
	ReviewCadence     string                     `json:"review_cadence,omitempty"`
	NextReviewDueAt   string                     `json:"next_review_due_at,omitempty"`
	LatestVersion     string                     `json:"latest_version,omitempty"`
	VersionStatus     string                     `json:"version_status,omitempty"`
	ApprovalStatus    string                     `json:"approval_status,omitempty"`
	AcceptanceSummary grcPolicyAcceptanceSummary `json:"acceptance_summary"`
	ExceptionSummary  grcPolicyExceptionSummary  `json:"exception_summary"`
	Versions          []grcPolicyVersionItem     `json:"versions,omitempty"`
	Approvals         []grcPolicyApprovalItem    `json:"approvals,omitempty"`
	Attestations      []grcPolicyAcceptanceItem  `json:"attestations,omitempty"`
	Reviews           []grcPolicyReviewItem      `json:"reviews,omitempty"`
	Exceptions        []grcPolicyExceptionItem   `json:"exceptions,omitempty"`
	Assignments       []grcPolicyAssignmentItem  `json:"assignments,omitempty"`
	Controls          []grcPolicyControlRef      `json:"controls,omitempty"`
	Evidence          []grcPolicyEvidenceRef     `json:"evidence,omitempty"`
	Attributes        map[string]string          `json:"attributes,omitempty"`
}

type grcPolicyVersionItem struct {
	ID            string                    `json:"id"`
	URN           string                    `json:"urn"`
	PolicyID      string                    `json:"policy_id,omitempty"`
	Title         string                    `json:"title"`
	Version       string                    `json:"version,omitempty"`
	Status        string                    `json:"status,omitempty"`
	Author        string                    `json:"author,omitempty"`
	Owner         string                    `json:"owner,omitempty"`
	CreatedAt     string                    `json:"created_at,omitempty"`
	ApprovedAt    string                    `json:"approved_at,omitempty"`
	EffectiveAt   string                    `json:"effective_at,omitempty"`
	ChangeSummary string                    `json:"change_summary,omitempty"`
	DiffSummary   string                    `json:"diff_summary,omitempty"`
	DiffURL       string                    `json:"diff_url,omitempty"`
	Controls      []grcPolicyControlRef     `json:"controls,omitempty"`
	Evidence      []grcPolicyEvidenceRef    `json:"evidence,omitempty"`
	Assignments   []grcPolicyAssignmentItem `json:"assignments,omitempty"`
}

type grcPolicyApprovalItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Step        string   `json:"step,omitempty"`
	Status      string   `json:"status,omitempty"`
	Approvers   []string `json:"approvers,omitempty"`
	RequestedBy string   `json:"requested_by,omitempty"`
	RequestedAt string   `json:"requested_at,omitempty"`
	ApprovedAt  string   `json:"approved_at,omitempty"`
	DueAt       string   `json:"due_at,omitempty"`
}

type grcPolicyAcceptanceItem struct {
	ID         string   `json:"id"`
	URN        string   `json:"urn"`
	PolicyID   string   `json:"policy_id,omitempty"`
	VersionID  string   `json:"policy_version_id,omitempty"`
	Person     string   `json:"person,omitempty"`
	Assignees  []string `json:"assignees,omitempty"`
	Status     string   `json:"status,omitempty"`
	AcceptedAt string   `json:"accepted_at,omitempty"`
	DueAt      string   `json:"due_at,omitempty"`
}

type grcPolicyReviewItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Cadence     string   `json:"cadence,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Reviewers   []string `json:"reviewers,omitempty"`
	ReviewDueAt string   `json:"review_due_at,omitempty"`
	ReviewedAt  string   `json:"reviewed_at,omitempty"`
}

type grcPolicyExceptionItem struct {
	ID         string                `json:"id"`
	URN        string                `json:"urn"`
	PolicyID   string                `json:"policy_id,omitempty"`
	VersionID  string                `json:"policy_version_id,omitempty"`
	Title      string                `json:"title"`
	Status     string                `json:"status,omitempty"`
	Owner      string                `json:"owner,omitempty"`
	Approvers  []string              `json:"approvers,omitempty"`
	Targets    []grcPolicyTargetRef  `json:"targets,omitempty"`
	Controls   []grcPolicyControlRef `json:"controls,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	ApprovedAt string                `json:"approved_at,omitempty"`
	ExpiresAt  string                `json:"expires_at,omitempty"`
}

type grcPolicyReminderItem struct {
	ID          string   `json:"id"`
	URN         string   `json:"urn"`
	PolicyID    string   `json:"policy_id,omitempty"`
	VersionID   string   `json:"policy_version_id,omitempty"`
	Title       string   `json:"title"`
	Status      string   `json:"status,omitempty"`
	Channel     string   `json:"channel,omitempty"`
	Recipients  []string `json:"recipients,omitempty"`
	EscalatedTo []string `json:"escalated_to,omitempty"`
	DueAt       string   `json:"due_at,omitempty"`
	SentAt      string   `json:"sent_at,omitempty"`
}

type grcPolicyLifecycleMapping struct {
	PolicyID    string                 `json:"policy_id,omitempty"`
	PolicyTitle string                 `json:"policy_title,omitempty"`
	SourceURN   string                 `json:"source_urn"`
	SourceType  string                 `json:"source_type"`
	Target      grcPolicyTargetRef     `json:"target"`
	Controls    []grcPolicyControlRef  `json:"controls,omitempty"`
	Evidence    []grcPolicyEvidenceRef `json:"evidence,omitempty"`
}

type grcPolicyLifecycleWork struct {
	ID        string `json:"id"`
	PolicyID  string `json:"policy_id,omitempty"`
	Policy    string `json:"policy,omitempty"`
	RecordURN string `json:"record_urn"`
	Type      string `json:"type"`
	Status    string `json:"status,omitempty"`
	Owner     string `json:"owner,omitempty"`
	DueAt     string `json:"due_at,omitempty"`
	Action    string `json:"action"`
}

type grcPolicyAcceptanceSummary struct {
	Accepted int `json:"accepted"`
	Overdue  int `json:"overdue"`
	Pending  int `json:"pending"`
	Total    int `json:"total"`
}

type grcPolicyExceptionSummary struct {
	Active   int `json:"active"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
}

type grcPolicyAssignmentItem struct {
	TargetURN  string `json:"target_urn"`
	TargetType string `json:"target_type,omitempty"`
	Label      string `json:"label"`
	Scope      string `json:"scope,omitempty"`
}

type grcPolicyControlRef struct {
	URN       string `json:"urn"`
	ControlID string `json:"control_id,omitempty"`
	Framework string `json:"framework,omitempty"`
	Title     string `json:"title,omitempty"`
}

type grcPolicyEvidenceRef struct {
	URN          string `json:"urn"`
	EntityType   string `json:"entity_type,omitempty"`
	Title        string `json:"title,omitempty"`
	DocumentID   string `json:"document_id,omitempty"`
	EvidenceType string `json:"evidence_type,omitempty"`
}

type grcPolicyTargetRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type,omitempty"`
	Label      string `json:"label"`
}

type grcPolicyGraphNode struct {
	URN        string
	TenantID   string
	SourceID   string
	RuntimeID  string
	EntityType string
	Label      string
	Attrs      map[string]string
}

type grcPolicyGraphRelation struct {
	From     *grcPolicyGraphNode
	To       *grcPolicyGraphNode
	Relation string
	Attrs    map[string]string
}

func Build(ctx context.Context, store ports.GraphQueryStore, scope Scope) (Response, error) {
	limit := int(scope.Limit)
	if limit <= 0 {
		limit = grcPolicyLifecycleDefaultLimit
	}
	entityTypeLimit := grcPolicyLifecycleEntityTypeLimit(limit)
	entityRowLimit := grcPolicyLifecycleEntityRowLimit(entityTypeLimit)
	entityRows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: grcPolicyLifecycleEntitiesQuery,
		Params: map[string]any{
			"tenant_id":    scope.TenantID,
			"source_id":    scope.SourceID,
			"runtime_id":   scope.RuntimeID,
			"entity_types": grcPolicyLifecycleEntityTypes,
			"type_limit":   entityTypeLimit,
		},
		RowLimit: entityRowLimit,
	})
	if err != nil {
		return Response{}, err
	}
	relationLimit := limit * 20
	if relationLimit < grcPolicyLifecycleDefaultRelationLimit {
		relationLimit = grcPolicyLifecycleDefaultRelationLimit
	}
	if relationLimit > ports.MaxCypherQueryRows {
		relationLimit = ports.MaxCypherQueryRows
	}
	relationRows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: grcPolicyLifecycleRelationsQuery,
		Params: map[string]any{
			"tenant_id":    scope.TenantID,
			"source_id":    scope.SourceID,
			"runtime_id":   scope.RuntimeID,
			"entity_types": grcPolicyLifecycleEntityTypes,
			"limit":        relationLimit,
		},
		RowLimit: relationLimit,
	})
	if err != nil {
		return Response{}, err
	}
	return grcPolicyLifecycleFromGraph(entityRows, relationRows, time.Now().UTC()), nil
}

func grcPolicyLifecycleEntityTypeLimit(limit int) int {
	if limit <= 0 {
		limit = grcPolicyLifecycleDefaultLimit
	}
	maxPerType := ports.MaxCypherQueryRows / len(grcPolicyLifecycleEntityTypes)
	if maxPerType > 0 && limit > maxPerType {
		return maxPerType
	}
	return limit
}

func grcPolicyLifecycleEntityRowLimit(typeLimit int) int {
	if typeLimit <= 0 {
		typeLimit = grcPolicyLifecycleDefaultLimit
	}
	rowLimit := typeLimit * len(grcPolicyLifecycleEntityTypes)
	if rowLimit > ports.MaxCypherQueryRows {
		return ports.MaxCypherQueryRows
	}
	return rowLimit
}

func grcPolicyLifecycleFromGraph(entityRows []ports.CypherRow, relationRows []ports.CypherRow, generatedAt time.Time) Response {
	nodes := map[string]*grcPolicyGraphNode{}
	entityNodeURNs := map[string]struct{}{}
	for _, row := range entityRows {
		node := grcPolicyNodeFromRow(row, "")
		if node != nil {
			nodes[node.URN] = node
			entityNodeURNs[node.URN] = struct{}{}
		}
	}
	relations := make([]grcPolicyGraphRelation, 0, len(relationRows))
	for _, row := range relationRows {
		from := grcPolicyNodeFromRow(row, "left_")
		to := grcPolicyNodeFromRow(row, "right_")
		if from == nil || to == nil {
			continue
		}
		nodes[from.URN] = from
		nodes[to.URN] = to
		relations = append(relations, grcPolicyGraphRelation{
			From:     from,
			To:       to,
			Relation: grcPolicyRowString(row, "relation"),
			Attrs:    grcPolicyAttrs(grcPolicyRowString(row, "relation_attributes_json")),
		})
	}

	policyBuilders := map[string]*grcPolicyLifecyclePolicy{}
	policyURNToID := map[string]string{}
	for _, node := range nodes {
		if _, ok := entityNodeURNs[node.URN]; !ok {
			continue
		}
		if !grcPolicyIsPolicyNode(node) {
			continue
		}
		item := grcPolicyLifecyclePolicy{
			ID:              grcPolicyPolicyID(node),
			URN:             node.URN,
			Title:           grcPolicyNodeTitle(node),
			Status:          grcPolicyAttr(node, "status", "policy_status", "lifecycle_state"),
			Owner:           grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
			Reviewer:        firstNonEmptyWith(grcPolicyAttr(node, "reviewer", "reviewer_user_id"), grcPolicyActionActors(node.URN, relations, "reviewed")),
			ReviewCadence:   grcPolicyAttr(node, "review_cadence", "cadence"),
			NextReviewDueAt: grcPolicyAttr(node, "next_review_due_at", "review_due_at", "due_at"),
			Controls:        grcPolicyControlsFor(node.URN, relations),
			Evidence:        grcPolicyEvidenceFor(node.URN, relations),
			Assignments:     grcPolicyAssignmentsFor(node.URN, relations),
			Attributes:      grcPolicyPublicAttrs(node.Attrs),
		}
		if item.ID == "" {
			item.ID = node.URN
		}
		policyBuilders[item.ID] = &item
		policyURNToID[node.URN] = item.ID
	}
	ensurePolicy := func(policyID string, label string) *grcPolicyLifecyclePolicy {
		policyID = strings.TrimSpace(policyID)
		if policyID == "" {
			policyID = strings.TrimSpace(label)
		}
		if policyID == "" {
			policyID = "unmapped"
		}
		if item, ok := policyBuilders[policyID]; ok {
			return item
		}
		item := &grcPolicyLifecyclePolicy{ID: policyID, Title: firstNonEmpty(label, policyID)}
		policyBuilders[policyID] = item
		return item
	}

	templates := []grcPolicyTemplateItem{}
	reminders := []grcPolicyReminderItem{}
	mappings := []grcPolicyLifecycleMapping{}
	for _, node := range nodes {
		if _, ok := entityNodeURNs[node.URN]; !ok {
			continue
		}
		switch node.EntityType {
		case "policy.template":
			templates = append(templates, grcPolicyTemplateFromNode(node, relations))
			mappings = append(mappings, grcPolicyMappingForNode(node, "", "", relations)...)
		case "policy.version":
			item := grcPolicyVersionFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Versions = append(policy.Versions, item)
			policy.Assignments = appendPolicyAssignments(policy.Assignments, item.Assignments)
			policy.Controls = appendPolicyControls(policy.Controls, item.Controls)
			policy.Evidence = appendPolicyEvidence(policy.Evidence, item.Evidence)
			mappings = append(mappings, grcPolicyMappingForNode(node, policy.ID, policy.Title, relations)...)
		case "policy.approval":
			item := grcPolicyApprovalFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Approvals = append(policy.Approvals, item)
		case "policy.acceptance":
			item := grcPolicyAcceptanceFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Attestations = append(policy.Attestations, item)
			policy.Assignments = appendPolicyAssignments(policy.Assignments, grcPolicyAssignmentsFor(node.URN, relations))
		case "policy.review":
			item := grcPolicyReviewFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Reviews = append(policy.Reviews, item)
		case "policy.exception":
			item := grcPolicyExceptionFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			policy.Exceptions = append(policy.Exceptions, item)
			policy.Controls = appendPolicyControls(policy.Controls, item.Controls)
			mappings = append(mappings, grcPolicyMappingForNode(node, policy.ID, policy.Title, relations)...)
		case "policy.reminder":
			item := grcPolicyReminderFromNode(node, relations)
			policy := ensurePolicy(firstNonEmpty(item.PolicyID, grcPolicyPolicyIDFromRelations(node.URN, relations, policyURNToID)), grcPolicyAttr(node, "policy_name"))
			item.PolicyID = policy.ID
			reminders = append(reminders, item)
		}
	}

	policies := make([]grcPolicyLifecyclePolicy, 0, len(policyBuilders))
	for _, policy := range policyBuilders {
		grcPolicyFinalize(policy, generatedAt)
		policies = append(policies, *policy)
	}
	sort.Slice(policies, func(i, j int) bool {
		return strings.ToLower(policies[i].Title) < strings.ToLower(policies[j].Title)
	})
	sort.Slice(templates, func(i, j int) bool {
		return strings.ToLower(templates[i].Title) < strings.ToLower(templates[j].Title)
	})
	sort.Slice(reminders, func(i, j int) bool {
		return grcPolicySortDate(reminders[i].DueAt, reminders[i].SentAt).Before(grcPolicySortDate(reminders[j].DueAt, reminders[j].SentAt))
	})
	return Response{
		Summary:     grcPolicyLifecycleSummaryFrom(policies, templates, mappings, generatedAt),
		Templates:   templates,
		Policies:    policies,
		WorkQueue:   grcPolicyLifecycleWorkQueue(policies, generatedAt),
		Reminders:   reminders,
		Mappings:    grcPolicyDeduplicateMappings(mappings),
		GeneratedAt: generatedAt,
	}
}

func grcPolicyNodeFromRow(row ports.CypherRow, prefix string) *grcPolicyGraphNode {
	urn := grcPolicyRowString(row, prefix+"urn")
	if urn == "" {
		return nil
	}
	return &grcPolicyGraphNode{
		URN:        urn,
		TenantID:   grcPolicyRowString(row, prefix+"tenant_id"),
		SourceID:   grcPolicyRowString(row, prefix+"source_id"),
		RuntimeID:  grcPolicyRowString(row, prefix+"runtime_id"),
		EntityType: grcPolicyRowString(row, prefix+"entity_type"),
		Label:      grcPolicyRowString(row, prefix+"label"),
		Attrs:      grcPolicyAttrs(grcPolicyRowString(row, prefix+"attributes_json")),
	}
}

func grcPolicyTemplateFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyTemplateItem {
	return grcPolicyTemplateItem{
		ID:         grcPolicyNodeID(node, "template_id", "policy_template_id"),
		URN:        node.URN,
		Title:      grcPolicyNodeTitle(node),
		Status:     grcPolicyAttr(node, "status", "template_status", "lifecycle_state"),
		Category:   grcPolicyAttr(node, "category", "policy_category"),
		Frameworks: grcPolicyListAttr(node, "frameworks", "framework"),
		Owner:      grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Controls:   grcPolicyControlsFor(node.URN, relations),
		Evidence:   grcPolicyEvidenceFor(node.URN, relations),
		Attributes: grcPolicyPublicAttrs(node.Attrs),
	}
}

func grcPolicyVersionFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyVersionItem {
	return grcPolicyVersionItem{
		ID:            grcPolicyNodeID(node, "policy_version_id", "version_id"),
		URN:           node.URN,
		PolicyID:      grcPolicyAttr(node, "policy_id"),
		Title:         grcPolicyNodeTitle(node),
		Version:       grcPolicyAttr(node, "version", "version_number"),
		Status:        grcPolicyAttr(node, "status", "policy_status", "lifecycle_state"),
		Author:        firstNonEmpty(grcPolicyActionActors(node.URN, relations, "authored")...),
		Owner:         grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		CreatedAt:     grcPolicyAttr(node, "created_at"),
		ApprovedAt:    grcPolicyAttr(node, "approved_at"),
		EffectiveAt:   grcPolicyAttr(node, "effective_at"),
		ChangeSummary: grcPolicyAttr(node, "change_summary", "summary"),
		DiffSummary:   grcPolicyAttr(node, "diff_summary", "diff"),
		DiffURL:       grcPolicyAttr(node, "diff_url", "compare_url"),
		Controls:      grcPolicyControlsFor(node.URN, relations),
		Evidence:      grcPolicyEvidenceFor(node.URN, relations),
		Assignments:   grcPolicyAssignmentsFor(node.URN, relations),
	}
}

func grcPolicyApprovalFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyApprovalItem {
	approvers := append([]string{}, grcPolicyActionActors(node.URN, relations, "approved")...)
	approvers = append(approvers, grcPolicyActionActors(node.URN, relations, "rejected")...)
	return grcPolicyApprovalItem{
		ID:          grcPolicyNodeID(node, "approval_id", "policy_approval_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Step:        grcPolicyAttr(node, "approval_step", "step"),
		Status:      grcPolicyAttr(node, "status", "approval_status"),
		Approvers:   uniqueStrings(append(approvers, grcPolicyListAttr(node, "approver_user_id", "approver_user_ids", "approved_by_user_id")...)),
		RequestedBy: firstNonEmpty(grcPolicyActionActors(node.URN, relations, "requested_approval")...),
		RequestedAt: grcPolicyAttr(node, "requested_at"),
		ApprovedAt:  grcPolicyAttr(node, "approved_at", "reviewed_at"),
		DueAt:       grcPolicyAttr(node, "due_at", "approval_due_at"),
	}
}

func grcPolicyAcceptanceFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyAcceptanceItem {
	return grcPolicyAcceptanceItem{
		ID:         grcPolicyNodeID(node, "acceptance_id", "policy_acceptance_id", "attestation_id"),
		URN:        node.URN,
		PolicyID:   grcPolicyAttr(node, "policy_id"),
		VersionID:  grcPolicyAttr(node, "policy_version_id", "version_id"),
		Person:     firstNonEmpty(grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationHasEvidence, false), grcPolicyAttr(node, "person_name", "email", "person_id", "user_id")),
		Assignees:  grcPolicyAssignmentLabelsFor(node.URN, relations),
		Status:     grcPolicyAttr(node, "status", "acceptance_status"),
		AcceptedAt: grcPolicyAttr(node, "accepted_at", "completed_at"),
		DueAt:      grcPolicyAttr(node, "due_at", "acceptance_due_at"),
	}
}

func grcPolicyReviewFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyReviewItem {
	return grcPolicyReviewItem{
		ID:          grcPolicyNodeID(node, "review_id", "policy_review_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Status:      grcPolicyAttr(node, "status", "review_status"),
		Cadence:     grcPolicyAttr(node, "review_cadence", "cadence"),
		Owner:       grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Reviewers:   uniqueStrings(append(grcPolicyActionActors(node.URN, relations, "reviewed"), grcPolicyListAttr(node, "reviewer_user_id", "reviewer_user_ids", "reviewed_by_user_id")...)),
		ReviewDueAt: grcPolicyAttr(node, "review_due_at", "due_at"),
		ReviewedAt:  grcPolicyAttr(node, "reviewed_at", "completed_at"),
	}
}

func grcPolicyExceptionFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyExceptionItem {
	return grcPolicyExceptionItem{
		ID:         grcPolicyNodeID(node, "exception_id", "waiver_id", "policy_exception_id"),
		URN:        node.URN,
		PolicyID:   grcPolicyAttr(node, "policy_id"),
		VersionID:  grcPolicyAttr(node, "policy_version_id", "version_id"),
		Title:      grcPolicyNodeTitle(node),
		Status:     grcPolicyAttr(node, "status", "exception_status", "waiver_status"),
		Owner:      grcPolicyRelatedLabel(node.URN, relations, fabriccontract.RelationOwnedBy, true),
		Approvers:  uniqueStrings(append(grcPolicyActionActors(node.URN, relations, "approved_exception"), grcPolicyListAttr(node, "approver_user_id", "approved_by_user_id")...)),
		Targets:    grcPolicyTargetsFor(node.URN, relations),
		Controls:   grcPolicyControlsFor(node.URN, relations),
		Reason:     grcPolicyAttr(node, "reason", "justification", "summary"),
		ApprovedAt: grcPolicyAttr(node, "approved_at"),
		ExpiresAt:  grcPolicyAttr(node, "expires_at", "expiration_at"),
	}
}

func grcPolicyReminderFromNode(node *grcPolicyGraphNode, relations []grcPolicyGraphRelation) grcPolicyReminderItem {
	return grcPolicyReminderItem{
		ID:          grcPolicyNodeID(node, "reminder_id", "policy_reminder_id", "escalation_id"),
		URN:         node.URN,
		PolicyID:    grcPolicyAttr(node, "policy_id"),
		VersionID:   grcPolicyAttr(node, "policy_version_id", "version_id"),
		Title:       grcPolicyNodeTitle(node),
		Status:      grcPolicyAttr(node, "status", "reminder_status", "escalation_status"),
		Channel:     grcPolicyAttr(node, "channel", "delivery_channel"),
		Recipients:  grcPolicyAssignmentLabelsFor(node.URN, relations),
		EscalatedTo: grcPolicyActionActors(node.URN, relations, "escalated"),
		DueAt:       grcPolicyAttr(node, "due_at", "scheduled_at"),
		SentAt:      grcPolicyAttr(node, "sent_at"),
	}
}

func grcPolicyFinalize(policy *grcPolicyLifecyclePolicy, now time.Time) {
	sort.Slice(policy.Versions, func(i, j int) bool {
		iDate, iOK := grcPolicyFirstDate(policy.Versions[i].ApprovedAt, policy.Versions[i].CreatedAt, policy.Versions[i].EffectiveAt)
		jDate, jOK := grcPolicyFirstDate(policy.Versions[j].ApprovedAt, policy.Versions[j].CreatedAt, policy.Versions[j].EffectiveAt)
		if iOK != jOK {
			return iOK
		}
		if iDate.Equal(jDate) {
			return firstNonEmpty(policy.Versions[i].URN, policy.Versions[i].ID) < firstNonEmpty(policy.Versions[j].URN, policy.Versions[j].ID)
		}
		return iDate.After(jDate)
	})
	sort.Slice(policy.Approvals, func(i, j int) bool {
		return grcPolicySortDate(policy.Approvals[i].DueAt, policy.Approvals[i].RequestedAt).Before(grcPolicySortDate(policy.Approvals[j].DueAt, policy.Approvals[j].RequestedAt))
	})
	sort.Slice(policy.Attestations, func(i, j int) bool {
		return grcPolicySortDate(policy.Attestations[i].DueAt, policy.Attestations[i].AcceptedAt).Before(grcPolicySortDate(policy.Attestations[j].DueAt, policy.Attestations[j].AcceptedAt))
	})
	sort.Slice(policy.Reviews, func(i, j int) bool {
		return grcPolicySortDate(policy.Reviews[i].ReviewDueAt, policy.Reviews[i].ReviewedAt).Before(grcPolicySortDate(policy.Reviews[j].ReviewDueAt, policy.Reviews[j].ReviewedAt))
	})
	for _, review := range policy.Reviews {
		if policy.Reviewer == "" {
			policy.Reviewer = firstNonEmpty(review.Reviewers...)
		}
		if policy.ReviewCadence == "" {
			policy.ReviewCadence = review.Cadence
		}
		if policy.NextReviewDueAt == "" {
			policy.NextReviewDueAt = review.ReviewDueAt
		}
		if policy.Reviewer != "" && policy.ReviewCadence != "" && policy.NextReviewDueAt != "" {
			break
		}
	}
	sort.Slice(policy.Exceptions, func(i, j int) bool {
		return grcPolicySortDate(policy.Exceptions[i].ExpiresAt, policy.Exceptions[i].ApprovedAt).Before(grcPolicySortDate(policy.Exceptions[j].ExpiresAt, policy.Exceptions[j].ApprovedAt))
	})
	if len(policy.Versions) > 0 {
		policy.LatestVersion = firstNonEmpty(policy.Versions[0].Version, policy.Versions[0].ID)
		policy.VersionStatus = policy.Versions[0].Status
		if policy.Owner == "" {
			policy.Owner = policy.Versions[0].Owner
		}
	}
	for _, approval := range policy.Approvals {
		if grcPolicyPendingStatus(approval.Status) {
			policy.ApprovalStatus = approval.Status
			break
		}
	}
	if policy.ApprovalStatus == "" && len(policy.Approvals) > 0 {
		policy.ApprovalStatus = policy.Approvals[0].Status
	}
	policy.AcceptanceSummary = grcPolicyAcceptanceRollup(policy.Attestations, now)
	policy.ExceptionSummary = grcPolicyExceptionRollup(policy.Exceptions, now)
	policy.Assignments = uniqueAssignments(policy.Assignments)
	policy.Controls = uniqueControls(policy.Controls)
	policy.Evidence = uniqueEvidence(policy.Evidence)
}

func grcPolicyLifecycleSummaryFrom(policies []grcPolicyLifecyclePolicy, templates []grcPolicyTemplateItem, mappings []grcPolicyLifecycleMapping, now time.Time) grcPolicyLifecycleSummary {
	summary := grcPolicyLifecycleSummary{Policies: len(policies), Templates: len(templates)}
	accepted := 0
	totalAttestations := 0
	mappedControls := map[string]struct{}{}
	evidence := map[string]struct{}{}
	for _, template := range templates {
		for _, control := range template.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range template.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	for _, mapping := range mappings {
		for _, control := range mapping.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range mapping.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	for _, policy := range policies {
		for _, version := range policy.Versions {
			if grcPolicyDraftStatus(version.Status) {
				summary.DraftVersions++
			}
		}
		for _, approval := range policy.Approvals {
			if grcPolicyPendingStatus(approval.Status) {
				summary.PendingApprovals++
			}
		}
		for _, review := range policy.Reviews {
			if grcPolicyOverdue(review.ReviewDueAt, review.Status, now) {
				summary.OverdueReviews++
			}
		}
		summary.OpenExceptions += policy.ExceptionSummary.Active
		summary.ExpiringExceptions += policy.ExceptionSummary.Expiring
		summary.OverdueAttestations += policy.AcceptanceSummary.Overdue
		accepted += policy.AcceptanceSummary.Accepted
		totalAttestations += policy.AcceptanceSummary.Total
		for _, control := range policy.Controls {
			if control.ControlID != "" {
				mappedControls[control.ControlID] = struct{}{}
			}
		}
		for _, item := range policy.Evidence {
			if item.URN != "" {
				evidence[item.URN] = struct{}{}
			}
		}
	}
	if totalAttestations > 0 {
		summary.AttestationCoveragePct = int(float64(accepted) / float64(totalAttestations) * 100)
	}
	summary.MappedControls = len(mappedControls)
	summary.EvidenceItems = len(evidence)
	return summary
}

func grcPolicyLifecycleWorkQueue(policies []grcPolicyLifecyclePolicy, now time.Time) []grcPolicyLifecycleWork {
	items := []grcPolicyLifecycleWork{}
	for _, policy := range policies {
		for _, version := range policy.Versions {
			if grcPolicyDraftStatus(version.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: version.URN + ":draft", PolicyID: policy.ID, Policy: policy.Title, RecordURN: version.URN, Type: "version", Status: version.Status, Owner: firstNonEmpty(version.Owner, policy.Owner), DueAt: firstNonEmpty(version.EffectiveAt, version.CreatedAt), Action: "Review draft"})
			}
		}
		for _, approval := range policy.Approvals {
			if grcPolicyPendingStatus(approval.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: approval.URN + ":approval", PolicyID: policy.ID, Policy: policy.Title, RecordURN: approval.URN, Type: "approval", Status: approval.Status, Owner: firstNonEmpty(approval.RequestedBy, firstNonEmpty(approval.Approvers...)), DueAt: approval.DueAt, Action: "Approve version"})
			}
		}
		for _, review := range policy.Reviews {
			if grcPolicyOverdue(review.ReviewDueAt, review.Status, now) || grcPolicyPendingStatus(review.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: review.URN + ":review", PolicyID: policy.ID, Policy: policy.Title, RecordURN: review.URN, Type: "review", Status: review.Status, Owner: firstNonEmpty(review.Owner, firstNonEmpty(review.Reviewers...), policy.Owner), DueAt: review.ReviewDueAt, Action: "Complete owner review"})
			}
		}
		for _, attestation := range policy.Attestations {
			if grcPolicyAcceptanceOpenStatus(attestation.Status) {
				items = append(items, grcPolicyLifecycleWork{ID: attestation.URN + ":attestation", PolicyID: policy.ID, Policy: policy.Title, RecordURN: attestation.URN, Type: "attestation", Status: attestation.Status, Owner: firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)), DueAt: attestation.DueAt, Action: "Send reminder"})
			}
		}
		for _, exception := range policy.Exceptions {
			if grcPolicyExceptionOpen(exception.Status) {
				action := "Review exception"
				if grcPolicyExpiring(exception.ExpiresAt, now) {
					action = "Renew or close exception"
				}
				items = append(items, grcPolicyLifecycleWork{ID: exception.URN + ":exception", PolicyID: policy.ID, Policy: policy.Title, RecordURN: exception.URN, Type: "exception", Status: exception.Status, Owner: firstNonEmpty(exception.Owner, firstNonEmpty(exception.Approvers...)), DueAt: exception.ExpiresAt, Action: action})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left := grcPolicySortDate(items[i].DueAt)
		right := grcPolicySortDate(items[j].DueAt)
		if left.Equal(right) {
			return items[i].RecordURN < items[j].RecordURN
		}
		return left.Before(right)
	})
	return items
}

func grcPolicyAcceptanceRollup(items []grcPolicyAcceptanceItem, now time.Time) grcPolicyAcceptanceSummary {
	var summary grcPolicyAcceptanceSummary
	for _, item := range items {
		if grcPolicyClosedStatus(item.Status) {
			continue
		}
		status := strings.TrimSpace(item.Status)
		if grcPolicyAcceptedStatus(item.Status) || (status == "" && item.AcceptedAt != "") {
			summary.Total++
			summary.Accepted++
			continue
		}
		if !grcPolicyAcceptanceOpenStatus(item.Status) {
			continue
		}
		summary.Total++
		if grcPolicyOverdue(item.DueAt, item.Status, now) {
			summary.Overdue++
		} else {
			summary.Pending++
		}
	}
	return summary
}

func grcPolicyExceptionRollup(items []grcPolicyExceptionItem, now time.Time) grcPolicyExceptionSummary {
	var summary grcPolicyExceptionSummary
	for _, item := range items {
		if strings.TrimSpace(item.Status) == "" {
			continue
		}
		if grcPolicyClosedStatus(item.Status) {
			if grcPolicyPast(item.ExpiresAt, now) {
				summary.Expired++
			}
			continue
		}
		if grcPolicyPast(item.ExpiresAt, now) {
			summary.Expired++
			continue
		}
		summary.Active++
		if grcPolicyExpiring(item.ExpiresAt, now) {
			summary.Expiring++
		}
	}
	return summary
}

func grcPolicyMappingForNode(node *grcPolicyGraphNode, policyID string, policyTitle string, relations []grcPolicyGraphRelation) []grcPolicyLifecycleMapping {
	controls := grcPolicyControlsFor(node.URN, relations)
	evidence := grcPolicyEvidenceFor(node.URN, relations)
	targets := grcPolicyTargetsFor(node.URN, relations)
	if len(targets) == 0 && (len(controls) > 0 || len(evidence) > 0) {
		targets = []grcPolicyTargetRef{{URN: node.URN, EntityType: node.EntityType, Label: grcPolicyNodeTitle(node)}}
	}
	mappings := make([]grcPolicyLifecycleMapping, 0, len(targets))
	for _, target := range targets {
		mappings = append(mappings, grcPolicyLifecycleMapping{
			PolicyID:    firstNonEmpty(policyID, grcPolicyAttr(node, "policy_id")),
			PolicyTitle: policyTitle,
			SourceURN:   node.URN,
			SourceType:  node.EntityType,
			Target:      target,
			Controls:    controls,
			Evidence:    evidence,
		})
	}
	return mappings
}

func grcPolicyPolicyIDFromRelations(urn string, relations []grcPolicyGraphRelation, policyURNToID map[string]string) string {
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn {
			continue
		}
		if relation.Relation != fabriccontract.RelationAssociatedWith && relation.Relation != fabriccontract.RelationBelongsTo {
			continue
		}
		if policyID := policyURNToID[relation.To.URN]; policyID != "" {
			return policyID
		}
		if relation.To.EntityType == "policy.version" {
			return grcPolicyAttr(relation.To, "policy_id")
		}
	}
	return ""
}

func grcPolicyControlsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyControlRef {
	controls := []grcPolicyControlRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn {
			continue
		}
		if relation.Relation != fabriccontract.RelationSupports && relation.Relation != fabriccontract.RelationAssociatedWith {
			continue
		}
		if !grcPolicyIsControlNode(relation.To) {
			continue
		}
		controls = append(controls, grcPolicyControlRef{
			URN:       relation.To.URN,
			ControlID: grcPolicyAttr(relation.To, "control_external_id", "control_id", "policy_id"),
			Framework: grcPolicyAttr(relation.To, "framework", "framework_name"),
			Title:     grcPolicyNodeTitle(relation.To),
		})
	}
	return uniqueControls(controls)
}

func grcPolicyEvidenceFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyEvidenceRef {
	evidence := []grcPolicyEvidenceRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationHasEvidence {
			continue
		}
		evidence = append(evidence, grcPolicyEvidenceRef{
			URN:          relation.To.URN,
			EntityType:   relation.To.EntityType,
			Title:        grcPolicyNodeTitle(relation.To),
			DocumentID:   grcPolicyAttr(relation.To, "document_id"),
			EvidenceType: grcPolicyAttr(relation.To, "evidence_type", "document_type"),
		})
	}
	return uniqueEvidence(evidence)
}

func grcPolicyAssignmentsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyAssignmentItem {
	items := []grcPolicyAssignmentItem{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationAssignedTo {
			continue
		}
		items = append(items, grcPolicyAssignmentItem{
			TargetURN:  relation.To.URN,
			TargetType: relation.To.EntityType,
			Label:      grcPolicyNodeTitle(relation.To),
			Scope:      grcPolicyAttrMap(relation.Attrs, "scope", "assignment_scope"),
		})
	}
	return uniqueAssignments(items)
}

func grcPolicyAssignmentLabelsFor(urn string, relations []grcPolicyGraphRelation) []string {
	assignments := grcPolicyAssignmentsFor(urn, relations)
	labels := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		labels = append(labels, assignment.Label)
	}
	return uniqueStrings(labels)
}

func grcPolicyTargetsFor(urn string, relations []grcPolicyGraphRelation) []grcPolicyTargetRef {
	targets := []grcPolicyTargetRef{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.From.URN != urn || relation.Relation != fabriccontract.RelationTargeted {
			continue
		}
		targets = append(targets, grcPolicyTargetRef{URN: relation.To.URN, EntityType: relation.To.EntityType, Label: grcPolicyNodeTitle(relation.To)})
	}
	return uniqueTargets(targets)
}

func grcPolicyActionActors(urn string, relations []grcPolicyGraphRelation, action string) []string {
	actors := []string{}
	for _, relation := range relations {
		if relation.From == nil || relation.To == nil || relation.To.URN != urn || relation.Relation != fabriccontract.RelationActedOn {
			continue
		}
		if action != "" && !strings.EqualFold(grcPolicyAttrMap(relation.Attrs, "action"), action) {
			continue
		}
		actors = append(actors, grcPolicyNodeTitle(relation.From))
	}
	return uniqueStrings(actors)
}

func grcPolicyRelatedLabel(urn string, relations []grcPolicyGraphRelation, relationName string, outgoing bool) string {
	for _, relation := range relations {
		if relation.Relation != relationName || relation.From == nil || relation.To == nil {
			continue
		}
		if outgoing && relation.From.URN == urn {
			return grcPolicyNodeTitle(relation.To)
		}
		if !outgoing && relation.To.URN == urn {
			return grcPolicyNodeTitle(relation.From)
		}
	}
	return ""
}

func grcPolicyIsPolicyNode(node *grcPolicyGraphNode) bool {
	if node == nil || node.EntityType != "policy" {
		return false
	}
	return strings.EqualFold(grcPolicyAttr(node, "policy_type"), "policy")
}

func grcPolicyIsControlNode(node *grcPolicyGraphNode) bool {
	if node == nil || node.EntityType != "policy" {
		return false
	}
	return strings.EqualFold(grcPolicyAttr(node, "policy_type"), "control")
}

func grcPolicyNodeID(node *grcPolicyGraphNode, keys ...string) string {
	if node == nil {
		return ""
	}
	if value := grcPolicyAttr(node, keys...); value != "" {
		return value
	}
	if node.URN == "" {
		return ""
	}
	parts := strings.Split(node.URN, ":")
	return strings.TrimSpace(parts[len(parts)-1])
}

func grcPolicyPolicyID(node *grcPolicyGraphNode) string {
	if value := grcPolicyAttr(node, "policy_id"); value != "" {
		return value
	}
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.URN)
}

func grcPolicyNodeTitle(node *grcPolicyGraphNode) string {
	if node == nil {
		return ""
	}
	return firstNonEmpty(grcPolicyAttr(node, "title", "name", "policy_name", "display_name"), node.Label, grcPolicyNodeID(node, "id"))
}

func grcPolicyAttr(node *grcPolicyGraphNode, keys ...string) string {
	if node == nil {
		return ""
	}
	return grcPolicyAttrMap(node.Attrs, keys...)
}

func grcPolicyAttrMap(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			return value
		}
	}
	return ""
}

func grcPolicyListAttr(node *grcPolicyGraphNode, keys ...string) []string {
	values := []string{}
	for _, key := range keys {
		values = append(values, strings.FieldsFunc(grcPolicyAttr(node, key), func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		})...)
	}
	return uniqueStrings(values)
}

func grcPolicyPublicAttrs(attrs map[string]string) map[string]string {
	allowed := map[string]string{}
	for _, key := range []string{"category", "framework", "frameworks", "review_cadence", "status", "source_system"} {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			allowed[key] = value
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func grcPolicyAttrs(raw string) map[string]string {
	attrs := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return attrs
	}
	values := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return attrs
	}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				attrs[key] = trimmed
			}
		case []any:
			parts := []string{}
			for _, item := range typed {
				if trimmed := strings.TrimSpace(fmt.Sprint(item)); trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
			if len(parts) > 0 {
				attrs[key] = strings.Join(parts, ",")
			}
		case bool, float64:
			attrs[key] = fmt.Sprint(typed)
		}
	}
	return attrs
}

func grcPolicyRowString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	value := row.Values[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func grcPolicyAcceptedStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "accepted" || normalized == "completed" || normalized == "acknowledged"
}

func grcPolicyClosedStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "closed" || normalized == "expired" || normalized == "rejected" || normalized == "retired"
}

func grcPolicyDraftStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "draft" || normalized == "changes_requested"
}

func grcPolicyPendingStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "pending" || normalized == "requested" || normalized == "in_review" || normalized == "due" || normalized == "overdue"
}

func grcPolicyAcceptanceOpenStatus(status string) bool {
	return strings.TrimSpace(status) != "" && !grcPolicyAcceptedStatus(status) && !grcPolicyClosedStatus(status)
}

func grcPolicyExceptionOpen(status string) bool {
	return strings.TrimSpace(status) != "" && !grcPolicyClosedStatus(status)
}

func grcPolicyOverdue(rawDueAt string, status string, now time.Time) bool {
	if strings.TrimSpace(status) == "" || grcPolicyAcceptedStatus(status) || grcPolicyClosedStatus(status) {
		return false
	}
	dueAt, ok := grcPolicyTime(rawDueAt)
	return ok && dueAt.Before(now)
}

func grcPolicyPast(raw string, now time.Time) bool {
	value, ok := grcPolicyTime(raw)
	return ok && value.Before(now)
}

func grcPolicyExpiring(raw string, now time.Time) bool {
	value, ok := grcPolicyTime(raw)
	return ok && value.After(now) && value.Sub(now) <= grcPolicyLifecycleExceptionWindow
}

func grcPolicySortDate(values ...string) time.Time {
	if value, ok := grcPolicyFirstDate(values...); ok {
		return value
	}
	return time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
}

func grcPolicyFirstDate(values ...string) (time.Time, bool) {
	for _, value := range values {
		if parsed, ok := grcPolicyTime(value); ok {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func grcPolicyTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func appendPolicyAssignments(left []grcPolicyAssignmentItem, right []grcPolicyAssignmentItem) []grcPolicyAssignmentItem {
	return uniqueAssignments(append(left, right...))
}

func appendPolicyControls(left []grcPolicyControlRef, right []grcPolicyControlRef) []grcPolicyControlRef {
	return uniqueControls(append(left, right...))
}

func appendPolicyEvidence(left []grcPolicyEvidenceRef, right []grcPolicyEvidenceRef) []grcPolicyEvidenceRef {
	return uniqueEvidence(append(left, right...))
}

func uniqueAssignments(items []grcPolicyAssignmentItem) []grcPolicyAssignmentItem {
	seen := map[string]struct{}{}
	out := []grcPolicyAssignmentItem{}
	for _, item := range items {
		key := item.TargetURN
		if key == "" {
			key = item.Label
		}
		if strings.TrimSpace(key) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueControls(items []grcPolicyControlRef) []grcPolicyControlRef {
	seen := map[string]struct{}{}
	out := []grcPolicyControlRef{}
	for _, item := range items {
		key := firstNonEmpty(item.ControlID, item.URN)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return firstNonEmpty(out[i].ControlID, out[i].Title) < firstNonEmpty(out[j].ControlID, out[j].Title)
	})
	return out
}

func uniqueEvidence(items []grcPolicyEvidenceRef) []grcPolicyEvidenceRef {
	seen := map[string]struct{}{}
	out := []grcPolicyEvidenceRef{}
	for _, item := range items {
		key := item.URN
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueTargets(items []grcPolicyTargetRef) []grcPolicyTargetRef {
	seen := map[string]struct{}{}
	out := []grcPolicyTargetRef{}
	for _, item := range items {
		key := item.URN
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func firstNonEmptyWith(value string, fallback []string) string {
	values := append([]string{value}, fallback...)
	return firstNonEmpty(values...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func grcPolicyDeduplicateMappings(items []grcPolicyLifecycleMapping) []grcPolicyLifecycleMapping {
	seen := map[string]struct{}{}
	out := []grcPolicyLifecycleMapping{}
	for _, item := range items {
		key := item.SourceURN + "|" + item.Target.URN
		if key == "|" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceURN < out[j].SourceURN
	})
	return out
}
