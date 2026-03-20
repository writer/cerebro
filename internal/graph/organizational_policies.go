package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OrganizationalPolicyWriteRequest records one organizational policy plus its
// required acknowledgement scope.
type OrganizationalPolicyWriteRequest struct {
	ID                    string         `json:"id,omitempty"`
	Title                 string         `json:"title"`
	Summary               string         `json:"summary,omitempty"`
	PolicyVersion         string         `json:"policy_version"`
	Content               string         `json:"content,omitempty"`
	ContentDigest         string         `json:"content_digest,omitempty"`
	OwnerID               string         `json:"owner_id,omitempty"`
	ReviewCycleDays       int            `json:"review_cycle_days,omitempty"`
	FrameworkMappings     []string       `json:"framework_mappings,omitempty"`
	RequiredDepartmentIDs []string       `json:"required_department_ids,omitempty"`
	RequiredPersonIDs     []string       `json:"required_person_ids,omitempty"`
	SourceSystem          string         `json:"source_system,omitempty"`
	SourceEventID         string         `json:"source_event_id,omitempty"`
	ObservedAt            time.Time      `json:"observed_at,omitempty"`
	ValidFrom             time.Time      `json:"valid_from,omitempty"`
	ValidTo               *time.Time     `json:"valid_to,omitempty"`
	RecordedAt            time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom       time.Time      `json:"transaction_from,omitempty"`
	TransactionTo         *time.Time     `json:"transaction_to,omitempty"`
	Confidence            float64        `json:"confidence,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyWriteResult summarizes one policy registry update.
type OrganizationalPolicyWriteResult struct {
	PolicyID              string   `json:"policy_id"`
	PolicyVersion         string   `json:"policy_version"`
	AssignedDepartments   int      `json:"assigned_departments"`
	AssignedPeople        int      `json:"assigned_people"`
	ChangedFields         []string `json:"changed_fields,omitempty"`
	VersionHistoryEntries int      `json:"version_history_entries"`
	SourceSystem          string   `json:"source_system"`
	SourceEventID         string   `json:"source_event_id"`
}

// OrganizationalPolicyVersionHistoryEntry captures one tracked policy version
// plus the fields that changed relative to the previous recorded version.
type OrganizationalPolicyVersionHistoryEntry struct {
	PolicyVersion         string    `json:"policy_version"`
	Title                 string    `json:"title"`
	Summary               string    `json:"summary,omitempty"`
	ContentDigest         string    `json:"content_digest,omitempty"`
	OwnerID               string    `json:"owner_id,omitempty"`
	ReviewCycleDays       int       `json:"review_cycle_days,omitempty"`
	FrameworkMappings     []string  `json:"framework_mappings,omitempty"`
	RequiredDepartmentIDs []string  `json:"required_department_ids,omitempty"`
	RequiredPersonIDs     []string  `json:"required_person_ids,omitempty"`
	ChangedFields         []string  `json:"changed_fields,omitempty"`
	ObservedAt            time.Time `json:"observed_at,omitempty"`
	SourceSystem          string    `json:"source_system,omitempty"`
	SourceEventID         string    `json:"source_event_id,omitempty"`
}

type organizationalPolicyVersionState struct {
	PolicyVersion         string
	Title                 string
	Summary               string
	ContentDigest         string
	OwnerID               string
	ReviewCycleDays       int
	FrameworkMappings     []string
	RequiredDepartmentIDs []string
	RequiredPersonIDs     []string
}

// OrganizationalPolicyAcknowledgmentRequest records one person acknowledging
// one organizational policy.
type OrganizationalPolicyAcknowledgmentRequest struct {
	PersonID       string         `json:"person_id"`
	PolicyID       string         `json:"policy_id"`
	PolicyVersion  string         `json:"policy_version,omitempty"`
	AcknowledgedAt time.Time      `json:"acknowledged_at,omitempty"`
	SourceSystem   string         `json:"source_system,omitempty"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// OrganizationalPolicyAcknowledgmentResult summarizes one acknowledgement write.
type OrganizationalPolicyAcknowledgmentResult struct {
	PersonID       string    `json:"person_id"`
	PolicyID       string    `json:"policy_id"`
	PolicyVersion  string    `json:"policy_version"`
	AcknowledgedAt time.Time `json:"acknowledged_at"`
	SourceSystem   string    `json:"source_system"`
	SourceEventID  string    `json:"source_event_id"`
}

// OrganizationalPolicyDepartmentRollup captures one department's current
// acknowledgement posture for a policy version.
type OrganizationalPolicyDepartmentRollup struct {
	DepartmentID       string   `json:"department_id"`
	DepartmentName     string   `json:"department_name,omitempty"`
	RequiredPeople     int      `json:"required_people"`
	AcknowledgedPeople int      `json:"acknowledged_people"`
	Coverage           float64  `json:"coverage"`
	PendingPersonIDs   []string `json:"pending_person_ids,omitempty"`
}

// OrganizationalPolicyAcknowledgmentReport summarizes current-version policy
// acknowledgement coverage across the org hierarchy.
type OrganizationalPolicyAcknowledgmentReport struct {
	PolicyID                 string                                 `json:"policy_id"`
	PolicyName               string                                 `json:"policy_name,omitempty"`
	PolicyVersion            string                                 `json:"policy_version"`
	GeneratedAt              time.Time                              `json:"generated_at"`
	RequiredPeople           int                                    `json:"required_people"`
	AcknowledgedPeople       int                                    `json:"acknowledged_people"`
	Coverage                 float64                                `json:"coverage"`
	PendingPersonIDs         []string                               `json:"pending_person_ids,omitempty"`
	UnscopedPendingPersonIDs []string                               `json:"unscoped_pending_person_ids,omitempty"`
	Departments              []OrganizationalPolicyDepartmentRollup `json:"departments,omitempty"`
}

// WriteOrganizationalPolicy upserts one organizational policy node and its
// required acknowledgement assignments.
func WriteOrganizationalPolicy(g *Graph, req OrganizationalPolicyWriteRequest) (OrganizationalPolicyWriteResult, error) {
	if g == nil {
		return OrganizationalPolicyWriteResult{}, fmt.Errorf("graph is required")
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		return OrganizationalPolicyWriteResult{}, fmt.Errorf("title is required")
	}
	policyVersion := strings.TrimSpace(req.PolicyVersion)
	if policyVersion == "" {
		return OrganizationalPolicyWriteResult{}, fmt.Errorf("policy_version is required")
	}

	policyID := strings.TrimSpace(req.ID)
	if policyID == "" {
		policyID = fmt.Sprintf("policy:%s", normalizeOrgKey(title))
	}
	if policyID == "policy:" {
		return OrganizationalPolicyWriteResult{}, fmt.Errorf("unable to derive policy id from title %q", title)
	}

	if existing, ok := g.GetNode(policyID); ok && existing != nil && existing.Kind != NodeKindPolicy {
		return OrganizationalPolicyWriteResult{}, fmt.Errorf("node %s already exists with kind %s", policyID, existing.Kind)
	}
	existingPolicy, _ := g.GetNode(policyID)

	ownerID := strings.TrimSpace(req.OwnerID)
	if ownerID != "" {
		owner, ok := g.GetNode(ownerID)
		if !ok || owner == nil {
			return OrganizationalPolicyWriteResult{}, fmt.Errorf("owner not found: %s", ownerID)
		}
		if owner.Kind != NodeKindPerson && owner.Kind != NodeKindDepartment {
			return OrganizationalPolicyWriteResult{}, fmt.Errorf("owner %s must be a person or department", ownerID)
		}
	}

	requiredDepartmentIDs, err := validatePolicyTargets(g, req.RequiredDepartmentIDs, NodeKindDepartment)
	if err != nil {
		return OrganizationalPolicyWriteResult{}, err
	}
	requiredPersonIDs, err := validatePolicyTargets(g, req.RequiredPersonIDs, NodeKindPerson)
	if err != nil {
		return OrganizationalPolicyWriteResult{}, err
	}

	frameworkMappings := uniquePolicyStrings(req.FrameworkMappings)
	content := strings.TrimSpace(req.Content)
	contentDigest := derivePolicyContentDigest(strings.TrimSpace(req.ContentDigest), content)
	reviewCycleDays := req.ReviewCycleDays
	if reviewCycleDays <= 0 && existingPolicy != nil {
		reviewCycleDays = readInt(existingPolicy.Properties, "review_cycle_days")
	}
	metadata := NormalizeWriteMetadata(req.ObservedAt, req.ValidFrom, req.ValidTo, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		RecordedAt:        req.RecordedAt,
		TransactionFrom:   req.TransactionFrom,
		TransactionTo:     req.TransactionTo,
		SourceSystem:      "policy_registry",
		SourceEventPrefix: "organizational-policy",
		DefaultConfidence: 0.95,
	})

	properties := cloneAnyMap(req.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	properties["policy_id"] = policyID
	properties["policy_version"] = policyVersion
	properties["title"] = title
	if summary := strings.TrimSpace(req.Summary); summary != "" {
		properties["summary"] = summary
	}
	if content != "" {
		properties["content"] = content
	}
	if contentDigest != "" {
		properties["content_digest"] = contentDigest
	}
	if ownerID != "" {
		properties["owner_id"] = ownerID
	}
	if reviewCycleDays > 0 {
		properties["review_cycle_days"] = reviewCycleDays
	}
	if len(frameworkMappings) > 0 {
		properties["framework_mappings"] = frameworkMappings
	}
	metadata.ApplyTo(properties)

	g.AddNode(&Node{
		ID:         policyID,
		Kind:       NodeKindPolicy,
		Name:       title,
		Provider:   metadata.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
	})

	assignmentTargets := make([]string, 0, len(requiredDepartmentIDs)+len(requiredPersonIDs))
	assignmentTargets = append(assignmentTargets, requiredDepartmentIDs...)
	assignmentTargets = append(assignmentTargets, requiredPersonIDs...)

	historyEntries, changedFields := nextOrganizationalPolicyVersionHistory(existingPolicy, g, organizationalPolicyVersionState{
		PolicyVersion:         policyVersion,
		Title:                 title,
		Summary:               strings.TrimSpace(req.Summary),
		ContentDigest:         contentDigest,
		OwnerID:               ownerID,
		ReviewCycleDays:       reviewCycleDays,
		FrameworkMappings:     frameworkMappings,
		RequiredDepartmentIDs: requiredDepartmentIDs,
		RequiredPersonIDs:     requiredPersonIDs,
	}, metadata)
	if len(historyEntries) > 0 {
		properties["version_history"] = organizationalPolicyVersionHistoryProperty(historyEntries)
	}

	syncOrganizationalPolicyAssignments(g, policyID, assignmentTargets, metadata)

	return OrganizationalPolicyWriteResult{
		PolicyID:              policyID,
		PolicyVersion:         policyVersion,
		AssignedDepartments:   len(requiredDepartmentIDs),
		AssignedPeople:        len(requiredPersonIDs),
		ChangedFields:         changedFields,
		VersionHistoryEntries: len(historyEntries),
		SourceSystem:          metadata.SourceSystem,
		SourceEventID:         metadata.SourceEventID,
	}, nil
}

// AcknowledgeOrganizationalPolicy records one person's acknowledgement of the
// current policy version.
func AcknowledgeOrganizationalPolicy(g *Graph, req OrganizationalPolicyAcknowledgmentRequest) (OrganizationalPolicyAcknowledgmentResult, error) {
	if g == nil {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("graph is required")
	}

	personID := strings.TrimSpace(req.PersonID)
	policyID := strings.TrimSpace(req.PolicyID)
	if personID == "" {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("person_id is required")
	}
	if policyID == "" {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("policy_id is required")
	}

	person, ok := g.GetNode(personID)
	if !ok || person == nil || person.Kind != NodeKindPerson {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("person not found: %s", personID)
	}
	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("policy not found: %s", policyID)
	}

	policyVersion := firstNonEmpty(strings.TrimSpace(req.PolicyVersion), currentOrganizationalPolicyVersion(policy))
	if policyVersion == "" {
		return OrganizationalPolicyAcknowledgmentResult{}, fmt.Errorf("policy %s has no current policy_version", policyID)
	}

	acknowledgedAt := req.AcknowledgedAt.UTC()
	metadata := NormalizeWriteMetadata(acknowledgedAt, acknowledgedAt, nil, req.SourceSystem, req.SourceEventID, req.Confidence, WriteMetadataDefaults{
		SourceSystem:      "policy_acknowledgment",
		SourceEventPrefix: "policy-acknowledgment",
		DefaultConfidence: 1.0,
	})

	properties := cloneAnyMap(req.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	properties["policy_version"] = policyVersion
	properties["acknowledged_at"] = metadata.ObservedAt.UTC().Format(time.RFC3339)
	metadata.ApplyTo(properties)

	g.AddEdge(&Edge{
		ID:         fmt.Sprintf("%s->%s:%s", personID, policyID, EdgeKindAcknowledged),
		Source:     personID,
		Target:     policyID,
		Kind:       EdgeKindAcknowledged,
		Effect:     EdgeEffectAllow,
		Properties: properties,
		Risk:       RiskNone,
	})

	return OrganizationalPolicyAcknowledgmentResult{
		PersonID:       personID,
		PolicyID:       policyID,
		PolicyVersion:  policyVersion,
		AcknowledgedAt: metadata.ObservedAt,
		SourceSystem:   metadata.SourceSystem,
		SourceEventID:  metadata.SourceEventID,
	}, nil
}

// OrganizationalPolicyAcknowledgmentStatus computes current-version
// acknowledgement coverage using department membership from the graph.
func OrganizationalPolicyAcknowledgmentStatus(g *Graph, policyID string) (*OrganizationalPolicyAcknowledgmentReport, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy_id is required")
	}

	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	currentVersion := currentOrganizationalPolicyVersion(policy)
	departmentMembers, departmentNames := departmentMembersByID(g)
	departmentsForPerson := departmentsByPerson(g)

	requiredPeople := make(map[string]struct{})
	assignedDepartments := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(policyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}
		switch target.Kind {
		case NodeKindDepartment:
			assignedDepartments[target.ID] = struct{}{}
			if departmentNames[target.ID] == "" {
				departmentNames[target.ID] = target.Name
			}
			for personID := range departmentMembers[target.ID] {
				requiredPeople[personID] = struct{}{}
			}
		case NodeKindPerson:
			requiredPeople[target.ID] = struct{}{}
		}
	}

	acknowledgedPeople := make(map[string]struct{})
	for _, edge := range g.GetInEdges(policyID) {
		if edge == nil || edge.Kind != EdgeKindAcknowledged {
			continue
		}
		source, ok := g.GetNode(edge.Source)
		if !ok || source == nil || source.Kind != NodeKindPerson {
			continue
		}
		if _, required := requiredPeople[source.ID]; !required {
			continue
		}
		ackVersion := strings.TrimSpace(readString(edge.Properties, "policy_version"))
		if currentVersion != "" {
			if ackVersion == "" || !strings.EqualFold(ackVersion, currentVersion) {
				continue
			}
		}
		acknowledgedPeople[source.ID] = struct{}{}
	}

	type departmentAccumulator struct {
		name         string
		required     map[string]struct{}
		acknowledged map[string]struct{}
	}

	departmentRollups := make(map[string]*departmentAccumulator)
	for departmentID := range assignedDepartments {
		departmentRollups[departmentID] = &departmentAccumulator{
			name:         departmentNames[departmentID],
			required:     make(map[string]struct{}),
			acknowledged: make(map[string]struct{}),
		}
	}

	unscopedRequired := make(map[string]struct{})
	unscopedAcknowledged := make(map[string]struct{})
	for personID := range requiredPeople {
		departments := departmentsForPerson[personID]
		if len(departments) == 0 {
			unscopedRequired[personID] = struct{}{}
			if _, acknowledged := acknowledgedPeople[personID]; acknowledged {
				unscopedAcknowledged[personID] = struct{}{}
			}
			continue
		}
		for departmentID := range departments {
			acc := departmentRollups[departmentID]
			if acc == nil {
				acc = &departmentAccumulator{
					name:         departmentNames[departmentID],
					required:     make(map[string]struct{}),
					acknowledged: make(map[string]struct{}),
				}
				departmentRollups[departmentID] = acc
			}
			acc.required[personID] = struct{}{}
			if _, acknowledged := acknowledgedPeople[personID]; acknowledged {
				acc.acknowledged[personID] = struct{}{}
			}
		}
	}

	departments := make([]OrganizationalPolicyDepartmentRollup, 0, len(departmentRollups))
	for departmentID, acc := range departmentRollups {
		pending := differenceSet(acc.required, acc.acknowledged)
		requiredCount := len(acc.required)
		ackCount := len(acc.acknowledged)
		departments = append(departments, OrganizationalPolicyDepartmentRollup{
			DepartmentID:       departmentID,
			DepartmentName:     firstNonEmpty(acc.name, departmentID),
			RequiredPeople:     requiredCount,
			AcknowledgedPeople: ackCount,
			Coverage:           ratio(ackCount, requiredCount),
			PendingPersonIDs:   pending,
		})
	}
	sort.Slice(departments, func(i, j int) bool {
		return departments[i].DepartmentID < departments[j].DepartmentID
	})

	requiredCount := len(requiredPeople)
	ackCount := len(acknowledgedPeople)
	return &OrganizationalPolicyAcknowledgmentReport{
		PolicyID:                 policyID,
		PolicyName:               firstNonEmpty(policy.Name, strings.TrimSpace(readString(policy.Properties, "title"))),
		PolicyVersion:            currentVersion,
		GeneratedAt:              time.Now().UTC(),
		RequiredPeople:           requiredCount,
		AcknowledgedPeople:       ackCount,
		Coverage:                 ratio(ackCount, requiredCount),
		PendingPersonIDs:         differenceSet(requiredPeople, acknowledgedPeople),
		UnscopedPendingPersonIDs: differenceSet(unscopedRequired, unscopedAcknowledged),
		Departments:              departments,
	}, nil
}

// OrganizationalPolicyVersionHistory returns the tracked policy version history
// for one policy node. When older policy nodes predate explicit history
// tracking, the current state is synthesized into one baseline entry.
func OrganizationalPolicyVersionHistory(g *Graph, policyID string) ([]OrganizationalPolicyVersionHistoryEntry, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is required")
	}

	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy_id is required")
	}

	policy, ok := g.GetNode(policyID)
	if !ok || policy == nil || policy.Kind != NodeKindPolicy {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	history := organizationalPolicyVersionHistoryFromProperties(policy.Properties)
	if len(history) > 0 {
		return history, nil
	}

	return []OrganizationalPolicyVersionHistoryEntry{
		organizationalPolicyVersionEntryFromState(
			organizationalPolicyVersionStateFromGraph(policy, g),
			organizationalPolicyHistoryMetadata(policy.Properties),
			nil,
		),
	}, nil
}

func validatePolicyTargets(g *Graph, targetIDs []string, expectedKind NodeKind) ([]string, error) {
	targetIDs = uniquePolicyStrings(targetIDs)
	for _, targetID := range targetIDs {
		node, ok := g.GetNode(targetID)
		if !ok || node == nil {
			return nil, fmt.Errorf("target not found: %s", targetID)
		}
		if node.Kind != expectedKind {
			return nil, fmt.Errorf("target %s must be a %s", targetID, expectedKind)
		}
	}
	return targetIDs, nil
}

func syncOrganizationalPolicyAssignments(g *Graph, policyID string, targetIDs []string, metadata WriteMetadata) {
	if g == nil || strings.TrimSpace(policyID) == "" {
		return
	}

	desiredTargets := make(map[string]struct{}, len(targetIDs))
	for _, targetID := range targetIDs {
		targetID = strings.TrimSpace(targetID)
		if targetID == "" {
			continue
		}
		desiredTargets[targetID] = struct{}{}
	}

	for _, edge := range g.GetOutEdges(policyID) {
		if edge == nil || edge.Kind != EdgeKindAssignedTo {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}
		if target.Kind != NodeKindDepartment && target.Kind != NodeKindPerson {
			continue
		}
		if _, keep := desiredTargets[target.ID]; keep {
			continue
		}
		g.RemoveEdge(policyID, target.ID, EdgeKindAssignedTo)
	}

	for targetID := range desiredTargets {
		properties := metadata.PropertyMap()
		properties["required_acknowledgment"] = true
		g.AddEdge(&Edge{
			ID:         fmt.Sprintf("%s->%s:%s", policyID, targetID, EdgeKindAssignedTo),
			Source:     policyID,
			Target:     targetID,
			Kind:       EdgeKindAssignedTo,
			Effect:     EdgeEffectAllow,
			Properties: properties,
			Risk:       RiskNone,
		})
	}
}

func currentOrganizationalPolicyVersion(policy *Node) string {
	if policy == nil {
		return ""
	}
	return firstNonEmpty(
		strings.TrimSpace(readString(policy.Properties, "policy_version")),
		strings.TrimSpace(readString(policy.Properties, "version")),
	)
}

func differenceSet(all map[string]struct{}, acknowledged map[string]struct{}) []string {
	if len(all) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(all))
	for key := range all {
		if _, ok := acknowledged[key]; ok {
			continue
		}
		out[key] = struct{}{}
	}
	return sortedSet(out)
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func uniquePolicyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func nextOrganizationalPolicyVersionHistory(policy *Node, g *Graph, next organizationalPolicyVersionState, metadata WriteMetadata) ([]OrganizationalPolicyVersionHistoryEntry, []string) {
	if policy == nil {
		return []OrganizationalPolicyVersionHistoryEntry{
			organizationalPolicyVersionEntryFromState(next, metadata, nil),
		}, nil
	}

	history := organizationalPolicyVersionHistoryFromProperties(policy.Properties)
	if len(history) == 0 {
		previous := organizationalPolicyVersionStateFromGraph(policy, g)
		previousEntry := organizationalPolicyVersionEntryFromState(previous, organizationalPolicyHistoryMetadata(policy.Properties), nil)
		if organizationalPolicyVersionStatesEqual(previous, next) {
			return []OrganizationalPolicyVersionHistoryEntry{previousEntry}, nil
		}
		changedFields := uniquePolicyStrings(organizationalPolicyChangedFields(previous, next))
		return []OrganizationalPolicyVersionHistoryEntry{
			previousEntry,
			organizationalPolicyVersionEntryFromState(next, metadata, changedFields),
		}, changedFields
	}

	previous := organizationalPolicyVersionStateFromEntry(history[len(history)-1])
	if organizationalPolicyVersionStatesEqual(previous, next) {
		return history, nil
	}

	changedFields := uniquePolicyStrings(organizationalPolicyChangedFields(previous, next))
	return append(history, organizationalPolicyVersionEntryFromState(next, metadata, changedFields)), changedFields
}

func organizationalPolicyVersionStateFromGraph(policy *Node, g *Graph) organizationalPolicyVersionState {
	state := organizationalPolicyVersionState{
		PolicyVersion:   strings.TrimSpace(readString(policy.Properties, "policy_version")),
		Title:           firstNonEmpty(strings.TrimSpace(readString(policy.Properties, "title")), strings.TrimSpace(policy.Name)),
		Summary:         strings.TrimSpace(readString(policy.Properties, "summary")),
		ContentDigest:   strings.TrimSpace(readString(policy.Properties, "content_digest")),
		OwnerID:         strings.TrimSpace(readString(policy.Properties, "owner_id")),
		ReviewCycleDays: readInt(policy.Properties, "review_cycle_days"),
		FrameworkMappings: organizationalPolicyStringSlice(
			policy.Properties["framework_mappings"],
		),
	}
	if state.ContentDigest == "" {
		state.ContentDigest = derivePolicyContentDigest("", readString(policy.Properties, "content"))
	}
	if g != nil {
		for _, edge := range g.GetOutEdges(policy.ID) {
			if edge == nil || edge.Kind != EdgeKindAssignedTo {
				continue
			}
			target, ok := g.GetNode(edge.Target)
			if !ok || target == nil {
				continue
			}
			switch target.Kind {
			case NodeKindDepartment:
				state.RequiredDepartmentIDs = append(state.RequiredDepartmentIDs, target.ID)
			case NodeKindPerson:
				state.RequiredPersonIDs = append(state.RequiredPersonIDs, target.ID)
			}
		}
	}
	state.RequiredDepartmentIDs = uniquePolicyStrings(state.RequiredDepartmentIDs)
	state.RequiredPersonIDs = uniquePolicyStrings(state.RequiredPersonIDs)
	return state
}

func organizationalPolicyVersionStateFromEntry(entry OrganizationalPolicyVersionHistoryEntry) organizationalPolicyVersionState {
	return organizationalPolicyVersionState{
		PolicyVersion:         strings.TrimSpace(entry.PolicyVersion),
		Title:                 strings.TrimSpace(entry.Title),
		Summary:               strings.TrimSpace(entry.Summary),
		ContentDigest:         strings.TrimSpace(entry.ContentDigest),
		OwnerID:               strings.TrimSpace(entry.OwnerID),
		ReviewCycleDays:       entry.ReviewCycleDays,
		FrameworkMappings:     uniquePolicyStrings(entry.FrameworkMappings),
		RequiredDepartmentIDs: uniquePolicyStrings(entry.RequiredDepartmentIDs),
		RequiredPersonIDs:     uniquePolicyStrings(entry.RequiredPersonIDs),
	}
}

func organizationalPolicyVersionStatesEqual(left, right organizationalPolicyVersionState) bool {
	if left.PolicyVersion != right.PolicyVersion || left.Title != right.Title || left.Summary != right.Summary ||
		left.ContentDigest != right.ContentDigest || left.OwnerID != right.OwnerID || left.ReviewCycleDays != right.ReviewCycleDays {
		return false
	}
	return stringSlicesEqual(left.FrameworkMappings, right.FrameworkMappings) &&
		stringSlicesEqual(left.RequiredDepartmentIDs, right.RequiredDepartmentIDs) &&
		stringSlicesEqual(left.RequiredPersonIDs, right.RequiredPersonIDs)
}

func organizationalPolicyChangedFields(previous, next organizationalPolicyVersionState) []string {
	changed := make([]string, 0, 8)
	if previous.PolicyVersion != next.PolicyVersion {
		changed = append(changed, "policy_version")
	}
	if previous.Title != next.Title {
		changed = append(changed, "title")
	}
	if previous.Summary != next.Summary {
		changed = append(changed, "summary")
	}
	if previous.ContentDigest != next.ContentDigest {
		changed = append(changed, "content_digest")
	}
	if previous.OwnerID != next.OwnerID {
		changed = append(changed, "owner_id")
	}
	if previous.ReviewCycleDays != next.ReviewCycleDays {
		changed = append(changed, "review_cycle_days")
	}
	if !stringSlicesEqual(previous.FrameworkMappings, next.FrameworkMappings) {
		changed = append(changed, "framework_mappings")
	}
	if !stringSlicesEqual(previous.RequiredDepartmentIDs, next.RequiredDepartmentIDs) {
		changed = append(changed, "required_department_ids")
	}
	if !stringSlicesEqual(previous.RequiredPersonIDs, next.RequiredPersonIDs) {
		changed = append(changed, "required_person_ids")
	}
	return changed
}

func organizationalPolicyVersionEntryFromState(state organizationalPolicyVersionState, metadata WriteMetadata, changedFields []string) OrganizationalPolicyVersionHistoryEntry {
	return OrganizationalPolicyVersionHistoryEntry{
		PolicyVersion:         state.PolicyVersion,
		Title:                 state.Title,
		Summary:               state.Summary,
		ContentDigest:         state.ContentDigest,
		OwnerID:               state.OwnerID,
		ReviewCycleDays:       state.ReviewCycleDays,
		FrameworkMappings:     uniquePolicyStrings(state.FrameworkMappings),
		RequiredDepartmentIDs: uniquePolicyStrings(state.RequiredDepartmentIDs),
		RequiredPersonIDs:     uniquePolicyStrings(state.RequiredPersonIDs),
		ChangedFields:         uniquePolicyStrings(changedFields),
		ObservedAt:            metadata.ObservedAt.UTC(),
		SourceSystem:          strings.TrimSpace(metadata.SourceSystem),
		SourceEventID:         strings.TrimSpace(metadata.SourceEventID),
	}
}

func organizationalPolicyHistoryMetadata(properties map[string]any) WriteMetadata {
	return WriteMetadata{
		ObservedAt:   organizationalPolicyTime(properties, "observed_at", "valid_from"),
		SourceSystem: readString(properties, "source_system"),
		SourceEventID: readString(
			properties,
			"source_event_id",
		),
	}
}

func organizationalPolicyTime(properties map[string]any, keys ...string) time.Time {
	for _, key := range keys {
		raw := strings.TrimSpace(readString(properties, key))
		if raw == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func organizationalPolicyVersionHistoryFromProperties(properties map[string]any) []OrganizationalPolicyVersionHistoryEntry {
	if properties == nil {
		return nil
	}
	rawEntries, ok := properties["version_history"]
	if !ok {
		return nil
	}

	var items []any
	switch typed := rawEntries.(type) {
	case []any:
		items = typed
	case []map[string]any:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	default:
		return nil
	}
	if len(items) == 0 {
		return nil
	}

	history := make([]OrganizationalPolicyVersionHistoryEntry, 0, len(items))
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok || len(record) == 0 {
			continue
		}
		history = append(history, OrganizationalPolicyVersionHistoryEntry{
			PolicyVersion:         readString(record, "policy_version"),
			Title:                 readString(record, "title"),
			Summary:               readString(record, "summary"),
			ContentDigest:         readString(record, "content_digest"),
			OwnerID:               readString(record, "owner_id"),
			ReviewCycleDays:       readInt(record, "review_cycle_days"),
			FrameworkMappings:     organizationalPolicyStringSlice(record["framework_mappings"]),
			RequiredDepartmentIDs: organizationalPolicyStringSlice(record["required_department_ids"]),
			RequiredPersonIDs:     organizationalPolicyStringSlice(record["required_person_ids"]),
			ChangedFields:         organizationalPolicyStringSlice(record["changed_fields"]),
			ObservedAt:            organizationalPolicyTime(record, "observed_at"),
			SourceSystem:          readString(record, "source_system"),
			SourceEventID:         readString(record, "source_event_id"),
		})
	}
	if len(history) == 0 {
		return nil
	}
	return history
}

func organizationalPolicyVersionHistoryProperty(entries []OrganizationalPolicyVersionHistoryEntry) []any {
	if len(entries) == 0 {
		return nil
	}
	out := make([]any, 0, len(entries))
	for _, entry := range entries {
		record := map[string]any{
			"policy_version": entry.PolicyVersion,
			"title":          entry.Title,
		}
		if entry.Summary != "" {
			record["summary"] = entry.Summary
		}
		if entry.ContentDigest != "" {
			record["content_digest"] = entry.ContentDigest
		}
		if entry.OwnerID != "" {
			record["owner_id"] = entry.OwnerID
		}
		if entry.ReviewCycleDays > 0 {
			record["review_cycle_days"] = entry.ReviewCycleDays
		}
		if len(entry.FrameworkMappings) > 0 {
			record["framework_mappings"] = uniquePolicyStrings(entry.FrameworkMappings)
		}
		if len(entry.RequiredDepartmentIDs) > 0 {
			record["required_department_ids"] = uniquePolicyStrings(entry.RequiredDepartmentIDs)
		}
		if len(entry.RequiredPersonIDs) > 0 {
			record["required_person_ids"] = uniquePolicyStrings(entry.RequiredPersonIDs)
		}
		if len(entry.ChangedFields) > 0 {
			record["changed_fields"] = uniquePolicyStrings(entry.ChangedFields)
		}
		if !entry.ObservedAt.IsZero() {
			record["observed_at"] = entry.ObservedAt.UTC().Format(time.RFC3339)
		}
		if entry.SourceSystem != "" {
			record["source_system"] = entry.SourceSystem
		}
		if entry.SourceEventID != "" {
			record["source_event_id"] = entry.SourceEventID
		}
		out = append(out, record)
	}
	return out
}

func organizationalPolicyStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return uniquePolicyStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			switch current := item.(type) {
			case string:
				values = append(values, current)
			case fmt.Stringer:
				values = append(values, current.String())
			default:
				values = append(values, fmt.Sprintf("%v", current))
			}
		}
		return uniquePolicyStrings(values)
	default:
		return nil
	}
}

func derivePolicyContentDigest(contentDigest, content string) string {
	contentDigest = strings.TrimSpace(contentDigest)
	if contentDigest != "" {
		return contentDigest
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
