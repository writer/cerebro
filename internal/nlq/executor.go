package nlq

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
)

type GraphDiffReader interface {
	DiffByTime(t1, t2 time.Time) (*graph.GraphDiff, error)
}

type Result struct {
	Question string `json:"question"`
	Plan     *Plan  `json:"plan"`
	Summary  string `json:"summary"`
	Result   any    `json:"result"`
}

type EntityFindingMatch struct {
	Entity   graph.EntityRecord  `json:"entity"`
	Findings []*findings.Finding `json:"findings"`
}

type EntityFindingsResult struct {
	GeneratedAt      time.Time            `json:"generated_at"`
	EntityCount      int                  `json:"entity_count"`
	MatchingEntities int                  `json:"matching_entities"`
	MatchingFindings int                  `json:"matching_findings"`
	Matches          []EntityFindingMatch `json:"matches,omitempty"`
}

type ReverseAccessMatch struct {
	Resource     graph.EntityRecord    `json:"resource"`
	AccessibleBy []*graph.AccessorNode `json:"accessible_by,omitempty"`
	TotalCount   int                   `json:"total_count"`
}

type ReverseAccessCollection struct {
	GeneratedAt time.Time            `json:"generated_at"`
	TargetCount int                  `json:"target_count"`
	Results     []ReverseAccessMatch `json:"results,omitempty"`
	Count       int                  `json:"count"`
}

type Executor struct {
	Graph    *graph.Graph
	Findings findings.FindingStore
	Diffs    GraphDiffReader
	Now      func() time.Time
}

func (e *Executor) Execute(_ context.Context, plan *Plan) (*Result, error) {
	if plan == nil {
		return nil, fmt.Errorf("plan is required")
	}
	if e == nil || e.Graph == nil {
		return nil, fmt.Errorf("graph is required")
	}
	if err := validatePlanPayload(*plan); err != nil {
		return nil, err
	}

	var (
		payload any
		summary string
		err     error
	)

	switch plan.Kind {
	case PlanKindEntityQuery:
		payload, summary, err = e.executeEntityQuery(*plan.EntityQuery)
	case PlanKindFindingsQuery:
		payload, summary, err = e.executeFindingsQuery(*plan.FindingsQuery)
	case PlanKindEntityFindingsQuery:
		payload, summary, err = e.executeEntityFindingsQuery(*plan.CompositeQuery)
	case PlanKindReverseAccessQuery:
		payload, summary, err = e.executeReverseAccessQuery(*plan.ReverseAccess)
	case PlanKindGraphChangeDiff:
		payload, summary, err = e.executeChangeQuery(*plan.ChangeQuery)
	default:
		err = ErrUnsupportedQuestion
	}
	if err != nil {
		return nil, err
	}

	return &Result{
		Question: plan.Question,
		Plan:     plan,
		Summary:  summary,
		Result:   payload,
	}, nil
}

func (e *Executor) executeEntityQuery(query EntityQuery) (any, string, error) {
	collection := graph.QueryEntities(e.Graph, graph.EntityQueryOptions{
		Kinds:         append([]graph.NodeKind(nil), query.Kinds...),
		Categories:    append([]graph.NodeKindCategory(nil), query.Categories...),
		Capabilities:  append([]graph.NodeKindCapability(nil), query.Capabilities...),
		Provider:      query.Provider,
		Account:       query.Account,
		Region:        query.Region,
		Risk:          query.Risk,
		Search:        query.Search,
		HasFindings:   cloneOptionalBool(query.HasFindings),
		Limit:         query.Limit,
		IncludeDetail: true,
	})
	return collection, fmt.Sprintf("Matched %d entities.", collection.Summary.MatchedEntities), nil
}

func (e *Executor) executeFindingsQuery(query FindingsQuery) (any, string, error) {
	if e.Findings == nil {
		return nil, "", fmt.Errorf("findings store not initialized")
	}
	all := e.Findings.List(findings.FindingFilter{
		Severity: query.Severity,
		Status:   query.Status,
		PolicyID: query.PolicyID,
		Domain:   query.Domain,
		Limit:    query.Limit,
	})
	filtered := filterFindingsByQuery(all, query.Query)
	payload := map[string]any{
		"total":    len(filtered),
		"count":    len(filtered),
		"findings": filtered,
	}
	return payload, fmt.Sprintf("Matched %d findings.", len(filtered)), nil
}

func (e *Executor) executeEntityFindingsQuery(query EntityFindingsQuery) (any, string, error) {
	if e.Findings == nil {
		return nil, "", fmt.Errorf("findings store not initialized")
	}
	entityPayload, _, err := e.executeEntityQuery(query.Entities)
	if err != nil {
		return nil, "", err
	}
	entities := entityPayload.(graph.EntityCollection)
	allFindings := e.Findings.List(findings.FindingFilter{
		Severity: query.Findings.Severity,
		Status:   query.Findings.Status,
		PolicyID: query.Findings.PolicyID,
		Domain:   query.Findings.Domain,
		Limit:    query.Findings.Limit,
	})
	filteredFindings := filterFindingsByQuery(allFindings, query.Findings.Query)

	entityByID := make(map[string]graph.EntityRecord, len(entities.Entities))
	matchesByEntity := make(map[string][]*findings.Finding, len(entities.Entities))
	matchingFindings := 0
	for _, entity := range entities.Entities {
		entityByID[entity.ID] = entity
	}
	for _, finding := range filteredFindings {
		matchedEntity := false
		for _, entityID := range matchingFindingEntityIDs(finding) {
			entity, ok := entityByID[entityID]
			if !ok {
				continue
			}
			entityByID[entity.ID] = entity
			matchesByEntity[entity.ID] = append(matchesByEntity[entity.ID], finding)
			matchedEntity = true
		}
		if matchedEntity {
			matchingFindings++
		}
	}

	matches := make([]EntityFindingMatch, 0, len(matchesByEntity))
	for entityID, entityFindings := range matchesByEntity {
		sort.Slice(entityFindings, func(i, j int) bool {
			if entityFindings[i].Severity != entityFindings[j].Severity {
				return entityFindings[i].Severity < entityFindings[j].Severity
			}
			return entityFindings[i].ID < entityFindings[j].ID
		})
		matches = append(matches, EntityFindingMatch{
			Entity:   entityByID[entityID],
			Findings: entityFindings,
		})
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].Findings) != len(matches[j].Findings) {
			return len(matches[i].Findings) > len(matches[j].Findings)
		}
		return matches[i].Entity.ID < matches[j].Entity.ID
	})

	result := EntityFindingsResult{
		GeneratedAt:      e.now(),
		EntityCount:      len(entities.Entities),
		MatchingEntities: len(matches),
		MatchingFindings: matchingFindings,
		Matches:          matches,
	}
	return result, fmt.Sprintf("Matched %d entities with %d findings.", result.MatchingEntities, result.MatchingFindings), nil
}

func (e *Executor) executeReverseAccessQuery(query ReverseAccessQuery) (any, string, error) {
	entityPayload, _, err := e.executeEntityQuery(query.Targets)
	if err != nil {
		return nil, "", err
	}
	entities := entityPayload.(graph.EntityCollection)
	results := make([]ReverseAccessMatch, 0, len(entities.Entities))
	totalAccessors := 0

	for _, entity := range entities.Entities {
		reverse := graph.ReverseAccess(e.Graph, entity.ID, query.MaxDepth)
		accessors := reverse.AccessibleBy
		if query.AdminOnly {
			accessors = filterAdminAccessors(accessors)
		}
		if len(accessors) == 0 {
			continue
		}
		totalAccessors += len(accessors)
		results = append(results, ReverseAccessMatch{
			Resource:     entity,
			AccessibleBy: accessors,
			TotalCount:   len(accessors),
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].TotalCount != results[j].TotalCount {
			return results[i].TotalCount > results[j].TotalCount
		}
		return results[i].Resource.ID < results[j].Resource.ID
	})

	payload := ReverseAccessCollection{
		GeneratedAt: e.now(),
		TargetCount: len(entities.Entities),
		Results:     results,
		Count:       len(results),
	}
	return payload, fmt.Sprintf("Found %d matching access paths across %d target resources.", totalAccessors, len(results)), nil
}

func (e *Executor) executeChangeQuery(query ChangeQuery) (any, string, error) {
	if e.Diffs == nil {
		return nil, "", fmt.Errorf("graph diff store not initialized")
	}
	diff, err := e.Diffs.DiffByTime(query.Since, query.Until)
	if err != nil {
		return nil, "", err
	}
	if diff == nil {
		diff = &graph.GraphDiff{}
	}
	summary := fmt.Sprintf(
		"Graph changed by %d added nodes, %d removed nodes, %d modified nodes, %d added edges, and %d removed edges.",
		len(diff.NodesAdded),
		len(diff.NodesRemoved),
		len(diff.NodesModified),
		len(diff.EdgesAdded),
		len(diff.EdgesRemoved),
	)
	return diff, summary, nil
}

func filterFindingsByQuery(items []*findings.Finding, query string) []*findings.Finding {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return append([]*findings.Finding(nil), items...)
	}

	filtered := make([]*findings.Finding, 0, len(items))
	for _, finding := range items {
		if finding == nil {
			continue
		}
		candidate := strings.ToLower(strings.Join([]string{
			finding.ID,
			finding.PolicyID,
			finding.PolicyName,
			finding.Title,
			finding.Description,
			finding.ResourceID,
			finding.ResourceName,
			finding.ResourceType,
			finding.Severity,
			finding.Domain,
			finding.SignalType,
		}, " "))
		if strings.Contains(candidate, query) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func matchingFindingEntityIDs(finding *findings.Finding) []string {
	if finding == nil {
		return nil
	}
	set := make(map[string]struct{}, len(finding.EntityIDs)+1)
	if strings.TrimSpace(finding.ResourceID) != "" {
		set[strings.TrimSpace(finding.ResourceID)] = struct{}{}
	}
	for _, entityID := range finding.EntityIDs {
		entityID = strings.TrimSpace(entityID)
		if entityID == "" {
			continue
		}
		set[entityID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for entityID := range set {
		out = append(out, entityID)
	}
	sort.Strings(out)
	return out
}

func filterAdminAccessors(accessors []*graph.AccessorNode) []*graph.AccessorNode {
	filtered := make([]*graph.AccessorNode, 0, len(accessors))
	for _, accessor := range accessors {
		if accessor == nil {
			continue
		}
		if accessor.EdgeKind == graph.EdgeKindCanAdmin || nodeLooksAdmin(accessor.Node) || actionsLookAdmin(accessor.Actions) || pathLooksAdmin(accessor.Path) {
			filtered = append(filtered, accessor)
		}
	}
	return filtered
}

func nodeLooksAdmin(node *graph.Node) bool {
	if node == nil {
		return false
	}
	if admin, ok := node.Properties["admin"].(bool); ok && admin {
		return true
	}
	if admin, ok := node.Properties["is_admin"].(bool); ok && admin {
		return true
	}
	role := strings.ToLower(strings.TrimSpace(stringValue(node.Properties["role"])))
	title := strings.ToLower(strings.TrimSpace(stringValue(node.Properties["title"])))
	name := strings.ToLower(strings.TrimSpace(node.Name))
	return strings.Contains(role, "admin") ||
		strings.Contains(title, "admin") ||
		strings.Contains(name, "admin") ||
		strings.Contains(name, "administrator")
}

func actionsLookAdmin(actions []string) bool {
	for _, action := range actions {
		action = strings.ToLower(strings.TrimSpace(action))
		if action == "*" || action == "*:*" || strings.Contains(action, "admin") || strings.Contains(action, "write") || strings.Contains(action, "delete") {
			return true
		}
	}
	return false
}

func pathLooksAdmin(path []string) bool {
	for _, segment := range path {
		segment = strings.ToLower(strings.TrimSpace(segment))
		if strings.Contains(segment, "admin") {
			return true
		}
	}
	return false
}

func cloneOptionalBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func (e *Executor) now() time.Time {
	if e != nil && e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}
