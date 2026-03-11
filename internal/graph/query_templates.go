package graph

import "sort"

// GraphQueryTemplate defines one reusable graph investigation query.
type GraphQueryTemplate struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	Mode               string         `json:"mode"`
	RequiredParameters []string       `json:"required_parameters,omitempty"`
	OptionalParameters []string       `json:"optional_parameters,omitempty"`
	Example            map[string]any `json:"example,omitempty"`
}

// DefaultGraphQueryTemplates returns built-in analyst templates for repeatable investigations.
func DefaultGraphQueryTemplates() []GraphQueryTemplate {
	templates := []GraphQueryTemplate{
		{
			ID:                 "identity-access-neighbors",
			Name:               "Identity Access Neighbors",
			Description:        "Inspect direct in/out access relationships for one identity or role.",
			Mode:               "neighbors",
			RequiredParameters: []string{"node_id"},
			OptionalParameters: []string{"direction", "limit", "as_of", "from", "to"},
			Example: map[string]any{
				"mode":      "neighbors",
				"node_id":   "person:alice@example.com",
				"direction": "both",
				"limit":     25,
			},
		},
		{
			ID:                 "principal-to-data-paths",
			Name:               "Principal To Data Paths",
			Description:        "Find shortest access paths from a principal to a sensitive resource.",
			Mode:               "paths",
			RequiredParameters: []string{"node_id", "target_id"},
			OptionalParameters: []string{"k", "max_depth", "as_of", "from", "to"},
			Example: map[string]any{
				"mode":      "paths",
				"node_id":   "person:alice@example.com",
				"target_id": "database:prod-payments",
				"k":         3,
				"max_depth": 6,
			},
		},
		{
			ID:                 "incident-window-impact",
			Name:               "Incident Window Impact",
			Description:        "Scope neighbors or paths to a specific incident time window for forensic replay.",
			Mode:               "neighbors",
			RequiredParameters: []string{"node_id", "from", "to"},
			OptionalParameters: []string{"direction", "limit"},
			Example: map[string]any{
				"mode":      "neighbors",
				"node_id":   "service:payments",
				"from":      "2026-03-09T01:00:00Z",
				"to":        "2026-03-09T03:00:00Z",
				"direction": "both",
			},
		},
		{
			ID:                 "ownership-blast-radius",
			Name:               "Ownership Blast Radius",
			Description:        "Map direct and indirect dependencies around an owner/team node before changes.",
			Mode:               "neighbors",
			RequiredParameters: []string{"node_id"},
			OptionalParameters: []string{"direction", "limit", "as_of"},
			Example: map[string]any{
				"mode":      "neighbors",
				"node_id":   "department:platform",
				"direction": "both",
				"limit":     50,
			},
		},
		{
			ID:                 "decision-to-outcome-links",
			Name:               "Decision To Outcome Links",
			Description:        "Follow decision nodes to actions and outcomes to evaluate closed-loop execution.",
			Mode:               "neighbors",
			RequiredParameters: []string{"node_id"},
			OptionalParameters: []string{"direction", "limit", "from", "to"},
			Example: map[string]any{
				"mode":      "neighbors",
				"node_id":   "decision:20260309:rollback",
				"direction": "both",
				"limit":     25,
			},
		},
		{
			ID:                 "customer-impact-paths",
			Name:               "Customer Impact Paths",
			Description:        "Trace graph paths from a failing service to affected customers or revenue entities.",
			Mode:               "paths",
			RequiredParameters: []string{"node_id", "target_id"},
			OptionalParameters: []string{"k", "max_depth", "from", "to"},
			Example: map[string]any{
				"mode":      "paths",
				"node_id":   "service:payments",
				"target_id": "customer:acme",
				"k":         5,
				"max_depth": 7,
			},
		},
	}

	sort.SliceStable(templates, func(i, j int) bool {
		return templates[i].ID < templates[j].ID
	})
	return templates
}
