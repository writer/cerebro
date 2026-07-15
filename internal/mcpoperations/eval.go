package mcpoperations

import (
	"sort"
	"strings"
)

type TaskSelectionCase struct {
	ID                     string   `json:"id"`
	UserRequest            string   `json:"user_request"`
	PermittedScopes        []string `json:"permitted_scopes"`
	ExpectedTool           string   `json:"expected_tool"`
	AllowedFollowupTools   []string `json:"allowed_followup_tools"`
	ForbiddenTools         []string `json:"forbidden_tools"`
	RequirePartialHandling bool     `json:"require_partial_handling"`
	MaximumCallCount       int      `json:"maximum_call_count"`
}

type TaskSelectionResult struct {
	ID           string
	SelectedTool string
	ExpectedTool string
	Passed       bool
}

// SelectTaskTool performs a deterministic offline selection check over task
// tool metadata. Runtime clients remain responsible for model/tool selection.
func SelectTaskTool(request string) string {
	request = strings.ToLower(strings.TrimSpace(request))
	type scoredOperation struct {
		name  string
		score int
	}
	scores := []scoredOperation{}
	for _, operation := range TaskTools() {
		score := 0
		for _, term := range operation.SelectionTerms {
			term = strings.ToLower(strings.TrimSpace(term))
			if term != "" && strings.Contains(request, term) {
				score += len(strings.Fields(term))
			}
		}
		if score > 0 {
			scores = append(scores, scoredOperation{name: operation.Name, score: score})
		}
	}
	if len(scores) == 0 {
		return ""
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score != scores[j].score {
			return scores[i].score > scores[j].score
		}
		return scores[i].name < scores[j].name
	})
	return scores[0].name
}

func EvaluateTaskSelection(cases []TaskSelectionCase) []TaskSelectionResult {
	results := make([]TaskSelectionResult, 0, len(cases))
	for _, evalCase := range cases {
		selected := SelectTaskTool(evalCase.UserRequest)
		results = append(results, TaskSelectionResult{
			ID:           evalCase.ID,
			SelectedTool: selected,
			ExpectedTool: evalCase.ExpectedTool,
			Passed:       selected == evalCase.ExpectedTool,
		})
	}
	return results
}
