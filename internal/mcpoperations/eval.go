package mcpoperations

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	TaskSelectionReportContract = "cerebro.mcp.task-selection-eval.v1"
	TaskSelectionSelector       = "advertised-metadata-overlap.v1"
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

type TaskToolDescriptor struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	InputNames  []string `json:"input_names,omitempty"`
}

type TaskSelectionResult struct {
	ID            string `json:"id"`
	SelectedTool  string `json:"selected_tool,omitempty"`
	ExpectedTool  string `json:"expected_tool"`
	Passed        bool   `json:"passed"`
	Score         int    `json:"score"`
	RunnerUpTool  string `json:"runner_up_tool,omitempty"`
	RunnerUpScore int    `json:"runner_up_score"`
	Margin        int    `json:"margin"`
}

type TaskSelectionToolScore struct {
	Tool       string `json:"tool"`
	Cases      int    `json:"cases"`
	Correct    int    `json:"correct"`
	AccuracyBP int    `json:"accuracy_basis_points"`
}

type TaskSelectionReport struct {
	Contract                string                   `json:"contract"`
	Selector                string                   `json:"selector"`
	Total                   int                      `json:"total"`
	Correct                 int                      `json:"correct"`
	Incorrect               int                      `json:"incorrect"`
	Unselected              int                      `json:"unselected"`
	AccuracyBP              int                      `json:"accuracy_basis_points"`
	TaskToolCount           int                      `json:"task_tool_count"`
	CoveredToolCount        int                      `json:"covered_tool_count"`
	ToolCoverageBP          int                      `json:"tool_coverage_basis_points"`
	MinimumCorrectMargin    int                      `json:"minimum_correct_margin"`
	AmbiguousSelectionCount int                      `json:"ambiguous_selection_count"`
	PerTool                 []TaskSelectionToolScore `json:"per_tool"`
	Results                 []TaskSelectionResult    `json:"results"`
}

type TaskSelectionBaseline struct {
	Contract                   string `json:"contract"`
	MinimumAccuracyBP          int    `json:"minimum_accuracy_basis_points"`
	MinimumToolCoverageBP      int    `json:"minimum_tool_coverage_basis_points"`
	MinimumCasesPerTool        int    `json:"minimum_cases_per_tool"`
	MinimumCorrectMargin       int    `json:"minimum_correct_margin"`
	MaximumIncorrect           int    `json:"maximum_incorrect"`
	MaximumUnselected          int    `json:"maximum_unselected"`
	MaximumAmbiguousSelections int    `json:"maximum_ambiguous_selections"`
}

func ScoreTaskSelection(cases []TaskSelectionCase, descriptors []TaskToolDescriptor) TaskSelectionReport {
	report := TaskSelectionReport{
		Contract:      TaskSelectionReportContract,
		Selector:      TaskSelectionSelector,
		Total:         len(cases),
		TaskToolCount: len(descriptors),
		Results:       make([]TaskSelectionResult, 0, len(cases)),
	}
	perTool := make(map[string]*TaskSelectionToolScore, len(descriptors))
	for _, descriptor := range descriptors {
		name := strings.TrimSpace(descriptor.Name)
		if name != "" {
			perTool[name] = &TaskSelectionToolScore{Tool: name}
		}
	}
	minimumMarginSet := false
	for _, evalCase := range cases {
		result := selectTaskTool(evalCase, descriptors)
		report.Results = append(report.Results, result)
		toolScore, knownExpected := perTool[evalCase.ExpectedTool]
		if knownExpected {
			toolScore.Cases++
		}
		switch {
		case result.SelectedTool == "":
			report.Unselected++
		case !result.Passed:
			report.Incorrect++
		default:
			report.Correct++
			if knownExpected {
				toolScore.Correct++
			}
			if !minimumMarginSet || result.Margin < report.MinimumCorrectMargin {
				report.MinimumCorrectMargin = result.Margin
				minimumMarginSet = true
			}
		}
		if result.SelectedTool != "" && result.Margin <= 0 {
			report.AmbiguousSelectionCount++
		}
	}
	report.AccuracyBP = basisPoints(report.Correct, report.Total)
	report.PerTool = make([]TaskSelectionToolScore, 0, len(perTool))
	for _, score := range perTool {
		if score.Cases > 0 {
			report.CoveredToolCount++
		}
		score.AccuracyBP = basisPoints(score.Correct, score.Cases)
		report.PerTool = append(report.PerTool, *score)
	}
	sort.Slice(report.PerTool, func(i, j int) bool { return report.PerTool[i].Tool < report.PerTool[j].Tool })
	report.ToolCoverageBP = basisPoints(report.CoveredToolCount, report.TaskToolCount)
	return report
}

func ValidateTaskSelectionBaseline(report TaskSelectionReport, baseline TaskSelectionBaseline) error {
	failures := []string{}
	if baseline.Contract != "" && baseline.Contract != report.Contract {
		failures = append(failures, fmt.Sprintf("contract = %q, want %q", report.Contract, baseline.Contract))
	}
	if report.AccuracyBP < baseline.MinimumAccuracyBP {
		failures = append(failures, fmt.Sprintf("accuracy = %d basis points, want at least %d", report.AccuracyBP, baseline.MinimumAccuracyBP))
	}
	if report.ToolCoverageBP < baseline.MinimumToolCoverageBP {
		failures = append(failures, fmt.Sprintf("tool coverage = %d basis points, want at least %d", report.ToolCoverageBP, baseline.MinimumToolCoverageBP))
	}
	if report.MinimumCorrectMargin < baseline.MinimumCorrectMargin {
		failures = append(failures, fmt.Sprintf("minimum correct margin = %d, want at least %d", report.MinimumCorrectMargin, baseline.MinimumCorrectMargin))
	}
	if report.Incorrect > baseline.MaximumIncorrect {
		failures = append(failures, fmt.Sprintf("incorrect selections = %d, want at most %d", report.Incorrect, baseline.MaximumIncorrect))
	}
	if report.Unselected > baseline.MaximumUnselected {
		failures = append(failures, fmt.Sprintf("unselected cases = %d, want at most %d", report.Unselected, baseline.MaximumUnselected))
	}
	if report.AmbiguousSelectionCount > baseline.MaximumAmbiguousSelections {
		failures = append(failures, fmt.Sprintf("ambiguous selections = %d, want at most %d", report.AmbiguousSelectionCount, baseline.MaximumAmbiguousSelections))
	}
	for _, score := range report.PerTool {
		if score.Cases < baseline.MinimumCasesPerTool {
			failures = append(failures, fmt.Sprintf("%s cases = %d, want at least %d", score.Tool, score.Cases, baseline.MinimumCasesPerTool))
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("task selection baseline failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

type scoredTaskTool struct {
	name  string
	score int
}

func selectTaskTool(evalCase TaskSelectionCase, descriptors []TaskToolDescriptor) TaskSelectionResult {
	scores := make([]scoredTaskTool, 0, len(descriptors))
	for _, descriptor := range descriptors {
		if name := strings.TrimSpace(descriptor.Name); name != "" {
			scores = append(scores, scoredTaskTool{name: name, score: scoreTaskTool(evalCase.UserRequest, descriptor)})
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score != scores[j].score {
			return scores[i].score > scores[j].score
		}
		return scores[i].name < scores[j].name
	})
	result := TaskSelectionResult{ID: evalCase.ID, ExpectedTool: evalCase.ExpectedTool}
	if len(scores) == 0 || scores[0].score == 0 {
		return result
	}
	result.SelectedTool = scores[0].name
	result.Score = scores[0].score
	result.Passed = result.SelectedTool == result.ExpectedTool
	if len(scores) > 1 {
		result.RunnerUpTool = scores[1].name
		result.RunnerUpScore = scores[1].score
	}
	result.Margin = result.Score - result.RunnerUpScore
	return result
}

func scoreTaskTool(request string, descriptor TaskToolDescriptor) int {
	query := selectionTokens(request)
	if len(query) == 0 {
		return 0
	}
	name := tokenSet(descriptor.Name)
	title := tokenSet(descriptor.Title)
	description := tokenSet(descriptor.Description)
	inputs := tokenSet(strings.Join(descriptor.InputNames, " "))
	score := 0
	for _, token := range query {
		switch {
		case name[token]:
			score += 7
		case title[token]:
			score += 5
		case description[token]:
			score += 2
		case inputs[token]:
			score++
		}
	}
	nameText := " " + strings.Join(selectionTokens(descriptor.Name), " ") + " "
	titleText := " " + strings.Join(selectionTokens(descriptor.Title), " ") + " "
	descriptionText := " " + strings.Join(selectionTokens(descriptor.Description), " ") + " "
	for index := 0; index+1 < len(query); index++ {
		phrase := " " + query[index] + " " + query[index+1] + " "
		switch {
		case strings.Contains(nameText, phrase):
			score += 8
		case strings.Contains(titleText, phrase):
			score += 5
		case strings.Contains(descriptionText, phrase):
			score += 2
		}
	}
	return score
}

func selectionTokens(value string) []string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	tokens := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, field := range fields {
		token := normalizeSelectionToken(field)
		if token == "" || selectionStopWords[token] || seen[token] {
			continue
		}
		seen[token] = true
		tokens = append(tokens, token)
	}
	return tokens
}

func normalizeSelectionToken(token string) string {
	switch token {
	case "assets":
		return "asset"
	case "builds":
		return "build"
	case "connections", "connected":
		return "connection"
	case "controls":
		return "control"
	case "dependencies":
		return "dependency"
	case "failed", "failing", "failures":
		return "failure"
	case "findings":
		return "finding"
	case "packets":
		return "packet"
	case "paths":
		return "path"
	case "relationships":
		return "relationship"
	case "runtimes":
		return "runtime"
	case "sources":
		return "source"
	case "versions":
		return "version"
	default:
		return token
	}
}

func tokenSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, token := range selectionTokens(value) {
		result[token] = true
	}
	return result
}

func basisPoints(numerator int, denominator int) int {
	if denominator <= 0 {
		return 0
	}
	return numerator * 10000 / denominator
}

var selectionStopWords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "before": true, "by": true, "cerebro": true, "for": true, "from": true,
	"give": true, "in": true, "into": true, "is": true, "it": true, "me": true,
	"of": true, "on": true, "one": true, "or": true, "our": true, "return": true,
	"show": true, "that": true, "the": true, "this": true, "to": true, "which": true,
	"with": true, "without": true,
}
