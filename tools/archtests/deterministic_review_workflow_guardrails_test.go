package archtests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeterministicReviewIsExactShaScopedAndReadOnly(t *testing.T) {
	root := repoRoot(t)
	workflowBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "deterministic-review.yml"))
	if err != nil {
		t.Fatalf("read deterministic review workflow: %v", err)
	}
	if errors := deterministicReviewGuardrailErrors(string(workflowBody)); len(errors) != 0 {
		t.Fatalf("deterministic review guardrails failed:\n- %s", strings.Join(errors, "\n- "))
	}
}

func TestGovulncheckGateRemainsPinnedAndFullRepository(t *testing.T) {
	gateBody, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "govulncheck_gate.py"))
	if err != nil {
		t.Fatalf("read govulncheck gate: %v", err)
	}
	if errors := govulncheckGateGuardrailErrors(string(gateBody)); len(errors) != 0 {
		t.Fatalf("govulncheck gate guardrails failed:\n- %s", strings.Join(errors, "\n- "))
	}
}

func TestDeterministicReviewGuardrailsRejectUnsafeChanges(t *testing.T) {
	root := repoRoot(t)
	workflowBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "deterministic-review.yml"))
	if err != nil {
		t.Fatalf("read deterministic review workflow: %v", err)
	}
	workflow := string(workflowBody)

	tests := []struct {
		name      string
		workflow  string
		wantError string
	}{
		{
			name:      "core checkout is not exact head",
			workflow:  replaceInCoreJob(t, workflow, `ref: ${{ github.event.pull_request.head.sha }}`, `ref: ${{ github.sha }}`),
			wantError: "core job must check out the exact pull request head",
		},
		{
			name:      "core checkout persists credentials",
			workflow:  replaceInCoreJob(t, workflow, "persist-credentials: false", "persist-credentials: true"),
			wantError: "core checkout must disable persisted credentials",
		},
		{
			name:      "workflow requests write access",
			workflow:  strings.Replace(workflow, "permissions:\n  contents: read", "permissions:\n  contents: write", 1),
			wantError: "workflow must declare read-only contents permission",
		},
		{
			name:      "duplicate leak scan",
			workflow:  strings.Replace(workflow, "run: make deterministic-review", `run: ./scripts/leak_check.sh range "${REVIEW_BASE}...${REVIEW_HEAD}"`, 1),
			wantError: "must not duplicate the dedicated leak check",
		},
		{
			name:      "duplicate Semgrep scan",
			workflow:  strings.Replace(workflow, "run: make deterministic-review", "run: semgrep scan", 1),
			wantError: "must not duplicate the dedicated Semgrep check",
		},
		{
			name:      "duplicate govulncheck scan",
			workflow:  strings.Replace(workflow, "run: make deterministic-review", "run: make govulncheck", 1),
			wantError: "must not duplicate the dedicated govulncheck check",
		},
		{
			name:      "aggregate accepts core failure",
			workflow:  strings.Replace(workflow, `test "${REVIEW_RESULT}" = success`, `test "${REVIEW_RESULT}" != cancelled`, 1),
			wantError: "aggregate must require core review success",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errors := deterministicReviewGuardrailErrors(test.workflow)
			if !containsError(errors, test.wantError) {
				t.Fatalf("expected error %q, got %v", test.wantError, errors)
			}
		})
	}
}

func TestGovulncheckGateGuardrailsRejectUnsafeChanges(t *testing.T) {
	gateBody, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "govulncheck_gate.py"))
	if err != nil {
		t.Fatalf("read govulncheck gate: %v", err)
	}
	gate := string(gateBody)
	tests := []struct {
		name      string
		gate      string
		wantError string
	}{
		{"scanner version is unpinned", strings.Replace(gate, "golang.org/x/vuln/cmd/govulncheck@v1.1.4", "golang.org/x/vuln/cmd/govulncheck@latest", 1), "gate must pin govulncheck v1.1.4"},
		{"scanner drops requested patterns", strings.Replace(gate, `"json", *patterns`, `"json"`, 1), "gate must pass the exact requested package patterns"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if errors := govulncheckGateGuardrailErrors(test.gate); !containsError(errors, test.wantError) {
				t.Fatalf("expected error %q, got %v", test.wantError, errors)
			}
		})
	}
}

func deterministicReviewGuardrailErrors(workflow string) []string {
	var errors []string
	if !strings.Contains(workflow, "permissions:\n  contents: read") {
		errors = append(errors, "workflow must declare read-only contents permission")
	}

	required := []string{
		"name: Deterministic Review",
		`review_base="$(git merge-base --octopus "${BASE_SHA}" "${HEAD_SHA}")"`,
		`git merge-base --is-ancestor "${review_base}" "${HEAD_SHA}"`,
		`echo "REVIEW_BASE=${review_base}"`,
		`echo "REVIEW_HEAD=${HEAD_SHA}"`,
		`git diff --name-only --diff-filter=ACMR "${REVIEW_BASE}...${REVIEW_HEAD}"`,
		"actionlint .github/workflows/deterministic-review.yml",
		"zizmor .github/workflows/deterministic-review.yml",
		"make deterministic-review",
		"shellcheck",
	}
	for _, marker := range required {
		if !strings.Contains(workflow, marker) {
			errors = append(errors, fmt.Sprintf("workflow missing guardrail %q", marker))
		}
	}

	forbidden := []string{
		"Factory-AI/droid-action",
		"FACTORY_API_KEY",
		"secrets.",
		"pull-requests: write",
		"issues: write",
		"id-token: write",
		"Droid",
	}
	for _, marker := range forbidden {
		if strings.Contains(workflow, marker) {
			errors = append(errors, fmt.Sprintf("workflow must not contain %q", marker))
		}
	}
	for marker, message := range map[string]string{
		"leak_check.sh":       "workflow must not duplicate the dedicated leak check",
		"semgrep scan":        "workflow must not duplicate the dedicated Semgrep check",
		"govulncheck_gate.py": "workflow must not duplicate the dedicated govulncheck check",
		"make govulncheck":    "workflow must not duplicate the dedicated govulncheck check",
	} {
		if strings.Contains(workflow, marker) {
			errors = append(errors, message)
		}
	}
	if strings.Contains(workflow, ": write") {
		errors = append(errors, "workflow must not request any write permission")
	}

	coreJob, ok := workflowSection(workflow, "  review:\n", "  deterministic-review:\n")
	if !ok {
		errors = append(errors, "workflow must define the core review job")
	} else {
		if !strings.Contains(coreJob, `ref: ${{ github.event.pull_request.head.sha }}`) {
			errors = append(errors, "core job must check out the exact pull request head")
		}
		if !strings.Contains(coreJob, "persist-credentials: false") {
			errors = append(errors, "core checkout must disable persisted credentials")
		}
	}

	aggregate, ok := workflowSection(workflow, "  deterministic-review:\n", "")
	if !ok {
		errors = append(errors, "workflow must define the stable deterministic-review aggregate")
	} else {
		for _, requirement := range []struct {
			marker string
			error  string
		}{
			{"if: ${{ always() }}", "aggregate must run for every dependency result"},
			{"needs: review", "aggregate must depend on the core review job"},
			{`test "${REVIEW_RESULT}" = success`, "aggregate must require core review success"},
		} {
			if !strings.Contains(aggregate, requirement.marker) {
				errors = append(errors, requirement.error)
			}
		}
	}

	return errors
}

func govulncheckGateGuardrailErrors(gate string) []string {
	var errors []string
	if !strings.Contains(gate, `DEFAULT_TOOL = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"`) {
		errors = append(errors, "gate must pin govulncheck v1.1.4")
	}
	if !strings.Contains(gate, `command = ["go", "run", DEFAULT_TOOL, "-format", "json", *patterns]`) {
		errors = append(errors, "gate must pass the exact requested package patterns")
	}
	if !strings.Contains(gate, `parser.add_argument("patterns", nargs="*", default=["./..."])`) {
		errors = append(errors, "gate must default to the full repository package pattern")
	}
	return errors
}

func workflowSection(workflow, startMarker, endMarker string) (string, bool) {
	start := strings.Index(workflow, startMarker)
	if start == -1 {
		return "", false
	}
	section := workflow[start:]
	if endMarker == "" {
		return section, true
	}
	end := strings.Index(section[len(startMarker):], endMarker)
	if end == -1 {
		return "", false
	}
	return section[:len(startMarker)+end], true
}

func replaceInCoreJob(t *testing.T, workflow, old, replacement string) string {
	t.Helper()
	section, ok := workflowSection(workflow, "  review:\n", "  deterministic-review:\n")
	if !ok || !strings.Contains(section, old) {
		t.Fatalf("core job fixture missing %q", old)
	}
	return strings.Replace(workflow, section, strings.Replace(section, old, replacement, 1), 1)
}

func containsError(values []string, target string) bool {
	for _, value := range values {
		if strings.Contains(value, target) {
			return true
		}
	}
	return false
}
