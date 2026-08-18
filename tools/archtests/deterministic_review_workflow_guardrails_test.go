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
	gateBody, err := os.ReadFile(filepath.Join(root, "scripts", "govulncheck_gate.py"))
	if err != nil {
		t.Fatalf("read govulncheck gate: %v", err)
	}

	if errors := deterministicReviewGuardrailErrors(string(workflowBody), string(gateBody)); len(errors) != 0 {
		t.Fatalf("deterministic review guardrails failed:\n- %s", strings.Join(errors, "\n- "))
	}
}

func TestDeterministicReviewGuardrailsRejectUnsafeChanges(t *testing.T) {
	root := repoRoot(t)
	workflowBody, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "deterministic-review.yml"))
	if err != nil {
		t.Fatalf("read deterministic review workflow: %v", err)
	}
	gateBody, err := os.ReadFile(filepath.Join(root, "scripts", "govulncheck_gate.py"))
	if err != nil {
		t.Fatalf("read govulncheck gate: %v", err)
	}
	workflow := string(workflowBody)
	gate := string(gateBody)

	tests := []struct {
		name      string
		workflow  string
		gate      string
		wantError string
	}{
		{
			name:      "make target replaces bounded Go-only gate",
			workflow:  strings.Replace(workflow, "python3 scripts/govulncheck_gate.py ./...", "make govulncheck", 1),
			gate:      gate,
			wantError: "invoke the direct full-repository govulncheck gate exactly once",
		},
		{
			name:      "gate runs twice",
			workflow:  strings.Replace(workflow, "python3 scripts/govulncheck_gate.py ./...", "python3 scripts/govulncheck_gate.py ./...\n          python3 scripts/govulncheck_gate.py ./...", 1),
			gate:      gate,
			wantError: "invoke the direct full-repository govulncheck gate exactly once",
		},
		{
			name:      "scan narrows package scope",
			workflow:  strings.Replace(workflow, "python3 scripts/govulncheck_gate.py ./...", "python3 scripts/govulncheck_gate.py ./cmd/...", 1),
			gate:      gate,
			wantError: "invoke the direct full-repository govulncheck gate exactly once",
		},
		{
			name:      "core checkout is not exact head",
			workflow:  replaceInCoreJob(t, workflow, `ref: ${{ github.event.pull_request.head.sha }}`, `ref: ${{ github.sha }}`),
			gate:      gate,
			wantError: "core job must check out the exact pull request head",
		},
		{
			name:      "vulnerability checkout is not exact head",
			workflow:  replaceInVulnerabilityJob(t, workflow, `ref: ${{ github.event.pull_request.head.sha }}`, `ref: ${{ github.sha }}`),
			gate:      gate,
			wantError: "vulnerability job must check out the exact pull request head",
		},
		{
			name:      "vulnerability checkout persists credentials",
			workflow:  replaceInVulnerabilityJob(t, workflow, "persist-credentials: false", "persist-credentials: true"),
			gate:      gate,
			wantError: "vulnerability checkout must disable persisted credentials",
		},
		{
			name:      "workflow requests write access",
			workflow:  strings.Replace(workflow, "permissions:\n  contents: read", "permissions:\n  contents: write", 1),
			gate:      gate,
			wantError: "workflow must declare read-only contents permission",
		},
		{
			name:      "aggregate accepts vulnerability failure",
			workflow:  strings.Replace(workflow, `test "${VULNERABILITY_RESULT}" = success`, `test "${VULNERABILITY_RESULT}" != cancelled`, 1),
			gate:      gate,
			wantError: "aggregate must require vulnerability success",
		},
		{
			name:      "scanner version is unpinned",
			workflow:  workflow,
			gate:      strings.Replace(gate, "golang.org/x/vuln/cmd/govulncheck@v1.1.4", "golang.org/x/vuln/cmd/govulncheck@latest", 1),
			wantError: "gate must pin govulncheck v1.1.4",
		},
		{
			name:      "scanner drops requested patterns",
			workflow:  workflow,
			gate:      strings.Replace(gate, `"json", *patterns`, `"json"`, 1),
			wantError: "gate must pass the exact requested package patterns",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errors := deterministicReviewGuardrailErrors(test.workflow, test.gate)
			if !containsError(errors, test.wantError) {
				t.Fatalf("expected error %q, got %v", test.wantError, errors)
			}
		})
	}
}

func deterministicReviewGuardrailErrors(workflow, gate string) []string {
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
		`./scripts/leak_check.sh range "${REVIEW_BASE}...${REVIEW_HEAD}"`,
		`git diff --name-only --diff-filter=ACMR "${REVIEW_BASE}...${REVIEW_HEAD}"`,
		"actionlint .github/workflows/deterministic-review.yml",
		"zizmor .github/workflows/deterministic-review.yml",
		"make deterministic-review",
		"semgrep scan",
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
	if strings.Contains(workflow, ": write") {
		errors = append(errors, "workflow must not request any write permission")
	}

	coreJob, ok := workflowSection(workflow, "  review:\n", "  vulnerability_review:\n")
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

	vulnerabilityJob, ok := workflowSection(workflow, "  vulnerability_review:\n", "  deterministic-review:\n")
	if !ok {
		errors = append(errors, "workflow must define separate vulnerability and aggregate jobs")
	} else {
		if !strings.Contains(vulnerabilityJob, `ref: ${{ github.event.pull_request.head.sha }}`) {
			errors = append(errors, "vulnerability job must check out the exact pull request head")
		}
		if !strings.Contains(vulnerabilityJob, "persist-credentials: false") {
			errors = append(errors, "vulnerability checkout must disable persisted credentials")
		}
		for _, marker := range []string{"make ", "cargo ", "rustup "} {
			if strings.Contains(vulnerabilityJob, marker) {
				errors = append(errors, fmt.Sprintf("vulnerability job must remain Go-only and must not contain %q", marker))
			}
		}
	}

	if strings.Count(workflow, "python3 scripts/govulncheck_gate.py") != 1 ||
		strings.Count(workflow, "python3 scripts/govulncheck_gate.py ./...") != 1 {
		errors = append(errors, "workflow must invoke the direct full-repository govulncheck gate exactly once")
	}
	if strings.Contains(workflow, "make govulncheck") {
		errors = append(errors, "workflow must not route the vulnerability job through the multi-tool Make target")
	}
	if !strings.Contains(gate, `DEFAULT_TOOL = "golang.org/x/vuln/cmd/govulncheck@v1.1.4"`) {
		errors = append(errors, "gate must pin govulncheck v1.1.4")
	}
	if !strings.Contains(gate, `command = ["go", "run", DEFAULT_TOOL, "-format", "json", *patterns]`) {
		errors = append(errors, "gate must pass the exact requested package patterns")
	}
	if !strings.Contains(gate, `parser.add_argument("patterns", nargs="*", default=["./..."])`) {
		errors = append(errors, "gate must default to the full repository package pattern")
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
			{"- review", "aggregate must depend on the core review job"},
			{"- vulnerability_review", "aggregate must depend on the vulnerability review job"},
			{`test "${REVIEW_RESULT}" = success`, "aggregate must require core review success"},
			{`test "${VULNERABILITY_RESULT}" = success`, "aggregate must require vulnerability success"},
		} {
			if !strings.Contains(aggregate, requirement.marker) {
				errors = append(errors, requirement.error)
			}
		}
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

func replaceInVulnerabilityJob(t *testing.T, workflow, old, replacement string) string {
	t.Helper()
	section, ok := workflowSection(workflow, "  vulnerability_review:\n", "  deterministic-review:\n")
	if !ok || !strings.Contains(section, old) {
		t.Fatalf("vulnerability job fixture missing %q", old)
	}
	return strings.Replace(workflow, section, strings.Replace(section, old, replacement, 1), 1)
}

func replaceInCoreJob(t *testing.T, workflow, old, replacement string) string {
	t.Helper()
	section, ok := workflowSection(workflow, "  review:\n", "  vulnerability_review:\n")
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
