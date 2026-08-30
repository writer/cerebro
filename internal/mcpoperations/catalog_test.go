package mcpoperations

import "testing"

func TestCatalogOperationsAreCompleteAndSorted(t *testing.T) {
	operations := Operations()
	if len(operations) == 0 {
		t.Fatal("Operations() empty")
	}
	for i, operation := range operations {
		if operation.Name == "" || operation.OwnerDomain == "" || operation.ResponseContract == "" {
			t.Fatalf("operation %d is incomplete: %#v", i, operation)
		}
		if operation.Behavior != BehaviorRead && operation.Behavior != BehaviorPropose && operation.Behavior != BehaviorExecute {
			t.Fatalf("operation %q behavior = %q", operation.Name, operation.Behavior)
		}
		if operation.Classification != ClassificationTask && operation.Classification != ClassificationExpert {
			t.Fatalf("operation %q classification = %q", operation.Name, operation.Classification)
		}
		if len(operation.RequiredScopes) == 0 {
			t.Fatalf("operation %q has no required scopes", operation.Name)
		}
		if i > 0 && operations[i-1].Name >= operation.Name {
			t.Fatalf("operations are not strictly sorted: %q before %q", operations[i-1].Name, operation.Name)
		}
	}
}

func TestAssessmentExecutionToolsRequireReadAndWriteScopes(t *testing.T) {
	for _, name := range []string{
		"cerebro.assessments.plan.create",
		"cerebro.assessments.plan.publish",
		"cerebro.assessments.run.request",
	} {
		operation, ok := Lookup(name)
		if !ok {
			t.Fatalf("Lookup(%q) missing", name)
		}
		if operation.Behavior != BehaviorExecute {
			t.Fatalf("Lookup(%q).Behavior = %q, want %q", name, operation.Behavior, BehaviorExecute)
		}
		if len(operation.RequiredScopes) != 2 || operation.RequiredScopes[0] != ScopeSecurityRead || operation.RequiredScopes[1] != ScopeGRCInventoryWrite {
			t.Fatalf("Lookup(%q).RequiredScopes = %#v", name, operation.RequiredScopes)
		}
	}
	if got := ToolsetForName("cerebro.assessments.run.get"); got != "assessments" {
		t.Fatalf("ToolsetForName(assessment) = %q, want assessments", got)
	}
}

func TestTaskProfileIsBoundedAndContainsNoExecution(t *testing.T) {
	tasks := TaskTools()
	if len(tasks) != 8 {
		t.Fatalf("task tools = %d, want 8", len(tasks))
	}
	for _, operation := range tasks {
		if operation.Name == "cerebro.action.execute" || operation.Behavior == "execute" {
			t.Fatalf("task profile exposes execution: %#v", operation)
		}
	}
	for _, name := range []string{
		"cerebro.findings.search",
		"cerebro.assets.search",
		"cerebro.graph.reason",
		"cerebro.investigation.context",
		"cerebro.risk.explain",
		"cerebro.evidence.packet",
		"cerebro.sources.health",
		"cerebro.action.plan",
	} {
		if !IsTaskTool(name) {
			t.Fatalf("task profile missing %s", name)
		}
	}
}

func TestRuntimeToolsRequireAnExpertOrFullProfile(t *testing.T) {
	for _, name := range []string{"cerebro.health", "cerebro.version"} {
		operation, ok := Lookup(name)
		if !ok || operation.Classification != ClassificationExpert {
			t.Fatalf("Lookup(%q) = %#v, %t; want expert operation", name, operation, ok)
		}
		if IsTaskTool(name) || EnabledForToolsets(name, Toolsets{"task": true}) {
			t.Fatalf("task profile unexpectedly enables %q", name)
		}
		if !EnabledForToolsets(name, Toolsets{"expert": true}) {
			t.Fatalf("expert profile does not enable %q", name)
		}
		if !EnabledForToolsets(name, Toolsets{"full": true}) {
			t.Fatalf("full profile does not enable %q", name)
		}
	}
}

func TestToolsetProfilesPreserveDomainAndFullSelection(t *testing.T) {
	toolsets := ParseToolsets("task, graph", []byte(`{"toolsets":["expert"]}`))
	for _, name := range []string{"task", "graph", "expert"} {
		if !toolsets[name] {
			t.Fatalf("toolsets = %#v, want %q", toolsets, name)
		}
	}
	if !EnabledForToolsets("cerebro.risk.explain", toolsets) || !EnabledForToolsets("cerebro.graph.reason", toolsets) || !EnabledForToolsets("cerebro.sources.list", toolsets) {
		t.Fatalf("profile selection rejected an enabled task, graph, or expert tool")
	}
	for _, profile := range []string{"full", "all"} {
		parsed := ParseToolsets(profile, nil)
		if !parsed["full"] || !EnabledForToolsets("cerebro.assessments.plan.create", parsed) {
			t.Fatalf("%s must select the full compatibility profile: %#v", profile, parsed)
		}
	}
}

func TestOperationsToolsetIncludesConnectorCertification(t *testing.T) {
	toolsets := Toolsets{"operations": true}
	if got := ToolsetForName("cerebro.connectors.list"); got != "operations" {
		t.Fatalf("ToolsetForName(cerebro.connectors.list) = %q, want operations", got)
	}
	if !EnabledForToolsets("cerebro.connectors.list", toolsets) {
		t.Fatal("operations toolset rejected cerebro.connectors.list")
	}
}

func TestToolFamilySanitizesTelemetryValue(t *testing.T) {
	t.Parallel()

	if got := ToolFamily("cerebro.bad\nfamily.tool"); got != "bad family" {
		t.Fatalf("ToolFamily() = %q, want %q", got, "bad family")
	}
}
