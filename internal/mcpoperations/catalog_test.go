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
		if operation.Behavior != BehaviorRead && operation.Behavior != BehaviorPropose {
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

func TestTaskProfileIsBoundedAndContainsNoExecution(t *testing.T) {
	tasks := TaskTools()
	if len(tasks) > 8 {
		t.Fatalf("task tools = %d, want at most 8", len(tasks))
	}
	for _, operation := range tasks {
		if operation.Name == "cerebro.action.execute" || operation.Behavior == "execute" {
			t.Fatalf("task profile exposes execution: %#v", operation)
		}
	}
	for _, name := range []string{"cerebro.health", "cerebro.version", "cerebro.risk.explain", "cerebro.evidence.packet", "cerebro.sources.health", "cerebro.action.plan"} {
		if !IsTaskTool(name) {
			t.Fatalf("task profile missing %s", name)
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
	if len(ParseToolsets("full", nil)) != 0 || len(ParseToolsets("all", nil)) != 0 {
		t.Fatalf("full and all must preserve the default unfiltered profile")
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
