package archtests

import (
	"path/filepath"
	"testing"
)

// connectorSetupFileLineBudgets keep the connection workflow from returning to
// one multi-thousand-line component. New stateful sections belong in focused
// sibling components; tightening these ceilings after later splits is expected.
var connectorSetupFileLineBudgets = map[string]int{
	"ConnectorSetupForm.tsx":             1825,
	"ConnectorCredentialBrokerPanel.tsx": 350,
	"ConnectorScopePolicyBuilder.tsx":    350,
}

func TestConnectorSetupComponentsDoNotGrow(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "apps", "web", "src", "components", "connectors")
	for name, budget := range connectorSetupFileLineBudgets {
		lines := countLines(t, filepath.Join(dir, name))
		if lines > budget {
			t.Errorf(
				"apps/web connector setup component %s grew to %d lines, budget %d; move the new behavior into a focused sibling component instead of raising the ceiling",
				name,
				lines,
				budget,
			)
		}
	}
}
