package github

import (
	"os"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceprojection"
)

func TestCheckedInGoOraclesReachBespokeGitHubProjections(t *testing.T) {
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read GitHub catalog: %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("load GitHub catalog: %v", err)
	}
	for _, family := range []string{
		familyAudit,
		familyRepository,
		familyDependabot,
		familyOrgInventory,
		familyPullRequest,
		familySecretScanning,
	} {
		t.Run(family, func(t *testing.T) {
			events, err := sourcecdk.LoadFixtureEventsWithContracts(
				os.DirFS("."),
				"testdata/read_"+family+".json",
				catalog.EventContracts,
			)
			if err != nil {
				t.Fatalf("load %s Go oracle: %v", family, err)
			}
			if len(events) == 0 {
				t.Fatalf("%s Go oracle has no events", family)
			}
			for _, event := range events {
				entities, links, err := sourceprojection.ProjectEvent(event)
				if err != nil {
					t.Fatalf("project %s event %s: %v", event.Kind, event.Id, err)
				}
				if len(entities) == 0 && len(links) == 0 {
					t.Fatalf("project %s event %s produced no graph delta", event.Kind, event.Id)
				}
			}
		})
	}
}
