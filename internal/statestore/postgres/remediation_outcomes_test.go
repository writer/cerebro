package postgres

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestRemediationOutcomeListQueryRequiresTenantAndBoundsLimit(t *testing.T) {
	if _, _, err := remediationOutcomeListQuery(ports.ListRemediationOutcomesRequest{}); err == nil {
		t.Fatal("remediationOutcomeListQuery() error = nil, want tenant error")
	}
	query, args, err := remediationOutcomeListQuery(ports.ListRemediationOutcomesRequest{
		TenantID: "tenant-a", FindingID: "finding-1", RuleID: "rule-1", Limit: 1000,
	})
	if err != nil {
		t.Fatalf("remediationOutcomeListQuery() error = %v", err)
	}
	for _, predicate := range []string{"tenant_id = $1", "finding_id = $2", "rule_id = $3", "LIMIT $4"} {
		if !strings.Contains(query, predicate) {
			t.Fatalf("query missing %q: %s", predicate, query)
		}
	}
	if got := args[len(args)-1]; got != uint32(50) {
		t.Fatalf("bounded limit = %#v, want 50", got)
	}
}

func TestResolutionEpisodeUpsertRejectsOlderReplay(t *testing.T) {
	for _, predicate := range []string{
		"EXCLUDED.as_of > platform_resolution_episodes.as_of",
		"EXCLUDED.revision_digest > platform_resolution_episodes.revision_digest",
	} {
		if !strings.Contains(resolutionEpisodeNewerObservationGuard, predicate) {
			t.Fatalf("episode upsert guard missing %q: %s", predicate, resolutionEpisodeNewerObservationGuard)
		}
	}
}

func TestRemediationOutcomeDDLUsesExistingPostgresBoundaryAndSafetyChecks(t *testing.T) {
	ddl := strings.Join(ensureRemediationOutcomeStatements, "\n")
	for _, contract := range []string{
		"PRIMARY KEY (tenant_id, id)",
		"UNIQUE (tenant_id, digest)",
		"CHECK (NOT verified_resolution OR verification_state = 'verified_closed')",
		"CHECK (verification_state <> 'censored' OR censored_reason <> '')",
		"PRIMARY KEY (tenant_id, episode_id)",
		"resolution_type <> 'verified'",
	} {
		if !strings.Contains(ddl, contract) {
			t.Fatalf("remediation DDL missing %q", contract)
		}
	}
}
