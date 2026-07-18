package main

import (
	"context"
	"fmt"
	"os"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphstore/neo4j"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const tenantID = "e2e-local"
const adminURN = "urn:cerebro:e2e-local:identity:privileged"
const appURN = "urn:cerebro:e2e-local:application:admin-console"
const repoURN = "urn:cerebro:e2e-local:repository:public-protected"
const guestURN = "urn:cerebro:e2e-local:identity:external-collaborator"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	seedPostgres(ctx, now)
	seedNeo4j(ctx)
	fmt.Println("seeded local GRC E2E stores")
}

func seedPostgres(ctx context.Context, now time.Time) {
	store, err := postgres.Open(config.StateStoreConfig{PostgresDSN: os.Getenv("CEREBRO_POSTGRES_DSN")})
	must(err)
	defer func() { _ = store.Close() }()
	must(store.Ping(ctx))
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "e2e-identity", SourceId: "identity", TenantId: tenantID, LastSyncedAt: timestamppb.New(now.Add(-5 * time.Minute))},
		{Id: "e2e-code", SourceId: "code", TenantId: tenantID, LastSyncedAt: timestamppb.New(now.Add(-4 * time.Minute))},
		{Id: "e2e-collaboration", SourceId: "collaboration", TenantId: tenantID, LastSyncedAt: timestamppb.New(now.Add(-3 * time.Minute))},
	}
	must(store.PutSourceRuntimes(ctx, runtimes))
	findings := []*ports.FindingRecord{
		{ID: "e2e-finding-critical", Fingerprint: "e2e-fp-critical", TenantID: tenantID, RuntimeID: "e2e-identity", RuleID: "identity.privileged_verification_missing", Title: "Privileged identity missing verification", Severity: "critical", Status: "open", Summary: "Seeded critical GRC finding for local E2E.", ResourceURNs: []string{adminURN}, EventIDs: []string{"evt-e2e-1"}, ObservedPolicyIDs: []string{"SOC2-CC6.1"}, PolicyID: "SOC2-CC6.1", PolicyName: "Logical Access", CheckID: "CC6.1-MFA", CheckName: "Privileged MFA", ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC6.1"}}, FindingRisk: ports.FindingRisk{RiskScore: 92, LikelihoodScore: 90, ImpactScore: 95, ConfidenceScore: 95, LikelihoodLevel: "critical", ImpactLevel: "critical", RiskModelVersion: findinganalysis.FindingRiskModelVersion}, Attributes: map[string]string{"owner": "security", "source": "identity"}, FindingWorkflow: ports.FindingWorkflow{DueAt: now.Add(-24 * time.Hour)}, FirstObservedAt: now.Add(-48 * time.Hour), LastObservedAt: now.Add(-2 * time.Minute)},
		{ID: "e2e-finding-high", Fingerprint: "e2e-fp-high", TenantID: tenantID, RuntimeID: "e2e-code", RuleID: "repo.public_sensitive", Title: "Public repository contains sensitive path", Severity: "high", Status: "open", Summary: "Seeded high finding to verify batching across runtimes.", ResourceURNs: []string{repoURN}, EventIDs: []string{"evt-e2e-2"}, ObservedPolicyIDs: []string{"SOC2-CC7.2"}, PolicyID: "SOC2-CC7.2", PolicyName: "Monitoring", CheckID: "CC7.2-REPO", CheckName: "Repository Exposure", ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC2", ControlID: "CC7.2"}}, FindingRisk: ports.FindingRisk{RiskScore: 74, LikelihoodScore: 70, ImpactScore: 80, ConfidenceScore: 90, LikelihoodLevel: "high", ImpactLevel: "high", RiskModelVersion: findinganalysis.FindingRiskModelVersion}, Attributes: map[string]string{"owner": "application-security", "source": "code"}, FindingWorkflow: ports.FindingWorkflow{Assignee: "owner@example.org", DueAt: now.Add(48 * time.Hour)}, FirstObservedAt: now.Add(-36 * time.Hour), LastObservedAt: now.Add(-1 * time.Minute)},
		{ID: "e2e-finding-medium", Fingerprint: "e2e-fp-medium", TenantID: tenantID, RuntimeID: "e2e-collaboration", RuleID: "collaboration.external_sponsor_missing", Title: "External collaborator lacks sponsor", Severity: "medium", Status: "open", Summary: "Seeded medium finding for UI table coverage.", ResourceURNs: []string{guestURN}, EventIDs: []string{"evt-e2e-3"}, ObservedPolicyIDs: []string{"ISO-A.5.15"}, PolicyID: "ISO-A.5.15", PolicyName: "Access Control", CheckID: "A.5.15-GUEST", CheckName: "External Guest Review", ControlRefs: []ports.FindingControlRef{{FrameworkName: "ISO27001", ControlID: "A.5.15"}}, FindingRisk: ports.FindingRisk{RiskScore: 45, LikelihoodScore: 45, ImpactScore: 45, ConfidenceScore: 85, LikelihoodLevel: "medium", ImpactLevel: "medium", RiskModelVersion: findinganalysis.FindingRiskModelVersion}, Attributes: map[string]string{"owner": "operations", "source": "collaboration"}, FindingWorkflow: ports.FindingWorkflow{Assignee: "operations@example.org"}, FirstObservedAt: now.Add(-24 * time.Hour), LastObservedAt: now.Add(-30 * time.Second)},
		{ID: "e2e-finding-resolved", Fingerprint: "e2e-fp-resolved", TenantID: tenantID, RuntimeID: "e2e-identity", RuleID: "identity.stale_account", Title: "Resolved stale account", Severity: "low", Status: "resolved", Summary: "Seeded resolved finding to validate summary excludes closed issues.", ResourceURNs: []string{"urn:cerebro:e2e-local:identity:former"}, EventIDs: []string{"evt-e2e-4"}, FindingRisk: ports.FindingRisk{RiskScore: 10, LikelihoodScore: 10, ImpactScore: 10, ConfidenceScore: 80, LikelihoodLevel: "low", ImpactLevel: "low", RiskModelVersion: findinganalysis.FindingRiskModelVersion}, Attributes: map[string]string{"owner": "security", "source": "identity"}, FindingWorkflow: ports.FindingWorkflow{Assignee: "security@example.org", StatusReason: "fixed in seed", StatusUpdatedAt: now.Add(-1 * time.Hour)}, FirstObservedAt: now.Add(-72 * time.Hour), LastObservedAt: now.Add(-1 * time.Hour)},
	}
	for _, finding := range findings {
		_, err := store.UpsertFinding(ctx, finding)
		must(err)
	}
	evidence := []*cerebrov1.FindingEvidence{
		{Id: "e2e-evidence-1", RuntimeId: "e2e-identity", RuleId: "identity.privileged_verification_missing", FindingId: "e2e-finding-critical", RunId: "e2e-run-1", EventIds: []string{"evt-e2e-1"}, GraphRootUrns: []string{adminURN}, Attributes: map[string]string{"kind": "identity"}, CreatedAt: timestamppb.New(now.Add(-2 * time.Minute)), LastObservedAt: timestamppb.New(now.Add(-2 * time.Minute))},
		{Id: "e2e-evidence-2", RuntimeId: "e2e-code", RuleId: "repo.public_sensitive", FindingId: "e2e-finding-high", RunId: "e2e-run-2", EventIds: []string{"evt-e2e-2"}, GraphRootUrns: []string{repoURN}, Attributes: map[string]string{"kind": "repository"}, CreatedAt: timestamppb.New(now.Add(-1 * time.Minute)), LastObservedAt: timestamppb.New(now.Add(-1 * time.Minute))},
		{Id: "e2e-evidence-3", RuntimeId: "e2e-collaboration", RuleId: "collaboration.external_sponsor_missing", FindingId: "e2e-finding-medium", RunId: "e2e-run-3", EventIds: []string{"evt-e2e-3"}, GraphRootUrns: []string{guestURN}, Attributes: map[string]string{"kind": "collaboration"}, CreatedAt: timestamppb.New(now.Add(-30 * time.Second)), LastObservedAt: timestamppb.New(now.Add(-30 * time.Second))},
	}
	for _, record := range evidence {
		must(store.PutFindingEvidence(ctx, record))
	}
}

func seedNeo4j(ctx context.Context) {
	store, err := neo4j.Open(config.GraphStoreConfig{Neo4jURI: os.Getenv("CEREBRO_NEO4J_URI"), Neo4jUsername: os.Getenv("CEREBRO_NEO4J_USERNAME"), Neo4jPassword: os.Getenv("CEREBRO_NEO4J_PASSWORD")})
	must(err)
	defer func() { _ = store.CloseContext(ctx) }()
	must(store.Ping(ctx))
	entities := []*ports.ProjectedEntity{
		{URN: adminURN, TenantID: tenantID, SourceID: "identity", RuntimeID: "e2e-identity", EntityType: "identity_user", Label: "privileged identity", Attributes: map[string]string{"email": "privileged@example.org"}},
		{URN: appURN, TenantID: tenantID, SourceID: "identity", RuntimeID: "e2e-identity", EntityType: "application", Label: "Privileged Admin Console", Attributes: map[string]string{"criticality": "high"}},
		{URN: repoURN, TenantID: tenantID, SourceID: "code", RuntimeID: "e2e-code", EntityType: "repository", Label: "public-protected", Attributes: map[string]string{"visibility": "public"}},
		{URN: guestURN, TenantID: tenantID, SourceID: "collaboration", RuntimeID: "e2e-collaboration", EntityType: "identity_user", Label: "external collaborator", Attributes: map[string]string{"external": "true"}},
	}
	for _, entity := range entities {
		must(store.UpsertProjectedEntity(ctx, entity))
	}
	links := []*ports.ProjectedLink{
		{TenantID: tenantID, SourceID: "identity", RuntimeID: "e2e-identity", FromURN: adminURN, ToURN: appURN, Relation: "admin_of", Attributes: map[string]string{"e2e": "true"}},
		{TenantID: tenantID, SourceID: "code", RuntimeID: "e2e-code", FromURN: adminURN, ToURN: repoURN, Relation: "can_access", Attributes: map[string]string{"e2e": "true"}},
		{TenantID: tenantID, SourceID: "collaboration", RuntimeID: "e2e-collaboration", FromURN: guestURN, ToURN: adminURN, Relation: "collaborates_with", Attributes: map[string]string{"e2e": "true"}},
	}
	for _, link := range links {
		must(store.UpsertProjectedLink(ctx, link))
	}
	neighborhood, err := store.GetEntityNeighborhood(ctx, adminURN, 10)
	must(err)
	if neighborhood.Root == nil || len(neighborhood.Neighbors) < 2 || len(neighborhood.Relations) < 2 {
		panic("seeded graph neighborhood is incomplete")
	}
}
