package assetrisk

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

const testTenant = "writer"

type fakeGraph struct {
	entities  map[string]ports.CatalogEntity
	relations map[string][]ports.EntityCatalogRelation
	calls     int
}

func newFakeGraph() *fakeGraph {
	return &fakeGraph{entities: map[string]ports.CatalogEntity{}, relations: map[string][]ports.EntityCatalogRelation{}}
}

func (g *fakeGraph) add(urn, kind string, attrs map[string]string) {
	g.entities[urn] = ports.CatalogEntity{URN: urn, TenantID: testTenant, EntityType: kind, Label: urn, Attributes: attrs}
}

// link records from -relation-> to, visible from both ends.
func (g *fakeGraph) link(from, relation, to string) {
	g.relations[from] = append(g.relations[from], ports.EntityCatalogRelation{Direction: ports.EntityRelationOutgoing, Relation: relation, Entity: g.entities[to]})
	g.relations[to] = append(g.relations[to], ports.EntityCatalogRelation{Direction: ports.EntityRelationIncoming, Relation: relation, Entity: g.entities[from]})
}

func (g *fakeGraph) ListEntities(_ context.Context, request ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	page := &ports.EntityCatalogPage{TenantID: request.Filter.TenantID, GraphRevision: 7}
	if entity, ok := g.entities[request.Filter.ExactAgentKey]; ok {
		page.Entities = []ports.CatalogEntity{entity}
	}
	return page, nil
}

func (g *fakeGraph) ListEntityRelations(_ context.Context, request ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	g.calls++
	allowed := map[string]bool{}
	for _, relation := range request.Relations {
		allowed[relation] = true
	}
	page := &ports.EntityRelationPage{TenantID: request.TenantID}
	for _, relation := range g.relations[request.AgentKey] {
		if allowed[relation.Relation] {
			page.Relations = append(page.Relations, relation)
		}
	}
	return page, nil
}

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func TestDefaultModelIsValid(t *testing.T) {
	if err := ValidateModel(DefaultModel(testTenant)); err != nil {
		t.Fatalf("ValidateModel(default) error = %v", err)
	}
	if Version(DefaultModel(testTenant), false) != ModelVersion {
		t.Fatal("unsaved model should report the built-in version")
	}
}

func TestDecodeModelReplacesPresentSectionsAndKeepsAbsentOnes(t *testing.T) {
	model, err := DecodeModel(testTenant, []byte(`{
		"asset_value": {"default": 0.3, "crown_jewel": 1, "production_boost": 0, "classification_attributes": ["Data_Classification"], "classifications": {"Restricted": 1}},
		"countermeasures": [],
		"relations": {"can_admin": {"probability": 0.5}}
	}`))
	if err != nil {
		t.Fatalf("DecodeModel() error = %v", err)
	}
	defaults := DefaultModel(testTenant)
	if len(model.AssetValue.Classifications) != 1 || model.AssetValue.Classifications["restricted"] != 1 {
		t.Fatalf("classifications = %#v, want only restricted", model.AssetValue.Classifications)
	}
	if len(model.AssetValue.KindValues) != len(defaults.AssetValue.KindValues) {
		t.Fatal("absent kind_values should keep defaults")
	}
	if model.AssetValue.ClassificationAttributes[0] != "data_classification" {
		t.Fatalf("classification attributes not normalized: %#v", model.AssetValue.ClassificationAttributes)
	}
	if len(model.Countermeasures) != 0 {
		t.Fatalf("countermeasures = %#v, want none", model.Countermeasures)
	}
	if len(model.Relations) != 1 || model.Relations["can_admin"].Direction != DirectionOutgoing {
		t.Fatalf("relations = %#v", model.Relations)
	}
	if model.Vulnerability.KnownExploited != defaults.Vulnerability.KnownExploited || len(model.Vulnerability.Relations) != 1 {
		t.Fatal("absent vulnerability section should keep defaults")
	}
	if Version(model, true) == ModelVersion {
		t.Fatal("saved model should report a content-addressed version")
	}
}

func TestDecodeModelRejectsInvalidValues(t *testing.T) {
	cases := map[string]string{
		"fraction":       `{"exposure": {"entry_probability": 1.5}}`,
		"direction":      `{"relations": {"can_admin": {"probability": 0.5, "direction": "sideways"}}}`,
		"cvss":           `{"vulnerability": {"cvss_critical": 6, "cvss_high": 7}}`,
		"duplicate":      `{"countermeasures": [{"key": "mfa", "attributes": ["a"], "reduction": 0.1}, {"key": "MFA", "attributes": ["b"], "reduction": 0.1}]}`,
		"no attributes":  `{"countermeasures": [{"key": "mfa", "attributes": [], "reduction": 0.1}]}`,
		"thresholds":     `{"thresholds": {"critical": 10, "high": 20, "medium": 5}}`,
		"depth":          `{"traversal": {"max_depth": 9, "max_paths": 10, "max_expansions": 10}}`,
		"no relations":   `{"relations": {}}`,
		"vuln as a step": `{"relations": {"affected_by": {"probability": 0.5}}}`,
		"malformed":      `{"relations": `,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeModel(testTenant, []byte(document)); !errors.Is(err, ErrInvalidModel) {
				t.Fatalf("DecodeModel() error = %v, want ErrInvalidModel", err)
			}
		})
	}
}

func TestAssetValueUsesKindClassificationCrownJewelAndProduction(t *testing.T) {
	model := DefaultModel(testTenant)
	cases := []struct {
		name   string
		entity ports.CatalogEntity
		want   float64
	}{
		{"unknown kind uses default", ports.CatalogEntity{EntityType: "widget"}, 0.2},
		{"segment match", ports.CatalogEntity{EntityType: "aws.rds_database"}, 0.8},
		{"classification raises", ports.CatalogEntity{EntityType: "aws.s3_bucket", Attributes: map[string]string{"data_classification": "Confidential"}}, 0.85},
		{"classification never lowers", ports.CatalogEntity{EntityType: "secret", Attributes: map[string]string{"classification": "public"}}, 0.9},
		{"crown jewel", ports.CatalogEntity{EntityType: "widget", Attributes: map[string]string{"crown_jewel": "true"}}, 1},
		{"production boost", ports.CatalogEntity{EntityType: "github.repository", Attributes: map[string]string{"environment": "production"}}, 0.75},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := AssetValue(model, tc.entity)
			approx(t, "value", got, tc.want)
		})
	}
}

func TestScoreVulnerabilityTakesStrongestSignal(t *testing.T) {
	model := DefaultModel(testTenant)
	vuln := func(attrs map[string]string, edge map[string]string) VulnerabilityInput {
		return VulnerabilityInput{Entity: ports.CatalogEntity{URN: "urn:vuln", EntityType: "vulnerability", Attributes: attrs}, EdgeAttributes: edge}
	}
	cases := []struct {
		name  string
		input VulnerabilityInput
		want  float64
	}{
		{"no intel", vuln(nil, nil), 0.05},
		{"epss", vuln(map[string]string{"epss_score": "0.42"}, nil), 0.42},
		{"cvss critical", vuln(map[string]string{"cvss_score": "9.8"}, nil), 0.3},
		{"severity fallback", vuln(map[string]string{"severity": "HIGH"}, nil), 0.15},
		{"kev beats epss", vuln(map[string]string{"epss_score": "0.4", "known_exploited": "true"}, nil), 0.85},
		{"ransomware", vuln(map[string]string{"known_exploited": "true", "kev_ransomware_use": "Known"}, nil), 0.95},
		{"edge carries intel", vuln(nil, map[string]string{"epss": "0.6"}), 0.6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signal, ok := ScoreVulnerability(model, tc.input)
			if !ok {
				t.Fatal("ScoreVulnerability() skipped an open vulnerability")
			}
			approx(t, "probability", signal.Probability, tc.want)
		})
	}
	if _, ok := ScoreVulnerability(model, vuln(map[string]string{"known_exploited": "true"}, map[string]string{"status": "fixed"})); ok {
		t.Fatal("fixed vulnerability should be skipped")
	}
}

func TestAssessEntityCombinesVulnerabilitiesAndCountermeasures(t *testing.T) {
	model := DefaultModel(testTenant)
	host := ports.CatalogEntity{URN: "urn:host", EntityType: "aws.ec2_instance", Attributes: map[string]string{"edr_active": "true", "public_ip": "true"}}
	vulns := []VulnerabilityInput{
		{Entity: ports.CatalogEntity{URN: "urn:v1", Attributes: map[string]string{"epss_score": "0.5"}}},
		{Entity: ports.CatalogEntity{URN: "urn:v2", Attributes: map[string]string{"epss_score": "0.5"}}},
	}
	node := AssessEntity(model, host, vulns, true)
	approx(t, "exploit", node.ExploitProbability, 0.75)
	approx(t, "countermeasure factor", node.CountermeasureFactor, 0.5)
	if node.Exposure != ExposureInternet || len(node.Countermeasures) != 1 || node.Countermeasures[0].Key != "edr" {
		t.Fatalf("assessment = %#v", node)
	}
	// 1 - (1-0.2)(1-0.75*1.0) = 0.8, halved by EDR.
	approx(t, "entry", EntryProbability(model, node), 0.4)

	empty := AssessEntity(model, ports.CatalogEntity{URN: "urn:host2", EntityType: "host"}, nil, true)
	approx(t, "no known vulnerability", empty.ExploitProbability, model.Vulnerability.NoKnownVulnerability)
}

func TestMFAOnlyAppliesToIdentityKinds(t *testing.T) {
	model := DefaultModel(testTenant)
	_, identityFactor := Countermeasures(model, ports.CatalogEntity{EntityType: "okta.user", Attributes: map[string]string{"mfa_enabled": "true"}})
	_, bucketFactor := Countermeasures(model, ports.CatalogEntity{EntityType: "aws.s3_bucket", Attributes: map[string]string{"mfa_enabled": "true"}})
	approx(t, "identity", identityFactor, 0.4)
	approx(t, "bucket", bucketFactor, 1)
}

// admin person -> owns workstation (KEV) ; admin identity -> can_admin app -> can_reach db host.
func adminGraph() *fakeGraph {
	g := newFakeGraph()
	g.add("urn:person:admin", "person", nil)
	g.add("urn:okta:user:admin", "okta.user", nil)
	g.add("urn:device:laptop", "device", nil)
	g.add("urn:vuln:cve-1", "vulnerability", map[string]string{"cve": "cve-2024-0001", "known_exploited": "true"})
	g.add("urn:app:payroll", "okta.application", nil)
	g.add("urn:host:db", "aws.rds_database", map[string]string{"data_classification": "restricted"})
	g.add("urn:vuln:cve-2", "vulnerability", map[string]string{"epss_score": "0.5"})
	g.add("urn:group:eng", "okta.group", nil)
	g.link("urn:device:laptop", "owned_by", "urn:person:admin")
	g.link("urn:device:laptop", "affected_by", "urn:vuln:cve-1")
	g.link("urn:person:admin", "same_actor", "urn:okta:user:admin")
	g.link("urn:okta:user:admin", "can_admin", "urn:app:payroll")
	g.link("urn:app:payroll", "can_reach", "urn:host:db")
	g.link("urn:host:db", "affected_by", "urn:vuln:cve-2")
	// Incoming member_of must not be walked: the group does not gain the user's access.
	g.link("urn:okta:user:admin", "member_of", "urn:group:eng")
	return g
}

func TestScorePathsChainsProbabilitiesFromCompromisedWorkstation(t *testing.T) {
	g := adminGraph()
	model := DefaultModel(testTenant)
	result, err := ScorePaths(context.Background(), g, model, PathRequest{TenantID: testTenant, RootURN: "urn:device:laptop"})
	if err != nil {
		t.Fatalf("ScorePaths() error = %v", err)
	}
	// Entry: 1-(1-0.2)(1-0.85*0.4) = 0.472.
	approx(t, "root probability", result.RootProbability, 0.472)
	if result.Root.VulnerabilityCount != 1 || !result.Root.Vulnerabilities[0].KnownExploited {
		t.Fatalf("root vulnerabilities = %#v", result.Root.Vulnerabilities)
	}
	byTarget := map[string]AttackPath{}
	for _, path := range result.Paths {
		byTarget[path.TargetURN] = path
	}
	db, ok := byTarget["urn:host:db"]
	if !ok {
		t.Fatalf("paths = %#v, want a path to the database", result.Paths)
	}
	// laptop -owned_by-> person (0.7) -same_actor-> user (0.95) -can_admin-> app (0.9) -can_reach-> db (0.5 * exploit 0.5).
	want := 0.472 * 0.7 * 0.95 * 0.9 * 0.5 * 0.5
	approx(t, "db probability", db.Probability, want)
	if db.Value != 1 || db.Score != Score(want, 1) {
		t.Fatalf("db path = %#v", db)
	}
	relations := []string{}
	for _, step := range db.Steps {
		relations = append(relations, step.Relation)
	}
	if got := len(relations); got != 4 || relations[0] != "owned_by" || relations[3] != "can_reach" || !db.Steps[3].RequiresExploit {
		t.Fatalf("db steps = %#v", db.Steps)
	}
	if _, ok := byTarget["urn:group:eng"]; !ok {
		t.Fatal("outgoing member_of from the user should reach the group")
	}
	if _, ok := byTarget["urn:vuln:cve-1"]; ok {
		t.Fatal("vulnerabilities must not be attack path targets")
	}
	if result.Paths[0].Score < result.Paths[len(result.Paths)-1].Score {
		t.Fatal("paths must be ordered by score")
	}
}

func TestScorePathsAssumeCompromisedAndDepthLimit(t *testing.T) {
	g := adminGraph()
	model := DefaultModel(testTenant)
	result, err := ScorePaths(context.Background(), g, model, PathRequest{TenantID: testTenant, RootURN: "urn:okta:user:admin", AssumeCompromised: true, MaxDepth: 1})
	if err != nil {
		t.Fatalf("ScorePaths() error = %v", err)
	}
	approx(t, "root probability", result.RootProbability, 1)
	for _, path := range result.Paths {
		if len(path.Steps) > 1 {
			t.Fatalf("path %s exceeds max depth: %#v", path.TargetURN, path.Steps)
		}
		if path.TargetURN == "urn:host:db" {
			t.Fatal("database is two hops away and must not be reached at depth 1")
		}
	}
}

func TestScorePathsCountermeasureCutsStep(t *testing.T) {
	g := newFakeGraph()
	g.add("urn:user:a", "okta.user", nil)
	g.add("urn:user:b", "okta.user", map[string]string{"mfa_enforced": "yes"})
	g.add("urn:role:admin", "aws.iam_role", nil)
	g.link("urn:user:a", "can_impersonate", "urn:user:b")
	g.link("urn:user:b", "can_assume", "urn:role:admin")
	result, err := ScorePaths(context.Background(), g, DefaultModel(testTenant), PathRequest{TenantID: testTenant, RootURN: "urn:user:a", AssumeCompromised: true})
	if err != nil {
		t.Fatalf("ScorePaths() error = %v", err)
	}
	for _, path := range result.Paths {
		if path.TargetURN == "urn:role:admin" {
			approx(t, "role probability", path.Probability, 0.8*0.4*0.8)
			return
		}
	}
	t.Fatalf("paths = %#v, want the role", result.Paths)
}

func TestScorePathsStopsAtExpansionBudget(t *testing.T) {
	g := adminGraph()
	model := DefaultModel(testTenant)
	model.Traversal.MaxExpansions = 2
	result, err := ScorePaths(context.Background(), g, model, PathRequest{TenantID: testTenant, RootURN: "urn:device:laptop", AssumeCompromised: true})
	if err != nil {
		t.Fatalf("ScorePaths() error = %v", err)
	}
	if g.calls > 2 || !result.Summary.Truncated {
		t.Fatalf("calls = %d truncated = %v, want budget enforced", g.calls, result.Summary.Truncated)
	}
}

func TestScorePathsErrors(t *testing.T) {
	model := DefaultModel(testTenant)
	if _, err := ScorePaths(context.Background(), nil, model, PathRequest{TenantID: testTenant, RootURN: "x"}); !errors.Is(err, ErrGraphUnavailable) {
		t.Fatalf("nil graph error = %v", err)
	}
	if _, err := ScorePaths(context.Background(), newFakeGraph(), model, PathRequest{TenantID: testTenant}); !errors.Is(err, ErrInvalidPathRequest) {
		t.Fatalf("missing root error = %v", err)
	}
	if _, err := ScorePaths(context.Background(), newFakeGraph(), model, PathRequest{TenantID: testTenant, RootURN: "urn:missing"}); !errors.Is(err, ErrRootNotFound) {
		t.Fatalf("missing entity error = %v", err)
	}
}
