package graphingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

type mapperContractFixture struct {
	Name            string                  `json:"name"`
	Event           mapperContractEvent     `json:"event"`
	SeedNodes       []mapperContractSeed    `json:"seed_nodes"`
	ExpectedMapping string                  `json:"expected_mapping"`
	ExpectedNodes   []mapperContractNode    `json:"expected_nodes"`
	ExpectedEdges   []mapperContractEdgeRef `json:"expected_edges"`
}

type mapperContractEvent struct {
	ID     string         `json:"id"`
	Type   string         `json:"type"`
	Time   string         `json:"time"`
	Source string         `json:"source"`
	Data   map[string]any `json:"data"`
}

type mapperContractSeed struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties"`
}

type mapperContractNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type mapperContractEdgeRef struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

func TestMapperContractFixtures(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("testdata", "mapper_contracts.json"))
	if err != nil {
		t.Fatalf("read mapper contract fixtures failed: %v", err)
	}
	var fixtures []mapperContractFixture
	if err := json.Unmarshal(payload, &fixtures); err != nil {
		t.Fatalf("decode mapper contract fixtures failed: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("expected at least one mapper contract fixture")
	}

	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}
	mapper, err := NewMapper(config, func(raw string, _ events.CloudEvent) string {
		raw = strings.ToLower(strings.TrimSpace(raw))
		if strings.Contains(raw, "@") {
			return "person:" + raw
		}
		return raw
	})
	if err != nil {
		t.Fatalf("new mapper failed: %v", err)
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			g := graph.New()
			for _, seed := range fixture.SeedNodes {
				g.AddNode(&graph.Node{
					ID:         seed.ID,
					Kind:       graph.NodeKind(strings.TrimSpace(seed.Kind)),
					Name:       seed.Name,
					Properties: seed.Properties,
				})
			}

			parsedTime, err := time.Parse(time.RFC3339, fixture.Event.Time)
			if err != nil {
				t.Fatalf("parse fixture time failed: %v", err)
			}
			result, err := mapper.Apply(g, events.CloudEvent{
				ID:     fixture.Event.ID,
				Type:   fixture.Event.Type,
				Time:   parsedTime,
				Source: fixture.Event.Source,
				Data:   fixture.Event.Data,
			})
			if err != nil {
				t.Fatalf("mapper apply failed: %v", err)
			}
			if !result.Matched {
				t.Fatalf("expected mapping match, got %#v", result)
			}
			if result.NodesRejected > 0 || result.EdgesRejected > 0 {
				t.Fatalf("expected contract fixture to be schema-valid, got %#v", result)
			}
			if !containsString(result.MappingNames, fixture.ExpectedMapping) {
				t.Fatalf("expected mapping %q in %#v", fixture.ExpectedMapping, result.MappingNames)
			}

			for _, expectedNode := range fixture.ExpectedNodes {
				node, ok := g.GetNode(expectedNode.ID)
				if !ok || node == nil {
					t.Fatalf("expected node %q", expectedNode.ID)
				}
				wantKind := graph.NodeKind(strings.TrimSpace(expectedNode.Kind))
				if node.Kind != wantKind {
					t.Fatalf("expected node %q kind %q, got %q", expectedNode.ID, wantKind, node.Kind)
				}
				for _, key := range []string{"source_system", "source_event_id", "observed_at", "valid_from", "confidence"} {
					if _, ok := node.Properties[key]; !ok {
						t.Fatalf("expected node %q metadata key %q, got %#v", expectedNode.ID, key, node.Properties)
					}
				}
			}

			for _, expectedEdge := range fixture.ExpectedEdges {
				edge := findEdge(g, expectedEdge.Source, expectedEdge.Target, graph.EdgeKind(strings.TrimSpace(expectedEdge.Kind)))
				if edge == nil {
					t.Fatalf("expected edge %s -> %s (%s)", expectedEdge.Source, expectedEdge.Target, expectedEdge.Kind)
				}
				for _, key := range []string{"source_system", "source_event_id", "observed_at", "valid_from", "confidence"} {
					if _, ok := edge.Properties[key]; !ok {
						t.Fatalf("expected edge %q metadata key %q, got %#v", edge.ID, key, edge.Properties)
					}
				}
			}
		})
	}
}

func findEdge(g *graph.Graph, source, target string, kind graph.EdgeKind) *graph.Edge {
	if g == nil {
		return nil
	}
	for _, edge := range g.GetOutEdges(source) {
		if edge == nil {
			continue
		}
		if edge.Target == target && edge.Kind == kind {
			return edge
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestMapperSourceDomainCoverageGuardrails(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	requiredDomains := []string{
		"github",
		"incident",
		"slack",
		"jira",
		"ci",
		"calendar",
		"docs",
		"support",
		"sales",
	}

	domainSeen := make(map[string]bool)
	domainSpecificKinds := make(map[string]bool)
	for _, mapping := range config.Mappings {
		domain := mapperSourceDomain(mapping.Source)
		if domain == "" {
			continue
		}
		domainSeen[domain] = true
		for _, node := range mapping.Nodes {
			kind := strings.ToLower(strings.TrimSpace(node.Kind))
			if kind == "" || kind == string(graph.NodeKindActivity) {
				continue
			}
			domainSpecificKinds[domain] = true
		}
	}

	missing := make([]string, 0)
	missingSpecific := make([]string, 0)
	for _, domain := range requiredDomains {
		if !domainSeen[domain] {
			missing = append(missing, domain)
		}
		if !domainSpecificKinds[domain] {
			missingSpecific = append(missingSpecific, domain)
		}
	}
	sort.Strings(missing)
	sort.Strings(missingSpecific)
	if len(missing) > 0 {
		t.Fatalf("missing required mapper domains: %v", missing)
	}
	if len(missingSpecific) > 0 {
		t.Fatalf("required domains missing canonical kinds (non-activity): %v", missingSpecific)
	}
}

func mapperSourceDomain(source string) string {
	parts := strings.Split(strings.TrimSpace(source), ".")
	if len(parts) < 3 {
		return ""
	}
	if parts[0] != "ensemble" || parts[1] != "tap" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}
