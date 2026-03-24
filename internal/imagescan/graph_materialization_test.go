package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/scanner"
)

func TestMaterializeRunsIntoGraphDedupesTagsAndLinksRuntimeAssets(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "production/payments",
		Kind:     graph.NodeKindWorkload,
		Name:     "payments",
		Provider: "k8s",
	})

	mapper := lineage.NewLineageMapper()
	if _, err := mapper.MapKubernetesResource(context.Background(), map[string]interface{}{
		"kind": "Deployment",
		"metadata": map[string]interface{}{
			"namespace": "production",
			"name":      "payments",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"image": "222222222222.dkr.ecr.us-west-2.amazonaws.com/payments/api@sha256:shared",
				},
			},
		},
	}); err != nil {
		t.Fatalf("map lineage: %v", err)
	}

	firstCompleted := time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC)
	secondCompleted := firstCompleted.Add(10 * time.Minute)
	result := MaterializeRunsIntoGraph(g, mapper, []RunRecord{
		{
			ID:          "image_scan:latest",
			Registry:    RegistryECR,
			Status:      RunStatusSucceeded,
			Stage:       RunStageCompleted,
			Target:      ScanTarget{Registry: RegistryECR, RegistryHost: "222222222222.dkr.ecr.us-west-2.amazonaws.com", Repository: "payments/api", Tag: "latest", Digest: "sha256:shared"},
			SubmittedAt: firstCompleted,
			UpdatedAt:   firstCompleted,
			CompletedAt: &firstCompleted,
			Analysis: &AnalysisReport{
				Result: scanner.ContainerScanResult{
					Vulnerabilities: []scanner.ImageVulnerability{{CVE: "CVE-2026-0001", Severity: "high"}},
					Summary:         scanner.VulnerabilitySummary{High: 1, Total: 1},
					OS:              "linux",
					Architecture:    "amd64",
				},
			},
		},
		{
			ID:          "image_scan:prod",
			Registry:    RegistryECR,
			Status:      RunStatusSucceeded,
			Stage:       RunStageCompleted,
			Target:      ScanTarget{Registry: RegistryECR, RegistryHost: "222222222222.dkr.ecr.us-west-2.amazonaws.com", Repository: "payments/api", Tag: "prod", Digest: "sha256:shared"},
			SubmittedAt: secondCompleted,
			UpdatedAt:   secondCompleted,
			CompletedAt: &secondCompleted,
			Analysis: &AnalysisReport{
				Result: scanner.ContainerScanResult{
					Vulnerabilities: []scanner.ImageVulnerability{{CVE: "CVE-2026-0001", Severity: "high"}},
					Summary:         scanner.VulnerabilitySummary{High: 1, Total: 1},
					OS:              "linux",
					Architecture:    "amd64",
				},
			},
		},
	}, secondCompleted)

	if result.ImageNodesUpserted != 1 {
		t.Fatalf("expected one image node, got %#v", result)
	}
	if result.RegistryNodesUpserted != 1 {
		t.Fatalf("expected one registry node, got %#v", result)
	}

	imageNodes := g.GetNodesByKind(graph.NodeKind("container_image"))
	if len(imageNodes) != 1 {
		t.Fatalf("expected one container image node, got %#v", imageNodes)
	}
	imageNode := imageNodes[0]
	if got := imageNode.Properties["digest"]; got != "sha256:shared" {
		t.Fatalf("expected digest to be recorded, got %#v", got)
	}
	rawTags, ok := imageNode.Properties["tags"].([]string)
	if !ok {
		t.Fatalf("expected []string tags, got %#v", imageNode.Properties["tags"])
	}
	if len(rawTags) != 2 || rawTags[0] != "latest" || rawTags[1] != "prod" {
		t.Fatalf("expected tags [latest prod], got %#v", rawTags)
	}

	registryNodes := g.GetNodesByKind(graph.NodeKind("container_registry"))
	if len(registryNodes) != 1 {
		t.Fatalf("expected one container registry node, got %#v", registryNodes)
	}

	outEdges := g.GetOutEdges("production/payments")
	var deployed bool
	for _, edge := range outEdges {
		if edge.Kind == graph.EdgeKindDeployedFrom && edge.Target == imageNode.ID {
			deployed = true
			break
		}
	}
	if !deployed {
		t.Fatalf("expected workload to be linked to image node, got %#v", outEdges)
	}
}
