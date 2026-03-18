package builders

import (
	"testing"
)

func TestSCMInference(t *testing.T) {
	// Setup graph with nodes containing tags
	g := New()

	// Node with git_repo tag
	g.AddNode(&Node{
		ID:   "arn:aws:lambda:us-east-1:123456789012:function/payment-service",
		Kind: NodeKindFunction,
		Tags: map[string]string{
			"git_repo": "https://github.com/org/payment-service.git",
		},
	})

	// Node with project tag (inference)
	g.AddNode(&Node{
		ID:   "arn:aws:s3:::frontend-assets",
		Kind: NodeKindBucket,
		Tags: map[string]string{
			"project": "org/frontend",
		},
	})

	// Setup builder
	b := &Builder{
		graph: g,
	}

	// Run inference
	b.buildSCMInference()

	// Verify Repository Nodes created
	repo1 := "https://github.com/org/payment-service.git"
	if _, exists := g.GetNode(repo1); !exists {
		t.Errorf("Repository node %s not created", repo1)
	}

	repo2 := "https://github.com/org/frontend"
	if _, exists := g.GetNode(repo2); !exists {
		t.Errorf("Repository node %s not created (inference failed)", repo2)
	}

	// Verify Edges
	edges := g.GetOutEdges("arn:aws:lambda:us-east-1:123456789012:function/payment-service")
	found := false
	for _, e := range edges {
		if e.Target == repo1 && e.Kind == EdgeKindDeployedFrom {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DeployedFrom edge not created for lambda")
	}
}
