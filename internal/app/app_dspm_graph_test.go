package app

import (
	"testing"

	"github.com/writer/cerebro/internal/dspm"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/testutil"
)

func TestEnrichSecurityGraphWithDSPMResult_UsesCopyOnWriteForLiveGraph(t *testing.T) {
	logger := testutil.Logger()
	nodeID := "arn:aws:s3:::customer-card-bucket"

	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{
		ID:       nodeID,
		Kind:     graph.NodeKindBucket,
		Name:     "customer-card-bucket",
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
	})
	liveGraph.BuildIndex()

	builder := builders.NewBuilder(newSchedulerGraphSource(), logger)
	builder.Graph().AddNode(&graph.Node{
		ID:       nodeID,
		Kind:     graph.NodeKindBucket,
		Name:     "customer-card-bucket",
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
	})
	builder.Graph().BuildIndex()

	app := &App{
		Logger:               logger,
		DSPM:                 dspm.NewScanner(nil, logger, dspm.DefaultScannerConfig()),
		SecurityGraph:        liveGraph,
		SecurityGraphBuilder: builder,
	}

	app.enrichSecurityGraphWithDSPMResult(&dspm.ScanTarget{
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
		Name:     "customer-card-bucket",
		ARN:      nodeID,
	}, &dspm.ScanResult{
		Classification: dspm.ClassificationRestricted,
		RiskScore:      92,
		Findings: []dspm.SensitiveDataFinding{
			{DataType: dspm.DataTypeEmail},
			{DataType: dspm.DataTypeCreditCard},
		},
	})

	current := app.CurrentSecurityGraph()
	if current == liveGraph {
		t.Fatal("expected live graph enrichment to swap in a cloned graph")
	}
	if !current.IsIndexBuilt() {
		t.Fatal("expected enriched live graph index to be rebuilt")
	}
	if !liveGraph.IsIndexBuilt() {
		t.Fatal("expected original live graph index to remain valid")
	}

	node, ok := current.GetNode(nodeID)
	if !ok || node == nil {
		t.Fatalf("expected live graph node %q to exist", nodeID)
	}
	if scanned, _ := node.Properties["dspm_scanned"].(bool); !scanned {
		t.Fatal("expected enriched live graph node to be marked as DSPM scanned")
	}

	builderNode, ok := builder.Graph().GetNode(nodeID)
	if !ok || builderNode == nil {
		t.Fatalf("expected builder graph node %q to exist", nodeID)
	}
	if !builder.Graph().IsIndexBuilt() {
		t.Fatal("expected builder graph index to remain valid after enrichment")
	}
}

func TestEnrichSecurityGraphWithDSPMResult_UsesConfiguredStoreWhenLiveGraphUnavailable(t *testing.T) {
	logger := testutil.Logger()
	nodeID := "arn:aws:s3:::customer-card-bucket"

	base := graph.New()
	base.AddNode(&graph.Node{
		ID:       nodeID,
		Kind:     graph.NodeKindBucket,
		Name:     "customer-card-bucket",
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
	})
	base.BuildIndex()

	app := &App{
		Logger: logger,
		DSPM:   dspm.NewScanner(nil, logger, dspm.DefaultScannerConfig()),
	}
	setConfiguredGraphFromGraph(t, app, base)

	app.enrichSecurityGraphWithDSPMResult(&dspm.ScanTarget{
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
		Name:     "customer-card-bucket",
		ARN:      nodeID,
	}, &dspm.ScanResult{
		Classification: dspm.ClassificationRestricted,
		RiskScore:      92,
		Findings: []dspm.SensitiveDataFinding{
			{DataType: dspm.DataTypeEmail},
			{DataType: dspm.DataTypeCreditCard},
		},
	})

	current := app.CurrentSecurityGraph()
	if current == nil {
		t.Fatal("expected configured graph base to hydrate a live graph during DSPM enrichment")
	}
	if !current.IsIndexBuilt() {
		t.Fatal("expected enriched live graph index to be rebuilt")
	}

	node, ok := current.GetNode(nodeID)
	if !ok || node == nil {
		t.Fatalf("expected hydrated live graph node %q to exist", nodeID)
	}
	if scanned, _ := node.Properties["dspm_scanned"].(bool); !scanned {
		t.Fatal("expected hydrated live graph node to be marked as DSPM scanned")
	}

	baseNode, ok := base.GetNode(nodeID)
	if !ok || baseNode == nil {
		t.Fatalf("expected original base node %q to exist", nodeID)
	}
	if _, exists := baseNode.Properties["dspm_scanned"]; exists {
		t.Fatal("expected original base graph value to remain unchanged in memory")
	}
}

func TestScopedDSPMGraphNodeNameMatch_DoesNotCaseFoldNodeID(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "mybucket",
		Kind:     graph.NodeKindBucket,
		Name:     "archive-bucket",
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
	})

	target := &dspm.ScanTarget{
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
	}

	if nodeID, ok := scopedDSPMGraphNodeNameMatch(g, target, []string{"MyBucket"}); ok {
		t.Fatalf("expected no fallback match for case-insensitive node ID collision, got %q", nodeID)
	}
}
