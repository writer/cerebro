package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/dspm"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/testutil"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestScanAndPersistDSPMFindings_PersistsAndRemediates(t *testing.T) {
	logger := testutil.Logger()
	findingStore := findings.NewStore()
	remediationEngine := remediation.NewEngine(logger)
	app := &App{
		Logger:        logger,
		Findings:      findingStore,
		Remediation:   remediationEngine,
		Notifications: notifications.NewManager(),
		Ticketing:     ticketing.NewService(),
		Webhooks:      webhooks.NewServiceForTesting(),
	}
	app.RemediationExecutor = remediation.NewExecutor(app.Remediation, app.Ticketing, app.Notifications, app.Findings, app.Webhooks)

	err := app.Remediation.AddRule(remediation.Rule{
		ID:          "test-dspm-resolve",
		Name:        "Resolve DSPM finding",
		Description: "test",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: dspm.PolicyIDRestrictedDataUnencrypted,
		},
		Actions: []remediation.Action{
			{Type: remediation.ActionResolveFinding},
		},
	})
	if err != nil {
		t.Fatalf("add remediation rule: %v", err)
	}

	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("4111-1111-1111-1111")},
		},
	}
	app.DSPM = dspm.NewScanner(fetcher, logger, dspm.DefaultScannerConfig())

	assets := []map[string]interface{}{
		{
			"_cq_id":          "bucket-1",
			"_cq_source_name": "aws",
			"name":            "customer-card-bucket",
			"arn":             "arn:aws:s3:::customer-card-bucket",
			"is_public":       true,
			"is_encrypted":    false,
			"region":          "us-west-2",
		},
	}

	count := app.scanAndPersistDSPMFindings(context.Background(), "aws_s3_buckets", assets)
	if count < 3 {
		t.Fatalf("expected at least 3 DSPM findings persisted, got %d", count)
	}
	if fetcher.fetchCalls != 1 {
		t.Fatalf("expected one DSPM fetch call, got %d", fetcher.fetchCalls)
	}

	restricted := app.Findings.List(findings.FindingFilter{PolicyID: dspm.PolicyIDRestrictedDataUnencrypted})
	if len(restricted) == 0 {
		t.Fatal("expected restricted-unencrypted DSPM finding")
	}
	if restricted[0].Status != "RESOLVED" {
		t.Fatalf("expected restricted-unencrypted finding to be auto-resolved by remediation rule, got %s", restricted[0].Status)
	}
}

func TestScanAndPersistDSPMFindings_SkipsNonScannableTables(t *testing.T) {
	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("4111-1111-1111-1111")},
		},
	}

	app := &App{
		Logger:   testutil.Logger(),
		Findings: findings.NewStore(),
		DSPM:     dspm.NewScanner(fetcher, testutil.Logger(), dspm.DefaultScannerConfig()),
	}

	count := app.scanAndPersistDSPMFindings(context.Background(), "aws_iam_users", []map[string]interface{}{
		{"id": "user-1", "name": "alice"},
	})
	if count != 0 {
		t.Fatalf("expected zero findings for non-DSPM table, got %d", count)
	}
	if fetcher.fetchCalls != 0 {
		t.Fatalf("expected no DSPM fetch calls for non-DSPM table, got %d", fetcher.fetchCalls)
	}
}

func TestScanAndPersistDSPMFindings_EnrichesSecurityGraphNodes(t *testing.T) {
	logger := testutil.Logger()
	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("customer email jane@example.com and card 4111-1111-1111-1111")},
		},
	}

	builder := builders.NewBuilder(newSchedulerGraphSource(), logger)
	builderNodeID := "arn:aws:s3:::customer-card-bucket"
	builder.Graph().AddNode(&graph.Node{
		ID:         builderNodeID,
		Kind:       graph.NodeKindBucket,
		Name:       "customer-card-bucket",
		Provider:   "aws",
		Properties: map[string]any{},
	})

	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{
		ID:         builderNodeID,
		Kind:       graph.NodeKindBucket,
		Name:       "customer-card-bucket",
		Provider:   "aws",
		Properties: map[string]any{},
	})

	app := &App{
		Logger:               logger,
		Findings:             findings.NewStore(),
		DSPM:                 dspm.NewScanner(fetcher, logger, dspm.DefaultScannerConfig()),
		SecurityGraph:        liveGraph,
		SecurityGraphBuilder: builder,
	}

	assets := []map[string]interface{}{
		{
			"_cq_id":          "bucket-1",
			"_cq_source_name": "aws",
			"name":            "customer-card-bucket",
			"arn":             builderNodeID,
			"is_public":       true,
			"is_encrypted":    false,
			"region":          "us-west-2",
		},
	}

	app.scanAndPersistDSPMFindings(context.Background(), "aws_s3_buckets", assets)

	for name, g := range map[string]*graph.Graph{
		"live":    app.CurrentSecurityGraph(),
		"builder": builder.Graph(),
	} {
		node, ok := g.GetNode(builderNodeID)
		if !ok || node == nil {
			t.Fatalf("expected %s graph node %q to exist", name, builderNodeID)
		}
		if scanned, _ := node.Properties["dspm_scanned"].(bool); !scanned {
			t.Fatalf("expected %s graph node to be marked as DSPM scanned", name)
		}
		if classification, _ := node.Properties["data_classification"].(string); classification != string(dspm.ClassificationRestricted) {
			t.Fatalf("expected %s graph node classification %q, got %v", name, dspm.ClassificationRestricted, node.Properties["data_classification"])
		}
		if containsPII, _ := node.Properties["contains_pii"].(bool); !containsPII {
			t.Fatalf("expected %s graph node to contain PII", name)
		}
		if containsPCI, _ := node.Properties["contains_pci"].(bool); !containsPCI {
			t.Fatalf("expected %s graph node to contain PCI", name)
		}
	}
}

func TestScanAndPersistDSPMFindings_NameFallbackRequiresScopedUniqueMatch(t *testing.T) {
	logger := testutil.Logger()
	fetcher := &stubDSPMFetcher{
		samples: []dspm.DataSample{
			{ObjectKey: "sample-1", Data: []byte("customer email jane@example.com and card 4111-1111-1111-1111")},
		},
	}

	liveGraph := graph.New()
	liveGraph.AddNode(&graph.Node{
		ID:       "bucket:acct-a:shared-bucket",
		Kind:     graph.NodeKindBucket,
		Name:     "shared-bucket",
		Provider: "aws",
		Account:  "acct-a",
		Region:   "us-west-2",
		Properties: map[string]any{
			"bucket_name": "shared-bucket",
		},
	})
	liveGraph.AddNode(&graph.Node{
		ID:       "bucket:acct-b:shared-bucket",
		Kind:     graph.NodeKindBucket,
		Name:     "shared-bucket",
		Provider: "aws",
		Account:  "acct-b",
		Region:   "us-west-2",
		Properties: map[string]any{
			"bucket_name": "shared-bucket",
		},
	})

	app := &App{
		Logger:        logger,
		Findings:      findings.NewStore(),
		DSPM:          dspm.NewScanner(fetcher, logger, dspm.DefaultScannerConfig()),
		SecurityGraph: liveGraph,
	}

	app.scanAndPersistDSPMFindings(context.Background(), "aws_s3_buckets", []map[string]interface{}{
		{
			"_cq_id":          "scan-target-id",
			"_cq_source_name": "aws",
			"name":            "shared-bucket",
			"account_id":      "acct-b",
			"region":          "us-west-2",
			"is_public":       true,
			"is_encrypted":    false,
		},
	})

	current := app.CurrentSecurityGraph()
	accountANode, _ := current.GetNode("bucket:acct-a:shared-bucket")
	if scanned, _ := accountANode.Properties["dspm_scanned"].(bool); scanned {
		t.Fatal("expected scoped name fallback to avoid enriching same-name bucket in another account")
	}

	accountBNode, ok := current.GetNode("bucket:acct-b:shared-bucket")
	if !ok || accountBNode == nil {
		t.Fatal("expected scoped same-name bucket to exist")
	}
	if scanned, _ := accountBNode.Properties["dspm_scanned"].(bool); !scanned {
		t.Fatal("expected scoped name fallback to enrich the uniquely matched bucket")
	}
}

type stubDSPMFetcher struct {
	samples    []dspm.DataSample
	fetchCalls int
}

func (s *stubDSPMFetcher) FetchSample(_ context.Context, _ *dspm.ScanTarget, _ int64) ([]dspm.DataSample, error) {
	s.fetchCalls++
	return s.samples, nil
}

func (s *stubDSPMFetcher) ListObjects(_ context.Context, _ *dspm.ScanTarget, _ int) ([]dspm.ObjectInfo, error) {
	return nil, nil
}
