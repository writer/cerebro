package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestBuilderBuild_ProjectsCloudRunAPIEndpoints(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT name, project_id, location, ingress, uri FROM gcp_cloudrun_services`, &DataQueryResult{
		Rows: []map[string]any{
			{
				"name":       "projects/proj-1/locations/us-central1/services/payments-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app/",
			},
			{
				"name":       "projects/proj-1/locations/us-central1/services/internal-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_INTERNAL_ONLY",
				"uri":        "https://internal-api-uc.a.run.app",
			},
		},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	g := builder.Graph()

	publicEndpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")
	publicEndpoint, ok := g.GetNode(publicEndpointID)
	if !ok {
		t.Fatalf("expected public API endpoint node %q", publicEndpointID)
	}
	if publicEndpoint.Kind != NodeKindAPIEndpoint {
		t.Fatalf("endpoint kind = %s, want %s", publicEndpoint.Kind, NodeKindAPIEndpoint)
	}
	if got := toString(publicEndpoint.Properties["host"]); got != "payments-api-uc.a.run.app" {
		t.Fatalf("endpoint host = %q, want %q", got, "payments-api-uc.a.run.app")
	}
	if got, _ := publicEndpoint.Properties["public"].(bool); !got {
		t.Fatalf("expected public endpoint node, got %#v", publicEndpoint.Properties["public"])
	}

	assertEdgeExists(t, g, "projects/proj-1/locations/us-central1/services/payments-api", publicEndpointID, EdgeKindServes)
	assertEdgeExists(t, g, publicEndpointID, "projects/proj-1/locations/us-central1/services/payments-api", EdgeKindTargets)
	assertEdgeExists(t, g, "internet", publicEndpointID, EdgeKindExposedTo)

	internalEndpointID := apiEndpointNodeID("https://internal-api-uc.a.run.app")
	internalEndpoint, ok := g.GetNode(internalEndpointID)
	if !ok {
		t.Fatalf("expected internal API endpoint node %q", internalEndpointID)
	}
	if got, _ := internalEndpoint.Properties["public"].(bool); got {
		t.Fatalf("expected internal endpoint node, got public=%#v", internalEndpoint.Properties["public"])
	}
	assertEdgeExists(t, g, "projects/proj-1/locations/us-central1/services/internal-api", internalEndpointID, EdgeKindServes)
	assertEdgeExists(t, g, internalEndpointID, "projects/proj-1/locations/us-central1/services/internal-api", EdgeKindTargets)
	if edge := findEdge(g, "internet", internalEndpointID, EdgeKindExposedTo); edge != nil {
		t.Fatalf("did not expect internet exposure edge for internal endpoint: %#v", edge)
	}
}

func TestBuilderApplyChanges_ProjectsCloudRunAPIEndpoints(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})

	base := time.Now().UTC().Add(-1 * time.Minute)
	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": "projects/proj-1/locations/us-central1/services/payments-api",
			"change_type": "added",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       "projects/proj-1/locations/us-central1/services/payments-api",
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(5 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base); err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	endpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")
	if _, ok := builder.Graph().GetNode(endpointID); !ok {
		t.Fatalf("expected projected API endpoint node %q after CDC apply", endpointID)
	}
	assertEdgeExists(t, builder.Graph(), "projects/proj-1/locations/us-central1/services/payments-api", endpointID, EdgeKindServes)
	assertEdgeExists(t, builder.Graph(), endpointID, "projects/proj-1/locations/us-central1/services/payments-api", EdgeKindTargets)
	assertEdgeExists(t, builder.Graph(), "internet", endpointID, EdgeKindExposedTo)
}

func TestBuilderApplyChanges_RemovesOrphanedAPIEndpointsAfterDelete(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})

	base := time.Now().UTC().Add(-2 * time.Minute)
	workloadID := "projects/proj-1/locations/us-central1/services/payments-api"
	endpointID := apiEndpointNodeID("https://payments-api-uc.a.run.app")

	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun-added",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": workloadID,
			"change_type": "added",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       workloadID,
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(5 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base); err != nil {
		t.Fatalf("ApplyChanges add failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode(endpointID); !ok {
		t.Fatalf("expected projected API endpoint node %q after add", endpointID)
	}

	source.events = []map[string]any{
		{
			"event_id":    "evt-cloudrun-removed",
			"table_name":  "gcp_cloudrun_services",
			"resource_id": workloadID,
			"change_type": "removed",
			"provider":    "gcp",
			"region":      "us-central1",
			"account_id":  "proj-1",
			"payload": map[string]any{
				"name":       workloadID,
				"project_id": "proj-1",
				"location":   "us-central1",
				"ingress":    "INGRESS_TRAFFIC_ALL",
				"uri":        "https://payments-api-uc.a.run.app",
			},
			"event_time": base.Add(20 * time.Second),
		},
	}

	if _, err := builder.ApplyChanges(context.Background(), base.Add(10*time.Second)); err != nil {
		t.Fatalf("ApplyChanges remove failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode(endpointID); ok {
		t.Fatalf("expected orphaned API endpoint node %q to be removed after workload delete", endpointID)
	}
	if edge := findEdge(builder.Graph(), "internet", endpointID, EdgeKindExposedTo); edge != nil {
		t.Fatalf("expected no internet exposure edge after workload delete, got %#v", edge)
	}
	if deleted, ok := builder.Graph().GetNodeIncludingDeleted(endpointID); !ok || deleted.DeletedAt == nil {
		t.Fatalf("expected endpoint node tombstone after workload delete, got %#v ok=%v", deleted, ok)
	}
}

func TestBuilderBuild_ProjectsAWSAPIAndEdgeEndpoints(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, region, account_id, endpoint_configuration FROM aws_apigateway_rest_apis`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":                     "abc123",
			"region":                 "us-east-1",
			"account_id":             "111111111111",
			"endpoint_configuration": map[string]any{"types": []string{"REGIONAL"}},
		}},
	})
	source.setResult(`SELECT rest_api_id, stage_name, region, account_id FROM aws_apigateway_stages`, &DataQueryResult{
		Rows: []map[string]any{{
			"rest_api_id": "abc123",
			"stage_name":  "prod",
			"region":      "us-east-1",
			"account_id":  "111111111111",
		}},
	})
	source.setResult(`SELECT rest_api_id, resource_path, http_method, authorization_type, api_key_required, authorizer_id, region, account_id FROM aws_apigateway_rest_api_methods`, &DataQueryResult{
		Rows: []map[string]any{{
			"rest_api_id":        "abc123",
			"resource_path":      "/users",
			"http_method":        "GET",
			"authorization_type": "NONE",
			"api_key_required":   false,
			"region":             "us-east-1",
			"account_id":         "111111111111",
		}},
	})
	source.setResult(`SELECT api_id, api_endpoint, region, account_id, protocol_type, cors_configuration, disable_execute_api_endpoint FROM aws_apigatewayv2_apis`, &DataQueryResult{
		Rows: []map[string]any{{
			"api_id":                       "xyz789",
			"api_endpoint":                 "https://xyz789.execute-api.us-east-1.amazonaws.com",
			"region":                       "us-east-1",
			"account_id":                   "111111111111",
			"protocol_type":                "HTTP",
			"cors_configuration":           map[string]any{"allow_origins": []any{"*"}},
			"disable_execute_api_endpoint": false,
		}},
	})
	source.setResult(`SELECT api_id, stage_name, region, account_id FROM aws_apigatewayv2_stages`, &DataQueryResult{
		Rows: []map[string]any{{
			"api_id":     "xyz789",
			"stage_name": "$default",
			"region":     "us-east-1",
			"account_id": "111111111111",
		}},
	})
	source.setResult(`SELECT arn, dns_name, scheme, region, account_id FROM aws_elbv2_load_balancers`, &DataQueryResult{
		Rows: []map[string]any{{
			"arn":        "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/payments/123",
			"dns_name":   "payments-alb-123.us-east-1.elb.amazonaws.com",
			"scheme":     "internet-facing",
			"region":     "us-east-1",
			"account_id": "111111111111",
		}},
	})
	source.setResult(`SELECT listener_arn, load_balancer_arn, port, protocol, region, account_id FROM aws_lb_listeners`, &DataQueryResult{
		Rows: []map[string]any{{
			"listener_arn":      "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/payments/123/456",
			"load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/payments/123",
			"port":              443,
			"protocol":          "HTTPS",
			"region":            "us-east-1",
			"account_id":        "111111111111",
		}},
	})
	source.setResult(`SELECT listener_arn, type, target_group_arn, authenticate_oidc_config, authenticate_cognito_config FROM default_actions`, &DataQueryResult{
		Rows: []map[string]any{{
			"listener_arn":     "arn:aws:elasticloadbalancing:us-east-1:111111111111:listener/app/payments/123/456",
			"type":             "authenticate_oidc",
			"target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/payments/789",
		}},
	})
	source.setResult(`SELECT id, domain_name, aliases, enabled, account_id FROM aws_cloudfront_distributions`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":          "dist-1",
			"domain_name": "d111111abcdef8.cloudfront.net",
			"aliases":     map[string]any{"items": []any{"api.example.com"}},
			"enabled":     true,
			"account_id":  "111111111111",
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	g := builder.Graph()

	restURL := "https://abc123.execute-api.us-east-1.amazonaws.com/prod/users"
	restNode, ok := g.GetNode(apiEndpointMethodNodeID("GET", restURL))
	if !ok {
		t.Fatalf("expected REST API endpoint node for %s", restURL)
	}
	if got := queryRowString(restNode.Properties, "auth_type"); got != "none" {
		t.Fatalf("REST endpoint auth_type = %q, want none", got)
	}
	assertEdgeExists(t, g, "internet", restNode.ID, EdgeKindExposedTo)

	httpURL := "https://xyz789.execute-api.us-east-1.amazonaws.com"
	httpNode, ok := g.GetNode(apiEndpointNodeID(httpURL))
	if !ok {
		t.Fatalf("expected HTTP API endpoint node for %s", httpURL)
	}
	if got, _ := httpNode.Properties["cors_permissive"].(bool); !got {
		t.Fatalf("expected HTTP API endpoint to be marked permissive CORS, got %#v", httpNode.Properties["cors_permissive"])
	}

	albURL := "https://payments-alb-123.us-east-1.elb.amazonaws.com"
	albNode, ok := g.GetNode(apiEndpointNodeID(albURL))
	if !ok {
		t.Fatalf("expected ALB endpoint node for %s", albURL)
	}
	if got := queryRowString(albNode.Properties, "auth_type"); got != "oidc" {
		t.Fatalf("ALB endpoint auth_type = %q, want oidc", got)
	}
	if got := queryRowString(albNode.Properties, "provider_service"); got != "aws_elbv2_listener" {
		t.Fatalf("ALB endpoint provider_service = %q, want aws_elbv2_listener", got)
	}

	cloudFrontURL := "https://api.example.com"
	if _, ok := g.GetNode(apiEndpointNodeID(cloudFrontURL)); !ok {
		t.Fatalf("expected CloudFront endpoint node for %s", cloudFrontURL)
	}
}
