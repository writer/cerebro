package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCloudSignalRulesDetectPublicExposure(t *testing.T) {
	rules := cloudRulesByID(t)
	for _, tt := range []struct {
		name        string
		sourceID    string
		kind        string
		attributes  map[string]string
		resourceURN string
	}{
		{
			name:     "aws",
			sourceID: "aws",
			kind:     "aws.resource_exposure",
			attributes: map[string]string{
				"domain":           "123456789012",
				"exposed_to":       "public_internet",
				"exposure_type":    "public_network_ingress",
				"family":           "resource_exposure",
				"internet_exposed": "true",
				"resource_id":      "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
				"resource_name":    "prod-web",
				"resource_type":    "security_group",
				"source_cidr":      "0.0.0.0/0",
			},
			resourceURN: "urn:cerebro:writer:aws_security_group:arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
		},
		{
			name:     "gcp",
			sourceID: "gcp",
			kind:     "gcp.resource_exposure",
			attributes: map[string]string{
				"domain":           "writer-prod",
				"exposed_to":       "public_internet",
				"exposure_type":    "public_network_ingress",
				"family":           "resource_exposure",
				"internet_exposed": "true",
				"resource_id":      "fw-1",
				"resource_name":    "allow-web",
				"resource_type":    "firewall_rule",
				"source_cidr":      "0.0.0.0/0",
			},
			resourceURN: "urn:cerebro:writer:gcp_firewall_rule:fw-1",
		},
		{
			name:     "azure",
			sourceID: "azure",
			kind:     "azure.resource_exposure",
			attributes: map[string]string{
				"domain":           "tenant-1",
				"exposed_to":       "public_internet",
				"exposure_type":    "public_network_ingress",
				"family":           "resource_exposure",
				"internet_exposed": "true",
				"resource_id":      "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
				"resource_name":    "web-nsg",
				"resource_type":    "network_security_group",
				"source_cidr":      "Internet",
			},
			resourceURN: "urn:cerebro:writer:azure_network_security_group:/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-public-exposure", TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[cloudPublicResourceExposureRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
		})
	}
}

func TestCloudSignalRulesDetectPrivilegePaths(t *testing.T) {
	rules := cloudRulesByID(t)
	for _, tt := range []struct {
		name        string
		sourceID    string
		kind        string
		attributes  map[string]string
		resourceURN string
	}{
		{
			name:     "aws-assume-role",
			sourceID: "aws",
			kind:     "aws.iam_role_trust",
			attributes: map[string]string{
				"domain":       "123456789012",
				"family":       "iam_role_trust",
				"path_type":    "assume_role_trust",
				"relationship": "can_assume",
				"subject_id":   "arn:aws:iam::999999999999:role/ExternalAdmin",
				"subject_type": "role",
				"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
				"target_type":  "role",
			},
			resourceURN: "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole",
		},
		{
			name:     "gcp-impersonation",
			sourceID: "gcp",
			kind:     "gcp.service_account_impersonation",
			attributes: map[string]string{
				"domain":        "writer-prod",
				"family":        "service_account_impersonation",
				"path_type":     "service_account_impersonation",
				"relationship":  "can_impersonate",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
				"target_email":  "sa@writer-prod.iam.gserviceaccount.com",
				"target_id":     "sa@writer-prod.iam.gserviceaccount.com",
				"target_type":   "service_account",
			},
			resourceURN: "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com",
		},
		{
			name:     "azure-app-role",
			sourceID: "azure",
			kind:     "azure.app_role_assignment",
			attributes: map[string]string{
				"domain":       "tenant-1",
				"family":       "app_role_assignment",
				"path_type":    "app_role_assignment",
				"relationship": "assigned_to",
				"subject_id":   "sp-1",
				"subject_type": "service_principal",
				"target_id":    "sp-resource-1",
				"target_type":  "service_principal",
			},
			resourceURN: "urn:cerebro:writer:azure_service_principal:sp-resource-1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name, TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[cloudPrivilegePathGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
		})
	}
}

func TestCloudSignalRulesDetectEffectiveAdminPermissions(t *testing.T) {
	rules := cloudRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-effective-admin",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "*",
			"domain":        "123456789012",
			"effect":        "allow",
			"resource_id":   "123456789012",
			"resource_type": "account",
			"subject_email": "admin@writer.com",
			"subject_id":    "admin@writer.com",
			"subject_type":  "user",
		},
	}
	records, err := rules[cloudEffectiveAdminPermissionRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:aws_account:123456789012")

	viewer := &cerebrov1.EventEnvelope{
		Id:       "aws-effective-viewer",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "ec2:DescribeInstances",
			"domain":        "123456789012",
			"effect":        "allow",
			"resource_id":   "123456789012",
			"resource_type": "account",
			"subject_id":    "viewer@writer.com",
			"subject_type":  "user",
		},
	}
	records, err = rules[cloudEffectiveAdminPermissionRuleID].Evaluate(context.Background(), runtime, viewer)
	if err != nil {
		t.Fatalf("Evaluate(viewer) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(viewer records) = %d, want 0", len(records))
	}
}

func TestCloudSignalRulesDetectKubernetesWorkloadIdentityBinding(t *testing.T) {
	rules := cloudRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "k8s-runtime", SourceId: "kubernetes", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "k8s-workload-identity",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload_identity_binding",
		Attributes: map[string]string{
			"cloud_provider":       "gcp",
			"cluster_id":           "prod-cluster",
			"family":               "workload_identity",
			"namespace":            "payments",
			"path_type":            "workload_identity",
			"relationship":         "can_impersonate",
			"service_account_name": "api",
			"target_email":         "payments-sa@writer-prod.iam.gserviceaccount.com",
			"target_id":            "payments-sa@writer-prod.iam.gserviceaccount.com",
			"target_type":          "service_account",
		},
	}
	records, err := rules[cloudPrivilegePathGrantedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:gcp_service_account:payments-sa@writer-prod.iam.gserviceaccount.com")
}

func cloudRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	rules := map[string]Rule{}
	for _, rule := range newCloudSignalRules() {
		rules[rule.Spec().GetId()] = rule
	}
	return rules
}
