package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
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

func TestCloudSignalRulesIgnoreLowContextCloudSignals(t *testing.T) {
	rules := cloudRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}

	publicTagOnly := &cerebrov1.EventEnvelope{
		Id:       "aws-public-tag-only",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.resource_exposure",
		Attributes: map[string]string{
			"family":        "resource_exposure",
			"public":        "true",
			"resource_id":   "arn:aws:s3:::docs",
			"resource_type": "bucket",
		},
	}
	records, err := rules[cloudPublicResourceExposureRuleID].Evaluate(context.Background(), runtime, publicTagOnly)
	if err != nil {
		t.Fatalf("Evaluate(publicTagOnly) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(publicTagOnly records) = %d, want 0", len(records))
	}

	targetOnly := &cerebrov1.EventEnvelope{
		Id:       "aws-target-only",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.iam_role_trust",
		Attributes: map[string]string{
			"family":    "iam_role_trust",
			"target_id": "arn:aws:iam::123456789012:role/ReadOnlyRole",
		},
	}
	records, err = rules[cloudPrivilegePathGrantedRuleID].Evaluate(context.Background(), runtime, targetOnly)
	if err != nil {
		t.Fatalf("Evaluate(targetOnly) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(targetOnly records) = %d, want 0", len(records))
	}
}

func TestCloudSignalRulesRespectRuntimeFamily(t *testing.T) {
	rules := cloudRulesByID(t)
	rule := rules[cloudPublicResourceExposureRuleID]
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws", Config: map[string]string{"family": "resource_exposure"}}) {
		t.Fatal("SupportsRuntime(resource_exposure) = false, want true")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws", Config: map[string]string{"family": "public_endpoint"}}) {
		t.Fatal("SupportsRuntime(public_endpoint) = true, want false")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "aws"}) {
		t.Fatal("SupportsRuntime(default cloudtrail) = true, want false")
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

	wildcardRead := &cerebrov1.EventEnvelope{
		Id:       "aws-effective-wildcard-read",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "s3:GetObject*",
			"domain":        "123456789012",
			"effect":        "allow",
			"resource_id":   "arn:aws:s3:::reports",
			"resource_type": "bucket",
			"subject_id":    "reader@writer.com",
			"subject_type":  "user",
		},
	}
	records, err = rules[cloudEffectiveAdminPermissionRuleID].Evaluate(context.Background(), runtime, wildcardRead)
	if err != nil {
		t.Fatalf("Evaluate(wildcardRead) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(wildcardRead records) = %d, want 0", len(records))
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

func TestCloudEffectiveAdminPermission(t *testing.T) {
	rules := cloudRulesByID(t)
	rule := rules[cloudEffectiveAdminPermissionRuleID]
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"cloud_account_urn", "principal_urn", "permission_urn"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "event_id" {
			t.Fatalf("FingerprintFields still contains event_id: %v", definition.FingerprintFields)
		}
	}
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	first := &cerebrov1.EventEnvelope{
		Id:       "aws-admin-first",
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
	second := &cerebrov1.EventEnvelope{
		Id:       "aws-admin-second",
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
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v), want one record", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v), want one record", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q (should be anchored to (account, principal, permission))", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}
	if got := firstFinding.Attributes["cloud_account_urn"]; got == "" {
		t.Fatalf("attributes[cloud_account_urn] = empty, want non-empty URN")
	}
	if got := firstFinding.Attributes["principal_urn"]; got == "" {
		t.Fatalf("attributes[principal_urn] = empty, want non-empty URN")
	}
	if got := firstFinding.Attributes["permission_urn"]; got == "" {
		t.Fatalf("attributes[permission_urn] = empty, want non-empty URN")
	}
	revoked := &cerebrov1.EventEnvelope{
		Id:       "aws-admin-revoked",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "s3:GetObject",
			"domain":        "123456789012",
			"effect":        "allow",
			"resource_id":   "123456789012",
			"resource_type": "account",
			"subject_email": "admin@writer.com",
			"subject_id":    "admin@writer.com",
			"subject_type":  "user",
		},
	}
	records, err = rule.Evaluate(context.Background(), runtime, revoked)
	if err != nil {
		t.Fatalf("Evaluate(revoked) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(revoked) returned %d findings, want 0 once admin permission removed", len(records))
	}
}

func TestCloudEffectivePermissionPrincipalURNPrefersSubjectID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		TenantId: "writer",
		SourceId: "aws",
	}
	attributes := map[string]string{
		"subject_email": "admin@writer.com",
		"subject_id":    "AIDAEXAMPLE",
		"subject_type":  "user",
	}

	if got, want := cloudEffectivePermissionPrincipalURN(event, attributes), "urn:cerebro:writer:aws_user:AIDAEXAMPLE"; got != want {
		t.Fatalf("cloudEffectivePermissionPrincipalURN() = %q, want %q", got, want)
	}
}

func TestCloudEffectivePermissionPrincipalTypeMatchesProjectionHyphenBehavior(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		TenantId: "writer",
		SourceId: "gcp",
	}
	attributes := map[string]string{
		"subject_id":   "payments-sa@writer-prod.iam.gserviceaccount.com",
		"subject_type": "service-account",
	}

	if got, want := cloudEffectivePermissionPrincipalURN(event, attributes), "urn:cerebro:writer:gcp_account:payments-sa@writer-prod.iam.gserviceaccount.com"; got != want {
		t.Fatalf("cloudEffectivePermissionPrincipalURN() = %q, want %q", got, want)
	}
}

func TestCloudPrivilegePathGranted(t *testing.T) {
	rules := cloudRulesByID(t)
	rule := rules[cloudPrivilegePathGrantedRuleID]
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"principal_urn", "target_principal_urn", "relationship"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	attrs := map[string]string{
		"domain":       "123456789012",
		"family":       "iam_role_trust",
		"path_type":    "assume_role_trust",
		"relationship": "can_assume",
		"subject_id":   "arn:aws:iam::999999999999:role/ExternalAdmin",
		"subject_type": "role",
		"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
		"target_type":  "role",
	}
	first := &cerebrov1.EventEnvelope{Id: "trust-first", TenantId: "writer", SourceId: "aws", Kind: "aws.iam_role_trust", Attributes: attrs}
	second := &cerebrov1.EventEnvelope{Id: "trust-second", TenantId: "writer", SourceId: "aws", Kind: "aws.iam_role_trust", Attributes: attrs}
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v)", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v)", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	for _, eventID := range []string{first.GetId(), second.GetId()} {
		if strings.Contains(firstFinding.Fingerprint, eventID) {
			t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, eventID)
		}
	}
	if got := firstFinding.Attributes["principal_urn"]; got == "" {
		t.Fatalf("attributes[principal_urn] = empty")
	}
	if got := firstFinding.Attributes["target_principal_urn"]; got == "" {
		t.Fatalf("attributes[target_principal_urn] = empty")
	}
	if got := firstFinding.Attributes["relationship"]; got == "" {
		t.Fatalf("attributes[relationship] = empty")
	}
	clean := &cerebrov1.EventEnvelope{Id: "trust-clean", TenantId: "writer", SourceId: "aws", Kind: "aws.iam_role_trust", Attributes: map[string]string{
		"domain":       "123456789012",
		"family":       "iam_role_trust",
		"path_type":    "read_only",
		"relationship": "can_describe",
		"subject_id":   "arn:aws:iam::999999999999:role/ExternalAdmin",
		"subject_type": "role",
		"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
		"target_type":  "role",
	}}
	records, err = rule.Evaluate(context.Background(), runtime, clean)
	if err != nil {
		t.Fatalf("Evaluate(clean) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(clean) returned %d findings, want 0 once trust path removed", len(records))
	}
}

func TestCloudPublicResourceExposure(t *testing.T) {
	rules := cloudRulesByID(t)
	rule := rules[cloudPublicResourceExposureRuleID]
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	wantFields := []string{"exposed_resource_urn"}
	if !cloudStringSlicesEqual(definition.FingerprintFields, wantFields) {
		t.Fatalf("FingerprintFields = %v, want %v", definition.FingerprintFields, wantFields)
	}
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	attrs := map[string]string{
		"domain":           "123456789012",
		"exposed_to":       "public_internet",
		"exposure_type":    "public_network_ingress",
		"family":           "resource_exposure",
		"internet_exposed": "true",
		"resource_id":      "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
		"resource_name":    "prod-web",
		"resource_type":    "security_group",
		"source_cidr":      "0.0.0.0/0",
	}
	first := &cerebrov1.EventEnvelope{Id: "exposure-first", TenantId: "writer", SourceId: "aws", Kind: "aws.resource_exposure", Attributes: attrs}
	second := &cerebrov1.EventEnvelope{Id: "exposure-second", TenantId: "writer", SourceId: "aws", Kind: "aws.resource_exposure", Attributes: attrs}
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v)", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v)", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	if strings.Contains(firstFinding.Fingerprint, first.GetId()) {
		t.Fatalf("fingerprint %q contains event id", firstFinding.Fingerprint)
	}
	if got := firstFinding.Attributes["exposed_resource_urn"]; got == "" {
		t.Fatalf("attributes[exposed_resource_urn] = empty")
	}
	clean := &cerebrov1.EventEnvelope{Id: "exposure-clean", TenantId: "writer", SourceId: "aws", Kind: "aws.resource_exposure", Attributes: map[string]string{
		"domain":        "123456789012",
		"exposed_to":    "internal_vpc",
		"family":        "resource_exposure",
		"resource_id":   "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
		"resource_type": "security_group",
		"source_cidr":   "10.0.0.0/8",
	}}
	records, err = rule.Evaluate(context.Background(), runtime, clean)
	if err != nil {
		t.Fatalf("Evaluate(clean) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(clean) returned %d findings, want 0 once resource made private", len(records))
	}
}

func TestCloudPublicResourceExposure_PrimaryResourceURNDeterministic(t *testing.T) {
	rules := cloudRulesByID(t)
	rule, ok := rules[cloudPublicResourceExposureRuleID].(*cloudSignalRule)
	if !ok {
		t.Fatalf("%s is %T, want *cloudSignalRule", cloudPublicResourceExposureRuleID, rules[cloudPublicResourceExposureRuleID])
	}
	runtime := &cerebrov1.SourceRuntime{Id: "aws-runtime", SourceId: "aws", TenantId: "writer"}
	resourceID := "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1"
	exposedResourceURN := "urn:cerebro:writer:aws_security_group:" + resourceID
	publicPrincipalURN := "urn:cerebro:writer:aws_public_principal:public_internet"
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-public-exposure",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.resource_exposure",
		Attributes: map[string]string{
			"domain":           "123456789012",
			"exposed_to":       "public_internet",
			"exposure_type":    "public_network_ingress",
			"family":           "resource_exposure",
			"internet_exposed": "true",
			"resource_id":      resourceID,
			"resource_name":    "prod-web",
			"resource_type":    "security_group",
			"source_cidr":      "0.0.0.0/0",
		},
	}
	projection := findingProjectionContext{
		PrimaryActorURN:    exposedResourceURN,
		PrimaryResourceURN: publicPrincipalURN,
		ResourceLabel:      "public internet",
		ResourceURNs:       []string{exposedResourceURN, publicPrincipalURN},
		Entities: []*ports.ProjectedEntity{
			{
				URN:        publicPrincipalURN,
				TenantID:   "writer",
				SourceID:   "aws",
				EntityType: "aws.public_principal",
				Label:      "public internet",
			},
			{
				URN:        exposedResourceURN,
				TenantID:   "writer",
				SourceID:   "aws",
				EntityType: "aws.security.group",
				Label:      "prod-web",
				Attributes: map[string]string{"resource_id": resourceID},
			},
		},
		Links: []*ports.ProjectedLink{
			{FromURN: publicPrincipalURN, ToURN: exposedResourceURN, Relation: "can_reach"},
			{FromURN: exposedResourceURN, ToURN: publicPrincipalURN, Relation: "can_reach"},
		},
	}

	seenPrimaryResources := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		fingerprintInputs := cloudPublicResourceExposureFingerprintInputs(event, event.GetAttributes(), projection)
		if len(fingerprintInputs) != 1 || fingerprintInputs[0] != exposedResourceURN {
			t.Fatalf("cloudPublicResourceExposureFingerprintInputs() = %v, want [%s]", fingerprintInputs, exposedResourceURN)
		}
		attributes := cloudFindingAttributes(event, runtime, rule.config, projection)
		seenPrimaryResources[attributes["primary_resource_urn"]] = struct{}{}
		if got := attributes["primary_resource_urn"]; got != exposedResourceURN {
			t.Fatalf("iteration %d primary_resource_urn = %q, want fingerprint-selected exposed resource %q", i, got, exposedResourceURN)
		}
	}
	if len(seenPrimaryResources) != 1 {
		t.Fatalf("primary_resource_urn values varied across iterations: %v", seenPrimaryResources)
	}
}

func cloudStringSlicesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloudRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	rules := map[string]Rule{}
	for _, rule := range newCloudSignalRules() {
		rules[rule.Spec().GetId()] = rule
	}
	return rules
}
