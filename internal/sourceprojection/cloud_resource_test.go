package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGCPCloudResourceMetadataLinksAccountExposureOwnerClassificationAndRuntimeIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "gcp-cloud-run-api",
		TenantId: "writer",
		SourceId: "gcp",
		Kind:     "gcp.cloud_run_service",
		Attributes: map[string]string{
			"crown_jewel":           "true",
			"data_classification":   "restricted",
			"external_exposure":     "true",
			"internet_exposed":      "true",
			"owner":                 "api-owner@writer.com",
			"project_id":            "writer-prod",
			"public":                "true",
			"public_endpoint":       "https://api-writer-prod.run.app",
			"region":                "us-central1",
			"resource_id":           "projects/writer-prod/locations/us-central1/services/api",
			"resource_name":         "api",
			"resource_provider":     "gcp",
			"resource_type":         "cloud_run_service",
			"service_account_email": "api@writer-prod.iam.gserviceaccount.com",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:gcp_cloud_run_service:projects/writer-prod/locations/us-central1/services/api"
	serviceAccountURN := "urn:cerebro:writer:gcp_service_account:api@writer-prod.iam.gserviceaccount.com"
	ownerURN := "urn:cerebro:writer:owner:api-owner@writer.com"
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "gcp.cloud.run.service" {
		t.Fatalf("cloud run entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
	assertProjectedLink(t, state, resourceURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, ownerURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:api-owner@writer.com")
	assertProjectedLink(t, state, resourceURN, relationHasClassification, "urn:cerebro:writer:data_classification:restricted")
	assertProjectedLink(t, state, resourceURN, relationTaggedAs, "urn:cerebro:writer:asset_tag:crown_jewel")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_public_principal:public_internet", relationCanReach, resourceURN)
	assertProjectedLink(t, state, resourceURN, relationCanReach, "urn:cerebro:writer:gcp_public_principal:public_internet")
	assertProjectedLink(t, state, resourceURN, relationRunsAs, serviceAccountURN)
	if link := state.links[resourceURN+"|"+relationRunsAs+"|"+serviceAccountURN]; link == nil || link.Attributes["match_type"] != "gcp_runtime_service_account" {
		t.Fatalf("runs_as link = %#v, want gcp runtime service account match", link)
	}
}

func TestProjectAzureCloudResourceMetadataLinksManagedIdentitiesAndResourceGroup(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	resourceID := "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1"
	event := &cerebrov1.EventEnvelope{
		Id:       "azure-vm-1",
		TenantId: "writer",
		SourceId: "azure",
		Kind:     "azure.virtual_machine",
		Attributes: map[string]string{
			"identity_principal_id":       "principal-system-1",
			"internet_exposed":            "true",
			"owner":                       "Compute Team",
			"public_host":                 "vm-1.eastus.cloudapp.azure.com",
			"public_network_access":       "Enabled",
			"resource_group":              "rg-prod",
			"resource_id":                 resourceID,
			"resource_name":               "vm-1",
			"resource_provider":           "azure",
			"resource_type":               "Microsoft.Compute/virtualMachines",
			"subscription_id":             "sub-1",
			"user_assigned_principal_ids": "principal-user-1,principal-user-2",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:azure_virtual_machine:" + resourceID
	systemIdentityURN := "urn:cerebro:writer:azure_service_principal:principal-system-1"
	userIdentityURN := "urn:cerebro:writer:azure_service_principal:principal-user-1"
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "azure.virtual.machine" {
		t.Fatalf("azure vm entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:azure_resource_group:sub-1:rg-prod")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_resource_group:sub-1:rg-prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, resourceURN, relationOwnedBy, "urn:cerebro:writer:owner:Compute Team")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_public_principal:public_internet", relationCanReach, resourceURN)
	assertProjectedLink(t, state, resourceURN, relationRunsAs, systemIdentityURN)
	assertProjectedLink(t, state, resourceURN, relationRunsAs, userIdentityURN)
}

func TestProjectAWSAnalyticsCloudResourceLinksAccountAndRole(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-glue-job-analytics",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.glue_job",
		Attributes: map[string]string{
			"domain":            "123456789012",
			"family":            "glue_job",
			"region":            "us-east-1",
			"relationship":      "runs_as",
			"resource_id":       "arn:aws:glue:us-east-1:123456789012:job/analytics-etl",
			"resource_name":     "analytics-etl",
			"resource_provider": "aws",
			"resource_type":     "glue_job",
			"role_arn":          "arn:aws:iam::123456789012:role/GlueJobRole",
			"role_name":         "GlueJobRole",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:aws_glue_job:arn:aws:glue:us-east-1:123456789012:job/analytics-etl"
	roleURN := "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/GlueJobRole"
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "aws.glue.job" {
		t.Fatalf("glue job entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, resourceURN, relationRunsAs, roleURN)
}
