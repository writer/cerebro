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

func TestProjectAWSDataResourceLinksNetworkAndElastiCacheContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-elasticache-cluster-orders",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.elasticache_cluster",
		Attributes: map[string]string{
			"cache_cluster_id":        "orders-001",
			"cache_subnet_group_name": "cache-subnets",
			"domain":                  "123456789012",
			"replication_group_id":    "orders-rg",
			"resource_id":             "arn:aws:elasticache:us-east-1:123456789012:cluster:orders-001",
			"resource_name":           "orders-001",
			"resource_provider":       "aws",
			"resource_type":           "elasticache_cluster",
			"security_group_ids":      "sg-cache",
			"subnet_ids":              "subnet-cache",
			"vpc_id":                  "vpc-1",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:aws_elasticache_cluster:arn:aws:elasticache:us-east-1:123456789012:cluster:orders-001"
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:aws_vpc:vpc-1")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:aws_subnet:subnet-cache")
	assertProjectedLink(t, state, resourceURN, relationMemberOf, "urn:cerebro:writer:aws_security_group:sg-cache")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:aws_elasticache_replication_group:orders-rg")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:aws_elasticache_subnet_group:cache-subnets")
}

func TestProjectAWSBatchResourcesUseCloudResourceProjection(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	computeEnvironmentARN := "arn:aws:batch:us-east-1:123456789012:compute-environment/prod-batch"
	jobQueueARN := "arn:aws:batch:us-east-1:123456789012:job-queue/prod-jobs"
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-batch-compute-environment-prod",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.batch_compute_environment",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"owner":             "platform@writer.com",
				"resource_id":       computeEnvironmentARN,
				"resource_name":     "prod-batch",
				"resource_provider": "aws",
				"resource_type":     "batch_compute_environment",
				"role_arn":          "arn:aws:iam::123456789012:role/service-role/AWSBatchServiceRole",
				"role_name":         "service-role/AWSBatchServiceRole",
			},
		},
		{
			Id:       "aws-batch-job-queue-prod",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.batch_job_queue",
			Attributes: map[string]string{
				"compute_environment_arns": computeEnvironmentARN,
				"domain":                   "123456789012",
				"resource_id":              jobQueueARN,
				"resource_name":            "prod-jobs",
				"resource_provider":        "aws",
				"resource_type":            "batch_job_queue",
			},
		},
	}

	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetKind(), err)
		}
	}

	computeURN := "urn:cerebro:writer:aws_batch_compute_environment:" + computeEnvironmentARN
	queueURN := "urn:cerebro:writer:aws_batch_job_queue:" + jobQueueARN
	roleURN := "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/service-role/AWSBatchServiceRole"
	if entity := state.entities[computeURN]; entity == nil || entity.EntityType != "aws.batch.compute.environment" {
		t.Fatalf("batch compute environment entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[queueURN]; entity == nil || entity.EntityType != "aws.batch.job.queue" {
		t.Fatalf("batch job queue entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, computeURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, computeURN, relationOwnedBy, "urn:cerebro:writer:owner:platform@writer.com")
	assertProjectedLink(t, state, computeURN, relationRunsAs, roleURN)
	assertProjectedLink(t, state, queueURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
}
func TestProjectAWSStorageAccessAndDataSyncResources(t *testing.T) {
	for _, tt := range []struct {
		name         string
		kind         string
		resourceID   string
		resourceType string
		entityType   string
		public       bool
	}{
		{
			name:         "s3 access point",
			kind:         "aws.s3_access_point",
			resourceID:   "arn:aws:s3:us-east-1:123456789012:accesspoint/prod-data-ap",
			resourceType: "s3_access_point",
			entityType:   "aws.s3.access.point",
		},
		{
			name:         "multi-region access point",
			kind:         "aws.s3_multi_region_access_point",
			resourceID:   "arn:aws:s3::123456789012:accesspoint/prod-global",
			resourceType: "s3_multi_region_access_point",
			entityType:   "aws.s3.multi.region.access.point",
		},
		{
			name:         "ebs volume",
			kind:         "aws.ebs_volume",
			resourceID:   "arn:aws:ec2:us-east-1:123456789012:volume/vol-123",
			resourceType: "ebs_volume",
			entityType:   "aws.ebs.volume",
		},
		{
			name:         "public ebs snapshot",
			kind:         "aws.ebs_snapshot",
			resourceID:   "snap-123",
			resourceType: "ebs_snapshot",
			entityType:   "aws.ebs.snapshot",
			public:       true,
		},
		{
			name:         "datasync task",
			kind:         "aws.datasync_task",
			resourceID:   "arn:aws:datasync:us-east-1:123456789012:task/task-123",
			resourceType: "datasync_task",
			entityType:   "aws.datasync.task",
		},
		{
			name:         "datasync location",
			kind:         "aws.datasync_location",
			resourceID:   "arn:aws:datasync:us-east-1:123456789012:location/loc-src",
			resourceType: "datasync_location",
			entityType:   "aws.datasync.location",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			event := &cerebrov1.EventEnvelope{
				Id:       "aws-storage-resource",
				TenantId: "writer",
				SourceId: "aws",
				Kind:     tt.kind,
				Attributes: map[string]string{
					"domain":            "123456789012",
					"internet_exposed":  boolString(tt.public),
					"owner":             "storage@writer.com",
					"public":            boolString(tt.public),
					"region":            "us-east-1",
					"resource_id":       tt.resourceID,
					"resource_name":     "storage-resource",
					"resource_provider": "aws",
					"resource_type":     tt.resourceType,
				},
			}

			if _, err := service.Project(context.Background(), event); err != nil {
				t.Fatalf("Project() error = %v", err)
			}

			resourceURN := "urn:cerebro:writer:aws_" + tt.resourceType + ":" + tt.resourceID
			if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != tt.entityType {
				t.Fatalf("entity = %#v, want type %s", entity, tt.entityType)
			}
			assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
			assertProjectedLink(t, state, resourceURN, relationOwnedBy, "urn:cerebro:writer:owner:storage@writer.com")
			if tt.public {
				assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, resourceURN)
			}
		})
	}
}
