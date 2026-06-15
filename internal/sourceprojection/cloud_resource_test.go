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

func TestProjectAWSAppRunnerServiceLinksAccountExposureOwnerAndRuntimeRole(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	serviceARN := "arn:aws:apprunner:us-east-1:123456789012:service/api/0f2d1e"
	roleARN := "arn:aws:iam::123456789012:role/AppRunnerInstanceRole"
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-app-runner-service-api",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.apprunner_service",
		Attributes: map[string]string{
			"domain":            "123456789012",
			"internet_exposed":  "true",
			"owner":             "platform@writer.com",
			"public":            "true",
			"public_endpoint":   "https://api.us-east-1.awsapprunner.com",
			"region":            "us-east-1",
			"resource_id":       serviceARN,
			"resource_name":     "api",
			"resource_provider": "aws",
			"resource_type":     "apprunner_service",
			"role_arn":          roleARN,
			"role_name":         "AppRunnerInstanceRole",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:aws_apprunner_service:" + serviceARN
	roleURN := "urn:cerebro:writer:aws_role:" + roleARN
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "aws.apprunner.service" {
		t.Fatalf("app runner entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, resourceURN, relationOwnedBy, "urn:cerebro:writer:owner:platform@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, resourceURN)
	assertProjectedLink(t, state, resourceURN, relationRunsAs, roleURN)
}

func TestProjectAWSStreamingCloudResourceMetadata(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	resourceARN := "arn:aws:kinesis:us-east-1:123456789012:stream/orders"
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-kinesis-orders",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.kinesis_stream",
		Attributes: map[string]string{
			"domain":            "123456789012",
			"encryption":        "KMS",
			"internet_exposed":  "true",
			"kms_key_id":        "arn:aws:kms:us-east-1:123456789012:key/key-123",
			"owner":             "streaming@writer.com",
			"public":            "true",
			"region":            "us-east-1",
			"resource_id":       resourceARN,
			"resource_name":     "orders",
			"resource_provider": "aws",
			"resource_type":     "kinesis_stream",
			"retention_hours":   "168",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:aws_kinesis_stream:" + resourceARN
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "aws.kinesis.stream" {
		t.Fatalf("kinesis stream entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, resourceURN, relationOwnedBy, "urn:cerebro:writer:owner:streaming@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:owner:streaming@writer.com", relationHasIdentifier, "urn:cerebro:writer:identifier:email:streaming@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, resourceURN)
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

func TestProjectAzureCognitiveServicesAccountLinksPublicExposure(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	resourceID := "/subscriptions/sub-1/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/openai-prod"
	event := &cerebrov1.EventEnvelope{
		Id:       "azure-openai-prod",
		TenantId: "writer",
		SourceId: "azure",
		Kind:     "azure.cognitive_services_account",
		Attributes: map[string]string{
			"kind":                  "OpenAI",
			"public_network_access": "Enabled",
			"resource_group":        "rg-ai",
			"resource_id":           resourceID,
			"resource_name":         "openai-prod",
			"resource_provider":     "azure",
			"resource_type":         "Microsoft.CognitiveServices/accounts",
			"subscription_id":       "sub-1",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:azure_cognitive_services_account:" + resourceID
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "azure.cognitive.services.account" {
		t.Fatalf("azure cognitive services account entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:azure_resource_group:sub-1:rg-ai")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_public_principal:public_internet", relationCanReach, resourceURN)
}

func TestProjectAzureMachineLearningWorkspaceLinksPublicExposure(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	resourceID := "/subscriptions/sub-1/resourceGroups/rg-ml/providers/Microsoft.MachineLearningServices/workspaces/ml-prod"
	event := &cerebrov1.EventEnvelope{
		Id:       "azure-ml-prod",
		TenantId: "writer",
		SourceId: "azure",
		Kind:     "azure.machine_learning_workspace",
		Attributes: map[string]string{
			"public_network_access": "Enabled",
			"resource_group":        "rg-ml",
			"resource_id":           resourceID,
			"resource_name":         "ml-prod",
			"resource_provider":     "azure",
			"resource_type":         "Microsoft.MachineLearningServices/workspaces",
			"subscription_id":       "sub-1",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:azure_machine_learning_workspace:" + resourceID
	if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != "azure.machine.learning.workspace" {
		t.Fatalf("azure machine learning workspace entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:azure_resource_group:sub-1:rg-ml")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_public_principal:public_internet", relationCanReach, resourceURN)
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

func TestProjectAWSDatabaseInstanceLinksClusterAndAccount(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-docdb-instance",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.docdb_instance",
		Attributes: map[string]string{
			"cluster_arn":            "arn:aws:rds:us-east-1:123456789012:cluster:docdb-prod",
			"cluster_name":           "docdb-prod",
			"db_cluster_identifier":  "docdb-prod",
			"db_instance_identifier": "docdb-prod-1",
			"domain":                 "123456789012",
			"owner":                  "database@writer.com",
			"region":                 "us-east-1",
			"resource_id":            "arn:aws:rds:us-east-1:123456789012:db:docdb-prod-1",
			"resource_name":          "docdb-prod-1",
			"resource_provider":      "aws",
			"resource_type":          "docdb_instance",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	instanceURN := "urn:cerebro:writer:aws_docdb_instance:arn:aws:rds:us-east-1:123456789012:db:docdb-prod-1"
	clusterURN := "urn:cerebro:writer:aws_docdb_cluster:arn:aws:rds:us-east-1:123456789012:cluster:docdb-prod"
	if entity := state.entities[clusterURN]; entity == nil || entity.EntityType != "aws.docdb.cluster" {
		t.Fatalf("docdb cluster entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, instanceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
}

func TestProjectAWSNetworkEdgeCloudResources(t *testing.T) {
	for _, tt := range []struct {
		kind         string
		resourceID   string
		resourceType string
		entityType   string
	}{
		{kind: "aws.apigateway_stage", resourceID: "v2:api-123:prod", resourceType: "apigateway_stage", entityType: "aws.apigateway.stage"},
		{kind: "aws.apigateway_route", resourceID: "v2:api-123:route-1", resourceType: "apigateway_route", entityType: "aws.apigateway.route"},
		{kind: "aws.apigateway_integration", resourceID: "v2:api-123:int-1", resourceType: "apigateway_integration", entityType: "aws.apigateway.integration"},
		{kind: "aws.elbv2_listener", resourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/orders/abc/def", resourceType: "elbv2_listener", entityType: "aws.elbv2.listener"},
		{kind: "aws.elbv2_target_group", resourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders/tg", resourceType: "elbv2_target_group", entityType: "aws.elbv2.target.group"},
		{kind: "aws.cloudfront_origin_access_control", resourceID: "oac-123", resourceType: "cloudfront_origin_access_control", entityType: "aws.cloudfront.origin.access.control"},
		{kind: "aws.cloudfront_key_group", resourceID: "kg-123", resourceType: "cloudfront_key_group", entityType: "aws.cloudfront.key.group"},
		{kind: "aws.cloudfront_public_key", resourceID: "pk-123", resourceType: "cloudfront_public_key", entityType: "aws.cloudfront.public.key"},
		{kind: "aws.cloudfront_response_headers_policy", resourceID: "rhp-123", resourceType: "cloudfront_response_headers_policy", entityType: "aws.cloudfront.response.headers.policy"},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			event := &cerebrov1.EventEnvelope{
				Id:       tt.kind + "-1",
				TenantId: "writer",
				SourceId: "aws",
				Kind:     tt.kind,
				Attributes: map[string]string{
					"domain":            "123456789012",
					"internet_exposed":  "true",
					"public":            "true",
					"region":            "us-east-1",
					"resource_id":       tt.resourceID,
					"resource_name":     "orders",
					"resource_provider": "aws",
					"resource_type":     tt.resourceType,
				},
			}

			if _, err := service.Project(context.Background(), event); err != nil {
				t.Fatalf("Project() error = %v", err)
			}

			resourceURN := "urn:cerebro:writer:aws_" + tt.resourceType + ":" + tt.resourceID
			if entity := state.entities[resourceURN]; entity == nil || entity.EntityType != tt.entityType {
				t.Fatalf("resource entity = %#v, want type %s", entity, tt.entityType)
			}
			assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
			assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, resourceURN)
		})
	}
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
			name:         "ebs encryption by default",
			kind:         "aws.ec2_ebs_encryption_by_default",
			resourceID:   "arn:aws:ec2:us-east-1:123456789012:ebs-encryption-by-default/default",
			resourceType: "ec2_ebs_encryption_by_default",
			entityType:   "aws.ec2.ebs.encryption.by.default",
		},
		{
			name:         "guardduty detector",
			kind:         "aws.guardduty_detector",
			resourceID:   "arn:aws:guardduty:us-east-1:123456789012:detector/detector-1",
			resourceType: "guardduty_detector",
			entityType:   "aws.guardduty.detector",
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
