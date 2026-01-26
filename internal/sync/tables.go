package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// TableSpec defines a table to sync
type TableSpec struct {
	Name    string
	Columns []string
	Fetch   func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error)
}

// SyncResult holds results for a single table sync
type SyncResult struct {
	Table    string
	Region   string
	Synced   int
	Errors   int
	Duration time.Duration
	Changes  *ChangeSet
}

// ChangeSet tracks what changed during sync
type ChangeSet struct {
	Added    []string
	Removed  []string
	Modified []string
}

func (c *ChangeSet) HasChanges() bool {
	if c == nil {
		return false
	}
	return len(c.Added) > 0 || len(c.Removed) > 0 || len(c.Modified) > 0
}

func (c *ChangeSet) Summary() string {
	if c == nil {
		return "+0/~0/-0"
	}
	return fmt.Sprintf("+%d/~%d/-%d", len(c.Added), len(c.Modified), len(c.Removed))
}

// getAWSTables returns all AWS table definitions
func (e *SyncEngine) getAWSTables() []TableSpec {
	return []TableSpec{
		// ECS
		e.ecsClusterTable(),
		e.ecsServiceTable(),
		e.ecsTaskDefinitionTable(),
		// EC2
		e.ec2InstanceTable(),
		// VPC & Networking (from tables_vpc.go - more comprehensive)
		e.ec2SecurityGroupTable(),
		e.ec2VpcTable(),
		e.ec2NaclTable(),
		e.ec2SubnetTable(),
		e.ec2RouteTableTable(),
		e.ec2InternetGatewayTable(),
		e.ec2NatGatewayTable(),
		e.ec2EbsVolumeTable(),
		e.ec2EbsSnapshotTable(),
		// IAM
		e.iamRoleTable(),
		e.iamUserTable(),
		e.iamCredentialReportTable(),
		// Storage
		e.s3BucketTable(),
		// ECR
		e.ecrRepositoryTable(),
		e.ecrImageTable(),
		e.ecrPublicRepositoryTable(),
		e.ecrLifecyclePolicyTable(),
		// Compute
		e.lambdaFunctionTable(),
		// Security - GuardDuty
		e.guarddutyDetectorTable(),
		e.guarddutyFindingsTable(),
		// Security - SecurityHub
		e.securityHubTable(),
		e.securityHubFindingsTable(),
		e.securityHubStandardsTable(),
		// Security - KMS & Secrets
		e.kmsKeyTable(),
		e.secretsManagerSecretTable(),
		// Config
		e.configRecorderTable(),
		e.configRuleTable(),
		e.configDeliveryChannelTable(),
		e.configConformancePackTable(),
		// EKS
		e.eksClusterTable(),
		e.eksNodegroupTable(),
		e.eksFargateProfileTable(),
		// API Gateway
		e.apiGatewayRestApiTable(),
		e.apiGatewayStageTable(),
		e.apiGatewayV2ApiTable(),
		e.apiGatewayV2StageTable(),
		// SageMaker
		e.sagemakerNotebookTable(),
		e.sagemakerModelTable(),
		e.sagemakerEndpointTable(),
		e.sagemakerTrainingJobTable(),
		e.sagemakerEndpointConfigTable(),
		// Database
		e.rdsInstanceTable(),
		e.dynamoDBTableTable(),
		e.redshiftClusterTable(),
		// Networking - ELB
		e.elbv2LoadBalancerTable(),
		e.elbv2TargetGroupTable(),
		// Messaging
		e.snsTopicTable(),
		e.sqsQueueTable(),
		// Storage (EFS)
		e.efsFileSystemTable(),
		e.efsMountTargetTable(),
		// Logging
		e.cloudtrailTrailTable(),
		e.cloudwatchLogGroupTable(),
		// CodeBuild
		e.codebuildProjectTable(),
		e.codebuildSourceCredentialTable(),
		// AppSync
		e.appsyncGraphQLApiTable(),
		// Bedrock
		e.bedrockCustomModelTable(),
		e.bedrockProvisionedThroughputTable(),
		e.bedrockGuardrailTable(),
		// CloudFront
		e.cloudfrontDistributionTable(),
	}
}

func (e *SyncEngine) getAccountIDFromConfig(ctx context.Context, cfg aws.Config) string {
	if e.accountID != "" {
		return e.accountID
	}
	stsClient := sts.NewFromConfig(cfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err == nil && out.Account != nil {
		e.accountID = *out.Account
	}
	return e.accountID
}
