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
	Name                string
	Columns             []string
	Fetch               func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error)
	Mode                TableSyncMode
	Scope               TableRegionScope
	IncrementalLookback time.Duration
}

type TableSyncMode int

const (
	TableSyncModeFull TableSyncMode = iota
	TableSyncModeIncremental
)

type TableRegionScope int

const (
	TableRegionScopeRegional TableRegionScope = iota
	TableRegionScopeGlobal
)

// SyncResult holds results for a single table sync
type SyncResult struct {
	Table    string
	Region   string
	Synced   int
	Errors   int
	Error    string
	Duration time.Duration
	Changes  *ChangeSet
	SyncTime time.Time
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
	tables := []TableSpec{
		// ECS
		e.ecsClusterTable(),
		e.ecsServiceTable(),
		e.ecsTaskDefinitionTable(),

		// EC2 - Core
		e.ec2InstanceTable(),
		e.ec2SecurityGroupTable(),
		e.ec2SecurityGroupRuleTable(),
		e.ec2VpcTable(),
		e.ec2NaclTable(),
		e.ec2SubnetTable(),
		e.ec2RouteTableTable(),
		e.ec2InternetGatewayTable(),
		e.ec2NatGatewayTable(),
		e.ec2EbsVolumeTable(),
		e.ec2EbsSnapshotTable(),
		e.ec2RegionalConfigTable(),

		// EC2 - Network & VPN
		e.ec2ImageTable(),
		e.ec2EipTable(),
		e.ec2KeyPairTable(),
		e.ec2LaunchTemplateTable(),
		e.ec2NetworkInterfaceTable(),
		e.ec2FlowLogTable(),
		e.ec2VpcEndpointTable(),
		e.ec2VpcPeeringConnectionTable(),
		e.ec2TransitGatewayTable(),
		e.ec2TransitGatewayAttachmentTable(),
		e.ec2TransitGatewayRouteTableTable(),
		e.ec2ManagedPrefixListTable(),
		e.ec2ClientVpnEndpointTable(),
		e.ec2DedicatedHostTable(),
		e.ec2IpamTable(),
		e.ec2ReservedInstanceTable(),
		e.ec2CapacityReservationTable(),
		e.ec2SpotInstanceRequestTable(),
		e.ec2CustomerGatewayTable(),
		e.ec2VpnGatewayTable(),
		e.ec2VpnConnectionTable(),
		e.ec2DhcpOptionsTable(),

		// IAM - Core
		e.iamRoleTable(),
		e.iamUserTable(),
		e.iamCredentialReportTable(),

		// IAM - Extended
		e.iamPolicyTable(),
		e.iamPolicyVersionTable(),
		e.iamGroupTable(),
		e.iamUserAccessKeyTable(),
		e.iamMfaDeviceTable(),
		e.iamVirtualMfaDeviceTable(),
		e.iamPasswordPolicyTable(),
		e.iamAccountSummaryTable(),
		e.iamAccountAliasTable(),
		e.iamUserLoginProfileTable(),
		e.iamSigningCertificateTable(),
		e.iamSSHPublicKeyTable(),
		e.iamServiceSpecificCredentialTable(),
		e.iamAccessAdvisorTable(),
		e.iamInstanceProfileTable(),
		e.iamSamlProviderTable(),
		e.iamOidcProviderTable(),
		e.iamServerCertificateTable(),
		e.iamRolePolicyTable(),
		e.iamRoleAttachedPolicyTable(),
		e.iamUserAttachedPolicyTable(),
		e.iamGroupAttachedPolicyTable(),
		e.iamUserPolicyTable(),
		e.iamGroupPolicyTable(),
		e.iamUserGroupTable(),

		// S3 - Core
		e.s3BucketTable(),

		// S3 - Extended
		e.s3BucketPolicyTable(),
		e.s3BucketGrantTable(),
		e.s3BucketEncryptionTable(),
		e.s3BucketVersioningTable(),
		e.s3BucketLoggingTable(),
		e.s3BucketPublicAccessBlockTable(),
		e.s3BucketOwnershipControlsTable(),
		e.s3BucketPolicyStatusTable(),
		e.s3BucketNotificationTable(),
		e.s3BucketInventoryTable(),
		e.s3BucketObjectLockTable(),
		e.s3AccessPointTable(),
		e.s3BucketLifecycleTable(),
		e.s3BucketReplicationTable(),
		e.s3BucketCorsTable(),
		e.s3BucketWebsiteTable(),
		e.s3ObjectTable(),

		// ECR
		e.ecrRepositoryTable(),
		e.ecrImageTable(),
		e.ecrPublicRepositoryTable(),
		e.ecrLifecyclePolicyTable(),

		// Lambda
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
		e.kmsAliasTable(),
		e.kmsKeyPolicyTable(),
		e.kmsGrantTable(),
		e.kmsKeyRotationStatusTable(),
		e.kmsCustomKeyStoreTable(),
		e.secretsManagerSecretTable(),

		// Security - WAF
		e.wafv2WebAclTable(),
		e.wafv2IpSetTable(),
		e.wafv2RuleGroupTable(),
		e.wafv2RegexPatternSetTable(),

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
		e.apiGatewayMethodTable(),
		e.apiGatewayStageTable(),
		e.apiGatewayV2ApiTable(),
		e.apiGatewayV2StageTable(),

		// SageMaker
		e.sagemakerNotebookTable(),
		e.sagemakerModelTable(),
		e.sagemakerModelPackageGroupTable(),
		e.sagemakerEndpointTable(),
		e.sagemakerTrainingJobTable(),
		e.sagemakerEndpointConfigTable(),

		// Database - RDS
		e.rdsInstanceTable(),
		e.rdsClusterTable(),
		e.rdsSnapshotTable(),
		e.rdsClusterSnapshotTable(),
		e.rdsSubnetGroupTable(),
		e.rdsParameterGroupTable(),
		e.rdsClusterParameterGroupTable(),
		e.rdsOptionGroupTable(),
		e.rdsProxyTable(),
		e.rdsProxyEndpointTable(),
		e.rdsEventSubscriptionTable(),

		// Database - DynamoDB
		e.dynamoDBTableTable(),

		// Database - Redshift
		e.redshiftClusterTable(),

		// Database - ElastiCache
		e.elasticacheClusterTable(),
		e.elasticacheReplicationGroupTable(),
		e.elasticacheSubnetGroupTable(),
		e.elasticacheParameterGroupTable(),

		// Database - OpenSearch
		e.opensearchDomainTable(),

		// Networking - ELB
		e.elbv2LoadBalancerTable(),
		e.elbv2TargetGroupTable(),
		e.elbv2ListenerTable(),
		e.elbv2ListenerActionTable(),

		// Messaging
		e.snsTopicTable(),
		e.snsSubscriptionTable(),
		e.sqsQueueTable(),

		// Storage - EFS
		e.efsFileSystemTable(),
		e.efsMountTargetTable(),

		// Logging
		e.cloudtrailTrailTable(),
		e.cloudtrailEventSelectorTable(),
		e.cloudtrailInsightSelectorTable(),
		e.cloudtrailEventDataStoreTable(),
		e.cloudtrailChannelTable(),
		e.cloudtrailResourcePolicyTable(),
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

		// ACM (Certificate Manager)
		e.acmCertificateTable(),

		// Route53
		e.route53HostedZoneTable(),
		e.route53RecordSetTable(),
		e.route53HealthCheckTable(),

		// SSM (Systems Manager)
		e.ssmParameterTable(),
		e.ssmManagedInstanceTable(),
		e.ssmPatchComplianceTable(),
		e.ssmDocumentTable(),

		// Inspector
		e.inspectorFindingTable(),
		e.inspectorCoverageTable(),

		// Access Analyzer
		e.accessAnalyzerAnalyzerTable(),
		e.accessAnalyzerFindingTable(),

		// Backup
		e.backupVaultTable(),
		e.backupPlanTable(),
		e.backupProtectedResourceTable(),
		e.backupRecoveryPointTable(),

		// Auto Scaling
		e.autoscalingGroupTable(),
		e.autoscalingLaunchConfigTable(),
		e.autoscalingPolicyTable(),
		e.autoscalingScheduledActionTable(),
		e.autoscalingLifecycleHookTable(),

		// CloudWatch Extended
		e.cloudwatchAlarmTable(),
		e.cloudwatchCompositeAlarmTable(),
		e.cloudwatchDashboardTable(),
		e.cloudwatchMetricStreamTable(),

		// EventBridge
		e.eventbridgeEventBusTable(),
		e.eventbridgeRuleTable(),
		e.eventbridgeTargetTable(),
		e.eventbridgeArchiveTable(),
		e.eventbridgeApiDestinationTable(),

		// Kinesis & Firehose
		e.kinesisStreamTable(),
		e.firehoseDeliveryStreamTable(),

		// Organizations
		e.organizationsAccountTable(),
		e.organizationsOrganizationTable(),
		e.organizationsRootsTable(),
		e.organizationsPolicyTable(),
		e.organizationsPolicyTargetsTable(),
		e.organizationsDelegatedAdministratorsTable(),
		e.organizationsOUTable(),
		e.organizationsAccountParentsTable(),
		// CloudFormation
		e.cloudformationStackTable(),
		e.cloudformationStackResourceTable(),

		// Step Functions
		e.sfnStateMachineTable(),
		e.sfnActivityTable(),

		// Cognito
		e.cognitoUserPoolTable(),
		e.cognitoUserPoolClientTable(),
		e.cognitoIdentityProviderTable(),

		// SES
		e.sesIdentityTable(),
		e.sesConfigurationSetTable(),

		// MSK (Kafka)
		e.mskClusterTable(),
		e.mskConfigurationTable(),

		// Transfer Family
		e.transferServerTable(),
		e.transferUserTable(),

		// FSx
		e.fsxFileSystemTable(),
		e.fsxVolumeTable(),
		e.fsxBackupTable(),

		// DocumentDB
		e.docdbClusterTable(),
		e.docdbInstanceTable(),

		// Neptune
		e.neptuneClusterTable(),
		e.neptuneInstanceTable(),

		// MWAA (Airflow)
		e.mwaaEnvironmentTable(),

		// Cloud Control (all supported AWS resource types)
		e.cloudcontrolResourceTypeTable(),
		e.cloudcontrolResourceTable(),

		// Resource Groups Tagging API
		e.resourceGroupTaggingResourceTable(),
	}

	return normalizeAWSTableSpecs(tables)
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
