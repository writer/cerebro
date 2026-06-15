package aws

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/sources/internal/awsaccount"
	"github.com/writer/cerebro/sources/internal/textutil"
)

//go:embed catalog.yaml
var catalogFS embed.FS

var emailPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
var awsRoleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

const (
	defaultFamily                            = familyCloudTrail
	defaultRegion                            = "us-east-1"
	defaultPageSize                          = 10
	maxPageSize                              = 200
	cloudTrailCursorVersion                  = 1
	cloudTrailCursorMaxAge                   = 55 * time.Minute
	publicEndpointCursorV2                   = 2
	awsAssumeRoleSessionName                 = "cerebro-source-runtime"
	familyAccessKey                          = "access_key"
	familyACMCertificate                     = "acm_certificate"
	familyAppRunnerService                   = "apprunner_service"
	familyAssetMetadata                      = "asset_metadata"
	familyAthenaDataCatalog                  = "athena_data_catalog"
	familyAthenaWorkgroup                    = "athena_workgroup"
	familyBatchComputeEnv                    = "batch_compute_environment"
	familyBatchJobQueue                      = "batch_job_queue"
	familyBackupPlan                         = "backup_plan"
	familyBackupProtected                    = "backup_protected_resource"
	familyBackupRecoveryPoint                = "backup_recovery_point"
	familyBackupVault                        = "backup_vault"
	familyCloudTrail                         = "cloudtrail"
	familyCloudWatchAlarm                    = "cloudwatch_alarm"
	familyCloudWatchLogGroup                 = "cloudwatch_log_group"
	familyDataSyncLocation                   = "datasync_location"
	familyDataSyncTask                       = "datasync_task"
	familyDynamoDBBackup                     = "dynamodb_backup"
	familyDynamoDBStream                     = "dynamodb_stream"
	familyDynamoDBTable                      = "dynamodb_table"
	familyEBSSnapshot                        = "ebs_snapshot"
	familyEBSVolume                          = "ebs_volume"
	familyEC2EBSEncryptionByDefault          = "ec2_ebs_encryption_by_default"
	familyEC2Instance                        = "ec2_instance"
	familyVPC                                = "vpc"
	familySubnet                             = "subnet"
	familySecurityGroup                      = "security_group"
	familyRouteTable                         = "route_table"
	familyInternetGateway                    = "internet_gateway"
	familyNATGateway                         = "nat_gateway"
	familyVPCEndpoint                        = "vpc_endpoint"
	familyECRRepository                      = "ecr_repository"
	familyECSService                         = "ecs_service"
	familyECSTask                            = "ecs_task"
	familyECSTaskDefinition                  = "ecs_task_definition"
	familyEFSAccessPoint                     = "efs_access_point"
	familyEFSFileSystem                      = "efs_file_system"
	familyEKSCluster                         = "eks_cluster"
	familyEKSNodegroup                       = "eks_nodegroup"
	familyEKSFargateProfile                  = "eks_fargate_profile"
	familyEKSPodIdentity                     = "eks_pod_identity_association"
	familyGlobalAccelerator                  = "globalaccelerator_accelerator"
	familyGAListener                         = "globalaccelerator_listener"
	familyGAEndpointGroup                    = "globalaccelerator_endpoint_group"
	familyVPCLatticeService                  = "vpclattice_service"
	familyVPCLatticeListener                 = "vpclattice_listener"
	familyVPCLatticeTG                       = "vpclattice_target_group"
	familyELBV2LoadBalancer                  = "elbv2_load_balancer"
	familyELBV2Listener                      = "elbv2_listener"
	familyELBV2TargetGroup                   = "elbv2_target_group"
	familyAPIGatewayStage                    = "apigateway_stage"
	familyAPIGatewayRoute                    = "apigateway_route"
	familyAPIGatewayInteg                    = "apigateway_integration"
	familyCloudFrontDistribution             = "cloudfront_distribution"
	familyCloudFrontOAC                      = "cloudfront_origin_access_control"
	familyCloudFrontKeyGroup                 = "cloudfront_key_group"
	familyCloudFrontPublicKey                = "cloudfront_public_key"
	familyCloudFrontRHP                      = "cloudfront_response_headers_policy"
	familyEffectivePermission                = "effective_permission"
	familyEventBridgeArchive                 = "eventbridge_archive"
	familyEventBridgeBus                     = "eventbridge_event_bus"
	familyEventBridgePipe                    = "eventbridge_pipe"
	familyEventBridgeRule                    = "eventbridge_rule"
	familyFirehoseDelivery                   = "firehose_delivery_stream"
	familyGlueCrawler                        = "glue_crawler"
	familyGlueDatabase                       = "glue_database"
	familyGlueJob                            = "glue_job"
	familyGlueTable                          = "glue_table"
	familyIAMGroup                           = "iam_group"
	familyIAMMembership                      = "iam_group_membership"
	familyIAMRoleTrust                       = "iam_role_trust"
	familyIAMRoleAssign                      = "iam_role_assignment"
	familyIAMRole                            = "iam_role"
	familyIAMUser                            = "iam_user"
	familyIdentityCenterAssignment           = "identity_center_account_assignment"
	familyIdentityCenterPermission           = "identity_center_permission_set"
	familyIdentityStoreGroup                 = "identitystore_group"
	familyIdentityStoreMember                = "identitystore_group_membership"
	familyIdentityStoreUser                  = "identitystore_user"
	familyKinesisStream                      = "kinesis_stream"
	familyKMSKey                             = "kms_key"
	familyLakeFormationLFTag                 = "lakeformation_lf_tag"
	familyLakeFormationPerm                  = "lakeformation_permission"
	familyLakeFormationRes                   = "lakeformation_resource"
	familyLambdaFunction                     = "lambda_function"
	familyMSKCluster                         = "msk_cluster"
	familyOrganizationsAcct                  = "organizations_account"
	familyOrganizationsOU                    = "organizations_organizational_unit"
	familyOrganizationsPolicy                = "organizations_policy"
	familyPublicEndpoint                     = "public_endpoint"
	familyRDSInstance                        = "rds_instance"
	familyResourceExposure                   = "resource_exposure"
	familyRoute53ResolverEndpoint            = "route53_resolver_endpoint"
	familyRoute53ResolverRule                = "route53_resolver_rule"
	familyS3AccessPoint                      = "s3_access_point"
	familyS3Bucket                           = "s3_bucket"
	familyS3MultiRegionAccessPoint           = "s3_multi_region_access_point"
	familySchedulerSchedule                  = "scheduler_schedule"
	familySchedulerGroup                     = "scheduler_schedule_group"
	familySecret                             = "secret"
	familySNSTopic                           = "sns_topic"
	familySQSQueue                           = "sqs_queue"
	familySSOAssignment                      = "sso_account_assignment"
	familySSOInstance                        = "sso_instance"
	familySSOPermissionSet                   = "sso_permission_set"
	familySSMAssociation                     = "ssm_association"
	familySSMDocument                        = "ssm_document"
	familySSMManagedInstance                 = "ssm_managed_instance"
	familySSMParameter                       = "ssm_parameter"
	familyStepFunctionActivity               = "stepfunctions_activity"
	familyStepFunctionStateMachine           = "stepfunctions_state_machine"
	familyOrganizationsRoot                  = "organizations_root"
	familyElastiCacheCluster                 = "elasticache_cluster"
	familyElastiCacheReplicationGroup        = "elasticache_replication_group"
	familyElastiCacheSubnetGroup             = "elasticache_subnet_group"
	familyFSxFileSystem                      = "fsx_file_system"
	familyOpenSearchDomain                   = "opensearch_domain"
	familyOpenSearchServerlessCollection     = "opensearch_serverless_collection"
	familyOpenSearchServerlessSecurityPolicy = "opensearch_serverless_security_policy"
	familyDocDBCluster                       = "docdb_cluster"
	familyDocDBInstance                      = "docdb_instance"
	familyNeptuneCluster                     = "neptune_cluster"
	familyNeptuneInstance                    = "neptune_instance"
	familyRedshiftCluster                    = "redshift_cluster"
)

// Source reads AWS IAM inventory and CloudTrail activity through the AWS SDK for Go v2.
type Source struct {
	spec     *cerebrov1.SourceSpec
	clients  awsClientFactory
	families *sourcecdk.FamilyEngine[settings]
}

type settings struct {
	family          string
	accountID       string
	region          string
	profile         string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	roleARN         string
	externalID      string
	assumeRoleARNs  string
	tenantID        string
	includeGlobal   bool
	groupName       string
	principalType   string
	principalName   string
	userName        string
	identityCenter  identityCenterSettings
	cloudTrail      cloudTrailSettings
	wafv2Scope      string
	perPage         int
}

type identityCenterSettings struct {
	storeID          string
	groupID          string
	instanceARN      string
	permissionSetARN string
	targetAccountID  string
}

type cloudTrailSettings struct {
	lookupKey   string
	lookupValue string
	startTime   string
	endTime     string
	since       string
}

type awsClientFactory func(context.Context, settings) (awsClients, error)

type awsClients struct {
	awsPlatformClients
	awsRuntimeClients
	awsAnalyticsClients
	awsGovernanceClients
	awsStorageClients
	awsSecurityClients
	awsDataClients
}

type awsACMAPI interface {
	ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	ListTagsForCertificate(context.Context, *acm.ListTagsForCertificateInput, ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error)
}

type awsPlatformClients struct {
	cfg             awssdk.Config
	acm             awsACMAPI
	iam             awsIAMAPI
	cloudTrail      awsCloudTrailAPI
	ec2             awsEC2API
	route53         awsRoute53API
	route53Resolver awsRoute53ResolverAPI
	cloudFront      awsCloudFrontAPI
	elbv2           awsELBV2API
	globalAccel     awsGlobalAcceleratorAPI
	vpcLattice      awsVPCLatticeAPI
	ecs             awsECSAPI
	eks             awsEKSAPI
	ecr             awsECRAPI
	apiGateway      awsAPIGatewayAPI
	apiGatewayV2    awsAPIGatewayV2API
	lambda          awsLambdaAPI
	tagging         awsResourceGroupsTaggingAPI
	s3              awsS3API
	s3ByRegion      func(string) awsS3API
}

type awsStorageClients struct {
	s3control       awsS3ControlAPI
	datasync        awsDataSyncAPI
	backup          awsBackupAPI
	dynamodb        awsDynamoDBAPI
	dynamodbStreams awsDynamoDBStreamsAPI
	efs             awsEFSAPI
}

type awsDataClients struct {
	elasticache          awsElastiCacheAPI
	fsx                  awsFSxAPI
	openSearch           awsOpenSearchAPI
	openSearchServerless awsOpenSearchServerlessAPI
}

type awsRuntimeClients struct {
	batch          awsBatchAPI
	rds            awsRDSAPI
	kms            awsKMSAPI
	secrets        awsSecretsManagerAPI
	sqs            awsSQSAPI
	sns            awsSNSAPI
	appRunner      awsAppRunnerAPI
	stepFunctions  awsStepFunctionsAPI
	eventBridge    awsEventBridgeAPI
	pipes          awsPipesAPI
	scheduler      awsSchedulerAPI
	cloudWatch     awsCloudWatchAPI
	cloudWatchLogs awsCloudWatchLogsAPI
	ssm            awsSSMAPI
}

type awsAnalyticsClients struct {
	kinesis  awsKinesisAPI
	firehose awsFirehoseAPI
	kafka    awsKafkaAPI
	glue     awsGlueAPI
	athena   awsAthenaAPI
	lake     awsLakeFormationAPI
	redshift awsRedshiftAPI
	docdb    awsDocDBAPI
	neptune  awsNeptuneAPI
}

type awsGovernanceClients struct {
	organizations awsOrganizationsAPI
	sso           awsSSOAdminAPI
	identityStore awsIdentityStoreAPI
}

type awsIAMAPI interface {
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListGroups(context.Context, *iam.ListGroupsInput, ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetGroup(context.Context, *iam.GetGroupInput, ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
}

type awsCloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type awsRedshiftAPI interface {
	DescribeClusters(context.Context, *redshift.DescribeClustersInput, ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

type awsDocDBAPI interface {
	DescribeDBClusters(context.Context, *docdb.DescribeDBClustersInput, ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *docdb.DescribeDBInstancesInput, ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error)
	ListTagsForResource(context.Context, *docdb.ListTagsForResourceInput, ...func(*docdb.Options)) (*docdb.ListTagsForResourceOutput, error)
}

type awsNeptuneAPI interface {
	DescribeDBClusters(context.Context, *neptune.DescribeDBClustersInput, ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
	DescribeDBInstances(context.Context, *neptune.DescribeDBInstancesInput, ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error)
	ListTagsForResource(context.Context, *neptune.ListTagsForResourceInput, ...func(*neptune.Options)) (*neptune.ListTagsForResourceOutput, error)
}

type awsDynamoDBAPI interface {
	ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	ListTagsOfResource(context.Context, *dynamodb.ListTagsOfResourceInput, ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error)
	DescribeContinuousBackups(context.Context, *dynamodb.DescribeContinuousBackupsInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
	DescribeTimeToLive(context.Context, *dynamodb.DescribeTimeToLiveInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTimeToLiveOutput, error)
	ListBackups(context.Context, *dynamodb.ListBackupsInput, ...func(*dynamodb.Options)) (*dynamodb.ListBackupsOutput, error)
}

type awsDynamoDBStreamsAPI interface {
	ListStreams(context.Context, *dynamodbstreams.ListStreamsInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.ListStreamsOutput, error)
	DescribeStream(context.Context, *dynamodbstreams.DescribeStreamInput, ...func(*dynamodbstreams.Options)) (*dynamodbstreams.DescribeStreamOutput, error)
}

type awsEC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	DescribeInternetGateways(context.Context, *ec2.DescribeInternetGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeInternetGatewaysOutput, error)
	DescribeNatGateways(context.Context, *ec2.DescribeNatGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSnapshotAttribute(context.Context, *ec2.DescribeSnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error)
	GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
}

type awsECSAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	ListTaskDefinitions(context.Context, *ecs.ListTaskDefinitionsInput, ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

type awsEFSAPI interface {
	DescribeFileSystems(context.Context, *efs.DescribeFileSystemsInput, ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
	DescribeMountTargets(context.Context, *efs.DescribeMountTargetsInput, ...func(*efs.Options)) (*efs.DescribeMountTargetsOutput, error)
	DescribeMountTargetSecurityGroups(context.Context, *efs.DescribeMountTargetSecurityGroupsInput, ...func(*efs.Options)) (*efs.DescribeMountTargetSecurityGroupsOutput, error)
	DescribeAccessPoints(context.Context, *efs.DescribeAccessPointsInput, ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error)
}

type awsEKSAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListNodegroups(context.Context, *eks.ListNodegroupsInput, ...func(*eks.Options)) (*eks.ListNodegroupsOutput, error)
	DescribeNodegroup(context.Context, *eks.DescribeNodegroupInput, ...func(*eks.Options)) (*eks.DescribeNodegroupOutput, error)
	ListFargateProfiles(context.Context, *eks.ListFargateProfilesInput, ...func(*eks.Options)) (*eks.ListFargateProfilesOutput, error)
	DescribeFargateProfile(context.Context, *eks.DescribeFargateProfileInput, ...func(*eks.Options)) (*eks.DescribeFargateProfileOutput, error)
	ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(context.Context, *eks.DescribePodIdentityAssociationInput, ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

type awsECRAPI interface {
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	ListTagsForResource(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
}

type awsRoute53API interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type awsRoute53ResolverAPI interface {
	ListResolverEndpoints(context.Context, *route53resolver.ListResolverEndpointsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverEndpointsOutput, error)
	ListResolverRules(context.Context, *route53resolver.ListResolverRulesInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverRulesOutput, error)
	ListTagsForResource(context.Context, *route53resolver.ListTagsForResourceInput, ...func(*route53resolver.Options)) (*route53resolver.ListTagsForResourceOutput, error)
}

type awsCloudFrontAPI interface {
	ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	ListOriginAccessControls(context.Context, *cloudfront.ListOriginAccessControlsInput, ...func(*cloudfront.Options)) (*cloudfront.ListOriginAccessControlsOutput, error)
	ListKeyGroups(context.Context, *cloudfront.ListKeyGroupsInput, ...func(*cloudfront.Options)) (*cloudfront.ListKeyGroupsOutput, error)
	ListPublicKeys(context.Context, *cloudfront.ListPublicKeysInput, ...func(*cloudfront.Options)) (*cloudfront.ListPublicKeysOutput, error)
	ListResponseHeadersPolicies(context.Context, *cloudfront.ListResponseHeadersPoliciesInput, ...func(*cloudfront.Options)) (*cloudfront.ListResponseHeadersPoliciesOutput, error)
}

type awsELBV2API interface {
	DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(context.Context, *elbv2.DescribeListenersInput, ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error)
	DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
}

type awsGlobalAcceleratorAPI interface {
	ListAccelerators(context.Context, *globalaccelerator.ListAcceleratorsInput, ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error)
	ListListeners(context.Context, *globalaccelerator.ListListenersInput, ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error)
	ListEndpointGroups(context.Context, *globalaccelerator.ListEndpointGroupsInput, ...func(*globalaccelerator.Options)) (*globalaccelerator.ListEndpointGroupsOutput, error)
}

type awsVPCLatticeAPI interface {
	ListServices(context.Context, *vpclattice.ListServicesInput, ...func(*vpclattice.Options)) (*vpclattice.ListServicesOutput, error)
	ListListeners(context.Context, *vpclattice.ListListenersInput, ...func(*vpclattice.Options)) (*vpclattice.ListListenersOutput, error)
	ListTargetGroups(context.Context, *vpclattice.ListTargetGroupsInput, ...func(*vpclattice.Options)) (*vpclattice.ListTargetGroupsOutput, error)
}

type awsAPIGatewayAPI interface {
	GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
	GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	GetStages(context.Context, *apigateway.GetStagesInput, ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
	GetResources(context.Context, *apigateway.GetResourcesInput, ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error)
	GetIntegration(context.Context, *apigateway.GetIntegrationInput, ...func(*apigateway.Options)) (*apigateway.GetIntegrationOutput, error)
}

type awsAPIGatewayV2API interface {
	GetApis(context.Context, *apigatewayv2.GetApisInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error)
	GetStages(context.Context, *apigatewayv2.GetStagesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
	GetRoutes(context.Context, *apigatewayv2.GetRoutesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetRoutesOutput, error)
	GetIntegrations(context.Context, *apigatewayv2.GetIntegrationsInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetIntegrationsOutput, error)
}

type awsLambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

type awsResourceGroupsTaggingAPI interface {
	GetResources(context.Context, *resourcegroupstaggingapi.GetResourcesInput, ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}

type awsS3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketLogging(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

type awsS3ControlAPI interface {
	ListAccessPoints(context.Context, *s3control.ListAccessPointsInput, ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error)
	GetAccessPoint(context.Context, *s3control.GetAccessPointInput, ...func(*s3control.Options)) (*s3control.GetAccessPointOutput, error)
	GetAccessPointPolicyStatus(context.Context, *s3control.GetAccessPointPolicyStatusInput, ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error)
	ListMultiRegionAccessPoints(context.Context, *s3control.ListMultiRegionAccessPointsInput, ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error)
	GetMultiRegionAccessPoint(context.Context, *s3control.GetMultiRegionAccessPointInput, ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointOutput, error)
	GetMultiRegionAccessPointPolicyStatus(context.Context, *s3control.GetMultiRegionAccessPointPolicyStatusInput, ...func(*s3control.Options)) (*s3control.GetMultiRegionAccessPointPolicyStatusOutput, error)
	ListTagsForResource(context.Context, *s3control.ListTagsForResourceInput, ...func(*s3control.Options)) (*s3control.ListTagsForResourceOutput, error)
}

type awsElastiCacheAPI interface {
	DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
	DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
	DescribeCacheSubnetGroups(context.Context, *elasticache.DescribeCacheSubnetGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheSubnetGroupsOutput, error)
	ListTagsForResource(context.Context, *elasticache.ListTagsForResourceInput, ...func(*elasticache.Options)) (*elasticache.ListTagsForResourceOutput, error)
}

type awsFSxAPI interface {
	DescribeFileSystems(context.Context, *fsx.DescribeFileSystemsInput, ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error)
	ListTagsForResource(context.Context, *fsx.ListTagsForResourceInput, ...func(*fsx.Options)) (*fsx.ListTagsForResourceOutput, error)
}

type awsOpenSearchAPI interface {
	ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomains(context.Context, *opensearch.DescribeDomainsInput, ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error)
	ListTags(context.Context, *opensearch.ListTagsInput, ...func(*opensearch.Options)) (*opensearch.ListTagsOutput, error)
}

type awsOpenSearchServerlessAPI interface {
	ListCollections(context.Context, *opensearchserverless.ListCollectionsInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error)
	BatchGetCollection(context.Context, *opensearchserverless.BatchGetCollectionInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.BatchGetCollectionOutput, error)
	ListTagsForResource(context.Context, *opensearchserverless.ListTagsForResourceInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListTagsForResourceOutput, error)
	ListSecurityPolicies(context.Context, *opensearchserverless.ListSecurityPoliciesInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.ListSecurityPoliciesOutput, error)
	GetSecurityPolicy(context.Context, *opensearchserverless.GetSecurityPolicyInput, ...func(*opensearchserverless.Options)) (*opensearchserverless.GetSecurityPolicyOutput, error)
}

type awsRDSAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

type awsKMSAPI interface {
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

type awsSecretsManagerAPI interface {
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

type awsDataSyncAPI interface {
	ListTasks(context.Context, *datasync.ListTasksInput, ...func(*datasync.Options)) (*datasync.ListTasksOutput, error)
	DescribeTask(context.Context, *datasync.DescribeTaskInput, ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error)
	ListLocations(context.Context, *datasync.ListLocationsInput, ...func(*datasync.Options)) (*datasync.ListLocationsOutput, error)
	DescribeLocationS3(context.Context, *datasync.DescribeLocationS3Input, ...func(*datasync.Options)) (*datasync.DescribeLocationS3Output, error)
	DescribeLocationEfs(context.Context, *datasync.DescribeLocationEfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationEfsOutput, error)
	DescribeLocationFsxLustre(context.Context, *datasync.DescribeLocationFsxLustreInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxLustreOutput, error)
	DescribeLocationFsxOntap(context.Context, *datasync.DescribeLocationFsxOntapInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOntapOutput, error)
	DescribeLocationFsxOpenZfs(context.Context, *datasync.DescribeLocationFsxOpenZfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxOpenZfsOutput, error)
	DescribeLocationFsxWindows(context.Context, *datasync.DescribeLocationFsxWindowsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationFsxWindowsOutput, error)
	DescribeLocationNfs(context.Context, *datasync.DescribeLocationNfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationNfsOutput, error)
	DescribeLocationSmb(context.Context, *datasync.DescribeLocationSmbInput, ...func(*datasync.Options)) (*datasync.DescribeLocationSmbOutput, error)
	DescribeLocationObjectStorage(context.Context, *datasync.DescribeLocationObjectStorageInput, ...func(*datasync.Options)) (*datasync.DescribeLocationObjectStorageOutput, error)
	DescribeLocationHdfs(context.Context, *datasync.DescribeLocationHdfsInput, ...func(*datasync.Options)) (*datasync.DescribeLocationHdfsOutput, error)
	DescribeLocationAzureBlob(context.Context, *datasync.DescribeLocationAzureBlobInput, ...func(*datasync.Options)) (*datasync.DescribeLocationAzureBlobOutput, error)
	ListTagsForResource(context.Context, *datasync.ListTagsForResourceInput, ...func(*datasync.Options)) (*datasync.ListTagsForResourceOutput, error)
}

type awsSQSAPI interface {
	ListQueues(context.Context, *sqs.ListQueuesInput, ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
	ListQueueTags(context.Context, *sqs.ListQueueTagsInput, ...func(*sqs.Options)) (*sqs.ListQueueTagsOutput, error)
}

type awsSNSAPI interface {
	ListTopics(context.Context, *sns.ListTopicsInput, ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(context.Context, *sns.GetTopicAttributesInput, ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
	ListTagsForResource(context.Context, *sns.ListTagsForResourceInput, ...func(*sns.Options)) (*sns.ListTagsForResourceOutput, error)
}

type awsBackupAPI interface {
	ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	ListBackupPlans(context.Context, *backup.ListBackupPlansInput, ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
	GetBackupPlan(context.Context, *backup.GetBackupPlanInput, ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error)
	ListProtectedResources(context.Context, *backup.ListProtectedResourcesInput, ...func(*backup.Options)) (*backup.ListProtectedResourcesOutput, error)
	ListRecoveryPointsByBackupVault(context.Context, *backup.ListRecoveryPointsByBackupVaultInput, ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error)
	ListTags(context.Context, *backup.ListTagsInput, ...func(*backup.Options)) (*backup.ListTagsOutput, error)
}

type awsAppRunnerAPI interface {
	ListServices(context.Context, *apprunner.ListServicesInput, ...func(*apprunner.Options)) (*apprunner.ListServicesOutput, error)
	DescribeService(context.Context, *apprunner.DescribeServiceInput, ...func(*apprunner.Options)) (*apprunner.DescribeServiceOutput, error)
	ListTagsForResource(context.Context, *apprunner.ListTagsForResourceInput, ...func(*apprunner.Options)) (*apprunner.ListTagsForResourceOutput, error)
}

type awsStepFunctionsAPI interface {
	ListStateMachines(context.Context, *sfn.ListStateMachinesInput, ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(context.Context, *sfn.DescribeStateMachineInput, ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
	ListActivities(context.Context, *sfn.ListActivitiesInput, ...func(*sfn.Options)) (*sfn.ListActivitiesOutput, error)
	ListTagsForResource(context.Context, *sfn.ListTagsForResourceInput, ...func(*sfn.Options)) (*sfn.ListTagsForResourceOutput, error)
}

type awsEventBridgeAPI interface {
	ListEventBuses(context.Context, *eventbridge.ListEventBusesInput, ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
	ListRules(context.Context, *eventbridge.ListRulesInput, ...func(*eventbridge.Options)) (*eventbridge.ListRulesOutput, error)
	ListTargetsByRule(context.Context, *eventbridge.ListTargetsByRuleInput, ...func(*eventbridge.Options)) (*eventbridge.ListTargetsByRuleOutput, error)
	ListArchives(context.Context, *eventbridge.ListArchivesInput, ...func(*eventbridge.Options)) (*eventbridge.ListArchivesOutput, error)
	ListTagsForResource(context.Context, *eventbridge.ListTagsForResourceInput, ...func(*eventbridge.Options)) (*eventbridge.ListTagsForResourceOutput, error)
}

type awsPipesAPI interface {
	ListPipes(context.Context, *pipes.ListPipesInput, ...func(*pipes.Options)) (*pipes.ListPipesOutput, error)
	DescribePipe(context.Context, *pipes.DescribePipeInput, ...func(*pipes.Options)) (*pipes.DescribePipeOutput, error)
	ListTagsForResource(context.Context, *pipes.ListTagsForResourceInput, ...func(*pipes.Options)) (*pipes.ListTagsForResourceOutput, error)
}

type awsSchedulerAPI interface {
	ListSchedules(context.Context, *scheduler.ListSchedulesInput, ...func(*scheduler.Options)) (*scheduler.ListSchedulesOutput, error)
	ListScheduleGroups(context.Context, *scheduler.ListScheduleGroupsInput, ...func(*scheduler.Options)) (*scheduler.ListScheduleGroupsOutput, error)
	ListTagsForResource(context.Context, *scheduler.ListTagsForResourceInput, ...func(*scheduler.Options)) (*scheduler.ListTagsForResourceOutput, error)
}

type awsCloudWatchAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
	ListTagsForResource(context.Context, *cloudwatch.ListTagsForResourceInput, ...func(*cloudwatch.Options)) (*cloudwatch.ListTagsForResourceOutput, error)
}

type awsCloudWatchLogsAPI interface {
	DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	ListTagsForResource(context.Context, *cloudwatchlogs.ListTagsForResourceInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListTagsForResourceOutput, error)
}

type awsSSMAPI interface {
	DescribeInstanceInformation(context.Context, *ssm.DescribeInstanceInformationInput, ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
	ListDocuments(context.Context, *ssm.ListDocumentsInput, ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error)
	ListAssociations(context.Context, *ssm.ListAssociationsInput, ...func(*ssm.Options)) (*ssm.ListAssociationsOutput, error)
	DescribeParameters(context.Context, *ssm.DescribeParametersInput, ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	ListTagsForResource(context.Context, *ssm.ListTagsForResourceInput, ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
}

type awsKinesisAPI interface {
	ListStreams(context.Context, *kinesis.ListStreamsInput, ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(context.Context, *kinesis.DescribeStreamSummaryInput, ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
	ListTagsForStream(context.Context, *kinesis.ListTagsForStreamInput, ...func(*kinesis.Options)) (*kinesis.ListTagsForStreamOutput, error)
	GetResourcePolicy(context.Context, *kinesis.GetResourcePolicyInput, ...func(*kinesis.Options)) (*kinesis.GetResourcePolicyOutput, error)
}

type awsFirehoseAPI interface {
	ListDeliveryStreams(context.Context, *firehose.ListDeliveryStreamsInput, ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
	DescribeDeliveryStream(context.Context, *firehose.DescribeDeliveryStreamInput, ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error)
	ListTagsForDeliveryStream(context.Context, *firehose.ListTagsForDeliveryStreamInput, ...func(*firehose.Options)) (*firehose.ListTagsForDeliveryStreamOutput, error)
}

type awsKafkaAPI interface {
	ListClustersV2(context.Context, *kafka.ListClustersV2Input, ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
	DescribeClusterV2(context.Context, *kafka.DescribeClusterV2Input, ...func(*kafka.Options)) (*kafka.DescribeClusterV2Output, error)
	ListTagsForResource(context.Context, *kafka.ListTagsForResourceInput, ...func(*kafka.Options)) (*kafka.ListTagsForResourceOutput, error)
}

type awsGlueAPI interface {
	GetDatabases(context.Context, *glue.GetDatabasesInput, ...func(*glue.Options)) (*glue.GetDatabasesOutput, error)
	GetTables(context.Context, *glue.GetTablesInput, ...func(*glue.Options)) (*glue.GetTablesOutput, error)
	ListCrawlers(context.Context, *glue.ListCrawlersInput, ...func(*glue.Options)) (*glue.ListCrawlersOutput, error)
	GetCrawler(context.Context, *glue.GetCrawlerInput, ...func(*glue.Options)) (*glue.GetCrawlerOutput, error)
	ListJobs(context.Context, *glue.ListJobsInput, ...func(*glue.Options)) (*glue.ListJobsOutput, error)
	GetJob(context.Context, *glue.GetJobInput, ...func(*glue.Options)) (*glue.GetJobOutput, error)
	GetTags(context.Context, *glue.GetTagsInput, ...func(*glue.Options)) (*glue.GetTagsOutput, error)
}

type awsAthenaAPI interface {
	ListWorkGroups(context.Context, *athena.ListWorkGroupsInput, ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error)
	GetWorkGroup(context.Context, *athena.GetWorkGroupInput, ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error)
	ListDataCatalogs(context.Context, *athena.ListDataCatalogsInput, ...func(*athena.Options)) (*athena.ListDataCatalogsOutput, error)
	GetDataCatalog(context.Context, *athena.GetDataCatalogInput, ...func(*athena.Options)) (*athena.GetDataCatalogOutput, error)
	ListTagsForResource(context.Context, *athena.ListTagsForResourceInput, ...func(*athena.Options)) (*athena.ListTagsForResourceOutput, error)
}

type awsLakeFormationAPI interface {
	ListResources(context.Context, *lakeformation.ListResourcesInput, ...func(*lakeformation.Options)) (*lakeformation.ListResourcesOutput, error)
	ListLFTags(context.Context, *lakeformation.ListLFTagsInput, ...func(*lakeformation.Options)) (*lakeformation.ListLFTagsOutput, error)
	ListPermissions(context.Context, *lakeformation.ListPermissionsInput, ...func(*lakeformation.Options)) (*lakeformation.ListPermissionsOutput, error)
}

type awsOrganizationsAPI interface {
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListParents(context.Context, *organizations.ListParentsInput, ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPolicies(context.Context, *organizations.ListPoliciesInput, ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(context.Context, *organizations.ListTargetsForPolicyInput, ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

type awsSSOAdminAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
}

type awsIdentityStoreAPI interface {
	ListUsers(context.Context, *identitystore.ListUsersInput, ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error)
	ListGroups(context.Context, *identitystore.ListGroupsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupsOutput, error)
	ListGroupMemberships(context.Context, *identitystore.ListGroupMembershipsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error)
}

type awsFamilyOptions[T any] struct {
	Name           string
	Label          string
	List           func(context.Context, awsClients, settings, string, int) ([]T, string, error)
	Event          func(settings, T) (*primitives.Event, error)
	URN            func(settings, T) (string, error)
	Discover       func(context.Context, awsClients, settings) ([]sourcecdk.URN, error)
	CursorFallback func(T) string
}

type iamPolicyAssignment struct {
	PrincipalType string
	PrincipalName string
	Policy        iamtypes.AttachedPolicy
	PolicySource  string
	Actions       []string
}

type iamGroupMember struct {
	GroupName string
	User      iamtypes.User
}

type iamPrincipalAssignmentCursor struct {
	Stage  string `json:"stage,omitempty"`
	Marker string `json:"marker,omitempty"`
}

type awsResourceExposure struct {
	ResourceID   string
	ResourceName string
	ExposureID   string
	SourceCIDR   string
	Protocol     string
	PortRange    string
	Region       string
	Scope        string
	Group        ec2types.SecurityGroup
	Permission   ec2types.IpPermission
}

type awsPublicEndpoint struct {
	ResourceID           string
	ResourceName         string
	ResourceType         string
	EndpointID           string
	EndpointType         string
	Host                 string
	TargetHost           string
	TargetHosts          []string
	AlternateHosts       []string
	IP                   string
	TargetIP             string
	TargetIPs            []string
	DNSRecordType        string
	HostedZoneID         string
	HostedZoneName       string
	PrivateZone          bool
	Region               string
	Scope                string
	Service              string
	AttachedInstanceID   string
	AssociatedInstanceID string
}

type awsAssetMetadata struct {
	ResourceARN  string
	ResourceID   string
	ResourceName string
	ResourceType string
	Region       string
	Tags         map[string]string
}

type awsEC2Instance struct {
	Instance ec2types.Instance
	Role     iamtypes.Role
}

type awsECSService struct {
	ClusterARN string
	Service    ecstypes.Service
}

const (
	publicEndpointStageRoute53           = "route53"
	publicEndpointStageCloudFront        = "cloudfront"
	publicEndpointStageELB               = "load_balancer"
	publicEndpointStageAPIGateway        = "apigateway"
	publicEndpointStageAPIGatewayRestAPI = "apigateway_rest_api"
	publicEndpointStageAPIGatewayV2      = "apigatewayv2"
	publicEndpointStageAPIGatewayV2API   = "apigatewayv2_api"
	publicEndpointStageEIP               = "elastic_ip"
	publicEndpointStageENI               = "network_interface"
)

type publicEndpointCursor struct {
	Version                 int    `json:"version,omitempty"`
	Stage                   string `json:"stage,omitempty"`
	Token                   string `json:"token,omitempty"`
	Route53ZoneMarker       string `json:"route53_zone_marker,omitempty"`
	Route53NextZoneMarker   string `json:"route53_next_zone_marker,omitempty"`
	Route53ZoneID           string `json:"route53_zone_id,omitempty"`
	Route53ZoneName         string `json:"route53_zone_name,omitempty"`
	Route53PrivateZone      bool   `json:"route53_private_zone,omitempty"`
	Route53RecordName       string `json:"route53_record_name,omitempty"`
	Route53RecordType       string `json:"route53_record_type,omitempty"`
	Route53RecordIdentifier string `json:"route53_record_identifier,omitempty"`
}

type iamRoleTrust struct {
	Role          iamtypes.Role
	Statement     trustStatement
	Principal     string
	PrincipalType string
}

type iamTrustPrincipal struct {
	Type  string
	Value string
}

type trustPolicyDocument struct {
	Statement []trustStatement `json:"Statement"`
}

type trustStatement struct {
	Sid       string          `json:"Sid"`
	Effect    string          `json:"Effect"`
	Action    any             `json:"Action"`
	Principal json.RawMessage `json:"Principal"`
	Condition map[string]any  `json:"Condition"`
}

type cloudTrailDetail struct {
	EventName       string                  `json:"eventName"`
	EventSource     string                  `json:"eventSource"`
	EventTime       string                  `json:"eventTime"`
	SourceIPAddress string                  `json:"sourceIPAddress"`
	UserIdentity    cloudTrailUserIdentity  `json:"userIdentity"`
	Resources       []cloudTrailResourceRef `json:"resources"`
}

type cloudTrailUserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	UserName    string `json:"userName"`
}

type cloudTrailResourceRef struct {
	ARN       string `json:"ARN"`
	ARNLower  string `json:"arn"`
	Name      string `json:"resourceName"`
	Type      string `json:"resourceType"`
	AccountID string `json:"accountId"`
}

type cloudTrailCursor struct {
	Version       int    `json:"version,omitempty"`
	Token         string `json:"token,omitempty"`
	StartTime     string `json:"start_time,omitempty"`
	EndTime       string `json:"end_time,omitempty"`
	StartSelector string `json:"start_selector,omitempty"`
	EndSelector   string `json:"end_selector,omitempty"`
	LookupKey     string `json:"lookup_key,omitempty"`
	LookupValue   string `json:"lookup_value,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
}

// New constructs the live AWS source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, clients: newAWSClients}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured AWS family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns AWS resource URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized AWS events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{
		awsFamily(s.clients, awsFamilyOptions[iamtypes.AccessKeyMetadata]{
			Name:  familyAccessKey,
			Label: "aws iam access keys",
			List:  listAccessKeys,
			Event: accessKeyEvent,
			URN: func(settings settings, key iamtypes.AccessKeyMetadata) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:access_key:%s:%s", settings.accountID, settings.userName, awssdk.ToString(key.AccessKeyId)), nil
			},
			CursorFallback: func(key iamtypes.AccessKeyMetadata) string { return awssdk.ToString(key.AccessKeyId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsACMCertificate]{
			Name:  familyACMCertificate,
			Label: "aws acm certificates",
			List:  listACMCertificates,
			Event: acmCertificateEvent,
			URN: func(settings settings, certificate awsACMCertificate) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_acm_certificate:%s", settings.accountID, firstNonEmpty(awssdk.ToString(certificate.Certificate.CertificateArn), awssdk.ToString(certificate.Certificate.DomainName))), nil
			},
			CursorFallback: func(certificate awsACMCertificate) string {
				return firstNonEmpty(awssdk.ToString(certificate.Certificate.CertificateArn), awssdk.ToString(certificate.Certificate.DomainName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAssetMetadata]{
			Name:  familyAssetMetadata,
			Label: "aws asset metadata",
			List:  listAssetMetadata,
			Event: assetMetadataEvent,
			URN: func(settings settings, asset awsAssetMetadata) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_asset_metadata:%s", settings.accountID, firstNonEmpty(asset.ResourceARN, asset.ResourceID)), nil
			},
			CursorFallback: func(asset awsAssetMetadata) string { return firstNonEmpty(asset.ResourceARN, asset.ResourceID) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsRedshiftCluster]{
			Name:  familyRedshiftCluster,
			Label: "aws redshift clusters",
			List:  listRedshiftClusters,
			Event: redshiftClusterEvent,
			URN: func(settings settings, record awsRedshiftCluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_redshift_cluster:%s", settings.accountID, firstNonEmpty(redshiftClusterARN(settings, awssdk.ToString(record.Cluster.ClusterIdentifier)), awssdk.ToString(record.Cluster.ClusterIdentifier))), nil
			},
			CursorFallback: func(record awsRedshiftCluster) string {
				return awssdk.ToString(record.Cluster.ClusterIdentifier)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDocDBCluster]{
			Name:  familyDocDBCluster,
			Label: "aws documentdb clusters",
			List:  listDocDBClusters,
			Event: docDBClusterEvent,
			URN: func(settings settings, record awsDocDBCluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_docdb_cluster:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Cluster.DBClusterArn), awssdk.ToString(record.Cluster.DBClusterIdentifier))), nil
			},
			CursorFallback: func(record awsDocDBCluster) string {
				return firstNonEmpty(awssdk.ToString(record.Cluster.DBClusterArn), awssdk.ToString(record.Cluster.DBClusterIdentifier))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDocDBInstance]{
			Name:  familyDocDBInstance,
			Label: "aws documentdb instances",
			List:  listDocDBInstances,
			Event: docDBInstanceEvent,
			URN: func(settings settings, record awsDocDBInstance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_docdb_instance:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))), nil
			},
			CursorFallback: func(record awsDocDBInstance) string {
				return firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsNeptuneCluster]{
			Name:  familyNeptuneCluster,
			Label: "aws neptune clusters",
			List:  listNeptuneClusters,
			Event: neptuneClusterEvent,
			URN: func(settings settings, record awsNeptuneCluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_neptune_cluster:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Cluster.DBClusterArn), awssdk.ToString(record.Cluster.DBClusterIdentifier))), nil
			},
			CursorFallback: func(record awsNeptuneCluster) string {
				return firstNonEmpty(awssdk.ToString(record.Cluster.DBClusterArn), awssdk.ToString(record.Cluster.DBClusterIdentifier))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsNeptuneInstance]{
			Name:  familyNeptuneInstance,
			Label: "aws neptune instances",
			List:  listNeptuneInstances,
			Event: neptuneInstanceEvent,
			URN: func(settings settings, record awsNeptuneInstance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_neptune_instance:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))), nil
			},
			CursorFallback: func(record awsNeptuneInstance) string {
				return firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDynamoDBTable]{
			Name:  familyDynamoDBTable,
			Label: "aws dynamodb tables",
			List:  listDynamoDBTables,
			Event: dynamoDBTableEvent,
			URN: func(settings settings, table awsDynamoDBTable) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_dynamodb_table:%s", settings.accountID, firstNonEmpty(awssdk.ToString(table.Table.TableArn), awssdk.ToString(table.Table.TableName))), nil
			},
			CursorFallback: func(table awsDynamoDBTable) string {
				return firstNonEmpty(awssdk.ToString(table.Table.TableArn), awssdk.ToString(table.Table.TableName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDynamoDBBackup]{
			Name:  familyDynamoDBBackup,
			Label: "aws dynamodb backups",
			List:  listDynamoDBBackups,
			Event: dynamoDBBackupEvent,
			URN: func(settings settings, backup awsDynamoDBBackup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_dynamodb_backup:%s", settings.accountID, firstNonEmpty(awssdk.ToString(backup.BackupArn), awssdk.ToString(backup.BackupName))), nil
			},
			CursorFallback: func(backup awsDynamoDBBackup) string { return awssdk.ToString(backup.BackupArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDynamoDBStream]{
			Name:  familyDynamoDBStream,
			Label: "aws dynamodb streams",
			List:  listDynamoDBStreams,
			Event: dynamoDBStreamEvent,
			URN: func(settings settings, stream awsDynamoDBStream) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_dynamodb_stream:%s", settings.accountID, firstNonEmpty(awssdk.ToString(stream.Stream.StreamArn), awssdk.ToString(stream.Stream.StreamLabel))), nil
			},
			CursorFallback: func(stream awsDynamoDBStream) string {
				return firstNonEmpty(awssdk.ToString(stream.Stream.StreamArn), awssdk.ToString(stream.Stream.StreamLabel))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBatchComputeEnvironment]{
			Name:  familyBatchComputeEnv,
			Label: "aws batch compute environments",
			List:  listBatchComputeEnvironments,
			Event: batchComputeEnvironmentEvent,
			URN: func(settings settings, environment awsBatchComputeEnvironment) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_batch_compute_environment:%s", settings.accountID, firstNonEmpty(awssdk.ToString(environment.ComputeEnvironmentArn), awssdk.ToString(environment.ComputeEnvironmentName))), nil
			},
			CursorFallback: func(environment awsBatchComputeEnvironment) string {
				return firstNonEmpty(awssdk.ToString(environment.ComputeEnvironmentArn), awssdk.ToString(environment.ComputeEnvironmentName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBatchJobQueue]{
			Name:  familyBatchJobQueue,
			Label: "aws batch job queues",
			List:  listBatchJobQueues,
			Event: batchJobQueueEvent,
			URN: func(settings settings, queue awsBatchJobQueue) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_batch_job_queue:%s", settings.accountID, firstNonEmpty(awssdk.ToString(queue.JobQueueArn), awssdk.ToString(queue.JobQueueName))), nil
			},
			CursorFallback: func(queue awsBatchJobQueue) string {
				return firstNonEmpty(awssdk.ToString(queue.JobQueueArn), awssdk.ToString(queue.JobQueueName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBackupVault]{
			Name:  familyBackupVault,
			Label: "aws backup vaults",
			List:  listBackupVaults,
			Event: backupVaultEvent,
			URN: func(settings settings, vault awsBackupVault) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_backup_vault:%s", settings.accountID, firstNonEmpty(vault.ARN, backupVaultARN(settings, vault.Name), vault.Name)), nil
			},
			CursorFallback: func(vault awsBackupVault) string { return firstNonEmpty(vault.ARN, vault.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBackupPlan]{
			Name:  familyBackupPlan,
			Label: "aws backup plans",
			List:  listBackupPlans,
			Event: backupPlanEvent,
			URN: func(settings settings, plan awsBackupPlan) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_backup_plan:%s", settings.accountID, firstNonEmpty(plan.ARN, plan.ID, plan.Name)), nil
			},
			CursorFallback: func(plan awsBackupPlan) string { return firstNonEmpty(plan.ARN, plan.ID, plan.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBackupProtectedResource]{
			Name:  familyBackupProtected,
			Label: "aws backup protected resources",
			List:  listBackupProtectedResources,
			Event: backupProtectedResourceEvent,
			URN: func(settings settings, resource awsBackupProtectedResource) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_backup_protected_resource:%s", settings.accountID, firstNonEmpty(awssdk.ToString(resource.ResourceArn), awssdk.ToString(resource.ResourceName))), nil
			},
			CursorFallback: func(resource awsBackupProtectedResource) string {
				return firstNonEmpty(awssdk.ToString(resource.ResourceArn), awssdk.ToString(resource.ResourceName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsBackupRecoveryPoint]{
			Name:  familyBackupRecoveryPoint,
			Label: "aws backup recovery points",
			List:  listBackupRecoveryPoints,
			Event: backupRecoveryPointEvent,
			URN: func(settings settings, point awsBackupRecoveryPoint) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_backup_recovery_point:%s", settings.accountID, firstNonEmpty(awssdk.ToString(point.RecoveryPointArn), awssdk.ToString(point.ResourceArn))), nil
			},
			CursorFallback: func(point awsBackupRecoveryPoint) string {
				return firstNonEmpty(awssdk.ToString(point.RecoveryPointArn), awssdk.ToString(point.ResourceArn))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsKinesisStream]{
			Name:  familyKinesisStream,
			Label: "aws kinesis streams",
			List:  listKinesisStreams,
			Event: kinesisStreamEvent,
			URN: func(settings settings, stream awsKinesisStream) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_kinesis_stream:%s", settings.accountID, firstNonEmpty(awssdk.ToString(stream.Summary.StreamARN), awssdk.ToString(stream.Summary.StreamName))), nil
			},
			CursorFallback: func(stream awsKinesisStream) string {
				return firstNonEmpty(awssdk.ToString(stream.Summary.StreamARN), awssdk.ToString(stream.Summary.StreamName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsFirehoseDeliveryStream]{
			Name:  familyFirehoseDelivery,
			Label: "aws firehose delivery streams",
			List:  listFirehoseDeliveryStreams,
			Event: firehoseDeliveryStreamEvent,
			URN: func(settings settings, stream awsFirehoseDeliveryStream) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_firehose_delivery_stream:%s", settings.accountID, firstNonEmpty(awssdk.ToString(stream.Description.DeliveryStreamARN), awssdk.ToString(stream.Description.DeliveryStreamName))), nil
			},
			CursorFallback: func(stream awsFirehoseDeliveryStream) string {
				return firstNonEmpty(awssdk.ToString(stream.Description.DeliveryStreamARN), awssdk.ToString(stream.Description.DeliveryStreamName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsMSKCluster]{
			Name:  familyMSKCluster,
			Label: "aws msk clusters",
			List:  listMSKClusters,
			Event: mskClusterEvent,
			URN: func(settings settings, cluster awsMSKCluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_msk_cluster:%s", settings.accountID, firstNonEmpty(awssdk.ToString(cluster.Cluster.ClusterArn), awssdk.ToString(cluster.Cluster.ClusterName))), nil
			},
			CursorFallback: func(cluster awsMSKCluster) string {
				return firstNonEmpty(awssdk.ToString(cluster.Cluster.ClusterArn), awssdk.ToString(cluster.Cluster.ClusterName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlueDatabase]{
			Name:  familyGlueDatabase,
			Label: "aws glue databases",
			List:  listGlueDatabases,
			Event: glueDatabaseEvent,
			URN: func(settings settings, database awsGlueDatabase) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_glue_database:%s", settings.accountID, firstNonEmpty(glueDatabaseARN(settings, awssdk.ToString(database.Database.CatalogId), awssdk.ToString(database.Database.Name)), awssdk.ToString(database.Database.Name))), nil
			},
			CursorFallback: func(database awsGlueDatabase) string {
				return awssdk.ToString(database.Database.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlueTable]{
			Name:  familyGlueTable,
			Label: "aws glue tables",
			List:  listGlueTables,
			Event: glueTableEvent,
			URN: func(settings settings, table awsGlueTable) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_glue_table:%s", settings.accountID, glueTableResourceID(settings, table)), nil
			},
			CursorFallback: func(table awsGlueTable) string {
				return firstNonEmpty(firstNonEmpty(table.DatabaseName, awssdk.ToString(table.Table.DatabaseName))+"/"+awssdk.ToString(table.Table.Name), awssdk.ToString(table.Table.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlueCrawler]{
			Name:  familyGlueCrawler,
			Label: "aws glue crawlers",
			List:  listGlueCrawlers,
			Event: glueCrawlerEvent,
			URN: func(settings settings, crawler awsGlueCrawler) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_glue_crawler:%s", settings.accountID, firstNonEmpty(glueCrawlerARN(settings, awssdk.ToString(crawler.Crawler.Name)), awssdk.ToString(crawler.Crawler.Name))), nil
			},
			CursorFallback: func(crawler awsGlueCrawler) string {
				return awssdk.ToString(crawler.Crawler.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlueJob]{
			Name:  familyGlueJob,
			Label: "aws glue jobs",
			List:  listGlueJobs,
			Event: glueJobEvent,
			URN: func(settings settings, job awsGlueJob) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_glue_job:%s", settings.accountID, firstNonEmpty(glueJobARN(settings, awssdk.ToString(job.Job.Name)), awssdk.ToString(job.Job.Name))), nil
			},
			CursorFallback: func(job awsGlueJob) string {
				return awssdk.ToString(job.Job.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAthenaWorkgroup]{
			Name:  familyAthenaWorkgroup,
			Label: "aws athena workgroups",
			List:  listAthenaWorkgroups,
			Event: athenaWorkgroupEvent,
			URN: func(settings settings, workgroup awsAthenaWorkgroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_athena_workgroup:%s", settings.accountID, firstNonEmpty(athenaWorkgroupARN(settings, awssdk.ToString(workgroup.WorkGroup.Name)), awssdk.ToString(workgroup.WorkGroup.Name))), nil
			},
			CursorFallback: func(workgroup awsAthenaWorkgroup) string {
				return awssdk.ToString(workgroup.WorkGroup.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAthenaDataCatalog]{
			Name:  familyAthenaDataCatalog,
			Label: "aws athena data catalogs",
			List:  listAthenaDataCatalogs,
			Event: athenaDataCatalogEvent,
			URN: func(settings settings, catalog awsAthenaDataCatalog) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_athena_data_catalog:%s", settings.accountID, firstNonEmpty(athenaDataCatalogARN(settings, awssdk.ToString(catalog.Catalog.Name)), awssdk.ToString(catalog.Catalog.Name))), nil
			},
			CursorFallback: func(catalog awsAthenaDataCatalog) string {
				return awssdk.ToString(catalog.Catalog.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsLakeFormationResource]{
			Name:  familyLakeFormationRes,
			Label: "aws lake formation resources",
			List:  listLakeFormationResources,
			Event: lakeFormationResourceEvent,
			URN: func(settings settings, resource awsLakeFormationResource) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_lakeformation_resource:%s", settings.accountID, firstNonEmpty(awssdk.ToString(resource.Resource.ResourceArn), awssdk.ToString(resource.Resource.RoleArn))), nil
			},
			CursorFallback: func(resource awsLakeFormationResource) string {
				return firstNonEmpty(awssdk.ToString(resource.Resource.ResourceArn), awssdk.ToString(resource.Resource.RoleArn))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsLakeFormationLFTag]{
			Name:  familyLakeFormationLFTag,
			Label: "aws lake formation lf-tags",
			List:  listLakeFormationLFTags,
			Event: lakeFormationLFTagEvent,
			URN: func(settings settings, tag awsLakeFormationLFTag) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_lakeformation_lf_tag:%s", settings.accountID, lakeFormationLFTagResourceID(tag)), nil
			},
			CursorFallback: func(tag awsLakeFormationLFTag) string { return lakeFormationLFTagResourceID(tag) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsLakeFormationPermission]{
			Name:  familyLakeFormationPerm,
			Label: "aws lake formation permissions",
			List:  listLakeFormationPermissions,
			Event: lakeFormationPermissionEvent,
			URN: func(settings settings, permission awsLakeFormationPermission) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_lakeformation_permission:%s", settings.accountID, lakeFormationPermissionResourceID(permission)), nil
			},
			CursorFallback: func(permission awsLakeFormationPermission) string {
				return lakeFormationPermissionResourceID(permission)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsS3Bucket]{
			Name:  familyS3Bucket,
			Label: "aws s3 buckets",
			List:  listS3Buckets,
			Event: s3BucketEvent,
			URN: func(settings settings, bucket awsS3Bucket) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_s3_bucket:%s", settings.accountID, firstNonEmpty(bucket.ARN, bucket.Name)), nil
			},
			CursorFallback: func(bucket awsS3Bucket) string { return firstNonEmpty(bucket.ARN, bucket.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsS3AccessPoint]{
			Name:  familyS3AccessPoint,
			Label: "aws s3 access points",
			List:  listS3AccessPoints,
			Event: s3AccessPointEvent,
			URN: func(settings settings, accessPoint awsS3AccessPoint) (string, error) {
				name := firstNonEmpty(s3AccessPointDetailName(accessPoint.Detail), awssdk.ToString(accessPoint.Summary.Name))
				arn := s3AccessPointARN(settings, firstNonEmpty(s3AccessPointDetailARN(accessPoint.Detail), awssdk.ToString(accessPoint.Summary.AccessPointArn)), name)
				return fmt.Sprintf("urn:cerebro:%s:aws_s3_access_point:%s", settings.accountID, firstNonEmpty(arn, name)), nil
			},
			CursorFallback: func(accessPoint awsS3AccessPoint) string {
				return firstNonEmpty(s3AccessPointDetailARN(accessPoint.Detail), awssdk.ToString(accessPoint.Summary.AccessPointArn), awssdk.ToString(accessPoint.Summary.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsS3MultiRegionAccessPoint]{
			Name:  familyS3MultiRegionAccessPoint,
			Label: "aws s3 multi-region access points",
			List:  listS3MultiRegionAccessPoints,
			Event: s3MultiRegionAccessPointEvent,
			URN: func(settings settings, accessPoint awsS3MultiRegionAccessPoint) (string, error) {
				name := awssdk.ToString(accessPoint.Report.Name)
				return fmt.Sprintf("urn:cerebro:%s:aws_s3_multi_region_access_point:%s", settings.accountID, firstNonEmpty(s3MultiRegionAccessPointARN(settings, awssdk.ToString(accessPoint.Report.Alias), name), name)), nil
			},
			CursorFallback: func(accessPoint awsS3MultiRegionAccessPoint) string {
				return awssdk.ToString(accessPoint.Report.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.Volume]{
			Name:  familyEBSVolume,
			Label: "aws ebs volumes",
			List:  listEBSVolumes,
			Event: ebsVolumeEvent,
			URN: func(settings settings, volume ec2types.Volume) (string, error) {
				volumeID := awssdk.ToString(volume.VolumeId)
				return fmt.Sprintf("urn:cerebro:%s:aws_ebs_volume:%s", settings.accountID, firstNonEmpty(ebsVolumeARN(settings, volumeID), volumeID)), nil
			},
			CursorFallback: func(volume ec2types.Volume) string { return awssdk.ToString(volume.VolumeId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEBSSnapshot]{
			Name:  familyEBSSnapshot,
			Label: "aws ebs snapshots",
			List:  listEBSSnapshots,
			Event: ebsSnapshotEvent,
			URN: func(settings settings, snapshot awsEBSSnapshot) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ebs_snapshot:%s", settings.accountID, awssdk.ToString(snapshot.Snapshot.SnapshotId)), nil
			},
			CursorFallback: func(snapshot awsEBSSnapshot) string { return awssdk.ToString(snapshot.Snapshot.SnapshotId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEC2EBSEncryptionByDefault]{
			Name:  familyEC2EBSEncryptionByDefault,
			Label: "aws ec2 ebs encryption by default",
			List:  listEC2EBSEncryptionByDefault,
			Event: ec2EBSEncryptionByDefaultEvent,
			URN: func(settings settings, record awsEC2EBSEncryptionByDefault) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ec2_ebs_encryption_by_default:%s", settings.accountID, record.ResourceID), nil
			},
			CursorFallback: func(record awsEC2EBSEncryptionByDefault) string { return record.ResourceID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsRDSInstance]{
			Name:  familyRDSInstance,
			Label: "aws rds instances",
			List:  listRDSInstances,
			Event: rdsInstanceEvent,
			URN: func(settings settings, record awsRDSInstance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_rds_instance:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))), nil
			},
			CursorFallback: func(record awsRDSInstance) string {
				return firstNonEmpty(awssdk.ToString(record.Instance.DBInstanceArn), awssdk.ToString(record.Instance.DBInstanceIdentifier))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsKMSKey]{
			Name:  familyKMSKey,
			Label: "aws kms keys",
			List:  listKMSKeys,
			Event: kmsKeyEvent,
			URN: func(settings settings, key awsKMSKey) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_kms_key:%s", settings.accountID, firstNonEmpty(awssdk.ToString(key.Metadata.Arn), awssdk.ToString(key.Metadata.KeyId))), nil
			},
			CursorFallback: func(key awsKMSKey) string {
				return firstNonEmpty(awssdk.ToString(key.Metadata.Arn), awssdk.ToString(key.Metadata.KeyId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[secretsmanagertypesSecret]{
			Name:  familySecret,
			Label: "aws secrets manager secrets",
			List:  listSecrets,
			Event: secretEvent,
			URN: func(settings settings, secret secretsmanagertypesSecret) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_secret:%s", settings.accountID, firstNonEmpty(awssdk.ToString(secret.ARN), awssdk.ToString(secret.Name))), nil
			},
			CursorFallback: func(secret secretsmanagertypesSecret) string {
				return firstNonEmpty(awssdk.ToString(secret.ARN), awssdk.ToString(secret.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSQSQueue]{
			Name:  familySQSQueue,
			Label: "aws sqs queues",
			List:  listSQSQueues,
			Event: sqsQueueEvent,
			URN: func(settings settings, queue awsSQSQueue) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_sqs_queue:%s", settings.accountID, firstNonEmpty(queue.ARN, queue.URL, queue.Name)), nil
			},
			CursorFallback: func(queue awsSQSQueue) string { return firstNonEmpty(queue.ARN, queue.URL, queue.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSNSTopic]{
			Name:  familySNSTopic,
			Label: "aws sns topics",
			List:  listSNSTopics,
			Event: snsTopicEvent,
			URN: func(settings settings, topic awsSNSTopic) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_sns_topic:%s", settings.accountID, firstNonEmpty(topic.ARN, topic.Name)), nil
			},
			CursorFallback: func(topic awsSNSTopic) string { return firstNonEmpty(topic.ARN, topic.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsECRRepository]{
			Name:  familyECRRepository,
			Label: "aws ecr repositories",
			List:  listECRRepositories,
			Event: ecrRepositoryEvent,
			URN: func(settings settings, repository awsECRRepository) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ecr_repository:%s", settings.accountID, firstNonEmpty(awssdk.ToString(repository.Repository.RepositoryArn), awssdk.ToString(repository.Repository.RepositoryName))), nil
			},
			CursorFallback: func(repository awsECRRepository) string {
				return firstNonEmpty(awssdk.ToString(repository.Repository.RepositoryArn), awssdk.ToString(repository.Repository.RepositoryName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOpenSearchDomain]{
			Name:  familyOpenSearchDomain,
			Label: "aws opensearch domains",
			List:  listOpenSearchDomains,
			Event: openSearchDomainEvent,
			URN: func(settings settings, domain awsOpenSearchDomain) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_opensearch_domain:%s", settings.accountID, firstNonEmpty(awssdk.ToString(domain.Domain.ARN), awssdk.ToString(domain.Domain.DomainName))), nil
			},
			CursorFallback: func(domain awsOpenSearchDomain) string {
				return firstNonEmpty(awssdk.ToString(domain.Domain.ARN), awssdk.ToString(domain.Domain.DomainName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOpenSearchServerlessCollection]{
			Name:  familyOpenSearchServerlessCollection,
			Label: "aws opensearch serverless collections",
			List:  listOpenSearchServerlessCollections,
			Event: openSearchServerlessCollectionEvent,
			URN: func(settings settings, collection awsOpenSearchServerlessCollection) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_opensearch_serverless_collection:%s", settings.accountID, firstNonEmpty(awssdk.ToString(collection.Collection.Arn), awssdk.ToString(collection.Collection.Id), awssdk.ToString(collection.Collection.Name))), nil
			},
			CursorFallback: func(collection awsOpenSearchServerlessCollection) string {
				return firstNonEmpty(awssdk.ToString(collection.Collection.Arn), awssdk.ToString(collection.Collection.Id), awssdk.ToString(collection.Collection.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOpenSearchServerlessSecurityPolicy]{
			Name:  familyOpenSearchServerlessSecurityPolicy,
			Label: "aws opensearch serverless security policies",
			List:  listOpenSearchServerlessSecurityPolicies,
			Event: openSearchServerlessSecurityPolicyEvent,
			URN: func(settings settings, policy awsOpenSearchServerlessSecurityPolicy) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_opensearch_serverless_security_policy:%s:%s", settings.accountID, policyTypeString(policy.Policy.Type), awssdk.ToString(policy.Policy.Name)), nil
			},
			CursorFallback: func(policy awsOpenSearchServerlessSecurityPolicy) string {
				return firstNonEmpty(awssdk.ToString(policy.Policy.PolicyVersion), awssdk.ToString(policy.Policy.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsElastiCacheReplicationGroup]{
			Name:  familyElastiCacheReplicationGroup,
			Label: "aws elasticache replication groups",
			List:  listElastiCacheReplicationGroups,
			Event: elasticacheReplicationGroupEvent,
			URN: func(settings settings, group awsElastiCacheReplicationGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_elasticache_replication_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(group.Group.ARN), awssdk.ToString(group.Group.ReplicationGroupId))), nil
			},
			CursorFallback: func(group awsElastiCacheReplicationGroup) string {
				return firstNonEmpty(awssdk.ToString(group.Group.ARN), awssdk.ToString(group.Group.ReplicationGroupId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsElastiCacheCluster]{
			Name:  familyElastiCacheCluster,
			Label: "aws elasticache clusters",
			List:  listElastiCacheClusters,
			Event: elasticacheClusterEvent,
			URN: func(settings settings, cluster awsElastiCacheCluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_elasticache_cluster:%s", settings.accountID, firstNonEmpty(awssdk.ToString(cluster.Cluster.ARN), awssdk.ToString(cluster.Cluster.CacheClusterId))), nil
			},
			CursorFallback: func(cluster awsElastiCacheCluster) string {
				return firstNonEmpty(awssdk.ToString(cluster.Cluster.ARN), awssdk.ToString(cluster.Cluster.CacheClusterId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsElastiCacheSubnetGroup]{
			Name:  familyElastiCacheSubnetGroup,
			Label: "aws elasticache subnet groups",
			List:  listElastiCacheSubnetGroups,
			Event: elasticacheSubnetGroupEvent,
			URN: func(settings settings, group awsElastiCacheSubnetGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_elasticache_subnet_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(group.Group.ARN), awssdk.ToString(group.Group.CacheSubnetGroupName))), nil
			},
			CursorFallback: func(group awsElastiCacheSubnetGroup) string {
				return firstNonEmpty(awssdk.ToString(group.Group.ARN), awssdk.ToString(group.Group.CacheSubnetGroupName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsFSxFileSystem]{
			Name:  familyFSxFileSystem,
			Label: "aws fsx file systems",
			List:  listFSxFileSystems,
			Event: fsxFileSystemEvent,
			URN: func(settings settings, fs awsFSxFileSystem) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_fsx_file_system:%s", settings.accountID, firstNonEmpty(awssdk.ToString(fs.FileSystem.ResourceARN), awssdk.ToString(fs.FileSystem.FileSystemId))), nil
			},
			CursorFallback: func(fs awsFSxFileSystem) string {
				return firstNonEmpty(awssdk.ToString(fs.FileSystem.ResourceARN), awssdk.ToString(fs.FileSystem.FileSystemId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEFSFileSystem]{
			Name:  familyEFSFileSystem,
			Label: "aws efs file systems",
			List:  listEFSFileSystems,
			Event: efsFileSystemEvent,
			URN: func(settings settings, fileSystem awsEFSFileSystem) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_efs_file_system:%s", settings.accountID, firstNonEmpty(awssdk.ToString(fileSystem.FileSystem.FileSystemArn), awssdk.ToString(fileSystem.FileSystem.FileSystemId))), nil
			},
			CursorFallback: func(fileSystem awsEFSFileSystem) string {
				return firstNonEmpty(awssdk.ToString(fileSystem.FileSystem.FileSystemArn), awssdk.ToString(fileSystem.FileSystem.FileSystemId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEFSAccessPoint]{
			Name:  familyEFSAccessPoint,
			Label: "aws efs access points",
			List:  listEFSAccessPoints,
			Event: efsAccessPointEvent,
			URN: func(settings settings, accessPoint awsEFSAccessPoint) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_efs_access_point:%s", settings.accountID, firstNonEmpty(awssdk.ToString(accessPoint.AccessPoint.AccessPointArn), awssdk.ToString(accessPoint.AccessPoint.AccessPointId))), nil
			},
			CursorFallback: func(accessPoint awsEFSAccessPoint) string {
				return firstNonEmpty(awssdk.ToString(accessPoint.AccessPoint.AccessPointArn), awssdk.ToString(accessPoint.AccessPoint.AccessPointId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDataSyncTask]{
			Name:  familyDataSyncTask,
			Label: "aws datasync tasks",
			List:  listDataSyncTasks,
			Event: dataSyncTaskEvent,
			URN: func(settings settings, task awsDataSyncTask) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_datasync_task:%s", settings.accountID, awssdk.ToString(task.Task.TaskArn)), nil
			},
			CursorFallback: func(task awsDataSyncTask) string { return awssdk.ToString(task.Task.TaskArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsDataSyncLocation]{
			Name:  familyDataSyncLocation,
			Label: "aws datasync locations",
			List:  listDataSyncLocations,
			Event: dataSyncLocationEvent,
			URN: func(settings settings, location awsDataSyncLocation) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_datasync_location:%s", settings.accountID, firstNonEmpty(awssdk.ToString(location.Entry.LocationArn), awssdk.ToString(location.Entry.LocationUri))), nil
			},
			CursorFallback: func(location awsDataSyncLocation) string {
				return firstNonEmpty(awssdk.ToString(location.Entry.LocationArn), awssdk.ToString(location.Entry.LocationUri))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAppRunnerService]{
			Name:  familyAppRunnerService,
			Label: "aws app runner services",
			List:  listAppRunnerServices,
			Event: appRunnerServiceEvent,
			URN: func(settings settings, service awsAppRunnerService) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_apprunner_service:%s", settings.accountID, firstNonEmpty(service.ARN, service.Name)), nil
			},
			CursorFallback: func(service awsAppRunnerService) string { return firstNonEmpty(service.ARN, service.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsStepFunctionStateMachine]{
			Name:  familyStepFunctionStateMachine,
			Label: "aws step functions state machines",
			List:  listStepFunctionStateMachines,
			Event: stepFunctionStateMachineEvent,
			URN: func(settings settings, stateMachine awsStepFunctionStateMachine) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_stepfunctions_state_machine:%s", settings.accountID, firstNonEmpty(stateMachine.ARN, stateMachine.Name)), nil
			},
			CursorFallback: func(stateMachine awsStepFunctionStateMachine) string {
				return firstNonEmpty(stateMachine.ARN, stateMachine.Name)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsStepFunctionActivity]{
			Name:  familyStepFunctionActivity,
			Label: "aws step functions activities",
			List:  listStepFunctionActivities,
			Event: stepFunctionActivityEvent,
			URN: func(settings settings, activity awsStepFunctionActivity) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_stepfunctions_activity:%s", settings.accountID, firstNonEmpty(activity.ARN, activity.Name)), nil
			},
			CursorFallback: func(activity awsStepFunctionActivity) string { return firstNonEmpty(activity.ARN, activity.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEventBridgeBus]{
			Name:  familyEventBridgeBus,
			Label: "aws eventbridge event buses",
			List:  listEventBridgeBuses,
			Event: eventBridgeBusEvent,
			URN: func(settings settings, bus awsEventBridgeBus) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eventbridge_event_bus:%s", settings.accountID, firstNonEmpty(bus.ARN, bus.Name)), nil
			},
			CursorFallback: func(bus awsEventBridgeBus) string { return firstNonEmpty(bus.ARN, bus.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEventBridgeRule]{
			Name:  familyEventBridgeRule,
			Label: "aws eventbridge rules",
			List:  listEventBridgeRules,
			Event: eventBridgeRuleEvent,
			URN: func(settings settings, rule awsEventBridgeRule) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eventbridge_rule:%s", settings.accountID, firstNonEmpty(rule.ARN, rule.Name)), nil
			},
			CursorFallback: func(rule awsEventBridgeRule) string { return firstNonEmpty(rule.ARN, rule.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEventBridgeArchive]{
			Name:  familyEventBridgeArchive,
			Label: "aws eventbridge archives",
			List:  listEventBridgeArchives,
			Event: eventBridgeArchiveEvent,
			URN: func(settings settings, archive awsEventBridgeArchive) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eventbridge_archive:%s", settings.accountID, firstNonEmpty(archive.ARN, archive.Name)), nil
			},
			CursorFallback: func(archive awsEventBridgeArchive) string { return firstNonEmpty(archive.ARN, archive.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEventBridgePipe]{
			Name:  familyEventBridgePipe,
			Label: "aws eventbridge pipes",
			List:  listEventBridgePipes,
			Event: eventBridgePipeEvent,
			URN: func(settings settings, pipe awsEventBridgePipe) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eventbridge_pipe:%s", settings.accountID, firstNonEmpty(pipe.ARN, pipe.Name)), nil
			},
			CursorFallback: func(pipe awsEventBridgePipe) string { return firstNonEmpty(pipe.ARN, pipe.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSchedulerSchedule]{
			Name:  familySchedulerSchedule,
			Label: "aws scheduler schedules",
			List:  listSchedulerSchedules,
			Event: schedulerScheduleEvent,
			URN: func(settings settings, schedule awsSchedulerSchedule) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_scheduler_schedule:%s", settings.accountID, firstNonEmpty(schedule.ARN, schedule.Name)), nil
			},
			CursorFallback: func(schedule awsSchedulerSchedule) string { return firstNonEmpty(schedule.ARN, schedule.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSchedulerGroup]{
			Name:  familySchedulerGroup,
			Label: "aws scheduler schedule groups",
			List:  listSchedulerGroups,
			Event: schedulerGroupEvent,
			URN: func(settings settings, group awsSchedulerGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_scheduler_schedule_group:%s", settings.accountID, firstNonEmpty(group.ARN, group.Name)), nil
			},
			CursorFallback: func(group awsSchedulerGroup) string { return firstNonEmpty(group.ARN, group.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsCloudWatchAlarm]{
			Name:  familyCloudWatchAlarm,
			Label: "aws cloudwatch alarms",
			List:  listCloudWatchAlarms,
			Event: cloudWatchAlarmEvent,
			URN: func(settings settings, alarm awsCloudWatchAlarm) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudwatch_alarm:%s", settings.accountID, firstNonEmpty(alarm.ARN, alarm.Name)), nil
			},
			CursorFallback: func(alarm awsCloudWatchAlarm) string { return firstNonEmpty(alarm.ARN, alarm.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsCloudWatchLogGroup]{
			Name:  familyCloudWatchLogGroup,
			Label: "aws cloudwatch log groups",
			List:  listCloudWatchLogGroups,
			Event: cloudWatchLogGroupEvent,
			URN: func(settings settings, group awsCloudWatchLogGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudwatch_log_group:%s", settings.accountID, firstNonEmpty(group.ARN, group.Name)), nil
			},
			CursorFallback: func(group awsCloudWatchLogGroup) string { return firstNonEmpty(group.ARN, group.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSMManagedInstance]{
			Name:  familySSMManagedInstance,
			Label: "aws ssm managed instances",
			List:  listSSMManagedInstances,
			Event: ssmManagedInstanceEvent,
			URN: func(settings settings, instance awsSSMManagedInstance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ssm_managed_instance:%s", settings.accountID, firstNonEmpty(instance.ID, instance.Name)), nil
			},
			CursorFallback: func(instance awsSSMManagedInstance) string { return firstNonEmpty(instance.ID, instance.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSMDocument]{
			Name:  familySSMDocument,
			Label: "aws ssm documents",
			List:  listSSMDocuments,
			Event: ssmDocumentEvent,
			URN: func(settings settings, document awsSSMDocument) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ssm_document:%s", settings.accountID, document.Name), nil
			},
			CursorFallback: func(document awsSSMDocument) string { return document.Name },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSMAssociation]{
			Name:  familySSMAssociation,
			Label: "aws ssm associations",
			List:  listSSMAssociations,
			Event: ssmAssociationEvent,
			URN: func(settings settings, association awsSSMAssociation) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ssm_association:%s", settings.accountID, firstNonEmpty(association.ID, association.Name)), nil
			},
			CursorFallback: func(association awsSSMAssociation) string { return firstNonEmpty(association.ID, association.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSMParameter]{
			Name:  familySSMParameter,
			Label: "aws ssm parameters",
			List:  listSSMParameters,
			Event: ssmParameterEvent,
			URN: func(settings settings, parameter awsSSMParameter) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ssm_parameter:%s", settings.accountID, firstNonEmpty(parameter.ARN, parameter.Name)), nil
			},
			CursorFallback: func(parameter awsSSMParameter) string { return firstNonEmpty(parameter.ARN, parameter.Name) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOrganizationsAccount]{
			Name:  familyOrganizationsAcct,
			Label: "aws organizations accounts",
			List:  listOrganizationsAccounts,
			Event: organizationsAccountEvent,
			URN: func(settings settings, account awsOrganizationsAccount) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_organizations_account:%s", settings.accountID, account.ID), nil
			},
			CursorFallback: func(account awsOrganizationsAccount) string { return account.ID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOrganizationsOU]{
			Name:  familyOrganizationsOU,
			Label: "aws organizations organizational units",
			List:  listOrganizationsOUs,
			Event: organizationsOUEvent,
			URN: func(settings settings, ou awsOrganizationsOU) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_organizations_organizational_unit:%s", settings.accountID, ou.ID), nil
			},
			CursorFallback: func(ou awsOrganizationsOU) string { return ou.ID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOrganizationsPolicy]{
			Name:  familyOrganizationsPolicy,
			Label: "aws organizations policies",
			List:  listOrganizationsPolicies,
			Event: organizationsPolicyEvent,
			URN: func(settings settings, policy awsOrganizationsPolicy) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_organizations_policy:%s", settings.accountID, policy.ID), nil
			},
			CursorFallback: func(policy awsOrganizationsPolicy) string { return policy.ID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsOrganizationsRoot]{
			Name:  familyOrganizationsRoot,
			Label: "aws organizations roots",
			List:  listOrganizationsRoots,
			Event: organizationsRootEvent,
			URN: func(settings settings, root awsOrganizationsRoot) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_organizations_root:%s", settings.accountID, root.ID), nil
			},
			CursorFallback: func(root awsOrganizationsRoot) string { return root.ID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSOInstance]{
			Name:  familySSOInstance,
			Label: "aws sso instances",
			List:  listSSOInstances,
			Event: ssoInstanceEvent,
			URN: func(settings settings, instance awsSSOInstance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_sso_instance:%s", settings.accountID, firstNonEmpty(instance.InstanceARN, instance.IdentityStoreID)), nil
			},
			CursorFallback: func(instance awsSSOInstance) string {
				return firstNonEmpty(instance.InstanceARN, instance.IdentityStoreID)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSOPermissionSet]{
			Name:  familySSOPermissionSet,
			Label: "aws sso permission sets",
			List:  listSSOPermissionSets,
			Event: ssoPermissionSetEvent,
			URN: func(settings settings, permissionSet awsSSOPermissionSet) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_sso_permission_set:%s", settings.accountID, permissionSet.PermissionSetARN), nil
			},
			CursorFallback: func(permissionSet awsSSOPermissionSet) string { return permissionSet.PermissionSetARN },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsSSOAccountAssignment]{
			Name:  familySSOAssignment,
			Label: "aws sso account assignments",
			List:  listSSOAccountAssignments,
			Event: ssoAccountAssignmentEvent,
			URN: func(settings settings, assignment awsSSOAccountAssignment) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_sso_account_assignment:%s:%s:%s", settings.accountID, assignment.AccountID, assignment.PermissionSetARN, assignment.PrincipalID), nil
			},
			CursorFallback: func(assignment awsSSOAccountAssignment) string {
				return strings.Join([]string{assignment.AccountID, assignment.PermissionSetARN, assignment.PrincipalID}, ":")
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsIdentityStoreUser]{
			Name:  familyIdentityStoreUser,
			Label: "aws identity store users",
			List:  listIdentityStoreUsers,
			Event: identityStoreUserEvent,
			URN: func(settings settings, user awsIdentityStoreUser) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_identitystore_user:%s", settings.accountID, user.UserID), nil
			},
			CursorFallback: func(user awsIdentityStoreUser) string { return user.UserID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsIdentityStoreGroup]{
			Name:  familyIdentityStoreGroup,
			Label: "aws identity store groups",
			List:  listIdentityStoreGroups,
			Event: identityStoreGroupEvent,
			URN: func(settings settings, group awsIdentityStoreGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_identitystore_group:%s", settings.accountID, group.GroupID), nil
			},
			CursorFallback: func(group awsIdentityStoreGroup) string { return group.GroupID },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsIdentityStoreGroupMembership]{
			Name:  familyIdentityStoreMember,
			Label: "aws identity store group memberships",
			List:  listIdentityStoreGroupMemberships,
			Event: identityStoreGroupMembershipEvent,
			URN: func(settings settings, membership awsIdentityStoreGroupMembership) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_identitystore_group_membership:%s:%s", settings.accountID, membership.GroupID, membership.MemberID), nil
			},
			CursorFallback: func(membership awsIdentityStoreGroupMembership) string {
				return strings.Join([]string{membership.GroupID, membership.MemberID}, ":")
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[identityCenterPermissionSet]{
			Name:  familyIdentityCenterPermission,
			Label: "aws iam identity center permission sets",
			List:  listIdentityCenterPermissionSets,
			Event: identityCenterPermissionSetEvent,
			URN: func(settings settings, record identityCenterPermissionSet) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_identity_center_permission_set:%s", settings.accountID, firstNonEmpty(awssdk.ToString(record.PermissionSet.PermissionSetArn), awssdk.ToString(record.PermissionSet.Name))), nil
			},
			CursorFallback: func(record identityCenterPermissionSet) string {
				return firstNonEmpty(awssdk.ToString(record.PermissionSet.PermissionSetArn), awssdk.ToString(record.PermissionSet.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[identityCenterAccountAssignment]{
			Name:  familyIdentityCenterAssignment,
			Label: "aws iam identity center account assignments",
			List:  listIdentityCenterAccountAssignments,
			Event: identityCenterAccountAssignmentEvent,
			URN: func(settings settings, record identityCenterAccountAssignment) (string, error) {
				assignment := record.Assignment
				return fmt.Sprintf("urn:cerebro:%s:aws_identity_center_account_assignment:%s:%s:%s", settings.accountID, awssdk.ToString(assignment.AccountId), firstNonEmpty(awssdk.ToString(assignment.PermissionSetArn), record.PermissionSetName), awssdk.ToString(assignment.PrincipalId)), nil
			},
			CursorFallback: func(record identityCenterAccountAssignment) string {
				assignment := record.Assignment
				return strings.Join([]string{awssdk.ToString(assignment.AccountId), firstNonEmpty(awssdk.ToString(assignment.PermissionSetArn), record.PermissionSetName), awssdk.ToString(assignment.PrincipalId)}, ":")
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[cloudtrailtypes.Event]{
			Name:  familyCloudTrail,
			Label: "aws cloudtrail events",
			List:  listCloudTrailEvents,
			Event: cloudTrailEvent,
			Discover: func(ctx context.Context, clients awsClients, settings settings) ([]sourcecdk.URN, error) {
				if err := awsCheck(ctx, clients, settings, listCloudTrailEvents, "aws cloudtrail events"); err != nil {
					return nil, err
				}
				return parseAWSURNs(fmt.Sprintf("urn:cerebro:%s:aws_account:%s", settings.accountID, settings.accountID))
			},
			CursorFallback: func(event cloudtrailtypes.Event) string { return awssdk.ToString(event.EventId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEC2Instance]{
			Name:  familyEC2Instance,
			Label: "aws ec2 instances",
			List:  listEC2Instances,
			Event: ec2InstanceEvent,
			URN: func(settings settings, instance awsEC2Instance) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ec2_instance:%s", settings.accountID, awssdk.ToString(instance.Instance.InstanceId)), nil
			},
			CursorFallback: func(instance awsEC2Instance) string { return awssdk.ToString(instance.Instance.InstanceId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.Vpc]{
			Name:  familyVPC,
			Label: "aws vpcs",
			List:  listVPCs,
			Event: vpcEvent,
			URN: func(settings settings, vpc ec2types.Vpc) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_vpc:%s", settings.accountID, awssdk.ToString(vpc.VpcId)), nil
			},
			CursorFallback: func(vpc ec2types.Vpc) string { return awssdk.ToString(vpc.VpcId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.Subnet]{
			Name:  familySubnet,
			Label: "aws subnets",
			List:  listSubnets,
			Event: subnetEvent,
			URN: func(settings settings, subnet ec2types.Subnet) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_subnet:%s", settings.accountID, awssdk.ToString(subnet.SubnetId)), nil
			},
			CursorFallback: func(subnet ec2types.Subnet) string { return awssdk.ToString(subnet.SubnetId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.SecurityGroup]{
			Name:  familySecurityGroup,
			Label: "aws security groups",
			List:  listSecurityGroups,
			Event: securityGroupEvent,
			URN: func(settings settings, group ec2types.SecurityGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_security_group:%s", settings.accountID, awssdk.ToString(group.GroupId)), nil
			},
			CursorFallback: func(group ec2types.SecurityGroup) string { return awssdk.ToString(group.GroupId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.RouteTable]{
			Name:  familyRouteTable,
			Label: "aws route tables",
			List:  listRouteTables,
			Event: routeTableEvent,
			URN: func(settings settings, table ec2types.RouteTable) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_route_table:%s", settings.accountID, awssdk.ToString(table.RouteTableId)), nil
			},
			CursorFallback: func(table ec2types.RouteTable) string { return awssdk.ToString(table.RouteTableId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.InternetGateway]{
			Name:  familyInternetGateway,
			Label: "aws internet gateways",
			List:  listInternetGateways,
			Event: internetGatewayEvent,
			URN: func(settings settings, gateway ec2types.InternetGateway) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_internet_gateway:%s", settings.accountID, awssdk.ToString(gateway.InternetGatewayId)), nil
			},
			CursorFallback: func(gateway ec2types.InternetGateway) string { return awssdk.ToString(gateway.InternetGatewayId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.NatGateway]{
			Name:  familyNATGateway,
			Label: "aws nat gateways",
			List:  listNATGateways,
			Event: natGatewayEvent,
			URN: func(settings settings, gateway ec2types.NatGateway) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_nat_gateway:%s", settings.accountID, awssdk.ToString(gateway.NatGatewayId)), nil
			},
			CursorFallback: func(gateway ec2types.NatGateway) string { return awssdk.ToString(gateway.NatGatewayId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ec2types.VpcEndpoint]{
			Name:  familyVPCEndpoint,
			Label: "aws vpc endpoints",
			List:  listVPCEndpoints,
			Event: vpcEndpointEvent,
			URN: func(settings settings, endpoint ec2types.VpcEndpoint) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_vpc_endpoint:%s", settings.accountID, awssdk.ToString(endpoint.VpcEndpointId)), nil
			},
			CursorFallback: func(endpoint ec2types.VpcEndpoint) string { return awssdk.ToString(endpoint.VpcEndpointId) },
		}),
		awsFamily(s.clients, awsFamilyOptions[lambdatypes.FunctionConfiguration]{
			Name:  familyLambdaFunction,
			Label: "aws lambda functions",
			List:  listLambdaFunctions,
			Event: lambdaFunctionEvent,
			URN: func(settings settings, fn lambdatypes.FunctionConfiguration) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_lambda_function:%s", settings.accountID, firstNonEmpty(awssdk.ToString(fn.FunctionArn), awssdk.ToString(fn.FunctionName))), nil
			},
			CursorFallback: func(fn lambdatypes.FunctionConfiguration) string { return awssdk.ToString(fn.FunctionArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsECSService]{
			Name:  familyECSService,
			Label: "aws ecs services",
			List:  listECSServices,
			Event: ecsServiceEvent,
			URN: func(settings settings, service awsECSService) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ecs_service:%s", settings.accountID, awssdk.ToString(service.Service.ServiceArn)), nil
			},
			CursorFallback: func(service awsECSService) string { return awssdk.ToString(service.Service.ServiceArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[awsECSTask]{
			Name:  familyECSTask,
			Label: "aws ecs tasks",
			List:  listECSTasks,
			Event: ecsTaskEvent,
			URN: func(settings settings, task awsECSTask) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ecs_task:%s", settings.accountID, awssdk.ToString(task.Task.TaskArn)), nil
			},
			CursorFallback: func(task awsECSTask) string { return awssdk.ToString(task.Task.TaskArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ecstypes.TaskDefinition]{
			Name:  familyECSTaskDefinition,
			Label: "aws ecs task definitions",
			List:  listECSTaskDefinitions,
			Event: ecsTaskDefinitionEvent,
			URN: func(settings settings, task ecstypes.TaskDefinition) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_ecs_task_definition:%s", settings.accountID, awssdk.ToString(task.TaskDefinitionArn)), nil
			},
			CursorFallback: func(task ecstypes.TaskDefinition) string { return awssdk.ToString(task.TaskDefinitionArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[ekstypes.Cluster]{
			Name:  familyEKSCluster,
			Label: "aws eks clusters",
			List:  listEKSClusters,
			Event: eksClusterEvent,
			URN: func(settings settings, cluster ekstypes.Cluster) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eks_cluster:%s", settings.accountID, firstNonEmpty(awssdk.ToString(cluster.Arn), eksClusterARN(settings, awssdk.ToString(cluster.Name)))), nil
			},
			CursorFallback: func(cluster ekstypes.Cluster) string {
				return firstNonEmpty(awssdk.ToString(cluster.Arn), awssdk.ToString(cluster.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEKSNodegroup]{
			Name:  familyEKSNodegroup,
			Label: "aws eks nodegroups",
			List:  listEKSNodegroups,
			Event: eksNodegroupEvent,
			URN: func(settings settings, nodegroup awsEKSNodegroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eks_nodegroup:%s", settings.accountID, awssdk.ToString(nodegroup.Nodegroup.NodegroupArn)), nil
			},
			CursorFallback: func(nodegroup awsEKSNodegroup) string {
				return firstNonEmpty(awssdk.ToString(nodegroup.Nodegroup.NodegroupArn), nodegroup.ClusterName+"/"+awssdk.ToString(nodegroup.Nodegroup.NodegroupName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsEKSFargateProfile]{
			Name:  familyEKSFargateProfile,
			Label: "aws eks fargate profiles",
			List:  listEKSFargateProfiles,
			Event: eksFargateProfileEvent,
			URN: func(settings settings, profile awsEKSFargateProfile) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eks_fargate_profile:%s", settings.accountID, awssdk.ToString(profile.Profile.FargateProfileArn)), nil
			},
			CursorFallback: func(profile awsEKSFargateProfile) string {
				return firstNonEmpty(awssdk.ToString(profile.Profile.FargateProfileArn), profile.ClusterName+"/"+awssdk.ToString(profile.Profile.FargateProfileName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[ekstypes.PodIdentityAssociation]{
			Name:  familyEKSPodIdentity,
			Label: "aws eks pod identity associations",
			List:  listEKSPodIdentityAssociations,
			Event: eksPodIdentityAssociationEvent,
			URN: func(settings settings, association ekstypes.PodIdentityAssociation) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_eks_pod_identity_association:%s", settings.accountID, firstNonEmpty(awssdk.ToString(association.AssociationArn), awssdk.ToString(association.AssociationId))), nil
			},
			CursorFallback: func(association ekstypes.PodIdentityAssociation) string {
				return firstNonEmpty(awssdk.ToString(association.AssociationArn), awssdk.ToString(association.AssociationId))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[globalacceleratortypes.Accelerator]{
			Name:  familyGlobalAccelerator,
			Label: "aws global accelerator accelerators",
			List:  listGlobalAccelerators,
			Event: globalAcceleratorEvent,
			URN: func(settings settings, accelerator globalacceleratortypes.Accelerator) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_globalaccelerator_accelerator:%s", settings.accountID, firstNonEmpty(awssdk.ToString(accelerator.AcceleratorArn), awssdk.ToString(accelerator.Name))), nil
			},
			CursorFallback: func(accelerator globalacceleratortypes.Accelerator) string {
				return firstNonEmpty(awssdk.ToString(accelerator.AcceleratorArn), awssdk.ToString(accelerator.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlobalAcceleratorListener]{
			Name:  familyGAListener,
			Label: "aws global accelerator listeners",
			List:  listGlobalAcceleratorListeners,
			Event: globalAcceleratorListenerEvent,
			URN: func(settings settings, listener awsGlobalAcceleratorListener) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_globalaccelerator_listener:%s", settings.accountID, awssdk.ToString(listener.Listener.ListenerArn)), nil
			},
			CursorFallback: func(listener awsGlobalAcceleratorListener) string {
				return awssdk.ToString(listener.Listener.ListenerArn)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsGlobalAcceleratorEndpointGroup]{
			Name:  familyGAEndpointGroup,
			Label: "aws global accelerator endpoint groups",
			List:  listGlobalAcceleratorEndpointGroups,
			Event: globalAcceleratorEndpointGroupEvent,
			URN: func(settings settings, group awsGlobalAcceleratorEndpointGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_globalaccelerator_endpoint_group:%s", settings.accountID, awssdk.ToString(group.EndpointGroup.EndpointGroupArn)), nil
			},
			CursorFallback: func(group awsGlobalAcceleratorEndpointGroup) string {
				return awssdk.ToString(group.EndpointGroup.EndpointGroupArn)
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[vpclatticetypes.ServiceSummary]{
			Name:  familyVPCLatticeService,
			Label: "aws vpc lattice services",
			List:  listVPCLatticeServices,
			Event: vpcLatticeServiceEvent,
			URN: func(settings settings, service vpclatticetypes.ServiceSummary) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_vpclattice_service:%s", settings.accountID, firstNonEmpty(awssdk.ToString(service.Arn), awssdk.ToString(service.Id), awssdk.ToString(service.Name))), nil
			},
			CursorFallback: func(service vpclatticetypes.ServiceSummary) string {
				return firstNonEmpty(awssdk.ToString(service.Arn), awssdk.ToString(service.Id), awssdk.ToString(service.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsVPCLatticeListener]{
			Name:  familyVPCLatticeListener,
			Label: "aws vpc lattice listeners",
			List:  listVPCLatticeListeners,
			Event: vpcLatticeListenerEvent,
			URN: func(settings settings, listener awsVPCLatticeListener) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_vpclattice_listener:%s", settings.accountID, firstNonEmpty(awssdk.ToString(listener.Listener.Arn), awssdk.ToString(listener.Listener.Id))), nil
			},
			CursorFallback: func(listener awsVPCLatticeListener) string {
				return firstNonEmpty(awssdk.ToString(listener.Listener.Arn), awssdk.ToString(listener.Listener.Id))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[vpclatticetypes.TargetGroupSummary]{
			Name:  familyVPCLatticeTG,
			Label: "aws vpc lattice target groups",
			List:  listVPCLatticeTargetGroups,
			Event: vpcLatticeTargetGroupEvent,
			URN: func(settings settings, target vpclatticetypes.TargetGroupSummary) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_vpclattice_target_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(target.Arn), awssdk.ToString(target.Id), awssdk.ToString(target.Name))), nil
			},
			CursorFallback: func(target vpclatticetypes.TargetGroupSummary) string {
				return firstNonEmpty(awssdk.ToString(target.Arn), awssdk.ToString(target.Id), awssdk.ToString(target.Name))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[elbv2types.LoadBalancer]{Name: familyELBV2LoadBalancer, Label: "aws elbv2 load balancers", List: listELBV2LoadBalancers, Event: elbv2LoadBalancerEvent, URN: func(settings settings, loadBalancer elbv2types.LoadBalancer) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:aws_elbv2_load_balancer:%s", settings.accountID, firstNonEmpty(awssdk.ToString(loadBalancer.LoadBalancerArn), awssdk.ToString(loadBalancer.LoadBalancerName))), nil
		}, CursorFallback: func(loadBalancer elbv2types.LoadBalancer) string {
			return firstNonEmpty(awssdk.ToString(loadBalancer.LoadBalancerArn), awssdk.ToString(loadBalancer.LoadBalancerName))
		}}),
		awsFamily(s.clients, awsFamilyOptions[elbv2types.Listener]{
			Name:  familyELBV2Listener,
			Label: "aws elbv2 listeners",
			List:  listELBV2Listeners,
			Event: elbv2ListenerEvent,
			URN: func(settings settings, listener elbv2types.Listener) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_elbv2_listener:%s", settings.accountID, awssdk.ToString(listener.ListenerArn)), nil
			},
			CursorFallback: func(listener elbv2types.Listener) string { return awssdk.ToString(listener.ListenerArn) },
		}),
		awsFamily(s.clients, awsFamilyOptions[elbv2types.TargetGroup]{
			Name:  familyELBV2TargetGroup,
			Label: "aws elbv2 target groups",
			List:  listELBV2TargetGroups,
			Event: elbv2TargetGroupEvent,
			URN: func(settings settings, target elbv2types.TargetGroup) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_elbv2_target_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(target.TargetGroupArn), awssdk.ToString(target.TargetGroupName))), nil
			},
			CursorFallback: func(target elbv2types.TargetGroup) string {
				return firstNonEmpty(awssdk.ToString(target.TargetGroupArn), awssdk.ToString(target.TargetGroupName))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAPIGatewayStage]{
			Name:  familyAPIGatewayStage,
			Label: "aws api gateway stages",
			List:  listAPIGatewayStages,
			Event: apiGatewayStageEvent,
			URN: func(settings settings, stage awsAPIGatewayStage) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_apigateway_stage:%s/%s", settings.accountID, stage.apiID(), stage.stageName()), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAPIGatewayRoute]{
			Name:  familyAPIGatewayRoute,
			Label: "aws api gateway routes",
			List:  listAPIGatewayRoutes,
			Event: apiGatewayRouteEvent,
			URN: func(settings settings, route awsAPIGatewayRoute) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_apigateway_route:%s/%s", settings.accountID, route.apiID(), route.routeID()), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsAPIGatewayIntegration]{
			Name:  familyAPIGatewayInteg,
			Label: "aws api gateway integrations",
			List:  listAPIGatewayIntegrations,
			Event: apiGatewayIntegrationEvent,
			URN: func(settings settings, integration awsAPIGatewayIntegration) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_apigateway_integration:%s/%s", settings.accountID, integration.apiID(), integration.integrationID()), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[cloudfronttypes.DistributionSummary]{Name: familyCloudFrontDistribution, Label: "aws cloudfront distributions", List: listCloudFrontDistributions, Event: cloudFrontDistributionEvent, URN: func(settings settings, distribution cloudfronttypes.DistributionSummary) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:aws_cloudfront_distribution:%s", settings.accountID, firstNonEmpty(awssdk.ToString(distribution.ARN), awssdk.ToString(distribution.Id))), nil
		}, CursorFallback: func(distribution cloudfronttypes.DistributionSummary) string {
			return firstNonEmpty(awssdk.ToString(distribution.ARN), awssdk.ToString(distribution.Id))
		}}),
		awsFamily(s.clients, awsFamilyOptions[cloudfronttypes.OriginAccessControlSummary]{
			Name:  familyCloudFrontOAC,
			Label: "aws cloudfront origin access controls",
			List:  listCloudFrontOACs,
			Event: cloudFrontOACEvent,
			URN: func(settings settings, oac cloudfronttypes.OriginAccessControlSummary) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudfront_origin_access_control:%s", settings.accountID, awssdk.ToString(oac.Id)), nil
			},
			CursorFallback: func(oac cloudfronttypes.OriginAccessControlSummary) string { return awssdk.ToString(oac.Id) },
		}),
		awsFamily(s.clients, awsFamilyOptions[cloudfronttypes.KeyGroupSummary]{
			Name:  familyCloudFrontKeyGroup,
			Label: "aws cloudfront key groups",
			List:  listCloudFrontKeyGroups,
			Event: cloudFrontKeyGroupEvent,
			URN: func(settings settings, summary cloudfronttypes.KeyGroupSummary) (string, error) {
				id := ""
				if summary.KeyGroup != nil {
					id = awssdk.ToString(summary.KeyGroup.Id)
				}
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudfront_key_group:%s", settings.accountID, id), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[cloudfronttypes.PublicKeySummary]{
			Name:  familyCloudFrontPublicKey,
			Label: "aws cloudfront public keys",
			List:  listCloudFrontPublicKeys,
			Event: cloudFrontPublicKeyEvent,
			URN: func(settings settings, key cloudfronttypes.PublicKeySummary) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudfront_public_key:%s", settings.accountID, awssdk.ToString(key.Id)), nil
			},
			CursorFallback: func(key cloudfronttypes.PublicKeySummary) string { return awssdk.ToString(key.Id) },
		}),
		awsFamily(s.clients, awsFamilyOptions[cloudfronttypes.ResponseHeadersPolicySummary]{
			Name:  familyCloudFrontRHP,
			Label: "aws cloudfront response headers policies",
			List:  listCloudFrontResponseHeadersPolicies,
			Event: cloudFrontResponseHeadersPolicyEvent,
			URN: func(settings settings, summary cloudfronttypes.ResponseHeadersPolicySummary) (string, error) {
				id := ""
				if summary.ResponseHeadersPolicy != nil {
					id = awssdk.ToString(summary.ResponseHeadersPolicy.Id)
				}
				return fmt.Sprintf("urn:cerebro:%s:aws_cloudfront_response_headers_policy:%s", settings.accountID, id), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamPolicyAssignment]{
			Name:  familyEffectivePermission,
			Label: "aws effective permissions",
			List:  listEffectivePermissions,
			Event: effectivePermissionEvent,
			URN: func(settings settings, assignment iamPolicyAssignment) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:effective_permission:%s:%s", settings.accountID, assignment.PrincipalName, firstNonEmpty(awssdk.ToString(assignment.Policy.PolicyArn), awssdk.ToString(assignment.Policy.PolicyName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsResourceExposure]{
			Name:  familyResourceExposure,
			Label: "aws resource exposures",
			List:  listResourceExposures,
			Event: resourceExposureEvent,
			URN: func(settings settings, exposure awsResourceExposure) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_resource_exposure:%s", settings.accountID, firstNonEmpty(exposure.ExposureID, exposure.ResourceID)), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsRoute53ResolverEndpoint]{
			Name:  familyRoute53ResolverEndpoint,
			Label: "aws route53 resolver endpoints",
			List:  listRoute53ResolverEndpoints,
			Event: route53ResolverEndpointEvent,
			URN: func(settings settings, endpoint awsRoute53ResolverEndpoint) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_route53_resolver_endpoint:%s", settings.accountID, firstNonEmpty(awssdk.ToString(endpoint.Endpoint.Arn), awssdk.ToString(endpoint.Endpoint.Id))), nil
			},
			CursorFallback: func(endpoint awsRoute53ResolverEndpoint) string {
				return firstNonEmpty(awssdk.ToString(endpoint.Endpoint.Arn), awssdk.ToString(endpoint.Endpoint.Id))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsRoute53ResolverRule]{
			Name:  familyRoute53ResolverRule,
			Label: "aws route53 resolver rules",
			List:  listRoute53ResolverRules,
			Event: route53ResolverRuleEvent,
			URN: func(settings settings, rule awsRoute53ResolverRule) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_route53_resolver_rule:%s", settings.accountID, firstNonEmpty(awssdk.ToString(rule.Rule.Arn), awssdk.ToString(rule.Rule.Id))), nil
			},
			CursorFallback: func(rule awsRoute53ResolverRule) string {
				return firstNonEmpty(awssdk.ToString(rule.Rule.Arn), awssdk.ToString(rule.Rule.Id))
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[awsPublicEndpoint]{
			Name:  familyPublicEndpoint,
			Label: "aws public endpoints",
			List:  listPublicEndpoints,
			Event: publicEndpointEvent,
			URN: func(settings settings, endpoint awsPublicEndpoint) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:aws_public_endpoint:%s", settings.accountID, firstNonEmpty(endpoint.EndpointID, endpoint.ResourceID, endpoint.IP, endpoint.Host)), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.Group]{
			Name:  familyIAMGroup,
			Label: "aws iam groups",
			List:  listIAMGroups,
			Event: iamGroupEvent,
			URN: func(settings settings, group iamtypes.Group) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_group:%s", settings.accountID, firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamGroupMember]{
			Name:  familyIAMMembership,
			Label: "aws iam group memberships",
			List:  listIAMGroupMembers,
			Event: iamGroupMembershipEvent,
			URN: func(settings settings, member iamGroupMember) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_group_membership:%s:%s", settings.accountID, firstNonEmpty(member.GroupName, settings.groupName), firstNonEmpty(awssdk.ToString(member.User.UserId), awssdk.ToString(member.User.UserName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamPolicyAssignment]{
			Name:  familyIAMRoleAssign,
			Label: "aws iam policy assignments",
			List:  listIAMPolicyAssignments,
			Event: iamRoleAssignmentEvent,
			URN: func(settings settings, assignment iamPolicyAssignment) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_role_assignment:%s:%s", settings.accountID, assignment.PrincipalName, firstNonEmpty(awssdk.ToString(assignment.Policy.PolicyArn), awssdk.ToString(assignment.Policy.PolicyName))), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamRoleTrust]{
			Name:  familyIAMRoleTrust,
			Label: "aws iam role trust policies",
			List:  listIAMRoleTrusts,
			Event: iamRoleTrustEvent,
			URN: func(settings settings, trust iamRoleTrust) (string, error) {
				roleID := firstNonEmpty(awssdk.ToString(trust.Role.RoleId), awssdk.ToString(trust.Role.RoleName))
				return fmt.Sprintf("urn:cerebro:%s:iam_role_trust:%s:%s", settings.accountID, roleID, sanitizeEventID(trust.Principal)), nil
			},
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.Role]{
			Name:  familyIAMRole,
			Label: "aws iam roles",
			List:  listIAMRoles,
			Event: iamRoleEvent,
			URN: func(settings settings, role iamtypes.Role) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_role:%s", settings.accountID, firstNonEmpty(awssdk.ToString(role.RoleId), awssdk.ToString(role.RoleName))), nil
			},
			CursorFallback: func(role iamtypes.Role) string { return awssdk.ToString(role.RoleName) },
		}),
		awsFamily(s.clients, awsFamilyOptions[iamtypes.User]{
			Name:  familyIAMUser,
			Label: "aws iam users",
			List:  listIAMUsers,
			Event: iamUserEvent,
			URN: func(settings settings, user iamtypes.User) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:iam_user:%s", settings.accountID, firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName))), nil
			},
			CursorFallback: func(user iamtypes.User) string { return awssdk.ToString(user.UserName) },
		}),
	}
	families = append(families, awsSecurityFamilies(s.clients)...)
	families = append(families, awsaccount.Families(s.clients, func(clients awsClients) any { return clients.iam }, func(settings settings) string { return settings.accountID })...)
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family }, families...)
}

func awsFamily[T any](clientFactory awsClientFactory, options awsFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return err
			}
			return awsCheck(ctx, clients, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return nil, err
			}
			if options.Discover != nil {
				return options.Discover(ctx, clients, settings)
			}
			records, _, err := options.List(ctx, clients, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, settings.accountID, err)
			}
			return awsURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			clients, err := clientFactory(ctx, settings)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, next, err := options.List(ctx, clients, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, settings.accountID, err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return awsPullFromRecords(records, next, build, options.CursorFallback)
		},
	}
}

func newAWSClients(ctx context.Context, settings settings) (awsClients, error) {
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(settings.region)}
	if settings.profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(settings.profile))
	}
	if settings.accessKeyID != "" || settings.secretAccessKey != "" || settings.sessionToken != "" {
		if settings.accessKeyID == "" || settings.secretAccessKey == "" {
			return awsClients{}, fmt.Errorf("aws access_key_id and secret_access_key must be provided together")
		}
		provider := credentials.NewStaticCredentialsProvider(settings.accessKeyID, settings.secretAccessKey, settings.sessionToken)
		options = append(options, awsconfig.WithCredentialsProvider(provider))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return awsClients{}, fmt.Errorf("load aws config: %w", err)
	}
	if settings.roleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), settings.roleARN, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = awsAssumeRoleSessionName
			if settings.externalID != "" {
				options.ExternalID = awssdk.String(settings.externalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	globalAcceleratorConfig := cfg
	globalAcceleratorConfig.Region = "us-west-2"
	return awsClients{
		awsPlatformClients: awsPlatformClients{
			cfg:             cfg,
			acm:             acm.NewFromConfig(cfg),
			iam:             iam.NewFromConfig(cfg),
			cloudTrail:      cloudtrail.NewFromConfig(cfg),
			ec2:             ec2.NewFromConfig(cfg),
			route53:         route53.NewFromConfig(cfg),
			route53Resolver: route53resolver.NewFromConfig(cfg),
			cloudFront:      cloudfront.NewFromConfig(cfg),
			elbv2:           elbv2.NewFromConfig(cfg),
			globalAccel:     globalaccelerator.NewFromConfig(globalAcceleratorConfig),
			vpcLattice:      vpclattice.NewFromConfig(cfg),
			ecs:             ecs.NewFromConfig(cfg),
			eks:             eks.NewFromConfig(cfg),
			ecr:             ecr.NewFromConfig(cfg),
			apiGateway:      apigateway.NewFromConfig(cfg),
			apiGatewayV2:    apigatewayv2.NewFromConfig(cfg),
			lambda:          lambda.NewFromConfig(cfg),
			tagging:         resourcegroupstaggingapi.NewFromConfig(cfg),
			s3:              s3.NewFromConfig(cfg),
			s3ByRegion: func(region string) awsS3API {
				regionalCfg := cfg
				regionalCfg.Region = region
				return s3.NewFromConfig(regionalCfg)
			},
		},
		awsRuntimeClients: awsRuntimeClients{
			batch:          batch.NewFromConfig(cfg),
			rds:            rds.NewFromConfig(cfg),
			kms:            kms.NewFromConfig(cfg),
			secrets:        secretsmanager.NewFromConfig(cfg),
			sqs:            sqs.NewFromConfig(cfg),
			sns:            sns.NewFromConfig(cfg),
			appRunner:      apprunner.NewFromConfig(cfg),
			stepFunctions:  sfn.NewFromConfig(cfg),
			eventBridge:    eventbridge.NewFromConfig(cfg),
			pipes:          pipes.NewFromConfig(cfg),
			scheduler:      scheduler.NewFromConfig(cfg),
			cloudWatch:     cloudwatch.NewFromConfig(cfg),
			cloudWatchLogs: cloudwatchlogs.NewFromConfig(cfg),
			ssm:            ssm.NewFromConfig(cfg),
		},
		awsAnalyticsClients: awsAnalyticsClients{
			kinesis:  kinesis.NewFromConfig(cfg),
			firehose: firehose.NewFromConfig(cfg),
			kafka:    kafka.NewFromConfig(cfg),
			glue:     glue.NewFromConfig(cfg),
			athena:   athena.NewFromConfig(cfg),
			lake:     lakeformation.NewFromConfig(cfg),
			redshift: redshift.NewFromConfig(cfg),
			docdb:    docdb.NewFromConfig(cfg),
			neptune:  neptune.NewFromConfig(cfg),
		},
		awsGovernanceClients: awsGovernanceClients{
			organizations: organizations.NewFromConfig(cfg),
			sso:           ssoadmin.NewFromConfig(cfg),
			identityStore: identitystore.NewFromConfig(cfg),
		},
		awsStorageClients: awsStorageClients{
			s3control:       s3control.NewFromConfig(cfg),
			datasync:        datasync.NewFromConfig(cfg),
			backup:          backup.NewFromConfig(cfg),
			dynamodb:        dynamodb.NewFromConfig(cfg),
			dynamodbStreams: dynamodbstreams.NewFromConfig(cfg),
			efs:             efs.NewFromConfig(cfg),
		},
		awsSecurityClients: newAWSSecurityClients(cfg),
		awsDataClients: awsDataClients{
			elasticache:          elasticache.NewFromConfig(cfg),
			fsx:                  fsx.NewFromConfig(cfg),
			openSearch:           opensearch.NewFromConfig(cfg),
			openSearchServerless: opensearchserverless.NewFromConfig(cfg),
		},
	}, nil
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:          configValue(cfg, "family"),
		accountID:       configValue(cfg, "account_id"),
		region:          configValue(cfg, "region"),
		profile:         configValue(cfg, "profile"),
		accessKeyID:     configValue(cfg, "access_key_id"),
		secretAccessKey: configValue(cfg, "secret_access_key"),
		sessionToken:    configValue(cfg, "session_token"),
		roleARN:         configValue(cfg, "role_arn"),
		externalID:      configValue(cfg, "external_id"),
		assumeRoleARNs:  configValue(cfg, sourceconfig.AWSAssumeRoleAllowlistKey),
		tenantID:        configValue(cfg, sourceconfig.RuntimeTenantIDKey),
		includeGlobal:   configBool(cfg, "include_global", true),
		groupName:       configValue(cfg, "group_name"),
		principalType:   configValue(cfg, "principal_type"),
		principalName:   configValue(cfg, "principal_name"),
		userName:        configValue(cfg, "user_name"),
		identityCenter: identityCenterSettings{
			storeID:          configValue(cfg, "identity_store_id"),
			groupID:          configValue(cfg, "group_id"),
			instanceARN:      configValue(cfg, "identity_center_instance_arn"),
			permissionSetARN: configValue(cfg, "permission_set_arn"),
			targetAccountID:  configValue(cfg, "target_account_id"),
		},
		cloudTrail: cloudTrailSettings{
			lookupKey:   configValue(cfg, "lookup_key"),
			lookupValue: configValue(cfg, "lookup_value"),
			startTime:   configValue(cfg, "start_time"),
			endTime:     configValue(cfg, "end_time"),
			since:       configValue(cfg, "since"),
		},
		wafv2Scope: configValue(cfg, "wafv2_scope"),
		perPage:    defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	if settings.accountID == "" {
		return settings, fmt.Errorf("aws account_id is required")
	}
	if settings.roleARN != "" {
		if err := validateAssumeRoleConfig(settings); err != nil {
			return settings, err
		}
	} else if settings.externalID != "" {
		return settings, fmt.Errorf("aws external_id requires role_arn")
	}
	if settings.region == "" {
		settings.region = defaultRegion
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse aws per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("aws per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyAccessAnalyzer, familyACMCertificate, familyAPIGatewayInteg, familyAPIGatewayRoute, familyAPIGatewayStage, familyAppRunnerService, familyAssetMetadata, familyAthenaDataCatalog, familyAthenaWorkgroup, familyBatchComputeEnv, familyBatchJobQueue, familyBackupPlan, familyBackupProtected, familyBackupRecoveryPoint, familyBackupVault, familyCloudFrontDistribution, familyCloudFrontKeyGroup, familyCloudFrontOAC, familyCloudFrontPublicKey, familyCloudFrontRHP, familyCloudTrail, familyCloudWatchAlarm, familyCloudWatchLogGroup, familyConfigRecorder, familyDataSyncLocation, familyDataSyncTask, familyEBSSnapshot, familyEBSVolume, familyEC2EBSEncryptionByDefault, familyEC2Instance, familyVPC, familySubnet, familySecurityGroup, familyRouteTable, familyInternetGateway, familyNATGateway, familyVPCEndpoint, familyECRRepository, familyECSService, familyECSTask, familyECSTaskDefinition, familyEKSCluster, familyEKSNodegroup, familyEKSFargateProfile, familyEKSPodIdentity, familyEffectivePermission, familyELBV2LoadBalancer, familyELBV2Listener, familyELBV2TargetGroup, familyEventBridgeArchive, familyEventBridgeBus, familyEventBridgePipe, familyEventBridgeRule, familyFirehoseDelivery, familyGAEndpointGroup, familyGAListener, familyGlobalAccelerator, familyGlueCrawler, familyGlueDatabase, familyGlueJob, familyGlueTable, familyGuardDutyFinding, "iam_account_password_policy", "iam_account_summary", "iam_credential_report", familyIAMGroup, familyIAMRole, familyIAMRoleTrust, familyIAMUser, familyIdentityCenterAssignment, familyIdentityCenterPermission, familyIdentityStoreGroup, familyIdentityStoreMember, familyIdentityStoreUser, familyInspector2Finding, familyKinesisStream, familyKMSKey, familyLakeFormationLFTag, familyLakeFormationPerm, familyLakeFormationRes, familyLambdaFunction, familyMacie2Finding, familyMSKCluster, familyNetworkFirewall, familyOrganizationsAcct, familyOrganizationsOU, familyOrganizationsPolicy, familyPublicEndpoint, familyRDSInstance, familyResourceExposure, familyRoute53ResolverEndpoint, familyRoute53ResolverRule, familyS3AccessPoint, familyS3Bucket, familyS3MultiRegionAccessPoint, familySchedulerGroup, familySchedulerSchedule, familySecret, familySecurityHubFinding, familySNSTopic, familySQSQueue, familySSMAssociation, familySSMDocument, familySSMManagedInstance, familySSMParameter, familySSOAssignment, familySSOInstance, familySSOPermissionSet, familyStepFunctionActivity, familyStepFunctionStateMachine, familyVPCLatticeListener, familyVPCLatticeService, familyVPCLatticeTG, familyWAFV2WebACL, familyDynamoDBBackup, familyDynamoDBStream, familyDynamoDBTable, familyEFSAccessPoint, familyEFSFileSystem, familyOrganizationsRoot, familyElastiCacheCluster, familyElastiCacheReplicationGroup, familyElastiCacheSubnetGroup, familyFSxFileSystem, familyOpenSearchDomain, familyOpenSearchServerlessCollection, familyOpenSearchServerlessSecurityPolicy, familyDocDBCluster, familyDocDBInstance, familyNeptuneCluster, familyNeptuneInstance, familyRedshiftCluster:
	case familyAccessKey:
		if settings.userName == "" {
			settings.userName = settings.principalName
		}
	case familyIAMMembership:
	case familyIAMRoleAssign:
		if settings.principalType == "" {
			settings.principalType = "user"
		}
		settings.principalType = strings.ToLower(settings.principalType)
		if settings.principalType != "user" && settings.principalType != "group" && settings.principalType != "role" {
			return settings, fmt.Errorf("aws principal_type must be user, group, or role when family=%q", familyIAMRoleAssign)
		}
	default:
		return settings, fmt.Errorf("unsupported aws family %q", settings.family)
	}
	return settings, nil
}

func validateAssumeRoleConfig(settings settings) error {
	matches := awsRoleARNPattern.FindStringSubmatch(settings.roleARN)
	if len(matches) != 3 {
		return fmt.Errorf("aws role_arn must be an IAM role ARN")
	}
	if matches[2] != settings.accountID {
		return fmt.Errorf("aws role_arn account must match account_id")
	}
	if settings.tenantID == "" {
		return fmt.Errorf("aws role_arn requires runtime tenant_id")
	}
	if !assumeRoleARNAllowed(settings.tenantID, settings.roleARN, settings.assumeRoleARNs) {
		return fmt.Errorf("aws role_arn is not allowed")
	}
	return nil
}

func assumeRoleARNAllowed(tenantID string, roleARN string, allowlist string) bool {
	tenantID = strings.TrimSpace(tenantID)
	roleARN = strings.TrimSpace(roleARN)
	if tenantID == "" || roleARN == "" {
		return false
	}
	for _, value := range strings.FieldsFunc(allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	}) {
		value = strings.TrimSpace(value)
		tenant, arn, ok := strings.Cut(value, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(tenant) == tenantID && strings.TrimSpace(arn) == roleARN {
			return true
		}
	}
	return false
}

func listAccessKeys(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamtypes.AccessKeyMetadata, string, error) {
	if strings.TrimSpace(settings.userName) == "" {
		users, next, err := listIAMUsers(ctx, clients, settings, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		keys := make([]iamtypes.AccessKeyMetadata, 0, len(users))
		for _, user := range users {
			userName := awssdk.ToString(user.UserName)
			if userName == "" {
				continue
			}
			out, err := clients.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: awssdk.String(userName)})
			if err != nil {
				return nil, "", err
			}
			for _, key := range out.AccessKeyMetadata {
				if awssdk.ToString(key.UserName) == "" {
					key.UserName = awssdk.String(userName)
				}
				keys = append(keys, key)
			}
		}
		return keys, next, nil
	}
	out, err := clients.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: awssdk.String(settings.userName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.AccessKeyMetadata, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMUsers(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.User, string, error) {
	out, err := clients.iam.ListUsers(ctx, &iam.ListUsersInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Users, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMRoles(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.Role, string, error) {
	out, err := clients.iam.ListRoles(ctx, &iam.ListRolesInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Roles, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMRoleTrusts(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamRoleTrust, string, error) {
	roles, next, err := listIAMRoles(ctx, clients, settings, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	trusts := make([]iamRoleTrust, 0)
	for _, role := range roles {
		trusts = append(trusts, roleTrusts(role)...)
	}
	return trusts, next, nil
}

func listAssetMetadata(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAssetMetadata, string, error) {
	out, err := clients.tagging.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
		PaginationToken:  stringPtr(cursor),
		ResourcesPerPage: int32Ptr(assetMetadataPageSize(limit)),
	})
	var expired *resourcegroupstaggingapitypes.PaginationTokenExpiredException
	if err != nil && strings.TrimSpace(cursor) != "" && errors.As(err, &expired) {
		out, err = clients.tagging.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
			ResourcesPerPage: int32Ptr(assetMetadataPageSize(limit)),
		})
	}
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAssetMetadata, 0, len(out.ResourceTagMappingList))
	for _, mapping := range out.ResourceTagMappingList {
		arn := awssdk.ToString(mapping.ResourceARN)
		resourceType, resourceID, resourceName, region := awsAssetMetadataIdentity(settings, arn)
		tags := awsAssetTagMap(mapping.Tags)
		records = append(records, awsAssetMetadata{
			ResourceARN:  arn,
			ResourceID:   resourceID,
			ResourceName: firstNonEmpty(tagLookup(tags, "Name"), resourceName, resourceID),
			ResourceType: resourceType,
			Region:       firstNonEmpty(region, settings.region),
			Tags:         tags,
		})
	}
	return records, awssdk.ToString(out.PaginationToken), nil
}

func listResourceExposures(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsResourceExposure, string, error) {
	out, err := clients.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: stringPtr(cursor), MaxResults: int32Ptr(ec2PageSize(limit))})
	if err != nil {
		return nil, "", err
	}
	exposures := make([]awsResourceExposure, 0)
	for _, group := range out.SecurityGroups {
		for permissionIndex, permission := range group.IpPermissions {
			for _, ipRange := range permission.IpRanges {
				cidr := awssdk.ToString(ipRange.CidrIp)
				if !publicCIDR(cidr) {
					continue
				}
				exposures = append(exposures, securityGroupExposure(settings, group, permission, cidr, permissionIndex))
			}
			for _, ipRange := range permission.Ipv6Ranges {
				cidr := awssdk.ToString(ipRange.CidrIpv6)
				if !publicCIDR(cidr) {
					continue
				}
				exposures = append(exposures, securityGroupExposure(settings, group, permission, cidr, permissionIndex))
			}
		}
	}
	return exposures, awssdk.ToString(out.NextToken), nil
}

func listPublicEndpoints(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsPublicEndpoint, string, error) {
	state, err := parsePublicEndpointCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	for {
		switch state.Stage {
		case publicEndpointStageRoute53:
			if !settings.includeGlobal {
				state = publicEndpointCursor{Stage: publicEndpointStageCloudFront}
				continue
			}
			endpoints, next, err := listRoute53PublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageCloudFront}
		case publicEndpointStageCloudFront:
			if !settings.includeGlobal {
				state = publicEndpointCursor{Stage: publicEndpointStageELB}
				continue
			}
			endpoints, next, err := listCloudFrontPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageELB}
		case publicEndpointStageELB:
			endpoints, next, err := listELBPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGateway}
		case publicEndpointStageAPIGateway:
			endpoints, next, err := listAPIGatewayPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayRestAPI}
		case publicEndpointStageAPIGatewayRestAPI:
			endpoints, next, err := listAPIGatewayRestAPIPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2}
		case publicEndpointStageAPIGatewayV2:
			endpoints, next, err := listAPIGatewayV2PublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2API}
		case publicEndpointStageAPIGatewayV2API:
			endpoints, next, err := listAPIGatewayV2APIPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageEIP}
		case publicEndpointStageEIP:
			endpoints, next, err := listAddressPublicEndpoints(ctx, clients, settings)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageENI}
		case publicEndpointStageENI:
			return listNetworkInterfacePublicEndpoints(ctx, clients, settings, state, limit)
		default:
			return nil, "", fmt.Errorf("unknown aws public_endpoint cursor stage %q", state.Stage)
		}
	}
}

func listRoute53PublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	zoneID := strings.TrimSpace(state.Route53ZoneID)
	zoneName := strings.TrimSpace(state.Route53ZoneName)
	nextZoneMarker := strings.TrimSpace(state.Route53NextZoneMarker)
	privateZone := state.Route53PrivateZone
	if zoneID == "" {
		zones, err := clients.route53.ListHostedZones(ctx, &route53.ListHostedZonesInput{Marker: stringPtr(state.Route53ZoneMarker), MaxItems: int32Ptr(1)})
		if err != nil {
			return nil, "", err
		}
		if len(zones.HostedZones) == 0 {
			if zones.IsTruncated && awssdk.ToString(zones.NextMarker) != "" {
				return nil, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageRoute53, Route53ZoneMarker: awssdk.ToString(zones.NextMarker)}), nil
			}
			return nil, "", nil
		}
		zone := zones.HostedZones[0]
		zoneID = route53HostedZoneID(awssdk.ToString(zone.Id))
		zoneName = dnsHost(awssdk.ToString(zone.Name))
		privateZone = zone.Config != nil && zone.Config.PrivateZone
		nextZoneMarker = awssdk.ToString(zones.NextMarker)
		if privateZone {
			if zones.IsTruncated && nextZoneMarker != "" {
				return nil, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageRoute53, Route53ZoneMarker: nextZoneMarker}), nil
			}
			return nil, "", nil
		}
	}
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: awssdk.String(zoneID),
		MaxItems:     int32Ptr(ec2PageSize(limit)),
	}
	if state.Route53RecordName != "" {
		input.StartRecordName = awssdk.String(state.Route53RecordName)
		input.StartRecordType = route53types.RRType(state.Route53RecordType)
		input.StartRecordIdentifier = stringPtr(state.Route53RecordIdentifier)
	}
	records, err := clients.route53.ListResourceRecordSets(ctx, input)
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(records.ResourceRecordSets))
	for _, record := range records.ResourceRecordSets {
		endpoint := route53PublicEndpoint(settings, zoneID, zoneName, privateZone, record)
		if endpoint.ResourceID == "" {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if records.IsTruncated {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{
			Stage:                   publicEndpointStageRoute53,
			Route53ZoneID:           zoneID,
			Route53ZoneName:         zoneName,
			Route53ZoneMarker:       state.Route53ZoneMarker,
			Route53NextZoneMarker:   nextZoneMarker,
			Route53PrivateZone:      privateZone,
			Route53RecordName:       awssdk.ToString(records.NextRecordName),
			Route53RecordType:       string(records.NextRecordType),
			Route53RecordIdentifier: awssdk.ToString(records.NextRecordIdentifier),
		}), nil
	}
	if nextZoneMarker != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageRoute53, Route53ZoneMarker: nextZoneMarker}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageCloudFront}), nil
}

func listCloudFrontPublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.cloudFront.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: stringPtr(state.Token), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	if out.DistributionList == nil {
		return nil, "", nil
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.DistributionList.Items))
	for _, distribution := range out.DistributionList.Items {
		if !awssdk.ToBool(distribution.Enabled) {
			continue
		}
		endpoints = append(endpoints, cloudFrontPublicEndpoint(settings, distribution))
	}
	if awssdk.ToBool(out.DistributionList.IsTruncated) && awssdk.ToString(out.DistributionList.NextMarker) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageCloudFront, Token: awssdk.ToString(out.DistributionList.NextMarker)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageELB}), nil
}

func listELBPublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.elbv2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: stringPtr(state.Token), PageSize: int32Ptr(ec2PageSize(limit))})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.LoadBalancers))
	for _, loadBalancer := range out.LoadBalancers {
		if loadBalancer.Scheme == elbv2types.LoadBalancerSchemeEnumInternal {
			continue
		}
		endpoints = append(endpoints, elbPublicEndpoint(settings, loadBalancer))
	}
	if awssdk.ToString(out.NextMarker) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageELB, Token: awssdk.ToString(out.NextMarker)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGateway}), nil
}

func listAPIGatewayPublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.apiGateway.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{Position: stringPtr(state.Token), Limit: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.Items))
	for _, domain := range out.Items {
		if apiGatewayDomainPrivate(domain.EndpointConfiguration) {
			continue
		}
		endpoints = append(endpoints, apiGatewayPublicEndpoint(settings, domain))
	}
	if awssdk.ToString(out.Position) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGateway, Token: awssdk.ToString(out.Position)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayRestAPI}), nil
}

func listAPIGatewayRestAPIPublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.apiGateway.GetRestApis(ctx, &apigateway.GetRestApisInput{Position: stringPtr(state.Token), Limit: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.Items))
	for _, api := range out.Items {
		if api.DisableExecuteApiEndpoint || apiGatewayDomainPrivate(api.EndpointConfiguration) {
			continue
		}
		endpoint := apiGatewayRestAPIPublicEndpoint(settings, api)
		if endpoint.ResourceID == "" || endpoint.Host == "" {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if awssdk.ToString(out.Position) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayRestAPI, Token: awssdk.ToString(out.Position)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2}), nil
}

func listAPIGatewayV2PublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.apiGatewayV2.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: stringPtr(state.Token), MaxResults: stringPtr(strconv.Itoa(limit))})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.Items))
	for _, domain := range out.Items {
		endpoints = append(endpoints, apiGatewayV2PublicEndpoint(settings, domain))
	}
	if awssdk.ToString(out.NextToken) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2, Token: awssdk.ToString(out.NextToken)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2API}), nil
}

func listAPIGatewayV2APIPublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.apiGatewayV2.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: stringPtr(state.Token), MaxResults: stringPtr(strconv.Itoa(limit))})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.Items))
	for _, api := range out.Items {
		if awssdk.ToBool(api.DisableExecuteApiEndpoint) {
			continue
		}
		endpoint := apiGatewayV2APIPublicEndpoint(settings, api)
		if endpoint.ResourceID == "" || endpoint.Host == "" {
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if awssdk.ToString(out.NextToken) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2API, Token: awssdk.ToString(out.NextToken)}), nil
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageEIP}), nil
}

func listAddressPublicEndpoints(ctx context.Context, clients awsClients, settings settings) ([]awsPublicEndpoint, string, error) {
	addresses, err := clients.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(addresses.Addresses))
	for _, address := range addresses.Addresses {
		ip := awssdk.ToString(address.PublicIp)
		if ip == "" {
			continue
		}
		allocationID := awssdk.ToString(address.AllocationId)
		networkInterfaceID := awssdk.ToString(address.NetworkInterfaceId)
		instanceID := awssdk.ToString(address.InstanceId)
		endpoints = append(endpoints, awsPublicEndpoint{
			ResourceID:           firstNonEmpty(allocationID, ip),
			ResourceName:         firstNonEmpty(allocationID, networkInterfaceID, ip),
			ResourceType:         "elastic_ip",
			EndpointID:           firstNonEmpty(allocationID, ip),
			EndpointType:         "public_ip",
			IP:                   ip,
			Region:               settings.region,
			Scope:                settings.accountID,
			Service:              "ec2",
			AssociatedInstanceID: instanceID,
		})
	}
	return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageENI}), nil
}

func listNetworkInterfacePublicEndpoints(ctx context.Context, clients awsClients, settings settings, state publicEndpointCursor, limit int) ([]awsPublicEndpoint, string, error) {
	out, err := clients.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NextToken: stringPtr(state.Token), MaxResults: int32Ptr(ec2PageSize(limit))})
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]awsPublicEndpoint, 0, len(out.NetworkInterfaces))
	for _, ni := range out.NetworkInterfaces {
		if ni.Association == nil {
			continue
		}
		ip := awssdk.ToString(ni.Association.PublicIp)
		host := dnsHost(awssdk.ToString(ni.Association.PublicDnsName))
		if ip == "" && host == "" {
			continue
		}
		networkInterfaceID := awssdk.ToString(ni.NetworkInterfaceId)
		instanceID := ""
		if ni.Attachment != nil {
			instanceID = awssdk.ToString(ni.Attachment.InstanceId)
		}
		endpoints = append(endpoints, awsPublicEndpoint{
			ResourceID:         firstNonEmpty(networkInterfaceID, ip, host),
			ResourceName:       firstNonEmpty(tagValue(ni.TagSet, "Name"), awssdk.ToString(ni.Description), networkInterfaceID, ip, host),
			ResourceType:       "network_interface",
			EndpointID:         firstNonEmpty(networkInterfaceID, ip, host),
			EndpointType:       "public_network_interface",
			Host:               host,
			IP:                 ip,
			Region:             settings.region,
			Scope:              settings.accountID,
			Service:            "ec2",
			AttachedInstanceID: instanceID,
		})
	}
	if awssdk.ToString(out.NextToken) != "" {
		return endpoints, encodePublicEndpointCursor(publicEndpointCursor{Stage: publicEndpointStageENI, Token: awssdk.ToString(out.NextToken)}), nil
	}
	return endpoints, "", nil
}

func listIAMGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]iamtypes.Group, string, error) {
	out, err := clients.iam.ListGroups(ctx, &iam.ListGroupsInput{Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	return out.Groups, nextMarker(out.IsTruncated, out.Marker), nil
}

func listIAMGroupMembers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamGroupMember, string, error) {
	if strings.TrimSpace(settings.groupName) == "" {
		groups, next, err := listIAMGroups(ctx, clients, settings, cursor, limit)
		if err != nil {
			return nil, "", err
		}
		members := make([]iamGroupMember, 0)
		for _, group := range groups {
			groupName := awssdk.ToString(group.GroupName)
			if groupName == "" {
				continue
			}
			out, err := clients.iam.GetGroup(ctx, &iam.GetGroupInput{GroupName: awssdk.String(groupName), MaxItems: awssdk.Int32(1000)})
			if err != nil {
				return nil, "", err
			}
			for _, user := range out.Users {
				members = append(members, iamGroupMember{GroupName: groupName, User: user})
			}
		}
		return members, next, nil
	}
	out, err := clients.iam.GetGroup(ctx, &iam.GetGroupInput{GroupName: awssdk.String(settings.groupName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
	if err != nil {
		return nil, "", err
	}
	members := make([]iamGroupMember, 0, len(out.Users))
	for _, user := range out.Users {
		members = append(members, iamGroupMember{GroupName: settings.groupName, User: user})
	}
	return members, nextMarker(out.IsTruncated, out.Marker), nil
}

func tagValue(tags []ec2types.Tag, key string) string {
	for _, tag := range tags {
		if strings.EqualFold(awssdk.ToString(tag.Key), key) {
			return awssdk.ToString(tag.Value)
		}
	}
	return ""
}

func route53PublicEndpoint(settings settings, zoneID string, zoneName string, privateZone bool, record route53types.ResourceRecordSet) awsPublicEndpoint {
	host := dnsHost(awssdk.ToString(record.Name))
	recordType := string(record.Type)
	if host == "" || !route53PublicRecordType(recordType) {
		return awsPublicEndpoint{}
	}
	targetHosts := make([]string, 0)
	targetIPs := make([]string, 0)
	if record.AliasTarget != nil {
		targetHosts = append(targetHosts, dnsHost(awssdk.ToString(record.AliasTarget.DNSName)))
	}
	for _, resourceRecord := range record.ResourceRecords {
		value := strings.Trim(strings.TrimSpace(awssdk.ToString(resourceRecord.Value)), `"`)
		if ip := normalizeIP(value); ip != "" {
			targetIPs = append(targetIPs, ip)
			continue
		}
		targetHosts = append(targetHosts, dnsHost(value))
	}
	targetHosts = cleanHosts(targetHosts)
	targetIPs = cleanStrings(targetIPs)
	setID := awssdk.ToString(record.SetIdentifier)
	endpointID := firstNonEmpty(setID, host+"-"+recordType)
	return awsPublicEndpoint{
		ResourceID:     firstNonEmpty(strings.Join(cleanStrings([]string{zoneID, host, recordType, setID}), ":"), host),
		ResourceName:   host,
		ResourceType:   "route53_record",
		EndpointID:     endpointID,
		EndpointType:   "dns_record",
		Host:           host,
		TargetHost:     firstString(targetHosts),
		TargetHosts:    targetHosts,
		TargetIP:       firstString(targetIPs),
		TargetIPs:      targetIPs,
		DNSRecordType:  recordType,
		HostedZoneID:   zoneID,
		HostedZoneName: zoneName,
		PrivateZone:    privateZone,
		Region:         "global",
		Scope:          settings.accountID,
		Service:        "route53",
	}
}

func cloudFrontPublicEndpoint(settings settings, distribution cloudfronttypes.DistributionSummary) awsPublicEndpoint {
	id := awssdk.ToString(distribution.Id)
	host := dnsHost(awssdk.ToString(distribution.DomainName))
	aliases := []string(nil)
	if distribution.Aliases != nil {
		aliases = distribution.Aliases.Items
	}
	return awsPublicEndpoint{
		ResourceID:     firstNonEmpty(awssdk.ToString(distribution.ARN), id, host),
		ResourceName:   firstNonEmpty(awssdk.ToString(distribution.Comment), id, host),
		ResourceType:   "cloudfront_distribution",
		EndpointID:     firstNonEmpty(id, host),
		EndpointType:   "cloudfront_distribution",
		Host:           host,
		AlternateHosts: cleanHosts(aliases),
		Region:         "global",
		Scope:          settings.accountID,
		Service:        "cloudfront",
	}
}

func elbPublicEndpoint(settings settings, loadBalancer elbv2types.LoadBalancer) awsPublicEndpoint {
	host := dnsHost(awssdk.ToString(loadBalancer.DNSName))
	lbType := string(loadBalancer.Type)
	resourceType := "load_balancer"
	if lbType != "" {
		resourceType = normalizeAWSResourceType(lbType + "_load_balancer")
	}
	return awsPublicEndpoint{
		ResourceID:   firstNonEmpty(awssdk.ToString(loadBalancer.LoadBalancerArn), awssdk.ToString(loadBalancer.LoadBalancerName), host),
		ResourceName: firstNonEmpty(awssdk.ToString(loadBalancer.LoadBalancerName), host),
		ResourceType: resourceType,
		EndpointID:   firstNonEmpty(awssdk.ToString(loadBalancer.LoadBalancerArn), awssdk.ToString(loadBalancer.LoadBalancerName), host),
		EndpointType: firstNonEmpty(lbType, "load_balancer"),
		Host:         host,
		Region:       settings.region,
		Scope:        settings.accountID,
		Service:      "elasticloadbalancing",
	}
}

func apiGatewayPublicEndpoint(settings settings, domain apigatewaytypes.DomainName) awsPublicEndpoint {
	targetHosts := cleanHosts([]string{awssdk.ToString(domain.DistributionDomainName), awssdk.ToString(domain.RegionalDomainName)})
	return awsPublicEndpoint{
		ResourceID:   firstNonEmpty(awssdk.ToString(domain.DomainNameArn), awssdk.ToString(domain.DomainName)),
		ResourceName: awssdk.ToString(domain.DomainName),
		ResourceType: "apigateway_domain",
		EndpointID:   firstNonEmpty(awssdk.ToString(domain.DomainNameArn), awssdk.ToString(domain.DomainName)),
		EndpointType: firstNonEmpty(apiGatewayEndpointTypes(domain.EndpointConfiguration), "apigateway_domain"),
		Host:         dnsHost(awssdk.ToString(domain.DomainName)),
		TargetHost:   firstString(targetHosts),
		TargetHosts:  targetHosts,
		Region:       settings.region,
		Scope:        settings.accountID,
		Service:      "apigateway",
	}
}

func apiGatewayRestAPIPublicEndpoint(settings settings, api apigatewaytypes.RestApi) awsPublicEndpoint {
	apiID := awssdk.ToString(api.Id)
	host := executeAPIHost(apiID, settings.region)
	return awsPublicEndpoint{
		ResourceID:   firstNonEmpty(apiID, host),
		ResourceName: firstNonEmpty(awssdk.ToString(api.Name), apiID, host),
		ResourceType: "apigateway_rest_api",
		EndpointID:   firstNonEmpty(apiID, host),
		EndpointType: firstNonEmpty(apiGatewayEndpointTypes(api.EndpointConfiguration), "execute_api"),
		Host:         host,
		Region:       settings.region,
		Scope:        settings.accountID,
		Service:      "apigateway",
	}
}

func apiGatewayV2PublicEndpoint(settings settings, domain apigatewayv2types.DomainName) awsPublicEndpoint {
	targetHosts := make([]string, 0, len(domain.DomainNameConfigurations))
	endpointTypes := make([]string, 0, len(domain.DomainNameConfigurations))
	for _, config := range domain.DomainNameConfigurations {
		targetHosts = append(targetHosts, awssdk.ToString(config.ApiGatewayDomainName))
		if string(config.EndpointType) != "" {
			endpointTypes = append(endpointTypes, string(config.EndpointType))
		}
	}
	targetHosts = cleanHosts(targetHosts)
	return awsPublicEndpoint{
		ResourceID:   firstNonEmpty(awssdk.ToString(domain.DomainNameArn), awssdk.ToString(domain.DomainName)),
		ResourceName: awssdk.ToString(domain.DomainName),
		ResourceType: "apigatewayv2_domain",
		EndpointID:   firstNonEmpty(awssdk.ToString(domain.DomainNameArn), awssdk.ToString(domain.DomainName)),
		EndpointType: firstNonEmpty(strings.Join(cleanStrings(endpointTypes), ","), "apigatewayv2_domain"),
		Host:         dnsHost(awssdk.ToString(domain.DomainName)),
		TargetHost:   firstString(targetHosts),
		TargetHosts:  targetHosts,
		Region:       settings.region,
		Scope:        settings.accountID,
		Service:      "apigatewayv2",
	}
}

func apiGatewayV2APIPublicEndpoint(settings settings, api apigatewayv2types.Api) awsPublicEndpoint {
	apiID := awssdk.ToString(api.ApiId)
	host := dnsHost(awssdk.ToString(api.ApiEndpoint))
	if host == "" && apiID != "" {
		host = executeAPIHost(apiID, settings.region)
	}
	protocol := string(api.ProtocolType)
	return awsPublicEndpoint{
		ResourceID:   firstNonEmpty(apiID, host),
		ResourceName: firstNonEmpty(awssdk.ToString(api.Name), apiID, host),
		ResourceType: "apigatewayv2_api",
		EndpointID:   firstNonEmpty(apiID, host),
		EndpointType: firstNonEmpty(protocol, "execute_api"),
		Host:         host,
		Region:       settings.region,
		Scope:        settings.accountID,
		Service:      "apigatewayv2",
	}
}

func listIAMPolicyAssignments(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamPolicyAssignment, string, error) {
	if strings.TrimSpace(settings.principalName) == "" {
		return listAllIAMPolicyAssignments(ctx, clients, settings, cursor, limit)
	}
	var policies []iamtypes.AttachedPolicy
	var next string
	parsed := parseIAMPrincipalAssignmentCursor(cursor)
	stage := parsed.Stage
	marker := parsed.Marker
	if strings.TrimSpace(cursor) == "" {
		stage = "attached"
	}
	if stage != "attached" && stage != "inline" {
		stage = "attached"
		marker = strings.TrimSpace(cursor)
	}
	if stage == "inline" {
		assignments, next, err := inlinePolicyAssignmentsPage(ctx, clients, settings.principalType, settings.principalName, marker, limit)
		if err != nil {
			return nil, "", err
		}
		if next != "" {
			return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "inline", Marker: next}), nil
		}
		return assignments, "", nil
	}
	switch settings.principalType {
	case "group":
		out, err := clients.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: awssdk.String(settings.principalName), Marker: stringPtr(marker), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	case "role":
		out, err := clients.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: awssdk.String(settings.principalName), Marker: stringPtr(marker), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	default:
		out, err := clients.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: awssdk.String(settings.principalName), Marker: stringPtr(marker), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policies = out.AttachedPolicies
		next = nextMarker(out.IsTruncated, out.Marker)
	}
	assignments, err := attachedPolicyAssignments(ctx, clients, settings.principalType, settings.principalName, policies)
	if err != nil {
		return nil, "", err
	}
	if next != "" {
		return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "attached", Marker: next}), nil
	}
	remaining := limit - len(assignments)
	if remaining <= 0 {
		return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "inline"}), nil
	}
	inlineAssignments, inlineNext, err := inlinePolicyAssignmentsPage(ctx, clients, settings.principalType, settings.principalName, "", remaining)
	if err != nil {
		return nil, "", err
	}
	assignments = append(assignments, inlineAssignments...)
	if inlineNext != "" {
		return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "inline", Marker: inlineNext}), nil
	}
	return assignments, "", nil
}

func listEffectivePermissions(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamPolicyAssignment, string, error) {
	return listIAMPolicyAssignments(ctx, clients, settings, cursor, limit)
}

func listAllIAMPolicyAssignments(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]iamPolicyAssignment, string, error) {
	parsed := parseIAMPrincipalAssignmentCursor(cursor)
	if parsed.Stage == "" {
		parsed.Stage = "user"
	}
	switch parsed.Stage {
	case "user":
		users, next, err := listIAMUsers(ctx, clients, settings, parsed.Marker, limit)
		if err != nil {
			return nil, "", err
		}
		assignments, err := attachedUserPolicyAssignments(ctx, clients, users)
		if err != nil {
			return nil, "", err
		}
		if next != "" {
			return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "user", Marker: next}), nil
		}
		return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "group"}), nil
	case "group":
		groups, next, err := listIAMGroups(ctx, clients, settings, parsed.Marker, limit)
		if err != nil {
			return nil, "", err
		}
		assignments, err := attachedGroupPolicyAssignments(ctx, clients, groups)
		if err != nil {
			return nil, "", err
		}
		if next != "" {
			return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "group", Marker: next}), nil
		}
		return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "role"}), nil
	case "role":
		roles, next, err := listIAMRoles(ctx, clients, settings, parsed.Marker, limit)
		if err != nil {
			return nil, "", err
		}
		assignments, err := attachedRolePolicyAssignments(ctx, clients, roles)
		if err != nil {
			return nil, "", err
		}
		if next != "" {
			return assignments, encodeIAMPrincipalAssignmentCursor(iamPrincipalAssignmentCursor{Stage: "role", Marker: next}), nil
		}
		return assignments, "", nil
	default:
		return nil, "", fmt.Errorf("invalid iam assignment cursor stage %q", parsed.Stage)
	}
}

func attachedUserPolicyAssignments(ctx context.Context, clients awsClients, users []iamtypes.User) ([]iamPolicyAssignment, error) {
	assignments := make([]iamPolicyAssignment, 0, len(users))
	for _, user := range users {
		userName := awssdk.ToString(user.UserName)
		if userName == "" {
			continue
		}
		out, err := clients.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: awssdk.String(userName), MaxItems: awssdk.Int32(1000)})
		if err != nil {
			return nil, err
		}
		attachedAssignments, err := attachedPolicyAssignments(ctx, clients, "user", userName, out.AttachedPolicies)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, attachedAssignments...)
		inlineAssignments, err := inlinePolicyAssignments(ctx, clients, "user", userName)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, inlineAssignments...)
	}
	return assignments, nil
}

func attachedGroupPolicyAssignments(ctx context.Context, clients awsClients, groups []iamtypes.Group) ([]iamPolicyAssignment, error) {
	assignments := make([]iamPolicyAssignment, 0, len(groups))
	for _, group := range groups {
		groupName := awssdk.ToString(group.GroupName)
		if groupName == "" {
			continue
		}
		out, err := clients.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: awssdk.String(groupName), MaxItems: awssdk.Int32(1000)})
		if err != nil {
			return nil, err
		}
		attachedAssignments, err := attachedPolicyAssignments(ctx, clients, "group", groupName, out.AttachedPolicies)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, attachedAssignments...)
		inlineAssignments, err := inlinePolicyAssignments(ctx, clients, "group", groupName)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, inlineAssignments...)
	}
	return assignments, nil
}

func attachedRolePolicyAssignments(ctx context.Context, clients awsClients, roles []iamtypes.Role) ([]iamPolicyAssignment, error) {
	assignments := make([]iamPolicyAssignment, 0, len(roles))
	for _, role := range roles {
		roleName := awssdk.ToString(role.RoleName)
		if roleName == "" {
			continue
		}
		out, err := clients.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: awssdk.String(roleName), MaxItems: awssdk.Int32(1000)})
		if err != nil {
			return nil, err
		}
		attachedAssignments, err := attachedPolicyAssignments(ctx, clients, "role", roleName, out.AttachedPolicies)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, attachedAssignments...)
		inlineAssignments, err := inlinePolicyAssignments(ctx, clients, "role", roleName)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, inlineAssignments...)
	}
	return assignments, nil
}

func attachedPolicyAssignments(ctx context.Context, clients awsClients, principalType string, principalName string, policies []iamtypes.AttachedPolicy) ([]iamPolicyAssignment, error) {
	assignments := make([]iamPolicyAssignment, 0, len(policies))
	for _, policy := range policies {
		actions, err := managedPolicyActions(ctx, clients, awssdk.ToString(policy.PolicyArn))
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, iamPolicyAssignment{
			PrincipalType: principalType,
			PrincipalName: principalName,
			Policy:        policy,
			PolicySource:  "attached",
			Actions:       actions,
		})
	}
	return assignments, nil
}

func managedPolicyActions(ctx context.Context, clients awsClients, policyARN string) ([]string, error) {
	policyARN = strings.TrimSpace(policyARN)
	if policyARN == "" {
		return nil, nil
	}
	policy, err := clients.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awssdk.String(policyARN)})
	if err != nil {
		return nil, err
	}
	versionID := ""
	if policy.Policy != nil {
		versionID = awssdk.ToString(policy.Policy.DefaultVersionId)
	}
	if versionID == "" {
		return nil, nil
	}
	version, err := clients.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: awssdk.String(policyARN), VersionId: awssdk.String(versionID)})
	if err != nil {
		return nil, err
	}
	if version.PolicyVersion == nil {
		return nil, nil
	}
	return policyDocumentActions(awssdk.ToString(version.PolicyVersion.Document)), nil
}

func inlinePolicyAssignments(ctx context.Context, clients awsClients, principalType string, principalName string) ([]iamPolicyAssignment, error) {
	assignments := make([]iamPolicyAssignment, 0)
	marker := ""
	for {
		page, next, err := inlinePolicyAssignmentsPage(ctx, clients, principalType, principalName, marker, 1000)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, page...)
		if next == "" {
			return assignments, nil
		}
		marker = next
	}
}

func inlinePolicyAssignmentsPage(ctx context.Context, clients awsClients, principalType string, principalName string, cursor string, limit int) ([]iamPolicyAssignment, string, error) {
	principalName = strings.TrimSpace(principalName)
	if principalName == "" {
		return nil, "", nil
	}
	var policyNames []string
	var next string
	switch principalType {
	case "group":
		out, err := clients.iam.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: awssdk.String(principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policyNames = out.PolicyNames
		next = nextMarker(out.IsTruncated, out.Marker)
	case "role":
		out, err := clients.iam.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: awssdk.String(principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policyNames = out.PolicyNames
		next = nextMarker(out.IsTruncated, out.Marker)
	default:
		out, err := clients.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: awssdk.String(principalName), Marker: stringPtr(cursor), MaxItems: int32Ptr(limit)})
		if err != nil {
			return nil, "", err
		}
		policyNames = out.PolicyNames
		next = nextMarker(out.IsTruncated, out.Marker)
		principalType = "user"
	}
	assignments := make([]iamPolicyAssignment, 0, len(policyNames))
	for _, policyName := range policyNames {
		policyName = strings.TrimSpace(policyName)
		if policyName == "" {
			continue
		}
		document, err := inlinePolicyDocument(ctx, clients, principalType, principalName, policyName)
		if err != nil {
			return nil, "", err
		}
		assignments = append(assignments, iamPolicyAssignment{
			PrincipalType: principalType,
			PrincipalName: principalName,
			Policy: iamtypes.AttachedPolicy{
				PolicyArn:  awssdk.String(inlinePolicyURN(principalType, principalName, policyName)),
				PolicyName: awssdk.String(policyName),
			},
			PolicySource: "inline",
			Actions:      policyDocumentActions(document),
		})
	}
	return assignments, next, nil
}

func inlinePolicyDocument(ctx context.Context, clients awsClients, principalType string, principalName string, policyName string) (string, error) {
	switch principalType {
	case "group":
		out, err := clients.iam.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: awssdk.String(principalName), PolicyName: awssdk.String(policyName)})
		if err != nil {
			return "", err
		}
		return awssdk.ToString(out.PolicyDocument), nil
	case "role":
		out, err := clients.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: awssdk.String(principalName), PolicyName: awssdk.String(policyName)})
		if err != nil {
			return "", err
		}
		return awssdk.ToString(out.PolicyDocument), nil
	default:
		out, err := clients.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: awssdk.String(principalName), PolicyName: awssdk.String(policyName)})
		if err != nil {
			return "", err
		}
		return awssdk.ToString(out.PolicyDocument), nil
	}
}

func inlinePolicyURN(principalType string, principalName string, policyName string) string {
	return "inline:" + strings.Join(cleanStrings([]string{principalType, principalName, policyName}), ":")
}

func listCloudTrailEvents(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]cloudtrailtypes.Event, string, error) {
	now := time.Now().UTC()
	state, resume := parseCloudTrailCursor(cursor, settings, now)
	input := &cloudtrail.LookupEventsInput{MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 1, 50))}
	if resume {
		input.NextToken = stringPtr(state.Token)
		if state.StartTime != "" {
			parsed, err := time.Parse(time.RFC3339Nano, state.StartTime)
			if err != nil {
				return nil, "", fmt.Errorf("parse aws cloudtrail cursor start_time: %w", err)
			}
			input.StartTime = &parsed
		}
		if state.EndTime != "" {
			parsed, err := time.Parse(time.RFC3339Nano, state.EndTime)
			if err != nil {
				return nil, "", fmt.Errorf("parse aws cloudtrail cursor end_time: %w", err)
			}
			input.EndTime = &parsed
		}
	}
	if settings.cloudTrail.lookupKey != "" && settings.cloudTrail.lookupValue != "" {
		input.LookupAttributes = []cloudtrailtypes.LookupAttribute{{AttributeKey: cloudtrailtypes.LookupAttributeKey(settings.cloudTrail.lookupKey), AttributeValue: awssdk.String(settings.cloudTrail.lookupValue)}}
	}
	if !resume && firstNonEmpty(settings.cloudTrail.startTime, settings.cloudTrail.since) != "" {
		parsed, err := parseAWSTimeSelector(firstNonEmpty(settings.cloudTrail.startTime, settings.cloudTrail.since), now)
		if err != nil {
			return nil, "", fmt.Errorf("parse aws start_time: %w", err)
		}
		input.StartTime = &parsed
	}
	if !resume && settings.cloudTrail.endTime != "" {
		parsed, err := time.Parse(time.RFC3339, settings.cloudTrail.endTime)
		if err != nil {
			return nil, "", fmt.Errorf("parse aws end_time: %w", err)
		}
		input.EndTime = &parsed
	}
	out, err := clients.cloudTrail.LookupEvents(ctx, input)
	var staleToken *cloudtrailtypes.InvalidNextTokenException
	if err != nil && resume && strings.TrimSpace(state.Token) != "" && errors.As(err, &staleToken) {
		input.NextToken = nil
		out, err = clients.cloudTrail.LookupEvents(ctx, input)
	}
	if err != nil {
		return nil, "", err
	}
	return out.Events, encodeCloudTrailCursor(settings, input, awssdk.ToString(out.NextToken), now), nil
}

func parseCloudTrailCursor(raw string, settings settings, now time.Time) (cloudTrailCursor, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cloudTrailCursor{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cloudTrailCursor{}, false
	}
	var cursor cloudTrailCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return cloudTrailCursor{}, false
	}
	if cursor.Version != cloudTrailCursorVersion || strings.TrimSpace(cursor.Token) == "" {
		return cloudTrailCursor{}, false
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(cursor.IssuedAt))
	if err != nil || now.Sub(issuedAt) > cloudTrailCursorMaxAge {
		return cloudTrailCursor{}, false
	}
	cursor.StartTime = strings.TrimSpace(cursor.StartTime)
	cursor.EndTime = strings.TrimSpace(cursor.EndTime)
	if cursor.StartTime != "" {
		if _, err := time.Parse(time.RFC3339Nano, cursor.StartTime); err != nil {
			return cloudTrailCursor{}, false
		}
	}
	if cursor.EndTime != "" {
		if _, err := time.Parse(time.RFC3339Nano, cursor.EndTime); err != nil {
			return cloudTrailCursor{}, false
		}
	}
	if cursor.StartSelector != firstNonEmpty(settings.cloudTrail.startTime, settings.cloudTrail.since) ||
		cursor.EndSelector != strings.TrimSpace(settings.cloudTrail.endTime) ||
		cursor.LookupKey != strings.TrimSpace(settings.cloudTrail.lookupKey) ||
		cursor.LookupValue != strings.TrimSpace(settings.cloudTrail.lookupValue) {
		return cloudTrailCursor{}, false
	}
	cursor.Token = strings.TrimSpace(cursor.Token)
	return cursor, true
}

func encodeCloudTrailCursor(settings settings, input *cloudtrail.LookupEventsInput, token string, issuedAt time.Time) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	cursor := cloudTrailCursor{
		Version:       cloudTrailCursorVersion,
		Token:         token,
		StartSelector: firstNonEmpty(settings.cloudTrail.startTime, settings.cloudTrail.since),
		EndSelector:   strings.TrimSpace(settings.cloudTrail.endTime),
		LookupKey:     strings.TrimSpace(settings.cloudTrail.lookupKey),
		LookupValue:   strings.TrimSpace(settings.cloudTrail.lookupValue),
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339Nano),
	}
	if input != nil && input.StartTime != nil {
		cursor.StartTime = input.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if input != nil && input.EndTime != nil {
		cursor.EndTime = input.EndTime.UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func iamUserEvent(settings settings, user iamtypes.User) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":       settings.accountID,
		"family":       familyIAMUser,
		"user_id":      firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.Arn), awssdk.ToString(user.UserName)),
		"login":        awssdk.ToString(user.UserName),
		"email":        emailLike(awssdk.ToString(user.UserName)),
		"display_name": awssdk.ToString(user.UserName),
		"arn":          awssdk.ToString(user.Arn),
		"is_admin":     boolString(containsAny(strings.ToLower(awssdk.ToString(user.UserName)), "admin", "root")),
	}
	addTimeAttribute(attributes, "created_at", user.CreateDate)
	addTimeAttribute(attributes, "last_login_at", user.PasswordLastUsed)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "user": user})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-user-"+firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)), "aws.iam_user", "aws/iam_user/v1", payload, attributes, firstTime(user.PasswordLastUsed, user.CreateDate))
}

func iamGroupEvent(settings settings, group iamtypes.Group) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":     settings.accountID,
		"family":     familyIAMGroup,
		"group_id":   firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.Arn), awssdk.ToString(group.GroupName)),
		"group_name": awssdk.ToString(group.GroupName),
		"arn":        awssdk.ToString(group.Arn),
	}
	addTimeAttribute(attributes, "created_at", group.CreateDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group": group})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-group-"+firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName)), "aws.iam_group", "aws/iam_group/v1", payload, attributes, firstTime(group.CreateDate))
}

func iamGroupMembershipEvent(settings settings, member iamGroupMember) (*primitives.Event, error) {
	user := member.User
	groupName := firstNonEmpty(member.GroupName, settings.groupName)
	attributes := map[string]string{
		"domain":         settings.accountID,
		"family":         familyIAMMembership,
		"group_id":       groupName,
		"group_name":     groupName,
		"member_email":   emailLike(awssdk.ToString(user.UserName)),
		"member_id":      firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.Arn), awssdk.ToString(user.UserName)),
		"member_user_id": firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)),
		"member_type":    "user",
		"role":           "member",
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "group_name": groupName, "user": user})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-iam-group-membership-%s-%s", groupName, firstNonEmpty(awssdk.ToString(user.UserId), awssdk.ToString(user.UserName)))
	return sourceEvent(settings, id, "aws.iam_group_membership", "aws/iam_group_membership/v1", payload, attributes, firstTime(user.CreateDate))
}

func iamRoleEvent(settings settings, role iamtypes.Role) (*primitives.Event, error) {
	attributes := map[string]string{
		"arn":            awssdk.ToString(role.Arn),
		"domain":         settings.accountID,
		"family":         familyIAMRole,
		"principal_type": "role",
		"user_id":        firstNonEmpty(awssdk.ToString(role.RoleId), awssdk.ToString(role.Arn), awssdk.ToString(role.RoleName)),
		"login":          awssdk.ToString(role.RoleName),
		"display_name":   awssdk.ToString(role.RoleName),
		"is_admin":       boolString(containsAny(strings.ToLower(awssdk.ToString(role.RoleName)), "admin", "power", "owner")),
	}
	addTimeAttribute(attributes, "created_at", role.CreateDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "role": role})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-role-"+firstNonEmpty(awssdk.ToString(role.RoleId), awssdk.ToString(role.RoleName)), "aws.iam_role", "aws/iam_role/v1", payload, attributes, firstTime(role.CreateDate))
}

func iamRoleTrustEvent(settings settings, trust iamRoleTrust) (*primitives.Event, error) {
	roleName := awssdk.ToString(trust.Role.RoleName)
	roleARN := awssdk.ToString(trust.Role.Arn)
	roleUniqueID := awssdk.ToString(trust.Role.RoleId)
	roleID := firstNonEmpty(roleARN, roleUniqueID, roleName)
	subjectType, subjectID := awsTrustPrincipal(trust.Principal, trust.PrincipalType)
	attributes := map[string]string{
		"domain":               settings.accountID,
		"external_id_required": boolString(trustExternalIDRequired(trust.Statement)),
		"family":               familyIAMRoleTrust,
		"is_external":          boolString(trustExternal(settings.accountID, trust.Principal)),
		"is_public":            boolString(subjectType == "public"),
		"path_type":            "assume_role_trust",
		"principal_arn":        trust.Principal,
		"relationship":         "can_assume",
		"role_id":              roleID,
		"role_name":            roleName,
		"role_type":            "aws_iam_role",
		"role_unique_id":       roleUniqueID,
		"statement_sid":        trust.Statement.Sid,
		"subject_id":           subjectID,
		"subject_type":         subjectType,
		"target_arn":           roleARN,
		"target_id":            roleID,
		"target_name":          roleName,
		"target_type":          "role",
		"trust_action":         strings.Join(stringList(trust.Statement.Action), ","),
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "role": trust.Role, "statement": trust.Statement, "principal": trust.Principal})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-iam-role-trust-%s-%s", firstNonEmpty(roleName, roleARN), trust.Principal)
	return sourceEvent(settings, id, "aws.iam_role_trust", "aws/iam_role_trust/v1", payload, attributes, firstTime(trust.Role.CreateDate))
}

func iamRoleAssignmentEvent(settings settings, assignment iamPolicyAssignment) (*primitives.Event, error) {
	policyName := awssdk.ToString(assignment.Policy.PolicyName)
	policyARN := awssdk.ToString(assignment.Policy.PolicyArn)
	attributes := map[string]string{
		"domain":         settings.accountID,
		"family":         familyIAMRoleAssign,
		"principal_type": assignment.PrincipalType,
		"role_id":        firstNonEmpty(policyARN, policyName),
		"role_name":      policyName,
		"role_type":      "aws_iam_policy",
		"policy_source":  firstNonEmpty(assignment.PolicySource, "attached"),
		"subject_email":  emailLike(assignment.PrincipalName),
		"subject_id":     assignment.PrincipalName,
		"subject_login":  assignment.PrincipalName,
		"subject_type":   assignment.PrincipalType,
		"is_admin":       boolString(isAdminPolicy(policyName, policyARN)),
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "assignment": assignment})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-iam-role-assignment-%s-%s", assignment.PrincipalName, firstNonEmpty(policyARN, policyName))
	return sourceEvent(settings, id, "aws.iam_role_assignment", "aws/iam_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func effectivePermissionEvent(settings settings, assignment iamPolicyAssignment) (*primitives.Event, error) {
	policyName := awssdk.ToString(assignment.Policy.PolicyName)
	policyARN := awssdk.ToString(assignment.Policy.PolicyArn)
	admin := isAdminPolicy(policyName, policyARN) || policyActionsAdmin(assignment.Actions)
	permission := firstNonEmpty(strings.Join(assignment.Actions, ","), policyName, policyARN)
	attributes := map[string]string{
		"actions":         permission,
		"domain":          settings.accountID,
		"effect":          "allow",
		"family":          familyEffectivePermission,
		"is_admin":        boolString(admin),
		"permission":      permission,
		"policy_source":   firstNonEmpty(assignment.PolicySource, "attached"),
		"principal_type":  assignment.PrincipalType,
		"privilege_level": map[bool]string{true: "admin", false: "policy_attachment"}[admin],
		"resource_id":     firstNonEmpty(policyARN, policyName, settings.accountID),
		"resource_name":   firstNonEmpty(policyName, policyARN, settings.accountID),
		"resource_type":   "aws_iam_policy",
		"role_id":         firstNonEmpty(policyARN, policyName),
		"role_name":       policyName,
		"role_type":       "aws_iam_policy",
		"scope":           settings.accountID,
		"subject_email":   emailLike(assignment.PrincipalName),
		"subject_id":      assignment.PrincipalName,
		"subject_login":   assignment.PrincipalName,
		"subject_name":    assignment.PrincipalName,
		"subject_type":    assignment.PrincipalType,
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "effective_permission": assignment})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("aws-effective-permission-%s-%s", assignment.PrincipalName, firstNonEmpty(policyARN, policyName))
	return sourceEvent(settings, id, "aws.effective_permission", "aws/effective_permission/v1", payload, attributes, time.Now().UTC())
}

func policyActionsAdmin(actions []string) bool {
	for _, action := range actions {
		normalized := strings.ToLower(strings.TrimSpace(action))
		if normalized == "*" || strings.HasSuffix(normalized, ":*") {
			return true
		}
	}
	return false
}

func accessKeyEvent(settings settings, key iamtypes.AccessKeyMetadata) (*primitives.Event, error) {
	userName := firstNonEmpty(awssdk.ToString(key.UserName), settings.userName)
	attributes := map[string]string{
		"credential_id":   awssdk.ToString(key.AccessKeyId),
		"credential_type": "aws_access_key",
		"domain":          settings.accountID,
		"event_type":      "aws_access_key_present",
		"family":          familyAccessKey,
		"resource_id":     awssdk.ToString(key.AccessKeyId),
		"resource_type":   "access_key",
		"status":          string(key.Status),
		"subject_email":   emailLike(userName),
		"subject_id":      userName,
		"subject_type":    "user",
	}
	addTimeAttribute(attributes, "created_at", key.CreateDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "access_key": key})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-access-key-"+firstNonEmpty(awssdk.ToString(key.AccessKeyId), userName), "aws.access_key", "aws/access_key/v1", payload, attributes, firstTime(key.CreateDate))
}

func assetMetadataEvent(settings settings, asset awsAssetMetadata) (*primitives.Event, error) {
	payload, err := json.Marshal(map[string]any{
		"account_id":    settings.accountID,
		"region":        asset.Region,
		"resource_arn":  asset.ResourceARN,
		"resource_id":   asset.ResourceID,
		"resource_name": asset.ResourceName,
		"resource_type": asset.ResourceType,
		"tags":          asset.Tags,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal aws asset metadata payload: %w", err)
	}
	attributes := map[string]string{
		"asset_criticality":   firstNonEmpty(tagLookup(asset.Tags, "asset_criticality", "business_criticality", "criticality", "tier"), criticalityFromTags(asset.Tags)),
		"aws_account_id":      settings.accountID,
		"contains_pci":        tagLookup(asset.Tags, "contains_pci", "pci"),
		"contains_phi":        tagLookup(asset.Tags, "contains_phi", "phi"),
		"contains_pii":        tagLookup(asset.Tags, "contains_pii", "pii"),
		"contains_secrets":    tagLookup(asset.Tags, "contains_secrets", "secrets"),
		"crown_jewel":         boolString(crownJewelFromTags(asset.Tags)),
		"data_classification": tagLookup(asset.Tags, "data_classification", "DataClassification", "data-classification", "data class", "data_class", "classification", "sensitivity", "data_sensitivity", "DataSensitivity"),
		"environment":         tagLookup(asset.Tags, "environment", "env", "stage"),
		"internet_exposed":    tagLookup(asset.Tags, "internet_exposed", "internet-exposed", "externally_exposed", "external_exposure"),
		"owner":               tagLookup(asset.Tags, "owner", "application_owner", "business_owner", "service_owner"),
		"public":              tagLookup(asset.Tags, "public", "public_access"),
		"region":              asset.Region,
		"resource_arn":        asset.ResourceARN,
		"resource_id":         asset.ResourceID,
		"resource_name":       asset.ResourceName,
		"resource_provider":   "aws",
		"resource_type":       asset.ResourceType,
		"source_provider":     "aws",
		"team":                tagLookup(asset.Tags, "team", "squad", "group"),
	}
	resourceKey := firstNonEmpty(asset.ResourceARN, asset.ResourceID, asset.ResourceName)
	return sourceEvent(settings, "aws-asset-metadata-"+resourceKey, "asset.data_sensitivity", "asset/data_sensitivity/v1", payload, attributes, time.Now().UTC())
}

func resourceExposureEvent(settings settings, exposure awsResourceExposure) (*primitives.Event, error) {
	attributes := map[string]string{
		"action":            "allow",
		"direction":         "ingress",
		"domain":            settings.accountID,
		"exposed_to":        "public_internet",
		"exposure_id":       exposure.ExposureID,
		"exposure_type":     "public_network_ingress",
		"external_exposure": "true",
		"family":            familyResourceExposure,
		"internet_exposed":  "true",
		"port_range":        exposure.PortRange,
		"protocol":          exposure.Protocol,
		"public":            "true",
		"region":            exposure.Region,
		"resource_id":       exposure.ResourceID,
		"resource_name":     exposure.ResourceName,
		"resource_provider": "aws",
		"resource_type":     "security_group",
		"rule_id":           exposure.ExposureID,
		"scope":             exposure.Scope,
		"source_cidr":       exposure.SourceCIDR,
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "security_group": exposure.Group, "permission": exposure.Permission})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-resource-exposure-"+exposure.ExposureID, "aws.resource_exposure", "aws/resource_exposure/v1", payload, attributes, time.Now().UTC())
}

func publicEndpointEvent(settings settings, endpoint awsPublicEndpoint) (*primitives.Event, error) {
	attributes := map[string]string{
		"alternate_hosts":        strings.Join(cleanHosts(endpoint.AlternateHosts), ","),
		"associated_instance_id": endpoint.AssociatedInstanceID,
		"attached_instance_id":   endpoint.AttachedInstanceID,
		"dns_record_type":        endpoint.DNSRecordType,
		"domain":                 settings.accountID,
		"endpoint_id":            endpoint.EndpointID,
		"endpoint_type":          endpoint.EndpointType,
		"external_exposure":      boolString(!endpoint.PrivateZone),
		"family":                 familyPublicEndpoint,
		"host":                   endpoint.Host,
		"hosted_zone_id":         endpoint.HostedZoneID,
		"hosted_zone_name":       endpoint.HostedZoneName,
		"internet_exposed":       boolString(!endpoint.PrivateZone),
		"ip":                     endpoint.IP,
		"private_zone":           boolString(endpoint.PrivateZone),
		"public":                 boolString(!endpoint.PrivateZone),
		"region":                 endpoint.Region,
		"resource_id":            endpoint.ResourceID,
		"resource_name":          endpoint.ResourceName,
		"resource_provider":      "aws",
		"resource_type":          endpoint.ResourceType,
		"scope":                  endpoint.Scope,
		"service":                endpoint.Service,
		"target_host":            endpoint.TargetHost,
		"target_hosts":           strings.Join(cleanHosts(endpoint.TargetHosts), ","),
		"target_ip":              endpoint.TargetIP,
		"target_ips":             strings.Join(cleanStrings(endpoint.TargetIPs), ","),
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "endpoint": endpoint})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-public-endpoint-"+firstNonEmpty(endpoint.EndpointID, endpoint.ResourceID, endpoint.IP, endpoint.Host), "aws.public_endpoint", "aws/public_endpoint/v1", payload, attributes, time.Now().UTC())
}

func cloudTrailEvent(settings settings, event cloudtrailtypes.Event) (*primitives.Event, error) {
	detail := cloudTrailDetail{}
	if raw := awssdk.ToString(event.CloudTrailEvent); raw != "" {
		_ = json.Unmarshal([]byte(raw), &detail)
	}
	resourceID, resourceType := cloudTrailResource(event, detail)
	actor := cloudTrailActor(event, detail)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(actor.UserName, actor.Arn, actor.PrincipalID, awssdk.ToString(event.Username)),
		"actor_email":        emailLike(firstNonEmpty(actor.UserName, actor.Arn, awssdk.ToString(event.Username))),
		"actor_id":           firstNonEmpty(actor.Arn, actor.PrincipalID, awssdk.ToString(event.Username)),
		"actor_type":         actor.Type,
		"domain":             settings.accountID,
		"event_name":         firstNonEmpty(detail.EventName, awssdk.ToString(event.EventName)),
		"event_type":         firstNonEmpty(detail.EventName, awssdk.ToString(event.EventName)),
		"family":             familyCloudTrail,
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_type":      resourceType,
		"source_ip":          detail.SourceIPAddress,
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "event": event, "detail": detail})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if event.EventTime != nil {
		occurredAt = event.EventTime.UTC()
	} else if detail.EventTime != "" {
		if parsed, err := time.Parse(time.RFC3339, detail.EventTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "aws-cloudtrail-"+firstNonEmpty(awssdk.ToString(event.EventId), attributes["event_type"], strconv.FormatInt(occurredAt.UnixNano(), 10)), "aws.cloudtrail", "aws/cloudtrail/v1", payload, attributes, occurredAt)
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.accountID,
		SourceId:   "aws",
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  schemaRef,
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func awsPullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		if next != "" {
			return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
		}
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: firstNonEmpty(next, fallback),
		},
	}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func awsCheck[T any](ctx context.Context, clients awsClients, settings settings, list func(context.Context, awsClients, settings, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, clients, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, settings.accountID, err)
	}
	return nil
}

func awsURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return parseAWSURNs(values...)
}

func parseAWSURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func nextMarker(truncated bool, marker *string) string {
	if !truncated {
		return ""
	}
	return awssdk.ToString(marker)
}

func int32Ptr(value int) *int32 {
	if value == 0 {
		return nil
	}
	if value > math.MaxInt32 {
		value = math.MaxInt32
	}
	if value < math.MinInt32 {
		value = math.MinInt32
	}
	parsed := int32(value)
	return &parsed
}

func stringPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func configBool(cfg sourcecdk.Config, key string, fallback bool) bool {
	value, ok := cfg.Lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "yes", "y":
		return true
	case "0", "f", "false", "no", "n":
		return false
	default:
		return fallback
	}
}

func parsePublicEndpointCursor(raw string) (publicEndpointCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return publicEndpointCursor{Version: publicEndpointCursorV2, Stage: publicEndpointStageRoute53}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return publicEndpointCursor{}, fmt.Errorf("parse aws public_endpoint cursor: %w", err)
	}
	var cursor publicEndpointCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return publicEndpointCursor{}, fmt.Errorf("parse aws public_endpoint cursor: %w", err)
	}
	if cursor.Stage == "" {
		cursor.Stage = publicEndpointStageRoute53
	}
	if cursor.Version != publicEndpointCursorV2 {
		return publicEndpointCursor{}, fmt.Errorf("parse aws public_endpoint cursor: unsupported cursor version %d", cursor.Version)
	}
	return cursor, nil
}

func encodePublicEndpointCursor(cursor publicEndpointCursor) string {
	if cursor.Stage == "" {
		return ""
	}
	if cursor.Version == 0 {
		cursor.Version = publicEndpointCursorV2
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func parseIAMPrincipalAssignmentCursor(cursor string) iamPrincipalAssignmentCursor {
	trimmed := strings.TrimSpace(cursor)
	if trimmed == "" {
		return iamPrincipalAssignmentCursor{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return iamPrincipalAssignmentCursor{Stage: "user", Marker: trimmed}
	}
	parsed := iamPrincipalAssignmentCursor{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return iamPrincipalAssignmentCursor{Stage: "user", Marker: trimmed}
	}
	return parsed
}

func encodeIAMPrincipalAssignmentCursor(cursor iamPrincipalAssignmentCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func route53HostedZoneID(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "/hostedzone/")
}

func route53PublicRecordType(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "A", "AAAA", "CNAME":
		return true
	default:
		return false
	}
}

func apiGatewayDomainPrivate(config *apigatewaytypes.EndpointConfiguration) bool {
	if config == nil || len(config.Types) == 0 {
		return false
	}
	for _, endpointType := range config.Types {
		if endpointType != apigatewaytypes.EndpointTypePrivate {
			return false
		}
	}
	return true
}

func apiGatewayEndpointTypes(config *apigatewaytypes.EndpointConfiguration) string {
	if config == nil {
		return ""
	}
	values := make([]string, 0, len(config.Types))
	for _, endpointType := range config.Types {
		values = append(values, string(endpointType))
	}
	return strings.Join(cleanStrings(values), ",")
}

func cleanHosts(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		host := dnsHost(value)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	return result
}

func cleanStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func firstString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func dnsHost(raw string) string {
	value := strings.Trim(strings.TrimSpace(raw), ".")
	value = strings.Trim(value, `"`)
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
}

func normalizeIP(raw string) string {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func normalizeAWSResourceType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, ".", "_")
	return strings.Trim(normalized, "_")
}

func executeAPIHost(apiID string, region string) string {
	apiID = strings.TrimSpace(apiID)
	region = strings.TrimSpace(region)
	if apiID == "" || region == "" {
		return ""
	}
	return fmt.Sprintf("%s.execute-api.%s.%s", apiID, region, awsDNSSuffix(region))
}

func awsDNSSuffix(region string) string {
	if strings.HasPrefix(strings.TrimSpace(region), "cn-") {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

func parseAWSTimeSelector(value string, now time.Time) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(trimmed), "P") {
		duration, err := parseSimpleISODuration(trimmed)
		if err != nil {
			return time.Time{}, err
		}
		return now.Add(-duration), nil
	}
	return time.Parse(time.RFC3339, trimmed)
}

func parseSimpleISODuration(value string) (time.Duration, error) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" || normalized[0] != 'P' {
		return 0, fmt.Errorf("duration must start with P")
	}
	remaining := strings.TrimPrefix(normalized, "P")
	days := 0
	if index := strings.Index(remaining, "D"); index >= 0 {
		parsed, err := strconv.Atoi(remaining[:index])
		if err != nil {
			return 0, err
		}
		days = parsed
		remaining = remaining[index+1:]
	}
	hours := 0
	minutes := 0
	if strings.HasPrefix(remaining, "T") {
		remaining = strings.TrimPrefix(remaining, "T")
		if index := strings.Index(remaining, "H"); index >= 0 {
			parsed, err := strconv.Atoi(remaining[:index])
			if err != nil {
				return 0, err
			}
			hours = parsed
			remaining = remaining[index+1:]
		}
		if index := strings.Index(remaining, "M"); index >= 0 {
			parsed, err := strconv.Atoi(remaining[:index])
			if err != nil {
				return 0, err
			}
			minutes = parsed
		}
	}
	if days == 0 && hours == 0 && minutes == 0 {
		return 0, fmt.Errorf("duration must include days, hours, or minutes")
	}
	return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute, nil
}

func cloudTrailActor(event cloudtrailtypes.Event, detail cloudTrailDetail) cloudTrailUserIdentity {
	if detail.UserIdentity.Arn != "" || detail.UserIdentity.PrincipalID != "" || detail.UserIdentity.UserName != "" {
		return detail.UserIdentity
	}
	return cloudTrailUserIdentity{UserName: awssdk.ToString(event.Username)}
}

func cloudTrailResource(event cloudtrailtypes.Event, detail cloudTrailDetail) (string, string) {
	if len(detail.Resources) != 0 {
		resource := detail.Resources[0]
		return firstNonEmpty(resource.ARN, resource.ARNLower, resource.Name), firstNonEmpty(resource.Type, "resource")
	}
	if len(event.Resources) != 0 {
		resource := event.Resources[0]
		return awssdk.ToString(resource.ResourceName), awssdk.ToString(resource.ResourceType)
	}
	return firstNonEmpty(awssdk.ToString(event.EventSource), awssdk.ToString(event.EventName)), "resource"
}

func roleTrusts(role iamtypes.Role) []iamRoleTrust {
	raw := awssdk.ToString(role.AssumeRolePolicyDocument)
	if raw == "" {
		return nil
	}
	if decoded, err := url.QueryUnescape(raw); err == nil {
		raw = decoded
	}
	document := trustPolicyDocument{}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}
	trusts := make([]iamRoleTrust, 0)
	for _, statement := range document.Statement {
		if !strings.EqualFold(statement.Effect, "Allow") || !containsStringAction(statement.Action, trustAssumeActions()...) {
			continue
		}
		for _, principal := range trustPrincipals(statement.Principal) {
			trusts = append(trusts, iamRoleTrust{Role: role, Statement: statement, Principal: principal.Value, PrincipalType: principal.Type})
		}
	}
	return trusts
}

func trustPrincipals(raw json.RawMessage) []iamTrustPrincipal {
	if len(raw) == 0 {
		return nil
	}
	if string(raw) == `"*"` {
		return []iamTrustPrincipal{{Type: "public", Value: "*"}}
	}
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	principals := make([]iamTrustPrincipal, 0)
	for principalType, value := range values {
		for _, principal := range stringList(value) {
			if strings.TrimSpace(principal) == "" {
				continue
			}
			principals = append(principals, iamTrustPrincipal{Type: principalType, Value: principal})
		}
	}
	return principals
}

func trustAssumeActions() []string {
	return []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"}
}

func awsTrustPrincipal(value string, principalType string) (string, string) {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(strings.TrimSpace(principalType)) {
	case "public":
		return "public", "public"
	case "service", "federated":
		return "service_principal", trimmed
	}
	switch {
	case trimmed == "*" || strings.EqualFold(trimmed, "anonymous"):
		return "public", "public"
	case strings.Contains(trimmed, ":role/"):
		return "role", trimmed
	case strings.Contains(trimmed, ":user/"):
		return "user", trimmed
	case awsAccountPrincipalID(trimmed) != "":
		return "account", awsAccountPrincipalID(trimmed)
	case strings.Contains(trimmed, "@"):
		return "user", trimmed
	default:
		return "account", trimmed
	}
}

func trustExternal(accountID string, principal string) bool {
	trimmed := strings.TrimSpace(principal)
	if accountID == "" {
		return trimmed == "*"
	}
	if principalAccountID := awsAccountPrincipalID(trimmed); principalAccountID != "" {
		return principalAccountID != accountID
	}
	return trimmed == "*" || strings.Contains(trimmed, ":iam::") && !strings.Contains(trimmed, ":iam::"+accountID+":")
}

func trustExternalIDRequired(statement trustStatement) bool {
	for key, value := range statement.Condition {
		if strings.Contains(strings.ToLower(key), "externalid") || containsAny(strings.ToLower(fmt.Sprint(value)), "sts:externalid", "externalid") {
			return true
		}
	}
	return false
}

func containsStringAction(value any, expected ...string) bool {
	for _, action := range stringList(value) {
		for _, candidate := range expected {
			if stringActionMatches(action, candidate) {
				return true
			}
		}
	}
	return false
}

func policyDocumentActions(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if decoded, err := url.QueryUnescape(raw); err == nil {
		raw = decoded
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil
	}
	return sortedUniqueStrings(policyDocumentActionValues(document["Statement"]))
}

func policyDocumentActionValues(value any) []string {
	switch typed := value.(type) {
	case []any:
		values := make([]string, 0)
		for _, item := range typed {
			values = append(values, policyDocumentActionValues(item)...)
		}
		return values
	case map[string]any:
		if effect := strings.TrimSpace(fmt.Sprint(typed["Effect"])); effect != "" && !strings.EqualFold(effect, "Allow") {
			return nil
		}
		return stringList(typed["Action"])
	default:
		return nil
	}
}

func stringActionMatches(action string, expected string) bool {
	normalizedAction := strings.ToLower(strings.TrimSpace(action))
	normalizedExpected := strings.ToLower(strings.TrimSpace(expected))
	if normalizedAction == "" || normalizedExpected == "" {
		return false
	}
	if normalizedAction == "*" || normalizedAction == normalizedExpected {
		return true
	}
	matched, err := path.Match(normalizedAction, normalizedExpected)
	if err == nil && matched {
		return true
	}
	return false
}

func sortedUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func awsAccountPrincipalID(value string) string {
	trimmed := strings.TrimSpace(value)
	if isAWSAccountID(trimmed) {
		return trimmed
	}
	marker := ":iam::"
	index := strings.Index(trimmed, marker)
	if index < 0 || !strings.HasSuffix(trimmed, ":root") {
		return ""
	}
	rest := trimmed[index+len(marker):]
	accountID, _, _ := strings.Cut(rest, ":")
	if isAWSAccountID(accountID) {
		return accountID
	}
	return ""
}

func isAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if rendered := strings.TrimSpace(fmt.Sprint(item)); rendered != "" {
				values = append(values, rendered)
			}
		}
		return values
	default:
		if rendered := strings.TrimSpace(fmt.Sprint(value)); rendered != "" && rendered != "<nil>" {
			return []string{rendered}
		}
		return nil
	}
}

func securityGroupExposure(settings settings, group ec2types.SecurityGroup, permission ec2types.IpPermission, cidr string, permissionIndex int) awsResourceExposure {
	resourceID := firstNonEmpty(awssdk.ToString(group.SecurityGroupArn), awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName))
	exposureID := fmt.Sprintf("%s-%d-%s", firstNonEmpty(awssdk.ToString(group.GroupId), awssdk.ToString(group.GroupName)), permissionIndex, cidr)
	return awsResourceExposure{
		ResourceID:   resourceID,
		ResourceName: firstNonEmpty(awssdk.ToString(group.GroupName), resourceID),
		ExposureID:   sanitizeEventID(exposureID),
		SourceCIDR:   cidr,
		Protocol:     awssdk.ToString(permission.IpProtocol),
		PortRange:    portRange(permission.FromPort, permission.ToPort),
		Region:       settings.region,
		Scope:        firstNonEmpty(awssdk.ToString(group.VpcId), settings.accountID),
		Group:        group,
		Permission:   permission,
	}
}

func publicCIDR(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "0.0.0.0/0" || trimmed == "::/0"
}

func portRange(from *int32, to *int32) string {
	if from == nil && to == nil {
		return "all"
	}
	if from != nil && to != nil && *from == *to {
		return strconv.FormatInt(int64(*from), 10)
	}
	return fmt.Sprintf("%s-%s", int32String(from), int32String(to))
}

func int32String(value *int32) string {
	if value == nil {
		return "*"
	}
	return strconv.FormatInt(int64(*value), 10)
}

func ec2PageSize(limit int) int {
	if limit > 0 && limit < 5 {
		return 5
	}
	return limit
}

func assetMetadataPageSize(limit int) int {
	if limit <= 0 {
		return defaultPageSize
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func awsAssetTagMap(tags []resourcegroupstaggingapitypes.Tag) map[string]string {
	values := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := strings.TrimSpace(awssdk.ToString(tag.Key))
		if key == "" {
			continue
		}
		values[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
	}
	return values
}

func tagLookup(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}
	normalized := make(map[string]string, len(tags))
	for key, value := range tags {
		normalized[normalizeTagKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeTagKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeTagKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.Trim(value, "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func crownJewelFromTags(tags map[string]string) bool {
	if taggedBool(tagLookup(tags, "crown_jewel", "crown-jewel", "tier0", "tier_0", "tier-0", "business_critical", "business-critical")) {
		return true
	}
	switch normalizeTagKey(firstNonEmpty(tagLookup(tags, "criticality", "tier", "asset_criticality"), tagLookup(tags, "data_classification", "sensitivity"))) {
	case "crown_jewel", "tier0", "tier_0", "critical":
		return true
	default:
		return false
	}
}

func criticalityFromTags(tags map[string]string) string {
	if crownJewelFromTags(tags) {
		return "critical"
	}
	return ""
}

func taggedBool(value string) bool {
	switch normalizeTagKey(value) {
	case "1", "t", "true", "y", "yes", "enabled":
		return true
	default:
		return false
	}
}

func awsAssetMetadataIdentity(settings settings, arn string) (string, string, string, string) {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return "resource", strings.TrimSpace(arn), strings.TrimSpace(arn), settings.region
	}
	service := strings.ToLower(parts[2])
	region := firstNonEmpty(parts[3], settings.region)
	resource := strings.TrimSpace(parts[5])
	resourceType, resourceID := awsResourceTypeAndID(service, arn, resource)
	return resourceType, resourceID, awsResourceName(resource), region
}

func awsResourceTypeAndID(service string, arn string, resource string) (string, string) {
	switch service {
	case "ec2":
		return awsEC2ResourceTypeAndID(arn, resource)
	case "elasticloadbalancing":
		return awsELBResourceTypeAndID(arn, resource)
	case "cloudfront":
		if id, ok := strings.CutPrefix(resource, "distribution/"); ok {
			return "cloudfront_distribution", firstNonEmpty(arn, id)
		}
	case "s3":
		return "bucket", firstNonEmpty(arn, strings.TrimPrefix(resource, ":::"))
	case "rds":
		if before, after, ok := strings.Cut(resource, ":"); ok {
			return normalizeAWSResourceType(before), firstNonEmpty(arn, after)
		}
	case "lambda":
		if before, after, ok := strings.Cut(resource, ":"); ok {
			return normalizeAWSResourceType(before), firstNonEmpty(arn, after)
		}
	}
	resourceType := "resource"
	resourceID := resource
	if before, after, ok := strings.Cut(resource, "/"); ok {
		resourceType = normalizeAWSResourceType(before)
		resourceID = after
	} else if before, after, ok := strings.Cut(resource, ":"); ok {
		resourceType = normalizeAWSResourceType(before)
		resourceID = after
	}
	return resourceType, firstNonEmpty(resourceID, arn)
}

func awsEC2ResourceTypeAndID(arn string, resource string) (string, string) {
	resourceType, resourceID, ok := strings.Cut(resource, "/")
	if !ok {
		return normalizeAWSResourceType(resource), firstNonEmpty(arn, resource)
	}
	switch resourceType {
	case "security-group":
		return "security_group", firstNonEmpty(arn, resourceID)
	case "network-interface":
		return "network_interface", resourceID
	case "instance":
		return "ec2_instance", resourceID
	default:
		return normalizeAWSResourceType(resourceType), firstNonEmpty(resourceID, arn)
	}
}

func awsELBResourceTypeAndID(arn string, resource string) (string, string) {
	switch {
	case strings.HasPrefix(resource, "loadbalancer/app/"):
		return "application_load_balancer", arn
	case strings.HasPrefix(resource, "loadbalancer/net/"):
		return "network_load_balancer", arn
	case strings.HasPrefix(resource, "loadbalancer/"):
		return "load_balancer", arn
	case strings.HasPrefix(resource, "targetgroup/"):
		return "target_group", arn
	default:
		return "load_balancer", firstNonEmpty(arn, resource)
	}
}

func awsResourceName(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return ""
	}
	if idx := strings.LastIndexAny(resource, "/:"); idx >= 0 && idx+1 < len(resource) {
		return resource[idx+1:]
	}
	return resource
}

func firstTime(values ...*time.Time) time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func addTimeAttribute(attributes map[string]string, key string, value *time.Time) {
	if value == nil || value.IsZero() {
		return
	}
	attributes[key] = value.UTC().Format(time.RFC3339)
}

func isAdminPolicy(values ...string) bool {
	joined := strings.ToLower(strings.Join(values, " "))
	return containsAny(joined, "administratoraccess", "admin", "poweruser", "iamfullaccess")
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	return strings.ToLower(strings.TrimSpace(emailPattern.FindString(trimmed)))
}

func boolString(value bool) string { return strconv.FormatBool(value) }

func firstNonEmpty(values ...string) string {
	return textutil.FirstNonEmpty(values...)
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}
