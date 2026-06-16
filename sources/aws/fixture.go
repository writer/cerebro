package aws

import (
	"context"
	"embed"
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic AWS source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{familyAccessAnalyzer, familyAccessKey, familyACMCertificate, familyAPIGatewayInteg, familyAPIGatewayMethod, familyAPIGatewayRestAPI, familyAPIGatewayRoute, familyAPIGatewayStage, familyAppRunnerService, familyAssetMetadata, familyAthenaDataCatalog, familyAthenaWorkgroup, familyBatchComputeEnv, familyBatchJobQueue, familyBackupPlan, familyBackupProtected, familyBackupRecoveryPoint, familyBackupVault, familyCodeBuildProject, familyCodeBuildSourceCredential, familyCloudFrontDistribution, familyCloudFrontKeyGroup, familyCloudFrontOAC, familyCloudFrontPublicKey, familyCloudFrontRHP, familyCloudTrail, familyCloudWatchAlarm, familyCloudWatchLogGroup, familyConfigRecorder, familyDataSyncLocation, familyDataSyncTask, familyDynamoDBBackup, familyDynamoDBStream, familyDynamoDBTable, familyEBSSnapshot, familyEBSVolume, familyEC2EBSEncryptionByDefault, familyEC2AMI, familyEC2Instance, familyVPC, familySubnet, familySecurityGroup, familyRouteTable, familyNetworkACL, familyInternetGateway, familyNATGateway, familyVPCFlowLog, familyVPCEndpoint, familyECRPublicRepository, familyECRRepository, familyECSService, familyECSTask, familyECSTaskDefinition, familyEFSAccessPoint, familyEFSFileSystem, familyEKSCluster, familyEKSNodegroup, familyEKSFargateProfile, familyEKSPodIdentity, familyEffectivePermission, familyELBV2LoadBalancer, familyELBV2Listener, familyELBV2TargetGroup, familyEventBridgeArchive, familyEventBridgeBus, familyEventBridgePipe, familyEventBridgeRule, familyFirehoseDelivery, familyGAEndpointGroup, familyGAListener, familyGlobalAccelerator, familyGlueCrawler, familyGlueDatabase, familyGlueJob, familyGlueTable, familyGuardDutyDetector, familyGuardDutyFinding, "iam_account_password_policy", "iam_account_summary", "iam_credential_report", familyIAMGroup, familyIAMMembership, familyIAMPolicy, familyIAMRole, familyIAMRoleAssign, familyIAMRoleTrust, familyIAMSAMLProvider, familyIAMUser, familyIdentityCenterAssignment, familyIdentityCenterPermission, familyIdentityStoreGroup, familyIdentityStoreMember, familyIdentityStoreUser, familyInspector2Finding, familyKinesisStream, familyKMSKey, familyLakeFormationLFTag, familyLakeFormationPerm, familyLakeFormationRes, familyLambdaFunction, familyMacie2Finding, familyMSKCluster, familyNetworkFirewall, familyOrganizationsAcct, familyOrganizationsOU, familyOrganizationsPolicy, familyPublicEndpoint, familyRDSDBSnapshot, familyRDSInstance, familyResourceExposure, familyRoute53ResolverEndpoint, familyRoute53ResolverRule, familyS3AccessPoint, familyS3Bucket, familyS3MultiRegionAccessPoint, familySchedulerSchedule, familySchedulerGroup, familySecret, familySecurityHubFinding, familySNSTopic, familySQSQueue, familySSMAssociation, familySSMDocument, familySSMManagedInstance, familySSMParameter, familySSOAssignment, familySSOInstance, familySSOPermissionSet, familyStepFunctionActivity, familyStepFunctionStateMachine, familyVPCLatticeListener, familyVPCLatticeService, familyVPCLatticeTG, familyWAFV2WebACL, familyOrganizationsRoot, familyElastiCacheCluster, familyElastiCacheReplicationGroup, familyElastiCacheSubnetGroup, familyFSxFileSystem, familyOpenSearchDomain, familyOpenSearchServerlessCollection, familyOpenSearchServerlessSecurityPolicy, familyDocDBCluster, familyDocDBInstance, familyNeptuneCluster, familyNeptuneInstance, familyRedshiftCluster} {
		urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover_"+family+".json")
		if err != nil {
			return nil, err
		}
		events, err := sourcecdk.LoadFixtureEvents(fixtureFS, "testdata/read_"+family+".json")
		if err != nil {
			return nil, err
		}
		families = append(families, sourcecdk.FixtureFamily{Name: family, URNs: urns, Events: events})
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          spec,
		DefaultFamily: defaultFamily,
		Check:         checkFixtureConfig,
		ResolveFamily: resolveFixtureFamily,
		Families:      families,
	})
}

func checkFixtureConfig(_ context.Context, cfg sourcecdk.Config) error {
	_, err := parseSettings(cfg)
	return err
}

func resolveFixtureFamily(cfg sourcecdk.Config) (string, error) {
	settings, err := parseSettings(cfg)
	if err != nil {
		return "", fmt.Errorf("parse aws fixture settings: %w", err)
	}
	return settings.family, nil
}
