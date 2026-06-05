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
	for _, family := range []string{familyAccessAnalyzer, familyAccessKey, familyACMCertificate, familyAPIGatewayInteg, familyAPIGatewayRoute, familyAPIGatewayStage, familyAppRunnerService, familyAssetMetadata, familyAthenaDataCatalog, familyAthenaWorkgroup, familyBatchComputeEnv, familyBatchJobQueue, familyBackupPlan, familyBackupProtected, familyBackupRecoveryPoint, familyBackupVault, familyCloudFrontKeyGroup, familyCloudFrontOAC, familyCloudFrontPublicKey, familyCloudFrontRHP, familyCloudTrail, familyCloudWatchAlarm, familyCloudWatchLogGroup, familyConfigRecorder, familyDataSyncLocation, familyDataSyncTask, familyDocDBCluster, familyDocDBInstance, familyEBSSnapshot, familyEBSVolume, familyEC2Instance, familyECRRepository, familyECSService, familyECSTask, familyECSTaskDefinition, familyEKSCluster, familyEKSNodegroup, familyEKSFargateProfile, familyEKSPodIdentity, familyElastiCacheCluster, familyElastiCacheReplica, familyElastiCacheSubnet, familyEffectivePermission, familyELBV2Listener, familyELBV2TargetGroup, familyEventBridgeArchive, familyEventBridgeBus, familyEventBridgePipe, familyEventBridgeRule, familyFirehoseDelivery, familyFSxFileSystem, familyGAEndpointGroup, familyGAListener, familyGlobalAccelerator, familyGlueCrawler, familyGlueDatabase, familyGlueJob, familyGlueTable, familyGuardDutyFinding, familyIAMGroup, familyIAMMembership, familyIAMRole, familyIAMRoleAssign, familyIAMRoleTrust, familyIAMUser, familyIdentityStoreGroup, familyIdentityStoreMember, familyIdentityStoreUser, familyInspector2Finding, familyKinesisStream, familyKMSKey, familyLakeFormationLFTag, familyLakeFormationPerm, familyLakeFormationRes, familyLambdaFunction, familyMacie2Finding, familyMSKCluster, familyNeptuneCluster, familyNeptuneInstance, familyNetworkFirewall, familyOpenSearchDomain, familyOpenSearchServerlessCollection, familyOpenSearchServerlessPolicy, familyOrganizationsAcct, familyOrganizationsOU, familyOrganizationsPolicy, familyPublicEndpoint, familyRDSInstance, familyRedshiftCluster, familyResourceExposure, familyRoute53ResolverEndpoint, familyRoute53ResolverRule, familyS3AccessPoint, familyS3Bucket, familyS3MultiRegionAccessPoint, familySchedulerSchedule, familySchedulerGroup, familySecret, familySecurityHubFinding, familySNSTopic, familySQSQueue, familySSMAssociation, familySSMDocument, familySSMManagedInstance, familySSMParameter, familySSOAssignment, familySSOInstance, familySSOPermissionSet, familyStepFunctionActivity, familyStepFunctionStateMachine, familyVPCLatticeListener, familyVPCLatticeService, familyVPCLatticeTG, familyWAFV2WebACL, familyOrganizationsRoot} {
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
