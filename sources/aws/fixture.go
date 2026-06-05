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
	for _, family := range []string{familyAccessKey, familyACMCertificate, familyAPIGatewayInteg, familyAPIGatewayRoute, familyAPIGatewayStage, familyAppRunnerService, familyAssetMetadata, familyAthenaDataCatalog, familyAthenaWorkgroup, familyBatchComputeEnv, familyBatchJobQueue, familyBackupPlan, familyBackupProtected, familyBackupRecoveryPoint, familyBackupVault, familyCloudFrontKeyGroup, familyCloudFrontOAC, familyCloudFrontPublicKey, familyCloudFrontRHP, familyCloudTrail, familyCloudWatchAlarm, familyCloudWatchLogGroup, familyDataSyncLocation, familyDataSyncTask, familyEBSSnapshot, familyEBSVolume, familyEC2Instance, familyECRRepository, familyECSService, familyECSTask, familyECSTaskDefinition, familyEKSCluster, familyEKSNodegroup, familyEKSFargateProfile, familyEKSPodIdentity, familyEffectivePermission, familyELBV2Listener, familyELBV2TargetGroup, familyEventBridgeArchive, familyEventBridgeBus, familyEventBridgePipe, familyEventBridgeRule, familyFirehoseDelivery, familyGAEndpointGroup, familyGAListener, familyGlobalAccelerator, familyGlueCrawler, familyGlueDatabase, familyGlueJob, familyGlueTable, familyIAMGroup, familyIAMMembership, familyIAMRole, familyIAMRoleAssign, familyIAMRoleTrust, familyIAMUser, familyIdentityStoreGroup, familyIdentityStoreMember, familyIdentityStoreUser, familyKinesisStream, familyKMSKey, familyLakeFormationLFTag, familyLakeFormationPerm, familyLakeFormationRes, familyLambdaFunction, familyMSKCluster, familyOrganizationsAcct, familyOrganizationsOU, familyOrganizationsPolicy, familyOrganizationsRoot, familyPublicEndpoint, familyRDSInstance, familyResourceExposure, familyRoute53ResolverEndpoint, familyRoute53ResolverRule, familyS3AccessPoint, familyS3Bucket, familyS3MultiRegionAccessPoint, familySchedulerSchedule, familySchedulerGroup, familySecret, familySNSTopic, familySQSQueue, familySSMAssociation, familySSMDocument, familySSMManagedInstance, familySSMParameter, familySSOAssignment, familySSOInstance, familySSOPermissionSet, familyStepFunctionActivity, familyStepFunctionStateMachine, familyVPCLatticeListener, familyVPCLatticeService, familyVPCLatticeTG} {
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
