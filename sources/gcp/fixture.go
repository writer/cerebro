package gcp

import (
	"context"
	"embed"
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic GCP source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{familyAssetMetadata, familyAIDataset, familyAIEndpoint, familyArtifactImage, familyArtifactRepo, familyAudit, familyBigQueryDataset, familyBigQueryTable, familyBigtableInstance, familyBigtableTable, familyCertificateManagerCertificate, familyCertificateManagerCertificateMap, familyCertificateManagerCertificateMapEntry, familyCertificateManagerDNSAuthorization, familyCloudFunction, familyCloudIDSEndpoint, familyCloudSchedulerJob, familyCloudRunRevision, familyCloudRunService, familyCloudSQLDatabase, familyCloudSQLInstance, familyCloudSQLUser, familyContainerRegistry, familyContainerVuln, familyComputeAddress, familyComputeBackendBucket, familyComputeBackendService, familyComputeDisk, familyComputeExternalVPNGateway, familyComputeFirewall, familyComputeForwardingRule, familyComputeHealthCheck, familyComputeInstance, familyComputeInstanceGroup, familyComputeInstanceGroupMgr, familyComputeInstanceTemplate, familyComputeInterconnect, familyComputeInterconnectAttachment, familyComputeNetworkEndpointGroup, familyComputeNetworkFirewallPolicy, familyComputeNetwork, familyComputePacketMirroring, familyComputeRoute, familyComputeRouter, familyComputeSecurityPolicy, familyComputeSSLCertificate, familyComputeSSLPolicy, familyComputeSubnetwork, familyComputeTargetGRPCProxy, familyComputeTargetHTTPProxy, familyComputeTargetHTTPSProxy, familyComputeTargetSSLProxy, familyComputeTargetTCPProxy, familyComputeTargetVPNGateway, familyComputeURLMap, familyComputeVPNGateway, familyComputeVPNTunnel, familyDNSManagedZone, familyDNSRecordSet, familyEffectivePermission, familyGCSBucket, familyGCSObject, familyGKECluster, familyGKENodePool, familyGroup, familyGroupMember, familyKMSKey, familyLoggingMetric, familyLoggingSink, familyMonitoringAlertPolicy, familyMonitoringNotificationChannel, familyOrgPolicy, familyPubSubSubscription, familyPubSubTopic, familyResourceExposure, familyResourceProject, familyRoleAssign, familySAImpersonation, familySecret, familySecretVersion, familySecurityCenterFinding, familyServiceAcct, familyServiceUsageService, familySpannerDatabase, familySpannerInstance, familyVPCAccessConnector, familyWorkloadIdentityPool, familyWorkloadIdentityProvider, familySAKey} {
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
		return "", fmt.Errorf("parse gcp fixture settings: %w", err)
	}
	return settings.family, nil
}
