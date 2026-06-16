package azure

import (
	"context"
	"embed"
	"fmt"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed testdata/*.json
var fixtureFS embed.FS

// NewFixture constructs the deterministic Azure source used by tests.
func NewFixture() (sourcecdk.Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	families := []sourcecdk.FixtureFamily{}
	for _, family := range []string{familyActivityLog, "activity_log_alert", familyAKSCluster, familyAppRoleAssignment, familyAppService, familyApplication, "application_gateway", "application_insight", familyAssetMetadata, "cognitive_services_account", familyContainerRegistry, familyCosmosAccount, familyCredential, "databricks_workspace", familyDirectoryAudit, familyDirectoryRoleAssign, familyEffectivePermission, familyFunctionApp, familyGroup, familyGroupMember, familyIAMRoleAssign, familyKeyVault, familyKeyVaultKey, familyKeyVaultSecret, "load_balancer", "log_alert", "machine_learning_workspace", familyManagedDisk, "metric_alert_rule", familyNetworkSecurityGrp, familyPublicIPAddress, familyResourceExposure, "role", "route_table", "security_contact", familyServicePrincipal, familySQLDatabase, "sql_managed_instance", familySQLServer, familyStorageAccount, familyUser, familyVirtualMachine, "virtual_machine_scale_set", familyVirtualNetwork} {
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
		return "", fmt.Errorf("parse azure fixture settings: %w", err)
	}
	return settings.family, nil
}
