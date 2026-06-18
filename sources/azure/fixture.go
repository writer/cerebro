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
	for _, family := range []string{familyActivityLog, "activity_log_alert", familyAKSCluster, familyAKSNodePool, familyAppRoleAssignment, familyAppService, familyApplication, "application_container", "application_gateway", "application_insight", familyAuthorizationPolicy, familyAssetMetadata, "cognitive_services_account", "cognitive_services_deployment", familyContainerRegistry, familyCosmosAccount, "cosmos_postgresql", "cosmos_postgresql_firewall_rule", familyCredential, "databricks_workspace", "defender_config", "diagnostic_setting", "diagnostic_setting_resource", familyDirectoryAudit, familyDirectoryRoleAssign, familyEffectivePermission, familyFunctionApp, familyGroup, familyGroupMember, familyIAMRoleAssign, familyKeyVault, familyKeyVaultKey, familyKeyVaultSecret, "load_balancer", "log_alert", "machine_learning_compute", "machine_learning_workspace", familyManagedDisk, "metric_alert_rule", familyMySQLServer, familyNetworkSecurityGrp, "policy_assignment", "postgresql_firewall_rule", "postgresql_server", familyPublicIPAddress, familyResourceExposure, "role", "route_table", "security_contact", "security_setting", "server_vulnerability", "server_vulnerability_subassessment", familyServicePrincipal, familySQLDatabase, "sql_managed_instance", "sql_managed_instance_tde", familySQLServer, "sql_server_on_virtual_machine", familyStorageAccount, familyStorageContainer, familyStorageQueue, familySubnet, "synapse_sql_pool", familyUser, familyVirtualMachine, "virtual_machine_extension", "virtual_machine_scale_set", "virtual_machine_scale_set_instance", familyVirtualNetwork} {
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
