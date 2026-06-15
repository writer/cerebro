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
	for _, family := range []string{familyActivityLog, familyAKSCluster, familyAppRoleAssignment, familyAppService, familyApplication, familyAssetMetadata, "cognitive_services_account", familyContainerRegistry, familyCosmosAccount, familyCredential, familyDirectoryAudit, familyDirectoryRoleAssign, familyEffectivePermission, familyFunctionApp, familyGroup, familyGroupMember, familyIAMRoleAssign, familyKeyVault, familyKeyVaultKey, familyKeyVaultSecret, familyManagedDisk, familyNetworkSecurityGrp, familyPublicIPAddress, familyResourceExposure, familyServicePrincipal, familySQLDatabase, familySQLServer, familyStorageAccount, familyUser, familyVirtualMachine, familyVirtualNetwork} {
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
