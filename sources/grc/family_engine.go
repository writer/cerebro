package grc

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	defaultFamily           = familyControlTest
	familyFramework         = "framework"
	familyControl           = "control"
	familyControlTest       = "control_test"
	familyPolicy            = "policy"
	familyDocument          = "document"
	familyVendor            = "vendor"
	familyVulnerability     = "vulnerability"
	familyVulnerableAsset   = "vulnerable_asset"
	familyMonitoredComputer = "monitored_computer"
	familyRiskScenario      = "risk_scenario"
	familyPerson            = "person"
	familyUser              = "user"
	familyIntegration       = "integration"
)

const (
	familyContract                 = "contract"
	familyRegulatoryNotification   = "regulatory_notification"
	familyRecoveryObjective        = "recovery_objective"
	familyAuthorizationPackage     = "authorization_package"
	familyPOAMItem                 = "poam_item"
	familyTrainingAttestation      = "training_attestation"
	familyDiscoveredVendor         = "discovered_vendor"
	familyEventLog                 = "event_log"
	familyGroup                    = "group"
	familyVendorRiskAttribute      = "vendor_risk_attribute"
	familyVulnerabilityRemediation = "vulnerability_remediation"
)

// Source is the provider-neutral GRC source. Provider-specific APIs are kept
// behind drivers; emitted event kinds stay canonical grc.*.

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := make([]sourcecdk.Family[settings], 0, len(grcFamilyDescriptors))
	for _, descriptor := range grcFamilyDescriptors {
		families = append(families, s.family(descriptor))
	}
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string { return string(settings.family) }, families...)
}

func (s *Source) family(descriptor grcFamilyDescriptor) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: string(descriptor.Family),
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, descriptor.Endpoint, "", 1)
			if err != nil {
				return fmt.Errorf("grc %s for %s: %w", string(descriptor.Family), settings.provider, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, descriptor.Endpoint, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("grc %s for %s: %w", string(descriptor.Family), settings.provider, err)
			}
			return urnsFor(settings, descriptor.Family, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, descriptor.Endpoint, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("grc %s for %s: %w", string(descriptor.Family), settings.provider, err)
			}
			return pullFromRecords(settings, descriptor.Family, records, next)
		},
	}
}
