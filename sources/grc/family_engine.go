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

var familyEndpoints = []struct {
	name grcFamily
	path string
}{
	{familyFramework, "/v1/frameworks"}, {familyControl, "/v1/controls"}, {familyControlTest, "/v1/tests"},
	{familyPolicy, "/v1/policies"}, {familyDocument, "/v1/documents"}, {familyContract, "/v1/contracts"},
	{familyRegulatoryNotification, "/v1/regulatory-notifications"}, {familyRecoveryObjective, "/v1/recovery-objectives"},
	{familyAuthorizationPackage, "/v1/authorization-packages"}, {familyPOAMItem, "/v1/poam-items"},
	{familyTrainingAttestation, "/v1/training-attestations"}, {familyDiscoveredVendor, "/v1/discovered-vendors"},
	{familyEventLog, "/v1/event-logs"}, {familyGroup, "/v1/groups"}, {familyVendorRiskAttribute, "/v1/vendor-risk-attributes"},
	{familyVendor, "/v1/vendors"}, {familyVulnerability, "/v1/vulnerabilities"},
	{familyVulnerabilityRemediation, "/v1/vulnerability-remediations"}, {familyVulnerableAsset, "/v1/vulnerable-assets"},
	{familyMonitoredComputer, "/v1/monitored-computers"},
	{familyRiskScenario, "/v1/risk-scenarios"}, {familyPerson, "/v1/people"}, {familyUser, "/v1/users"},
	{familyIntegration, "/v1/integrations"},
}

// Source is the provider-neutral GRC source. Provider-specific APIs are kept
// behind drivers; emitted event kinds stay canonical grc.*.

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := make([]sourcecdk.Family[settings], 0, len(familyEndpoints))
	for _, endpoint := range familyEndpoints {
		families = append(families, s.family(endpoint.name, endpoint.path))
	}
	return sourcecdk.NewFamilyEngine(s.parseSettings, func(settings settings) string { return string(settings.family) }, families...)
}

func (s *Source) family(name grcFamily, path string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: string(name),
		Check: func(ctx context.Context, settings settings) error {
			_, _, err := s.list(ctx, settings, path, "", 1)
			if err != nil {
				return fmt.Errorf("grc %s for %s: %w", string(name), settings.provider, err)
			}
			return nil
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			records, _, err := s.list(ctx, settings, path, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("grc %s for %s: %w", string(name), settings.provider, err)
			}
			return urnsFor(settings, name, records)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := s.list(ctx, settings, path, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("grc %s for %s: %w", string(name), settings.provider, err)
			}
			return pullFromRecords(settings, name, records, next)
		},
	}
}
