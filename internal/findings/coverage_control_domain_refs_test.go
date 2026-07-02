package findings

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

var intentionallyUnmappedCoverageControlDomains = map[string]struct{}{
	"source_operations": {},
}

func TestCoverageControlDomainRefsLoad(t *testing.T) {
	if coverageControlDomainRefSet.Version == "" {
		t.Fatal("coverage control domain refs version is empty")
	}
	for _, tc := range []struct {
		domain    string
		framework string
		control   string
	}{
		{domain: "identity_access", framework: "SOC 2", control: "CC6.1"},
		{domain: "authorization", framework: "NIST 800-53 r5", control: "AC-3"},
		{domain: "change_management", framework: "SOC 2", control: "CC8.1"},
		{domain: "device_posture", framework: "NIST 800-53 r5", control: "SI-3"},
	} {
		refs := controlRefsForControlDomains([]string{tc.domain})
		if len(refs) == 0 {
			t.Fatalf("%s produced no control refs", tc.domain)
		}
		found := false
		for _, ref := range refs {
			if ref.FrameworkName == tc.framework && ref.ControlID == tc.control {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s refs missing %s %s: %+v", tc.domain, tc.framework, tc.control, refs)
		}
	}
}

func TestEffectiveCoverageControlRefsUnionsDerived(t *testing.T) {
	dimension := sourcecdk.CoverageDimension{
		ID:             "datasets",
		ControlDomains: []string{"data_protection"},
		ControlRefs: []sourcecdk.CoverageControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC1.1"},
		},
	}
	refs := effectiveCoverageControlRefs(dimension)
	var hasDeclared, hasDerived bool
	for _, ref := range refs {
		if ref.FrameworkName == "SOC 2" && ref.ControlID == "CC1.1" {
			hasDeclared = true
		}
		if ref.FrameworkName == "NIST 800-53 r5" && ref.ControlID == "SC-28" {
			hasDerived = true
		}
	}
	if !hasDeclared || !hasDerived {
		t.Fatalf("effectiveCoverageControlRefs union incomplete: declared=%v derived=%v refs=%+v", hasDeclared, hasDerived, refs)
	}
}

func TestSourceCoverageDerivedRefsAreSourceBounded(t *testing.T) {
	detection := PublicDetection{
		ID:                        "gcp-storage-bucket-encryption-disabled",
		SourceID:                  "gcp",
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "encryption_configuration"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "NIST 800-53 r5", ControlID: "SC-28"},
		},
	}
	loggingDimension := func(id string) sourcecdk.CoverageDimension {
		return sourcecdk.CoverageDimension{
			ID:             id,
			Type:           "entity_family",
			Title:          id,
			Support:        sourcecdk.CoverageSupportSupported,
			HighValue:      true,
			EvidenceTypes:  []string{"encryption_configuration"},
			ControlDomains: []string{"data_protection"},
		}
	}
	contracts := []sourcecdk.CoverageContract{
		{SourceID: "gcp", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("buckets")}},
		{SourceID: "github", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("repositories")}},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) == 0 {
		t.Fatal("expected derived source coverage for the detection's own source")
	}
	for _, ref := range refs {
		if ref.SourceID != "gcp" {
			t.Fatalf("derived coverage crossed sources: got %q, want only gcp", ref.SourceID)
		}
	}
}

func TestSourceCoverageDerivedRefsRequireDimensionOrEvidenceMatch(t *testing.T) {
	detection := PublicDetection{
		ID:                        "aws-s3-bucket-no-public-access",
		Name:                      "S3 Bucket Public Access",
		SourceID:                  policyRuleSourceID,
		Tags:                      []string{"aws", "policy", "s3"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "cloud_configuration"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{
			{
				ID:             "iam_credential_report",
				Type:           "entity_family",
				Families:       []string{"iam_credential_report"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
			},
			{
				ID:             "s3_bucket",
				Type:           "entity_family",
				Families:       []string{"s3_bucket"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"network_exposure"},
				ControlDomains: []string{"network_security"},
			},
		},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only the matching S3 dimension: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "s3_bucket" {
		t.Fatalf("DimensionID = %q, want s3_bucket", refs[0].DimensionID)
	}
}

func TestSourceCoverageExplicitRefsCanMatchSourceWithoutDimensionOrEvidence(t *testing.T) {
	detection := PublicDetection{
		ID:       "aws-access-baseline",
		SourceID: "aws",
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "iam_credential_report",
			Type:          "entity_family",
			Families:      []string{"iam_credential_report"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.6",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want explicit control ref match: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "iam_credential_report" {
		t.Fatalf("DimensionID = %q, want iam_credential_report", refs[0].DimensionID)
	}
}

func TestSourceCoveragePrefersSpecificDimensionOverSourceOnlyExactControl(t *testing.T) {
	detection := PublicDetection{
		ID:       "github-webhook-modified",
		SourceID: "github",
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "source_control_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "github",
		Dimensions: []sourcecdk.CoverageDimension{
			{
				ID:            "programmatic_credentials",
				Type:          "app_entitlement",
				Families:      []string{"personal_access_token"},
				Support:       sourcecdk.CoverageSupportPartial,
				EvidenceTypes: []string{"identity_configuration"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
			{
				ID:            "webhooks",
				Type:          "app_entitlement",
				Families:      []string{"webhook"},
				Support:       sourcecdk.CoverageSupportPartial,
				EvidenceTypes: []string{"change_management"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
		},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only webhook-specific coverage: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "webhooks" {
		t.Fatalf("DimensionID = %q, want webhooks", refs[0].DimensionID)
	}
}

func TestPolicySourceCoverageIgnoresGenericAuditFamilyBoilerplate(t *testing.T) {
	detection := PublicDetection{
		ID:          "github-actions-dangerous-trigger",
		Description: "Flags failed resource-state evidence. Audit impact: source control evidence may not satisfy controls. Workflow uses pull_request_target.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"github", "policy"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "source_control_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "github",
		Dimensions: []sourcecdk.CoverageDimension{
			{
				ID:            "organization_authentication_policy",
				Type:          "entity_family",
				Families:      []string{"audit"},
				Support:       sourcecdk.CoverageSupportPartial,
				EvidenceTypes: []string{"identity_configuration"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
			{
				ID:            "actions_workflow_content",
				Type:          "entity_family",
				Families:      []string{"pull_request_target"},
				Support:       sourcecdk.CoverageSupportPartial,
				EvidenceTypes: []string{"change_management"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
		},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only workflow content coverage: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "actions_workflow_content" {
		t.Fatalf("DimensionID = %q, want actions_workflow_content", refs[0].DimensionID)
	}
}

func TestPolicySourceCoverageExplicitRefsRequireDimensionMatch(t *testing.T) {
	detection := PublicDetection{
		ID:       "aws-load-balancer-network-posture",
		Name:     "AWS Load Balancer Network Posture",
		SourceID: policyRuleSourceID,
		Tags:     []string{"aws", "policy"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "cloud_configuration",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "aws",
		Dimensions: []sourcecdk.CoverageDimension{
			{
				ID:            "s3_bucket",
				Type:          "entity_family",
				Families:      []string{"s3_bucket"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"network_exposure"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
			{
				ID:            "unrelated_cloud_configuration",
				Type:          "entity_family",
				Families:      []string{"unrelated"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"cloud_configuration"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
			{
				ID:            "elbv2_load_balancer",
				Type:          "entity_family",
				Families:      []string{"load_balancer"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"network_exposure"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			},
		},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only the named load balancer dimension: %#v", len(refs), refs)
	}
	if refs[0].DimensionID != "elbv2_load_balancer" {
		t.Fatalf("DimensionID = %q, want elbv2_load_balancer", refs[0].DimensionID)
	}
}

func TestPolicySourceCoverageRejectsConflictingCloudProviderDimension(t *testing.T) {
	detection := PublicDetection{
		ID:                        "azure-nsg-admin-port",
		Name:                      "NSG Allows Admin Ports from Internet",
		Description:               "Flags failed resource-state evidence for azure network security group.",
		SourceID:                  policyRuleSourceID,
		Tags:                      []string{"azure", "nsg", "policy"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{EvidenceType: "cloud_configuration"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
		},
	}
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID: "aws",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:            "security_group",
				Type:          "entity_family",
				Families:      []string{"security_group"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"network_exposure"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			}},
		},
		{
			SourceID: "azure",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:            "network_security_group",
				Type:          "entity_family",
				Families:      []string{"network_security_group", "nsg"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"network_exposure"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			}},
		},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want only azure network security group: %#v", len(refs), refs)
	}
	if refs[0].SourceID != "azure" || refs[0].DimensionID != "network_security_group" {
		t.Fatalf("SourceCoverageRefs[0] = %#v, want azure/network_security_group", refs[0])
	}
}

func TestPolicySourceCoverageRejectsConflictingIdentityProviderDimension(t *testing.T) {
	detection := PublicDetection{
		ID:          "m365-guest-admin",
		Name:        "Microsoft 365 Guest User with Admin Role",
		Description: "Flags failed M365 identity evidence for a guest admin role.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"m365", "identity", "admin"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "collaboration_control",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "okta",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "admin_roles",
			Type:          "relationship",
			Families:      []string{"admin_role"},
			Support:       sourcecdk.CoverageSupportPartial,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.2",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no cross-provider identity coverage", refs)
	}
}

func TestPolicySourceCoverageAllowsGenericIdentityEvidenceProviders(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-privileged-account-without-mfa",
		Name:        "Privileged Identity Without MFA",
		Description: "Flags failed identity evidence for privileged accounts with no MFA factor.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"identity", "mfa", "privileged-access"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_configuration",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "PCI DSS v4.0.1", ControlID: "8.3"},
		},
	}
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID: "okta",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:             "authenticators",
				Type:           "entity_family",
				Families:       []string{"authenticator", "mfa"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
			}},
		},
		{
			SourceID: "google_workspace",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:             "mfa_posture",
				Type:           "app_entitlement",
				Families:       []string{"mfa", "two_step_verification"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
			}},
		},
		{
			SourceID: "aws",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:             "iam_credential_report",
				Type:           "entity_family",
				Families:       []string{"mfa"},
				Support:        sourcecdk.CoverageSupportSupported,
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
			}},
		},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	got := make([]string, 0, len(refs))
	for _, ref := range refs {
		got = append(got, ref.SourceID+"/"+ref.DimensionID)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "google_workspace/mfa_posture,okta/authenticators" {
		t.Fatalf("SourceCoverageRefs = %v, want generic identity providers only", got)
	}
}

func TestSourceCoverageCapKeepsSupportedRefsOverPartialTies(t *testing.T) {
	detection := PublicDetection{
		ID:          "gcp-sa-impersonation",
		Name:        "GCP service accounts impersonation",
		Description: "Flags GCP service accounts impersonation risk.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"gcp", "iam", "impersonation", "service-accounts"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
		},
	}
	partialDimensions := make([]sourcecdk.CoverageDimension, 0, maxPublicDetectionSourceCoverageRefs)
	for i := 0; i < maxPublicDetectionSourceCoverageRefs; i++ {
		partialDimensions = append(partialDimensions, sourcecdk.CoverageDimension{
			ID:        "service_accounts_" + strconv.Itoa(i),
			Type:      "entity_family",
			Families:  []string{"service_accounts"},
			Support:   sourcecdk.CoverageSupportPartial,
			HighValue: true,
			ControlRefs: []sourcecdk.CoverageControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			},
		})
	}
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID:   "elevenlabs",
			Dimensions: partialDimensions,
		},
		{
			SourceID: "okta",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "support_access_events",
				Type:      "audit_event",
				Families:  []string{"impersonation", "support_access"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.2",
				}},
			}},
		},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != maxPublicDetectionSourceCoverageRefs {
		t.Fatalf("len(SourceCoverageRefs) = %d, want capped set %d", len(refs), maxPublicDetectionSourceCoverageRefs)
	}
	for _, ref := range refs {
		if ref.SourceID == "okta" && ref.DimensionID == "support_access_events" {
			return
		}
	}
	t.Fatalf("SourceCoverageRefs omitted supported okta/support_access_events: %#v", refs)
}

func TestSourceCoverageCapKeepsLifecycleRefsForInactiveIdentityDetections(t *testing.T) {
	detection := PublicDetection{
		ID:          "grc-inactive-identity-active-access",
		Name:        "Inactive GRC Identity Still Has Active Access",
		Description: "Detect inactive users whose identity still bridges to active access.",
		SourceID:    "grc",
		Tags:        []string{"identity", "offboarding"},
		EventKinds:  []string{"grc.user", "okta.user"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
		},
	}
	genericUserDimensions := make([]sourcecdk.CoverageDimension, 0, maxPublicDetectionSourceCoverageRefs)
	for i := 0; i < maxPublicDetectionSourceCoverageRefs; i++ {
		genericUserDimensions = append(genericUserDimensions, sourcecdk.CoverageDimension{
			ID:        "users_" + strconv.Itoa(i),
			Type:      "entity_family",
			Families:  []string{"user"},
			Support:   sourcecdk.CoverageSupportSupported,
			HighValue: true,
			ControlRefs: []sourcecdk.CoverageControlRef{
				{FrameworkName: "SOC 2", ControlID: "CC6.2"},
				{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
			},
		})
	}
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID:   "alpha",
			Dimensions: genericUserDimensions,
		},
		{
			SourceID: "okta",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "user_lifecycle",
				Type:      "lifecycle_state",
				Families:  []string{"deprovisioned", "suspended", "terminated_account", "user"},
				Support:   sourcecdk.CoverageSupportPartial,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{
					{FrameworkName: "SOC 2", ControlID: "CC6.2"},
					{FrameworkName: "SOC 2", ControlID: "CC6.6"},
					{FrameworkName: "ISO 27001:2022", ControlID: "A.5.16"},
					{FrameworkName: "ISO 27001:2022", ControlID: "A.5.18"},
				},
			}},
		},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != maxPublicDetectionSourceCoverageRefs {
		t.Fatalf("len(SourceCoverageRefs) = %d, want capped set %d", len(refs), maxPublicDetectionSourceCoverageRefs)
	}
	if !sourceCoverageRefsContain(refs, "okta", "user_lifecycle") {
		t.Fatalf("SourceCoverageRefs omitted okta/user_lifecycle for inactive identity detection: %#v", refs)
	}
}

func TestSourceCoverageCapKeepsAuditCoverageWhenAddingNewProvider(t *testing.T) {
	detection := PublicDetection{
		ID:          "container-root-user",
		Name:        "Container Running as Root",
		Description: "Audit impact. Checks whether containers are not running as root user.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"container", "root", "user"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.6"},
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "CIS Controls v8", ControlID: "4"},
		},
	}
	contracts := make([]sourcecdk.CoverageContract, 0, maxPublicDetectionSourceCoverageRefs+1)
	for i := 0; i < maxPublicDetectionSourceCoverageRefs-2; i++ {
		contracts = append(contracts, sourcecdk.CoverageContract{
			SourceID: "aaa" + strconv.Itoa(i),
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "users",
				Type:      "entity_family",
				Families:  []string{"user"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			}},
		})
	}
	contracts = append(contracts,
		sourcecdk.CoverageContract{
			SourceID: "linear",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "users",
				Type:      "entity_family",
				Families:  []string{"user"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.6",
				}},
			}},
		},
		sourcecdk.CoverageContract{
			SourceID: "kolide",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "checks",
				Type:      "lifecycle_state",
				Families:  []string{"check"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "CIS Controls v8",
					ControlID:     "4",
				}},
			}},
		},
		sourcecdk.CoverageContract{
			SourceID: "okta",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "audit_events",
				Type:      "audit_event",
				Families:  []string{"audit"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC7.1",
				}},
			}},
		},
	)

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != maxPublicDetectionSourceCoverageRefs {
		t.Fatalf("len(SourceCoverageRefs) = %d, want capped set %d", len(refs), maxPublicDetectionSourceCoverageRefs)
	}
	if !sourceCoverageRefsContain(refs, "kolide", "checks") {
		t.Fatalf("SourceCoverageRefs omitted kolide/checks: %#v", refs)
	}
	if !sourceCoverageRefsContain(refs, "okta", "audit_events") {
		t.Fatalf("SourceCoverageRefs omitted okta/audit_events: %#v", refs)
	}
}

func TestSourceCoverageAuditPreservationDoesNotDisplaceLifecycleRefs(t *testing.T) {
	detection := PublicDetection{
		ID:          "lifecycle-audit-pressure",
		Name:        "Identity Lifecycle Audit Pressure",
		Description: "Inactive users with audit evidence pressure.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"identity", "inactive", "audit"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
		},
	}
	contracts := make([]sourcecdk.CoverageContract, 0, maxPublicDetectionSourceCoverageRefs+3)
	contracts = append(contracts, sourcecdk.CoverageContract{
		SourceID: "okta",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:        "user_lifecycle",
			Type:      "lifecycle_state",
			Families:  []string{"inactive", "suspended", "user"},
			Support:   sourcecdk.CoverageSupportSupported,
			HighValue: true,
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.2",
			}},
		}},
	})
	for i := 0; i < maxPublicDetectionSourceCoverageRefs; i++ {
		contracts = append(contracts, sourcecdk.CoverageContract{
			SourceID: "source" + strconv.Itoa(i),
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:        "users",
				Type:      "entity_family",
				Families:  []string{"user"},
				Support:   sourcecdk.CoverageSupportSupported,
				HighValue: true,
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.2",
				}},
			}},
		})
	}
	contracts = append(contracts, sourcecdk.CoverageContract{
		SourceID: "audit_source",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:        "audit_events",
			Type:      "audit_event",
			Families:  []string{"audit"},
			Support:   sourcecdk.CoverageSupportSupported,
			HighValue: true,
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC7.1",
			}},
		}},
	})

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != maxPublicDetectionSourceCoverageRefs {
		t.Fatalf("len(SourceCoverageRefs) = %d, want capped set %d", len(refs), maxPublicDetectionSourceCoverageRefs)
	}
	if !sourceCoverageRefsContain(refs, "okta", "user_lifecycle") {
		t.Fatalf("SourceCoverageRefs omitted lifecycle ref under audit pressure: %#v", refs)
	}
	if !sourceCoverageRefsContain(refs, "audit_source", "audit_events") {
		t.Fatalf("SourceCoverageRefs omitted audit ref under cap pressure: %#v", refs)
	}
}

func sourceCoverageRefsContain(refs []SourceCoverageRef, sourceID string, dimensionID string) bool {
	for _, ref := range refs {
		if ref.SourceID == sourceID && ref.DimensionID == dimensionID {
			return true
		}
	}
	return false
}

func TestPolicySourceCoverageDoesNotGenericMatchSourceNamedIdentityPolicy(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-vanta-stale-login-90d",
		Name:        "Vanta Stale Active Accounts",
		Description: "Flags failed identity evidence for stale accounts in a named SaaS source.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"identity", "policy", "query", "stale-accounts", "vanta"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "okta",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:             "user_lifecycle",
			Type:           "lifecycle_state",
			Families:       []string{"stale_login", "user"},
			Support:        sourcecdk.CoverageSupportSupported,
			EvidenceTypes:  []string{"identity_governance"},
			ControlDomains: []string{"identity_access"},
		}},
	}}

	if refs := sourceCoverageRefsForDetection(detection, contracts); len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no generic cross-provider coverage for source-named policy", refs)
	}
}

func TestPolicySourceCoverageDoesNotUseFivetranAccountAccessForCloudIdentityRules(t *testing.T) {
	detection := PublicDetection{
		ID:          "aws-iam-no-policies-attached-user",
		Name:        "IAM Policies Attached to Groups Not Users",
		Description: "Flags failed resource-state evidence for aws iam user access.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"aws", "iam", "users", "groups", "identity", "policy"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "cloud_configuration",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "NIST 800-53 r5", ControlID: "AC-2"},
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
		},
	}
	contracts := []sourcecdk.CoverageContract{loadSourceCoverageContractForTest(t, "fivetran")}

	if refs := sourceCoverageRefsForDetection(detection, contracts); len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no Fivetran account access coverage for cloud IAM policy", refs)
	}
}

func loadSourceCoverageContractForTest(t *testing.T, sourceID string) sourcecdk.CoverageContract {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "sources", sourceID, "catalog.yaml")) // #nosec G304 -- test reads repository source catalog fixtures.
	if err != nil {
		t.Fatalf("read %s catalog: %v", sourceID, err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(payload)
	if err != nil {
		t.Fatalf("load %s catalog: %v", sourceID, err)
	}
	if catalog.CoverageContract == nil {
		t.Fatalf("%s catalog missing coverage contract", sourceID)
	}
	return *catalog.CoverageContract
}

func TestPolicySourceCoverageDoesNotUseCrossSourceOperationalSyncCoverage(t *testing.T) {
	detection := PublicDetection{
		ID:          "aws-cloudwatch-log-group-retention",
		Name:        "CloudWatch Log Group Retention",
		Description: "Flags failed resource-state evidence for AWS log group retention.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"aws", "cloudwatch", "logs", "log-group", "policy"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "cloud_configuration",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "NIST 800-53 r5", ControlID: "AU-12"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "fivetran",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:             "incremental_sync",
			Type:           "incremental_sync",
			Families:       []string{"log_services", "connections"},
			Support:        sourcecdk.CoverageSupportSupported,
			EvidenceTypes:  []string{"source_sync_status"},
			ControlDomains: []string{"source_operations"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "NIST 800-53 r5",
				ControlID:     "AU-12",
			}},
		}},
	}}

	if refs := sourceCoverageRefsForDetection(detection, contracts); len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no cross-source operational sync coverage for cloud logging policy", refs)
	}
}

func TestPolicySourceCoverageAllowsNamedCrossIdentityFinding(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-github-active-without-okta-link",
		Name:        "Active GitHub Identity With No Linked Okta Identity",
		Description: "Flags failed identity evidence when both GitHub and Okta identities are named in the finding.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"github", "okta", "identity", "organization_member", "user"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
		},
	}
	contracts := []sourcecdk.CoverageContract{
		{
			SourceID: "github",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:            "organization_members",
				Type:          "entity_family",
				Families:      []string{"organization_member"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"identity_governance"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.2",
				}},
			}},
		},
		{
			SourceID: "okta",
			Dimensions: []sourcecdk.CoverageDimension{{
				ID:            "users",
				Type:          "entity_family",
				Families:      []string{"user"},
				Support:       sourcecdk.CoverageSupportSupported,
				EvidenceTypes: []string{"identity_governance"},
				ControlRefs: []sourcecdk.CoverageControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.2",
				}},
			}},
		},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 2 {
		t.Fatalf("len(SourceCoverageRefs) = %d, want both named identity providers: %#v", len(refs), refs)
	}
	got := []string{refs[0].SourceID, refs[1].SourceID}
	sort.Strings(got)
	if strings.Join(got, ",") != "github,okta" {
		t.Fatalf("SourceCoverageRefs sources = %v, want github and okta", got)
	}
}

func TestPolicySourceCoverageAllowsAzureForNamedEntraFinding(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-entra-active-no-employee-record",
		Name:        "Entra ID Active Accounts Without Employee Record",
		Description: "Flags failed query-result evidence for entra user lifecycle evidence.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"entra", "identity", "active-account"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "azure",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "user",
			Type:          "entity_family",
			Families:      []string{"active_account", "entra_user", "user"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.1",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 || refs[0].SourceID != "azure" || refs[0].DimensionID != "user" {
		t.Fatalf("SourceCoverageRefs = %#v, want azure/user for named Entra coverage", refs)
	}
}

func TestPolicySourceCoverageAllowsAliasEquivalentIdentitySource(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-azure-active-no-employee-record",
		Name:        "Azure Active Accounts Without Employee Record",
		Description: "Flags failed query-result evidence for azure user lifecycle evidence.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"azure", "identity", "active-account"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "microsoft_entra_id",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "user",
			Type:          "entity_family",
			Families:      []string{"active_account", "azure_user", "user"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.1",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 1 || refs[0].SourceID != "microsoft_entra_id" || refs[0].DimensionID != "user" {
		t.Fatalf("SourceCoverageRefs = %#v, want microsoft_entra_id/user for alias-equivalent Azure coverage", refs)
	}
}

func TestPolicySourceCoverageRejectsDifferentNamedIdentitySource(t *testing.T) {
	detection := PublicDetection{
		ID:          "identity-okta-active-no-employee-record",
		Name:        "Okta Active Accounts Without Employee Record",
		Description: "Flags failed query-result evidence for okta user lifecycle evidence.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"okta", "identity", "active-account"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "identity_governance",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "microsoft_entra_id",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "user",
			Type:          "entity_family",
			Families:      []string{"active_account", "user"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.1",
			}},
		}},
	}}

	if refs := sourceCoverageRefsForDetection(detection, contracts); len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no microsoft_entra_id coverage for named Okta finding", refs)
	}
}

func TestPolicySourceCoverageDoesNotUseIdentityAliasesOutsideIdentityNamespace(t *testing.T) {
	detection := PublicDetection{
		ID:          "audit-entra-control-change",
		Name:        "Entra Control Change Missing Review",
		Description: "Flags failed policy evidence that mentions entra in supporting context.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"audit", "entra"},
	}

	if sourceMatchesDetection(detection, "azure", detectionCoverageSearchText(detection)) {
		t.Fatal("sourceMatchesDetection matched azure through identity aliases outside the identity policy namespace")
	}
}

func TestPolicySourceCoverageRejectsAzureForM365OnlyFinding(t *testing.T) {
	detection := PublicDetection{
		ID:          "m365-guest-admin",
		Name:        "M365 Guest User with Admin Role",
		Description: "Flags failed M365 identity evidence for a guest admin role.",
		SourceID:    policyRuleSourceID,
		Tags:        []string{"m365", "identity", "admin"},
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType: "collaboration_control",
		},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.2"},
		},
	}
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "azure",
		Dimensions: []sourcecdk.CoverageDimension{{
			ID:            "directory_role_assignment",
			Type:          "app_entitlement",
			Families:      []string{"admin_role"},
			Support:       sourcecdk.CoverageSupportSupported,
			EvidenceTypes: []string{"identity_configuration"},
			ControlRefs: []sourcecdk.CoverageControlRef{{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.2",
			}},
		}},
	}}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) != 0 {
		t.Fatalf("SourceCoverageRefs = %#v, want no Azure coverage for M365-only finding", refs)
	}
}

func TestCoverageControlIDMatchesGDPRArticleAliases(t *testing.T) {
	for _, legacy := range []string{"Art.5", "Art-5", "Art 5"} {
		matched, exact := coverageControlIDMatches(legacy, "Article 5")
		if !matched || !exact {
			t.Fatalf("coverageControlIDMatches(%q, Article 5) = (%v, %v), want exact match", legacy, matched, exact)
		}
	}

	detectionRefs := []ports.FindingControlRef{{FrameworkName: "GDPR", ControlID: "Art.30"}}
	coverageRefs := []sourcecdk.CoverageControlRef{{FrameworkName: "GDPR", ControlID: "Article 30"}}
	matched, exact := matchingCoverageControlRefs(detectionRefs, coverageRefs)
	if !exact || len(matched) != 1 {
		t.Fatalf("matchingCoverageControlRefs legacy GDPR alias = exact %v refs %#v, want one exact match", exact, matched)
	}
	if matched[0].ControlID != "Article 30" {
		t.Fatalf("matched control ID = %q, want Article 30", matched[0].ControlID)
	}
}

func TestCoverageControlDomainRefsCoverDeclaredSourceDomains(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "sources", "*", "catalog.yaml"))
	if err != nil {
		t.Fatalf("glob source catalogs: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("expected source catalogs")
	}

	var missing []string
	for _, path := range paths {
		payload, err := os.ReadFile(path) // #nosec G304 -- test reads repository source catalog fixtures.
		if err != nil {
			t.Fatalf("read source catalog %q: %v", path, err)
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			t.Fatalf("load source catalog %q: %v", path, err)
		}
		if catalog.CoverageContract == nil {
			continue
		}
		for _, dimension := range catalog.CoverageContract.Dimensions {
			for _, domain := range dimension.ControlDomains {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				if _, ok := coverageControlDomainRefSet.ControlDomains[domain]; ok {
					continue
				}
				if _, ok := intentionallyUnmappedCoverageControlDomains[domain]; ok {
					continue
				}
				rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
				missing = append(missing, rel+":"+dimension.ID+":"+domain)
			}
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("declared control_domains missing coverage mapping or explicit exemption: first=%s count=%d", missing[0], len(missing))
	}
}
