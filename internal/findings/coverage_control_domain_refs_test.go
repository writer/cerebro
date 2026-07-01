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
