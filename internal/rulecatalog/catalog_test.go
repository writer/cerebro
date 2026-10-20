package rulecatalog

import (
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
)

func TestBuiltinCatalogCoversEverySource(t *testing.T) {
	details := Builtin()
	origins := map[string]int{}
	domains := map[string]int{}
	seen := map[string]struct{}{}
	for _, detail := range details {
		if _, ok := seen[detail.ID]; ok {
			t.Fatalf("duplicate catalog id %q", detail.ID)
		}
		seen[detail.ID] = struct{}{}
		origins[detail.Origin]++
		domains[detail.Domain]++
		if detail.Name == "" || detail.Severity == "" || detail.Domain == "" || detail.Posture == "" || detail.Provider == "" {
			t.Fatalf("catalog entry %q is missing list fields: %+v", detail.ID, detail.Entry)
		}
		if detail.Remediation == "" {
			t.Fatalf("catalog entry %q has no remediation guidance", detail.ID)
		}
		if detail.AttackDescription == "" {
			t.Fatalf("catalog entry %q has no attack description", detail.ID)
		}
		if postureForDomain(detail.Domain) != detail.Posture {
			t.Fatalf("catalog entry %q posture %q does not match domain %q", detail.ID, detail.Posture, detail.Domain)
		}
	}
	for _, origin := range []string{OriginBuiltinPolicy, OriginBuiltinDetection, OriginCorrelation} {
		if origins[origin] == 0 {
			t.Fatalf("catalog has no %s entries: %v", origin, origins)
		}
	}
	for _, domain := range []string{DomainPaaS, DomainSaaS, DomainIdentity, DomainCorrelation} {
		if domains[domain] == 0 {
			t.Fatalf("catalog has no %s entries: %v", domain, domains)
		}
	}
}

func TestBuiltinPolicyDocumentsRoundTrip(t *testing.T) {
	for _, detail := range Builtin() {
		if detail.Origin != OriginBuiltinPolicy {
			continue
		}
		if detail.Document == "" {
			t.Fatalf("policy %q has no YAML document", detail.ID)
		}
		rule, issues, err := findingdsl.ParsePolicyRuleYAML("policies/custom/rule.yaml", []byte(detail.Document))
		if err != nil || len(issues) != 0 {
			t.Fatalf("policy %q document does not reparse: err=%v issues=%v\n%s", detail.ID, err, issues, detail.Document)
		}
		if rule.Metadata.ID != detail.ID {
			t.Fatalf("policy %q document id = %q", detail.ID, rule.Metadata.ID)
		}
	}
}

func TestBuiltinPortedRuleCarriesAuthoredGuidance(t *testing.T) {
	detail, ok := BuiltinRule("aws-user-inactive-admin-no-mfa")
	if !ok {
		t.Fatal("expected aws-user-inactive-admin-no-mfa in catalog")
	}
	if detail.Domain != DomainPaaS || detail.Posture != PostureCSPM || detail.Provider != "aws" {
		t.Fatalf("unexpected classification: %+v", detail.Entry)
	}
	if detail.Severity != "critical" || detail.Evaluation != EvaluationCEL || detail.Detection != DetectionPosture {
		t.Fatalf("unexpected severity/evaluation: %+v", detail.Entry)
	}
	if !strings.HasPrefix(detail.Remediation, "Disable or delete inactive admin accounts") {
		t.Fatalf("remediation = %q, want authored summary", detail.Remediation)
	}
	if detail.Summary != "An inactive AWS user with admin privileges does not have MFA enabled" {
		t.Fatalf("summary = %q, want authored description", detail.Summary)
	}
	if !strings.Contains(detail.AttackDescription, "Privilege Escalation (T1078)") {
		t.Fatalf("attack description = %q, want MITRE context", detail.AttackDescription)
	}
	if detail.SourcePath != "policies/cerebro/aws-user-inactive-admin-no-mfa.yaml" || !detail.Testable || detail.Editable {
		t.Fatalf("unexpected authoring fields: path=%q testable=%v editable=%v", detail.SourcePath, detail.Testable, detail.Editable)
	}
	for _, tag := range detail.Tags {
		if tag == "policy" || strings.HasPrefix(tag, "evidence:") || strings.HasPrefix(tag, "assessment:") {
			t.Fatalf("generated tag %q leaked into authored tags %v", tag, detail.Tags)
		}
	}
}

func TestCatalogDoesNotSurfaceLineageTags(t *testing.T) {
	for _, detail := range Builtin() {
		for _, tag := range detail.Tags {
			if isLineageTag(tag) {
				t.Fatalf("rule %q exposes lineage tag %q", detail.ID, tag)
			}
		}
		if strings.Contains(strings.ToLower(detail.Document), "- wiz") {
			t.Fatalf("rule %q document exposes a lineage tag:\n%s", detail.ID, detail.Document)
		}
	}
}

func TestClassifyPolicy(t *testing.T) {
	cases := []struct {
		name         string
		category     string
		resourceType string
		tags         []string
		sourceKinds  []string
		want         Classification
	}{
		{name: "aws resource", category: "aws", resourceType: "aws::s3::bucket", want: Classification{DomainPaaS, PostureCSPM, "aws"}},
		{name: "k8s alias", category: "kubernetes", resourceType: "k8s::core::pod", want: Classification{DomainPaaS, PostureCSPM, "kubernetes"}},
		{name: "github", category: "github", resourceType: "github.org", want: Classification{DomainSaaS, PostureSSPM, "github"}},
		{name: "identity category saas provider", category: "identity", resourceType: "slack_user", want: Classification{DomainIdentity, PostureISPM, "slack"}},
		{name: "okta graph", category: "identity", sourceKinds: []string{"okta.user", "okta.admin_role"}, want: Classification{DomainIdentity, PostureISPM, "okta"}},
		{name: "cross-source graph", category: "cerebro", sourceKinds: []string{"aws.cloudtrail", "okta.user"}, want: Classification{DomainCorrelation, PostureCorrelation, "aws+okta"}},
		{name: "generic resource uses provider tags", category: "cerebro", resourceType: "compute::instance", tags: []string{"wiz", "gcp"}, want: Classification{DomainPaaS, PostureCSPM, "gcp"}},
		{name: "generic cloud category", category: "container", resourceType: "container", want: Classification{DomainPaaS, PostureCSPM, providerMultiCloud}},
		{name: "unknown saas category", category: "hipaa", resourceType: "phi", want: Classification{DomainSaaS, PostureSSPM, "hipaa"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyPolicy(tc.category, tc.resourceType, tc.tags, tc.sourceKinds); got != tc.want {
				t.Fatalf("ClassifyPolicy() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCorrelationPatternsJoinMemberRules(t *testing.T) {
	detail, ok := BuiltinRule("cloud-public-exposure-with-privilege-path")
	if !ok {
		t.Fatal("expected correlation pattern in catalog")
	}
	if detail.Origin != OriginCorrelation || detail.Domain != DomainCorrelation || detail.Detection != DetectionCorrelation {
		t.Fatalf("unexpected correlation classification: %+v", detail.Entry)
	}
	if len(detail.CorrelatedRuleIDs) < 2 || detail.CorrelationWindow == "" {
		t.Fatalf("correlation detail missing members/window: %+v", detail)
	}
}
