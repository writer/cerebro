package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/compliancecontract"
)

func TestComplianceReadHTTPPoliciesUseDistinctScopes(t *testing.T) {
	tests := []struct {
		path  string
		scope string
	}{
		{path: "/grc/programs", scope: scopeComplianceProgramsRead},
		{path: "/grc/programs/program-1", scope: scopeComplianceProgramsRead},
		{path: "/grc/programs/program-1/control-implementations", scope: scopeComplianceProgramsRead},
		{path: "/grc/control-implementations/implementation-1", scope: scopeComplianceProgramsRead},
		{path: "/grc/evidence-artifacts", scope: scopeComplianceEvidenceRead},
		{path: "/grc/evidence-artifacts/artifact-1", scope: scopeComplianceEvidenceRead},
		{path: "/grc/assessment-plans", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/assessment-plans/plan-1", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-assessments", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-assessments/run-1", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-assessments/run-1/objectives", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-assessments/run-1/reviews", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-results/result-1", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/compliance-reviews/review-1", scope: scopeComplianceAssessmentsRead},
		{path: "/grc/work-items", scope: scopeComplianceWorkRead},
		{path: "/grc/work-items/work-1", scope: scopeComplianceWorkRead},
	}
	for _, test := range tests {
		policy := httpRoutePolicyFor("GET", test.path)
		if policy.Scope != test.scope || policy.AdminOnly {
			t.Fatalf("GET %s policy = %#v, want scope %q", test.path, policy, test.scope)
		}
	}
}

func TestComplianceReadConnectPoliciesUseDistinctScopes(t *testing.T) {
	tests := []struct {
		procedure string
		scope     string
	}{
		{cerebrov1connect.ComplianceReadServiceListComplianceProgramsProcedure, scopeComplianceProgramsRead},
		{cerebrov1connect.ComplianceReadServiceGetComplianceProgramProcedure, scopeComplianceProgramsRead},
		{cerebrov1connect.ComplianceReadServiceListControlImplementationsProcedure, scopeComplianceProgramsRead},
		{cerebrov1connect.ComplianceReadServiceGetControlImplementationProcedure, scopeComplianceProgramsRead},
		{cerebrov1connect.ComplianceReadServiceListEvidenceArtifactMetadataProcedure, scopeComplianceEvidenceRead},
		{cerebrov1connect.ComplianceReadServiceGetEvidenceArtifactMetadataProcedure, scopeComplianceEvidenceRead},
		{cerebrov1connect.ComplianceReadServiceListAssessmentPlansProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceGetAssessmentPlanProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceListAssessmentRunsProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceGetAssessmentRunProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceListAssessmentResultsProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceGetAssessmentResultProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceListAssessmentReviewsProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceGetAssessmentReviewProcedure, scopeComplianceAssessmentsRead},
		{cerebrov1connect.ComplianceReadServiceListComplianceWorkItemsProcedure, scopeComplianceWorkRead},
		{cerebrov1connect.ComplianceReadServiceGetComplianceWorkItemProcedure, scopeComplianceWorkRead},
	}
	for _, test := range tests {
		policy := connectProcedurePolicyFor(test.procedure)
		if policy.Scope != test.scope || policy.AdminOnly {
			t.Fatalf("%s policy = %#v, want scope %q", test.procedure, policy, test.scope)
		}
	}
}

func TestComplianceReadScopesDoNotGrantOtherReadSlices(t *testing.T) {
	evidenceReader := authPrincipal{Scopes: []string{scopeComplianceEvidenceRead}}
	if err := authorizePrincipalScope(evidenceReader, scopeComplianceEvidenceRead); err != nil {
		t.Fatalf("evidence reader rejected: %v", err)
	}
	for _, other := range []string{scopeComplianceProgramsRead, scopeComplianceAssessmentsRead, scopeComplianceWorkRead} {
		if err := authorizePrincipalScope(evidenceReader, other); !errors.Is(err, errScopeForbidden) {
			t.Fatalf("evidence reader authorized for %q: %v", other, err)
		}
	}
}

func TestComplianceReadContractIsPublishedButHandlerIsNotRegistered(t *testing.T) {
	contract := compliancecontract.VersionResponse().GetComplianceReads()
	if contract.GetServiceName() != cerebrov1connect.ComplianceReadServiceName {
		t.Fatalf("service_name = %q", contract.GetServiceName())
	}
	if contract.GetRouteState() != cerebrov1.ComplianceReadRouteState_COMPLIANCE_READ_ROUTE_STATE_CONTRACT_ONLY {
		t.Fatalf("route_state = %v, want contract only", contract.GetRouteState())
	}
	wantScopes := []string{
		scopeComplianceProgramsRead,
		scopeComplianceEvidenceRead,
		scopeComplianceAssessmentsRead,
		scopeComplianceWorkRead,
	}
	if !reflect.DeepEqual(contract.GetRequiredScopes(), wantScopes) {
		t.Fatalf("required_scopes = %v, want %v", contract.GetRequiredScopes(), wantScopes)
	}
	for _, scope := range wantScopes {
		if !containsAuthValue(supportedOAuthScopes(), scope) {
			t.Fatalf("OAuth discovery missing compliance read scope %q", scope)
		}
	}

	root := bootstrapRepoRoot(t)
	// #nosec G304 -- fixed repo-relative route registry path.
	body, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "routes.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "NewComplianceReadServiceHandler") {
		t.Fatal("compliance read Connect handler registered before durable store implementation")
	}
}
