package iac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// loadRepo reads every .tf file under testdata/<dir> into a ci.Repository,
// mirroring what a real RepositoryReader/ModuleReader adapter would hand to
// this package: pinned, immutable, already-materialized source bytes.
func loadRepo(t *testing.T, dir string) ci.Repository {
	t.Helper()
	base := filepath.Join("testdata", dir)
	var files []ci.SourceFile
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".tf" {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // test-only read of a fixed testdata tree walked above.
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(base, path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(b)
		files = append(files, ci.SourceFile{
			Path:    filepath.ToSlash(rel),
			Content: b,
			Digest:  hex.EncodeToString(sum[:]),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("loading fixture %s: %v", dir, err)
	}
	return ci.Repository{
		Pin:   ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: files,
	}
}

func singleFileRepo(content string) ci.Repository {
	return ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "inline-rev", Exact: true},
		Files: []ci.SourceFile{{
			Path:    "main.tf",
			Content: []byte(content),
			Digest:  "inline-digest",
		}},
	}
}

func mustDecl(t *testing.T, decls []ci.Declaration, id string) ci.Declaration {
	t.Helper()
	for _, d := range decls {
		if d.Principal.ID == id {
			return d
		}
	}
	var ids []string
	for _, d := range decls {
		ids = append(ids, d.Principal.ID)
	}
	t.Fatalf("expected a declaration for principal %q, got: %v", id, ids)
	return ci.Declaration{}
}

func hasGapCode(gaps []ci.Gap, code string) bool {
	for _, g := range gaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

func gapsWithCode(gaps []ci.Gap, code string) []ci.Gap {
	var out []ci.Gap
	for _, g := range gaps {
		if g.Code == code {
			out = append(out, g)
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func grantWithRole(grants []ci.Grant, role string) (ci.Grant, bool) {
	for _, g := range grants {
		if g.Role == role {
			return g, true
		}
	}
	return ci.Grant{}, false
}

func grantContainingAction(grants []ci.Grant, action string) bool {
	for _, g := range grants {
		if containsString(g.Actions, action) {
			return true
		}
	}
	return false
}

// fakeModuleReader is the test double for ci.ModuleReader: pinned public
// module content supplied by the test, never real network/filesystem I/O.
type fakeModuleReader struct {
	modules map[string]ci.Repository
}

func (f *fakeModuleReader) ReadModule(_ context.Context, source, version string) (ci.Repository, error) {
	key := source + "@" + version
	if repo, ok := f.modules[key]; ok {
		return repo, nil
	}
	return ci.Repository{}, fmt.Errorf("fakeModuleReader: no fixture registered for %s", key)
}

// TestAWSCore exercises a role declared with: a data.aws_iam_policy_document
// trust statement (principals + condition), an inline for_each policy, an
// unexpanded managed-policy attachment, a locally-declared permissions
// boundary, and group-membership-derived grants flowing onto a user.
func TestAWSCore(t *testing.T) {
	repo := loadRepo(t, "aws_core")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Account:    "111111111111",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	role := mustDecl(t, decls, "arn:aws:iam::111111111111:role/app-role")

	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected at least one trust grant from the assume-role policy document; gaps=%+v", gaps)
	}
	trust := role.Policy.Trust[0]
	if !containsString(trust.Actions, "sts:AssumeRoleWithWebIdentity") {
		t.Errorf("expected trust action sts:AssumeRoleWithWebIdentity, got %v", trust.Actions)
	}
	wantMember := "Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	if !containsString(trust.Members, wantMember) {
		t.Errorf("expected trust member %q, got %v", wantMember, trust.Members)
	}
	foundCondition := false
	for _, c := range trust.Conditions {
		if c.Operator == "StringEquals" &&
			c.Key == "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub" &&
			containsString(c.Values, "system:serviceaccount:default:app") {
			foundCondition = true
		}
	}
	if !foundCondition {
		t.Errorf("expected a StringEquals condition on the OIDC sub claim, got %+v", trust.Conditions)
	}

	if !grantContainingAction(role.Policy.Grants, "s3:GetObject") {
		t.Errorf("expected an s3:GetObject grant from the for_each inline policy, got %+v", role.Policy.Grants)
	}

	if _, ok := grantWithRole(role.Policy.Grants, "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"); !ok {
		t.Errorf("expected an unexpanded managed-policy grant for AmazonSageMakerFullAccess, got %+v", role.Policy.Grants)
	}

	if len(role.Policy.Boundaries) != 1 {
		t.Fatalf("expected exactly one permissions boundary, got %d", len(role.Policy.Boundaries))
	}
	if !grantContainingAction(role.Policy.Boundaries[0], "sts:AssumeRole") {
		t.Errorf("expected the boundary policy to include sts:AssumeRole, got %+v", role.Policy.Boundaries[0])
	}

	alice := mustDecl(t, decls, "arn:aws:iam::111111111111:user/alice")
	if !grantContainingAction(alice.Policy.Grants, "logs:GetLogEvents") {
		t.Errorf("expected alice to inherit logs:GetLogEvents via her aws_iam_group_policy membership, got %+v", alice.Policy.Grants)
	}
}

// TestGCPCore does not depend on the shared AWS policy parser at all, so it
// pins down this package's own GCP extraction precisely: for_each project
// bindings, a conditional organization binding, and a workload-identity
// service-account binding landing in Trust rather than Grants.
func TestGCPCore(t *testing.T) {
	repo := loadRepo(t, "gcp_core")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	sa := mustDecl(t, decls, "app-sa@my-project.iam.gserviceaccount.com")
	if sa.Principal.Provider != ci.GCP || sa.Principal.Kind != "service_account" {
		t.Errorf("expected a GCP service_account principal, got %+v", sa.Principal)
	}
	if !sa.Policy.Complete {
		t.Errorf("expected PolicyState.Complete=true for a fully resolved service account, gaps=%+v", gaps)
	}

	wantResource := "projects/my-project"
	for _, role := range []string{"roles/storage.objectViewer", "roles/logging.logWriter"} {
		g, ok := grantWithRole(sa.Policy.Grants, role)
		if !ok {
			t.Errorf("expected a grant for role %q, got %+v", role, sa.Policy.Grants)
			continue
		}
		if !containsString(g.Resources, wantResource) {
			t.Errorf("expected grant %q to have resource %q, got %v", role, wantResource, g.Resources)
		}
		if len(g.Members) != 0 {
			t.Errorf("expected grant %q to carry no Members (resource-shaped, not trust), got %v", role, g.Members)
		}
	}

	tagGrant, ok := grantWithRole(sa.Policy.Grants, "roles/resourcemanager.tagUser")
	if !ok {
		t.Fatalf("expected a conditional organization-level grant for roles/resourcemanager.tagUser, got %+v", sa.Policy.Grants)
	}
	if !containsString(tagGrant.Resources, "organizations/123456789") {
		t.Errorf("expected organization grant resource organizations/123456789, got %v", tagGrant.Resources)
	}
	if len(tagGrant.Conditions) != 1 || tagGrant.Conditions[0].Expression != `request.time < timestamp("2030-01-01T00:00:00Z")` {
		t.Errorf("expected the organization binding's CEL condition to be preserved verbatim, got %+v", tagGrant.Conditions)
	}

	if len(sa.Policy.Trust) != 1 {
		t.Fatalf("expected exactly one trust grant (workload identity), got %d: %+v", len(sa.Policy.Trust), sa.Policy.Trust)
	}
	trust := sa.Policy.Trust[0]
	if trust.Role != "roles/iam.workloadIdentityUser" {
		t.Errorf("expected trust role roles/iam.workloadIdentityUser, got %q", trust.Role)
	}
	wantTrustMember := "serviceAccount:my-project.svc.id.goog[default/app]"
	if !containsString(trust.Members, wantTrustMember) {
		t.Errorf("expected trust member %q, got %v", wantTrustMember, trust.Members)
	}
	wantTrustResource := "projects/my-project/serviceAccounts/app-sa@my-project.iam.gserviceaccount.com"
	if !containsString(trust.Resources, wantTrustResource) {
		t.Errorf("expected trust resource (target SA canonical name) %q, got %v", wantTrustResource, trust.Resources)
	}
	// Project/org-level bindings must never be mistaken for trust.
	for _, g := range sa.Policy.Grants {
		if g.Role == "roles/iam.workloadIdentityUser" {
			t.Errorf("workload identity binding leaked into Grants instead of staying in Trust: %+v", g)
		}
	}
}

// TestDynamicBlockPolicyDocumentRendering checks this package's own
// aws_iam_policy_document rendering (dynamic "statement"/"condition" block
// expansion) directly against the produced JSON text, independent of the
// shared ci.ParseAWSPolicy implementation.
func TestDynamicBlockPolicyDocumentRendering(t *testing.T) {
	repo := loadRepo(t, "dynamic_unresolved")
	files := indexFiles(repo.Files)
	mf := moduleFiles{pin: repo.Pin, dir: "", addr: "root", files: filesUnderDir(files, ""), index: files}
	rn := newRun(context.Background(), nil, ci.TerraformInput{Account: "444444444444"})

	pm, diags := parseModuleFiles(mf, rn)
	if diags.HasErrors() {
		t.Fatalf("unexpected parse errors: %s", diags.Error())
	}

	ctx := baseEvalContext()
	rn.resolveValueSymbols(pm, ctx, mf, 0, nil)

	dataVal, ok := ctx.Variables["data"]
	if !ok {
		t.Fatal("expected ctx.Variables[\"data\"] to be populated by resolveValueSymbols")
	}
	jsonVal := dataVal.GetAttr("aws_iam_policy_document").GetAttr("dynamic_doc").GetAttr("json")
	if !jsonVal.IsKnown() || jsonVal.IsNull() {
		t.Fatal("expected a known rendered policy document JSON string")
	}

	type renderedStatement struct {
		Sid       string                         `json:"Sid"`
		Action    []string                       `json:"Action"`
		Condition map[string]map[string][]string `json:"Condition"`
	}
	var doc struct {
		Statement []renderedStatement `json:"Statement"`
	}
	raw := jsonVal.AsString()
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("rendered policy document is not valid JSON (%v): %s", err, raw)
	}
	if len(doc.Statement) != 2 {
		t.Fatalf("expected 2 statements (1 static + 1 dynamic), got %d: %s", len(doc.Statement), raw)
	}
	byS := map[string]renderedStatement{}
	for _, s := range doc.Statement {
		byS[s.Sid] = s
	}

	base, ok := byS["Base"]
	if !ok {
		t.Fatalf("missing static Base statement: %s", raw)
	}
	if len(base.Action) != 1 || base.Action[0] != "s3:ListBucket" {
		t.Errorf("expected Base action [s3:ListBucket], got %v", base.Action)
	}
	if len(base.Condition) != 0 {
		t.Errorf("expected Base statement to have no condition, got %v", base.Condition)
	}

	extra, ok := byS["ExtraRead"]
	if !ok {
		t.Fatalf("missing dynamic-block-generated ExtraRead statement: %s", raw)
	}
	if len(extra.Action) != 1 || extra.Action[0] != "s3:GetObject" {
		t.Errorf("expected ExtraRead action [s3:GetObject] from var.extra_statements, got %v", extra.Action)
	}
	vals := extra.Condition["StringEquals"]["aws:PrincipalTag/team"]
	if len(vals) != 1 || vals[0] != "platform" {
		t.Errorf("expected ExtraRead's nested dynamic \"condition\" block to render StringEquals aws:PrincipalTag/team=[platform], got %v", vals)
	}
}

// TestUnresolvedComputedReferenceGap asserts that an EKS cluster's OIDC
// issuer, only knowable live, is preserved as a precise, actionable scoped
// gap naming the exact TerraformInput.ResolvedIdentifiers key that would
// unblock it, and that every dependent evaluation (the local, and the
// role's assume_role_policy) stays unresolved rather than fabricating a
// value, when that key is not supplied.
func TestUnresolvedComputedReferenceGap(t *testing.T) {
	repo := loadRepo(t, "dynamic_unresolved")
	reader := NewDeclarationReader(nil)
	_, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "444444444444"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	liveGaps := gapsWithCode(gaps, "iac.unresolved_live_identifier")
	if len(liveGaps) == 0 {
		t.Fatalf("expected an iac.unresolved_live_identifier gap naming the missing EKS OIDC issuer, got gaps=%+v", gaps)
	}
	found := false
	for _, g := range liveGaps {
		if strings.Contains(g.Message, "aws_eks_oidc_issuer:cluster") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the gap to name the exact ResolvedIdentifiers key needed (aws_eks_oidc_issuer:cluster), got: %+v", liveGaps)
	}
	if !hasGapCode(gaps, "iac.unresolved_computed_value") {
		t.Errorf("expected the dependent local.oidc_issuer evaluation to also surface iac.unresolved_computed_value rather than a fabricated value, got: %+v", gaps)
	}
}

// TestResolvedEKSOIDCIssuerUnblocksRoleTrust asserts that supplying the
// narrow TerraformInput.ResolvedIdentifiers binding for an EKS cluster's
// OIDC issuer (as a prior live collection pass would) lets the role's
// web-identity trust statement resolve through ordinary expression
// evaluation, with no change to any other declaration.
func TestResolvedEKSOIDCIssuerUnblocksRoleTrust(t *testing.T) {
	repo := loadRepo(t, "dynamic_unresolved")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: repo,
		Account:    "444444444444",
		ResolvedIdentifiers: map[string]string{
			"aws_eks_oidc_issuer:cluster": "oidc.eks.us-east-1.amazonaws.com/id/RESOLVEDEXAMPLE",
		},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if hasGapCode(gaps, "iac.unresolved_live_identifier") {
		t.Errorf("did not expect an unresolved_live_identifier gap once the issuer is supplied, got: %+v", gaps)
	}

	role := mustDecl(t, decls, "arn:aws:iam::444444444444:role/eks-app-role")
	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected the web-identity trust statement to resolve once the issuer is supplied, gaps=%+v", gaps)
	}
	wantMember := "Federated:arn:aws:iam::444444444444:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/RESOLVEDEXAMPLE"
	if !containsString(role.Policy.Trust[0].Members, wantMember) {
		t.Errorf("expected resolved OIDC trust member %q, got %v", wantMember, role.Policy.Trust[0].Members)
	}
}

// TestDynamicBlockExpansionErrorMarksIncomplete asserts that a dynamic
// "condition" block that fails to expand (a non-iterable for_each) is
// propagated as a scoped iac.block_expansion_error gap, and -- critically --
// that the role whose trust statement depends on it is reported
// PolicyState.Complete=false, never silently narrowed to "complete" just
// because a syntactically valid (but under-restricted) grant still came
// out the other end.
func TestDynamicBlockExpansionErrorMarksIncomplete(t *testing.T) {
	repo := loadRepo(t, "dynamic_block_error")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "999999999999"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	if !hasGapCode(gaps, "iac.block_expansion_error") {
		t.Fatalf("expected an iac.block_expansion_error gap from the malformed dynamic \"condition\" for_each, got: %+v", gaps)
	}

	role := mustDecl(t, decls, "arn:aws:iam::999999999999:role/broken-role")
	if role.Policy.Complete {
		t.Error("expected PolicyState.Complete=false: the trust statement's dynamic condition failed to expand, so the declared trust must not be reported as fully known")
	}
	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant to still be recorded (principals/actions were fine), got none")
	}
	for _, c := range role.Policy.Trust[0].Conditions {
		if c.Key == "aws:PrincipalTag/team" {
			t.Errorf("the malformed dynamic condition should not have been able to populate a condition value, got %+v", role.Policy.Trust[0].Conditions)
		}
	}
}

// TestGCPResourceGrantVsTrustSeparation asserts that a project/org/folder
// IAM binding granting a role to a declared service account's member string
// produces a resource-shaped Grant (Role+Resources, no Members) on that
// SA's own declaration, that a service-account-level binding produces a
// Trust grant anchored on the target SA's own canonical resource name, and
// that when the trusted member is itself a declared SA, its own ability to
// use the target is additionally recorded as that member's own outgoing
// Grant, not only as the target's trust.
func TestGCPResourceGrantVsTrustSeparation(t *testing.T) {
	repo := loadRepo(t, "gcp_sa_impersonation")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	target := mustDecl(t, decls, "target-sa@my-project.iam.gserviceaccount.com")
	caller := mustDecl(t, decls, "caller-sa@my-project.iam.gserviceaccount.com")

	storageGrant, ok := grantWithRole(target.Policy.Grants, "roles/storage.objectViewer")
	if !ok {
		t.Fatalf("expected target SA's own resource-shaped storage.objectViewer grant, got %+v; gaps=%+v", target.Policy.Grants, gaps)
	}
	if !containsString(storageGrant.Resources, "projects/my-project") {
		t.Errorf("expected grant resource projects/my-project, got %v", storageGrant.Resources)
	}
	if len(storageGrant.Members) != 0 {
		t.Errorf("expected the SA's own permission grant to carry no Members (that is a trust shape), got %v", storageGrant.Members)
	}

	if len(target.Policy.Trust) == 0 {
		t.Fatalf("expected target SA to have a trust grant from google_service_account_iam_member")
	}
	trust := target.Policy.Trust[0]
	if trust.Role != "roles/iam.serviceAccountTokenCreator" {
		t.Errorf("expected trust role roles/iam.serviceAccountTokenCreator, got %q", trust.Role)
	}
	wantCallerMember := "serviceAccount:caller-sa@my-project.iam.gserviceaccount.com"
	if !containsString(trust.Members, wantCallerMember) {
		t.Errorf("expected trust member %q, got %v", wantCallerMember, trust.Members)
	}
	wantTargetResource := "projects/my-project/serviceAccounts/target-sa@my-project.iam.gserviceaccount.com"
	if !containsString(trust.Resources, wantTargetResource) {
		t.Errorf("expected trust resource (target SA canonical name) %q, got %v", wantTargetResource, trust.Resources)
	}

	impersonateGrant, ok := grantWithRole(caller.Policy.Grants, "roles/iam.serviceAccountTokenCreator")
	if !ok {
		t.Fatalf("expected caller SA to have its own outgoing serviceAccountTokenCreator grant, got %+v", caller.Policy.Grants)
	}
	if !containsString(impersonateGrant.Resources, wantTargetResource) {
		t.Errorf("expected caller's outgoing grant to target %q, got %v", wantTargetResource, impersonateGrant.Resources)
	}
}

// TestUnsupportedFunctionGap asserts that calling a provider/time-dependent
// function this package does not support (timestamp()) is a scoped gap, not
// a silently-dropped or fabricated value.
func TestUnsupportedFunctionGap(t *testing.T) {
	repo := singleFileRepo(`
resource "aws_iam_role" "bad" {
  name = "bad-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
      Condition = {
        DateLessThan = { "aws:CurrentTime" = timestamp() }
      }
    }]
  })
}
`)
	reader := NewDeclarationReader(nil)
	_, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "666666666666"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unsupported_function") {
		t.Errorf("expected an iac.unsupported_function gap for timestamp(), got: %+v", gaps)
	}
}

// TestUnattributedGroupMemberGap asserts that a group membership reference
// to a user this analyzer never declared is a scoped gap, not a fabricated
// principal or a silently-dropped grant source.
func TestUnattributedGroupMemberGap(t *testing.T) {
	repo := singleFileRepo(`
resource "aws_iam_group" "team" {
  name = "team"
}

resource "aws_iam_group_membership" "team_members" {
  name  = "team-members"
  group = aws_iam_group.team.name
  users = ["external-user-not-declared-here"]
}
`)
	reader := NewDeclarationReader(nil)
	_, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "777777777777"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unattributed_grant") {
		t.Errorf("expected an iac.unattributed_grant gap for the undeclared group member, got: %+v", gaps)
	}
}

// TestCountExpansion exercises resource `count` addressing: each instance
// becomes its own declared principal, indexed exactly like Terraform
// addresses aws_iam_user.svc[0]/[1].
func TestCountExpansion(t *testing.T) {
	repo := singleFileRepo(`
resource "aws_iam_user" "svc" {
  count = 2
  name  = "svc-${count.index}"
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "888888888888"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("expected exactly 2 declarations from count=2, got %d; gaps=%+v", len(decls), gaps)
	}
	mustDecl(t, decls, "arn:aws:iam::888888888888:user/svc-0")
	mustDecl(t, decls, "arn:aws:iam::888888888888:user/svc-1")
}

// TestModuleContainment exercises a local module call: the child module's
// own trust statement, and a root-level resource that attaches a policy by
// referencing the child module's output (module.app_role.role_name), proving
// grant attribution works across a module boundary via the shared lookup
// table, not just within one file.
func TestModuleContainment(t *testing.T) {
	repo := loadRepo(t, "module_containment")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "222222222222"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	role := mustDecl(t, decls, "arn:aws:iam::222222222222:role/contained-role")
	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant from the local module's data.aws_iam_policy_document, gaps=%+v", gaps)
	}
	if !containsString(role.Policy.Trust[0].Members, "Service:ec2.amazonaws.com") {
		t.Errorf("expected trust member Service:ec2.amazonaws.com, got %v", role.Policy.Trust[0].Members)
	}
	if _, ok := grantWithRole(role.Policy.Grants, "arn:aws:iam::aws:policy/ReadOnlyAccess"); !ok {
		t.Errorf("expected the root-level attachment (via module.app_role.role_name) to attach ReadOnlyAccess, got %+v", role.Policy.Grants)
	}
}

// TestLocalDependsOnModuleOutput exercises the opposite dependency
// direction from TestModuleContainment: a local in the root module reads a
// child module's output (module.role.role_name), and a root-level resource
// depends on that local. This is only resolvable if locals and module calls
// are resolved as one dependency graph instead of two rigid sequential
// phases (locals-before-modules would leave the local unresolved; modules-
// before-locals would break a module argument that reads a local).
func TestLocalDependsOnModuleOutput(t *testing.T) {
	repo := loadRepo(t, "local_depends_module")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "123456789012"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}

	role := mustDecl(t, decls, "arn:aws:iam::123456789012:role/module-role")
	if _, ok := grantWithRole(role.Policy.Grants, "arn:aws:iam::aws:policy/ReadOnlyAccess"); !ok {
		t.Errorf("expected the root-level attachment (role = local.attach_role_name <- module.role.role_name) to attach ReadOnlyAccess, got %+v; gaps=%+v", role.Policy.Grants, gaps)
	}
}

func pinnedModuleRootRepo(withVersion bool) ci.Repository {
	versionLine := `version = "5.39.0"`
	if !withVersion {
		versionLine = ""
	}
	return singleFileRepo(fmt.Sprintf(`
module "irsa" {
  source = "terraform-aws-modules/iam-role-for-service-accounts-eks/aws"
  %s

  role_name = "irsa-role"
}
`, versionLine))
}

func pinnedModuleFixture(exact bool) ci.Repository {
	return ci.Repository{
		Pin: ci.SourcePin{Repository: "registry/terraform-aws-modules/iam-role-for-service-accounts-eks", Revision: "v5.39.0", Exact: exact},
		Files: []ci.SourceFile{{
			Path:   "main.tf",
			Digest: "module-digest",
			Content: []byte(`
variable "role_name" {
  type = string
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}
`),
		}},
	}
}

// TestPinnedPublicModule exercises a module call pinned via `version`,
// resolved entirely through the injected ModuleReader.
func TestPinnedPublicModule(t *testing.T) {
	mr := &fakeModuleReader{modules: map[string]ci.Repository{
		"terraform-aws-modules/iam-role-for-service-accounts-eks/aws@5.39.0": pinnedModuleFixture(true),
	}}
	reader := NewDeclarationReader(mr)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: pinnedModuleRootRepo(true),
		Account:    "555555555555",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	role := mustDecl(t, decls, "arn:aws:iam::555555555555:role/irsa-role")
	if len(role.Policy.Trust) == 0 || !containsString(role.Policy.Trust[0].Members, "Service:pods.eks.amazonaws.com") {
		t.Errorf("expected a trust member Service:pods.eks.amazonaws.com from the pinned public module, got %+v", role.Policy.Trust)
	}
	if hasGapCode(gaps, "iac.unpinned_module_source") {
		t.Errorf("did not expect an unpinned-module gap when version is set and the adapter reports Exact=true, got %+v", gaps)
	}
}

// TestUnpinnedPublicModuleGap asserts that a module call the adapter could
// not resolve to an immutable revision is a scoped gap, never silently
// treated as equivalent to a pinned read.
func TestUnpinnedPublicModuleGap(t *testing.T) {
	mr := &fakeModuleReader{modules: map[string]ci.Repository{
		"terraform-aws-modules/iam-role-for-service-accounts-eks/aws@": pinnedModuleFixture(false),
	}}
	reader := NewDeclarationReader(mr)
	_, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: pinnedModuleRootRepo(false),
		Account:    "555555555555",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unpinned_module_source") {
		t.Errorf("expected an iac.unpinned_module_source gap when the ModuleReader reports Exact=false, got %+v", gaps)
	}
}

// TestRemoteModuleMaterializedFromPinRoot reproduces finding 4: a module
// pinned to a "//subdir" materializes with repository-relative file paths
// and Repository.Pin.Root set to that subdir, not "". The evaluator must
// select the child module's files from Pin.Root, not always "".
func TestRemoteModuleMaterializedFromPinRoot(t *testing.T) {
	mr := &fakeModuleReader{modules: map[string]ci.Repository{
		"github.com/acme/modules//modules/foo@v1.0.0": {
			Pin: ci.SourcePin{Repository: "acme/modules", Revision: "deadbeef", Root: "modules/foo", Exact: true},
			Files: []ci.SourceFile{{
				Path:   "modules/foo/main.tf",
				Digest: "d1",
				Content: []byte(`
resource "aws_iam_role" "this" {
  name = "foo-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`),
			}},
		},
	}}
	reader := NewDeclarationReader(mr)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: singleFileRepo(`
module "foo" {
  source  = "github.com/acme/modules//modules/foo"
  version = "v1.0.0"
}
`),
		Account: "999999999999",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if hasGapCode(gaps, "iac.module_not_found") {
		t.Fatalf("did not expect iac.module_not_found when the module is materialized under its Pin.Root, got %+v", gaps)
	}
	mustDecl(t, decls, "arn:aws:iam::999999999999:role/foo-role")
}

// TestRemoteModuleLocalChildResolvesAgainstRemoteIndex reproduces finding
// 5: a local child module call ("./submodules/...") reached from inside a
// remotely materialized module must resolve against that remote
// repository's own complete file index, not the primary stack
// materialization.
func TestRemoteModuleLocalChildResolvesAgainstRemoteIndex(t *testing.T) {
	mr := &fakeModuleReader{modules: map[string]ci.Repository{
		"github.com/acme/modules//modules/aws_eks_cluster@v2.0.0": {
			Pin: ci.SourcePin{Repository: "acme/modules", Revision: "cafefeed", Root: "modules/aws_eks_cluster", Exact: true},
			Files: []ci.SourceFile{
				{
					Path:   "modules/aws_eks_cluster/main.tf",
					Digest: "d1",
					Content: []byte(`
module "irsa" {
  source = "./submodules/irsa_role"
}
`),
				},
				{
					Path:   "modules/aws_eks_cluster/submodules/irsa_role/main.tf",
					Digest: "d2",
					Content: []byte(`
resource "aws_iam_role" "this" {
  name = "irsa-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`),
				},
			},
		},
	}}
	reader := NewDeclarationReader(mr)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository: singleFileRepo(`
module "cluster" {
  source  = "github.com/acme/modules//modules/aws_eks_cluster"
  version = "v2.0.0"
}
`),
		Account: "888888888888",
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if hasGapCode(gaps, "iac.module_not_found") {
		t.Fatalf("did not expect iac.module_not_found for the local submodule inside the remote module, got %+v", gaps)
	}
	mustDecl(t, decls, "arn:aws:iam::888888888888:role/irsa-role")
}

// TestModuleArgumentReferencesIdentityResource reproduces finding 6: a root
// policy's ARN, passed into a child role module's input before that module
// is evaluated, must resolve so the child role receives the policy's
// grants (grant attachment itself still happens in the later passGrants
// pass, inside the child module).
func TestModuleArgumentReferencesIdentityResource(t *testing.T) {
	repo := loadRepo(t, "module_input_identity_arg")
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "444444444411"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if hasGapCode(gaps, "iac.unresolved_expression") {
		t.Errorf("did not expect an unresolved-expression gap for the module input referencing aws_iam_policy.authorized_hydration.arn, got %+v", gaps)
	}
	role := mustDecl(t, decls, "arn:aws:iam::444444444411:role/observability-role")
	if !grantContainingAction(role.Policy.Grants, "s3:GetObject") {
		t.Errorf("expected the role to receive the s3:GetObject grant attached by ARN through the module input, got %+v", role.Policy.Grants)
	}
}

// TestAWSCallerIdentityDataSource reproduces finding 7's AWS half: a
// data.aws_caller_identity.account_id reference, bounded to
// TerraformInput.Account, must resolve in an ordinary expression (here, an
// assume-role trust principal built by string interpolation).
func TestAWSCallerIdentityDataSource(t *testing.T) {
	repo := singleFileRepo(`
data "aws_caller_identity" "current" {}

locals {
  trust_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}

resource "aws_iam_role" "this" {
  name = "acct-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = local.trust_arn }
    }]
  })
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "777777777777"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	role := mustDecl(t, decls, "arn:aws:iam::777777777777:role/acct-role")
	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant; gaps=%+v", gaps)
	}
	want := "AWS:arn:aws:iam::777777777777:root"
	if !containsString(role.Policy.Trust[0].Members, want) {
		t.Errorf("expected trust member %q resolved from data.aws_caller_identity.current.account_id, got %v", want, role.Policy.Trust[0].Members)
	}
}

// TestGoogleProjectDataSource reproduces finding 7's GCP half:
// data.google_project.this.number, bounded to
// TerraformInput.ResolvedIdentifiers["gcp_project_number:<project>"], must
// resolve in an ordinary expression (here, a workload-identity principalSet
// member string built by a local, distinct from the already-supported
// google_iam_workload_identity_pool/_provider computed path).
func TestGoogleProjectDataSource(t *testing.T) {
	repo := singleFileRepo(`
data "google_project" "this" {}

locals {
  wif_member = "principalSet://iam.googleapis.com/projects/${data.google_project.this.number}/locations/global/workloadIdentityPools/proj.svc.id.goog/namespace/default"
}

resource "google_service_account" "this" {
  account_id = "svc"
}

resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.this.name
  role                = "roles/iam.workloadIdentityUser"
  member              = local.wif_member
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository:          repo,
		Project:             "proj",
		ResolvedIdentifiers: map[string]string{"gcp_project_number:proj": "123456789012"},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	sa := mustDecl(t, decls, "svc@proj.iam.gserviceaccount.com")
	if len(sa.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant; gaps=%+v", gaps)
	}
	want := "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj.svc.id.goog/namespace/default"
	if !containsString(sa.Policy.Trust[0].Members, want) {
		t.Errorf("expected trust member %q resolved from data.google_project.this.number, got %v", want, sa.Policy.Trust[0].Members)
	}
}

// TestUnrelatedUnresolvedLocalDoesNotGap reproduces finding 8: a local that
// is never reachable from any identity/trust/grant/module-input/output
// expression (here, one referencing an intentionally unsupported provider
// value) must never surface a gap or affect an unrelated, fully static
// role's completeness.
func TestUnrelatedUnresolvedLocalDoesNotGap(t *testing.T) {
	repo := singleFileRepo(`
locals {
  unrelated = data.sops_file.secrets.data
}

resource "aws_iam_role" "app" {
  name = "static-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "666666666666"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps from the unreachable local referencing an unsupported data source, got %+v", gaps)
	}
	role := mustDecl(t, decls, "arn:aws:iam::666666666666:role/static-role")
	if !role.Policy.Complete {
		t.Errorf("expected the fully static role to remain complete despite the unrelated unresolved local")
	}
}

// TestUnusedRootOutputDoesNotGap reproduces finding 8's root-output half: a
// root module `output` is never consumed by anything in this analysis (no
// parent module call reads module.<label>.<output> for the root), so a
// discarded output referencing unsupported data must never be evaluated at
// all, and must never gap an otherwise fully static, independently valid
// role.
func TestUnusedRootOutputDoesNotGap(t *testing.T) {
	repo := singleFileRepo(`
resource "aws_iam_role" "app" {
  name = "static-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

output "debug" {
  value = data.sops_file.secrets.data["foo"]
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "111111111133"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps from the discarded root output referencing unsupported data, got %+v", gaps)
	}
	role := mustDecl(t, decls, "arn:aws:iam::111111111133:role/static-role")
	if !role.Policy.Complete {
		t.Errorf("expected the fully static role to remain complete despite the unused root output")
	}
}

// TestUnusedChildModuleArgumentDoesNotGap reproduces finding 8's
// module-input half: a module call argument referencing unsupported data
// (here, data.sops_file, exactly like the local case above) must never be
// evaluated -- and so never gap -- unless the child module actually
// references the matching variable from an identity/trust/grant/
// boundary-reachable expression. The child module's role is declared using
// only the OTHER, used argument (role_name), so it must remain complete.
func TestUnusedChildModuleArgumentDoesNotGap(t *testing.T) {
	repo := ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: []ci.SourceFile{
			{Path: "main.tf", Digest: "d1", Content: []byte(`
module "role" {
  source        = "./modules/role"
  role_name     = "static-role"
  debug_payload = data.sops_file.secrets.data["foo"]
}
`)},
			{Path: "modules/role/main.tf", Digest: "d2", Content: []byte(`
variable "role_name" {
  type = string
}

variable "debug_payload" {
  type = string
}

resource "aws_iam_role" "this" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`)},
		},
	}
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "111111111144"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps from the unused module argument referencing unsupported data, got %+v", gaps)
	}
	role := mustDecl(t, decls, "arn:aws:iam::111111111144:role/static-role")
	if !role.Policy.Complete {
		t.Errorf("expected the child module's independently valid role to remain complete despite the unused argument, gaps=%+v", gaps)
	}
}

// TestAWSRegionDataSource reproduces finding 8's AWS region half: a
// data.aws_region.current.region reference (used by the configured EKS
// module to build its OIDC issuer host), bound to TerraformInput.Region,
// must resolve in an ordinary expression.
func TestAWSRegionDataSource(t *testing.T) {
	repo := singleFileRepo(`
data "aws_region" "current" {}

locals {
  oidc_issuer = "oidc.eks.${data.aws_region.current.region}.amazonaws.com/id/EXAMPLE1234567890"
}

resource "aws_iam_role" "this" {
  name = "eks-irsa-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::777777777777:oidc-provider/${local.oidc_issuer}" }
    }]
  })
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "777777777777", Region: "us-west-2"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	role := mustDecl(t, decls, "arn:aws:iam::777777777777:role/eks-irsa-role")
	if len(role.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant; gaps=%+v", gaps)
	}
	want := "Federated:arn:aws:iam::777777777777:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE1234567890"
	if !containsString(role.Policy.Trust[0].Members, want) {
		t.Errorf("expected trust member %q resolved from data.aws_region.current.region, got %v", want, role.Policy.Trust[0].Members)
	}
}

// TestTerraformRemoteStateMetadataBinding reproduces finding 8's GCP
// remote-state half: a GCP customer root's
// data.terraform_remote_state.bootstrap.outputs.project_number, bound via
// TerraformInput.MetadataBindings, must resolve in an ordinary expression
// (here, a workload-identity principalSet member built by a local) without
// ever reading actual Terraform state.
func TestTerraformRemoteStateMetadataBinding(t *testing.T) {
	repo := singleFileRepo(`
data "terraform_remote_state" "bootstrap" {
  backend = "gcs"
  config = {
    bucket = "unused-fixture-bucket"
  }
}

locals {
  wif_member = "principalSet://iam.googleapis.com/projects/${data.terraform_remote_state.bootstrap.outputs.project_number}/locations/global/workloadIdentityPools/example-project.svc.id.goog/namespace/default"
}

resource "google_service_account" "this" {
  account_id = "svc"
  project    = "example-project"
}

resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.this.name
  role                = "roles/iam.workloadIdentityUser"
  member              = local.wif_member
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository:          repo,
		Project:             "example-project",
		ResolvedIdentifiers: map[string]string{"gcp_project_number:example-project": "999999999999"},
		MetadataBindings: map[string]string{
			"data.terraform_remote_state.bootstrap.outputs.project_number": "project_number",
		},
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	sa := mustDecl(t, decls, "svc@example-project.iam.gserviceaccount.com")
	if len(sa.Policy.Trust) == 0 {
		t.Fatalf("expected a trust grant; gaps=%+v", gaps)
	}
	want := "principalSet://iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/example-project.svc.id.goog/namespace/default"
	if !containsString(sa.Policy.Trust[0].Members, want) {
		t.Errorf("expected trust member %q resolved from the bound data.terraform_remote_state.bootstrap.outputs.project_number, got %v", want, sa.Policy.Trust[0].Members)
	}
}

// TestTerraformRemoteStateUnboundStaysGap is the control for
// TestTerraformRemoteStateMetadataBinding: the exact same traversal with NO
// matching TerraformInput.MetadataBindings entry must stay an explicit
// unresolved gap -- never fabricated, and never silently read from actual
// state (there is none here to read).
func TestTerraformRemoteStateUnboundStaysGap(t *testing.T) {
	repo := singleFileRepo(`
data "terraform_remote_state" "bootstrap" {
  backend = "gcs"
  config = {
    bucket = "unused-fixture-bucket"
  }
}

locals {
  wif_member = "principalSet://iam.googleapis.com/projects/${data.terraform_remote_state.bootstrap.outputs.project_number}/locations/global/workloadIdentityPools/example-project.svc.id.goog/namespace/default"
}

resource "google_service_account" "this" {
  account_id = "svc"
  project    = "example-project"
}

resource "google_service_account_iam_member" "wi" {
  service_account_id = google_service_account.this.name
  role                = "roles/iam.workloadIdentityUser"
  member              = local.wif_member
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{
		Repository:          repo,
		Project:             "example-project",
		ResolvedIdentifiers: map[string]string{"gcp_project_number:example-project": "999999999999"},
		// No MetadataBindings: the remote-state traversal is unbound.
	})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unresolved_expression") {
		t.Fatalf("expected an iac.unresolved_expression gap for the unbound remote-state traversal, got %+v", gaps)
	}
	sa := mustDecl(t, decls, "svc@example-project.iam.gserviceaccount.com")
	if len(sa.Policy.Trust) != 0 {
		t.Errorf("expected no fabricated trust grant from the unbound/unresolved remote-state traversal, got %+v", sa.Policy.Trust)
	}
}

// TestTfvarsAutoLoadPrecedence reproduces finding 9: only
// "terraform.tfvars" and "*.auto.tfvars" are implicitly loaded, in
// Terraform's own precedence; an ordinary "prod.tfvars" is never
// auto-loaded.
func TestTfvarsAutoLoadPrecedence(t *testing.T) {
	repo := ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: []ci.SourceFile{
			{Path: "variables.tf", Digest: "d1", Content: []byte(`
variable "role_name" {
  type    = string
  default = "default-role"
}
`)},
			{Path: "main.tf", Digest: "d2", Content: []byte(`
resource "aws_iam_role" "this" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`)},
			{Path: "terraform.tfvars", Digest: "d3", Content: []byte(`role_name = "auto-role"` + "\n")},
			{Path: "prod.tfvars", Digest: "d4", Content: []byte(`role_name = "prod-role"` + "\n")},
		},
	}
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "555555555555"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	mustDecl(t, decls, "arn:aws:iam::555555555555:role/auto-role")
	for _, d := range decls {
		if d.Principal.ID == "arn:aws:iam::555555555555:role/prod-role" {
			t.Fatalf("prod.tfvars must not be implicitly auto-loaded, got role named from it; gaps=%+v", gaps)
		}
	}
}

// TestTfvarsJSONAutoLoadPrecedence reproduces R14 finding 1:
// terraform.tfvars.json was previously ignored (hclsyntax.ParseConfig
// cannot parse JSON syntax, so the JSON tfvars file was silently skipped
// with no gap), and *.auto.tfvars.json files were never even considered
// for implicit auto-loading. Both must be parsed (via
// github.com/hashicorp/hcl/v2/json) and participate in Terraform's own
// precedence: terraform.tfvars, then terraform.tfvars.json, then every
// *.auto.tfvars/*.auto.tfvars.json file in lexical filename order (later
// wins); an ordinary "prod.tfvars.json" is never auto-loaded, exactly like
// "prod.tfvars".
func TestTfvarsJSONAutoLoadPrecedence(t *testing.T) {
	repo := ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: []ci.SourceFile{
			{Path: "variables.tf", Digest: "d1", Content: []byte(`
variable "role_name" {
  type    = string
  default = "default-role"
}
`)},
			{Path: "main.tf", Digest: "d2", Content: []byte(`
resource "aws_iam_role" "this" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}
`)},
			{Path: "terraform.tfvars", Digest: "d3", Content: []byte(`role_name = "tfvars-role"` + "\n")},
			{Path: "terraform.tfvars.json", Digest: "d4", Content: []byte(`{"role_name": "tfvars-json-role"}` + "\n")},
			{Path: "zz.auto.tfvars.json", Digest: "d5", Content: []byte(`{"role_name": "auto-json-role"}` + "\n")},
			{Path: "prod.tfvars.json", Digest: "d6", Content: []byte(`{"role_name": "prod-json-role"}` + "\n")},
		},
	}
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Account: "444444444455"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps from well-formed tfvars JSON files, got %+v", gaps)
	}
	mustDecl(t, decls, "arn:aws:iam::444444444455:role/auto-json-role")
	for _, d := range decls {
		for _, bad := range []string{"tfvars-role", "tfvars-json-role", "prod-json-role"} {
			if d.Principal.ID == "arn:aws:iam::444444444455:role/"+bad {
				t.Fatalf("expected precedence to resolve to the auto.tfvars.json value, got role named %q", bad)
			}
		}
	}
}

// TestGCPResourceLevelIAMGrant reproduces finding 10: a
// google_pubsub_topic_iam_member grant to a declared service account must
// produce a resource-shaped Grant with a Cloud Asset-canonical resource
// name, not an empty "complete" policy.
func TestGCPResourceLevelIAMGrant(t *testing.T) {
	repo := singleFileRepo(`
resource "google_service_account" "mcp" {
  account_id = "mcp-gateway"
}

resource "google_pubsub_topic_iam_member" "grant" {
  project = "proj"
  topic   = "admin-audit-log"
  role    = "roles/pubsub.publisher"
  member  = google_service_account.mcp.member
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Project: "proj"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	sa := mustDecl(t, decls, "mcp-gateway@proj.iam.gserviceaccount.com")
	if !sa.Policy.Complete {
		t.Fatalf("expected the service account's policy to be complete, gaps=%+v", gaps)
	}
	grant, ok := grantWithRole(sa.Policy.Grants, "roles/pubsub.publisher")
	if !ok {
		t.Fatalf("expected a roles/pubsub.publisher grant from the pubsub topic IAM member, got %+v", sa.Policy.Grants)
	}
	want := "//pubsub.googleapis.com/projects/proj/topics/admin-audit-log"
	if !containsString(grant.Resources, want) {
		t.Errorf("expected canonical resource %q, got %v", want, grant.Resources)
	}
}

// TestUnsupportedGCPIAMResourceIsExplicitGap reproduces the other half of
// finding 10: a google_*_iam_member/_iam_binding/_iam_policy kind this
// reader does not canonicalize must never be silently skipped when it
// affects a declared principal.
func TestUnsupportedGCPIAMResourceIsExplicitGap(t *testing.T) {
	repo := singleFileRepo(`
resource "google_service_account" "svc" {
  account_id = "svc"
}

resource "google_bigquery_dataset_iam_member" "grant" {
  project    = "proj"
  dataset_id = "analytics"
  role       = "roles/bigquery.dataEditor"
  member     = google_service_account.svc.member
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Project: "proj"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unsupported_gcp_iam_resource") {
		t.Fatalf("expected an iac.unsupported_gcp_iam_resource gap for google_bigquery_dataset_iam_member, got %+v", gaps)
	}
	sa := mustDecl(t, decls, "svc@proj.iam.gserviceaccount.com")
	if sa.Policy.Complete {
		t.Errorf("expected the service account to be marked incomplete, since an unsupported IAM resource affects it")
	}
}

// TestTFJSONSiblingGrantNeverSilentlyOmitted reproduces R14 finding 2: an
// IAM grant declared in a ".tf.json" file beside a native ".tf" service
// account was previously invisible to this reader entirely (the file was
// filtered out before parsing ever saw it), so the grant was silently
// dropped and the service account looked fully Complete with zero grants.
// A ".tf.json" sibling must now produce an explicit, scoped
// "iac.unsupported_tf_json_config" gap and mark every declaration in that
// same module directory incomplete, never silently omitted.
func TestTFJSONSiblingGrantNeverSilentlyOmitted(t *testing.T) {
	repo := ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: []ci.SourceFile{
			{Path: "main.tf", Digest: "d1", Content: []byte(`
resource "google_service_account" "svc" {
  account_id = "svc"
  project    = "example-project"
}
`)},
			{Path: "grant.tf.json", Digest: "d2", Content: []byte(`{
  "resource": {
    "google_project_iam_member": {
      "grant": {
        "project": "example-project",
        "role": "roles/editor",
        "member": "${google_service_account.svc.member}"
      }
    }
  }
}`)},
		},
	}
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Project: "example-project"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unsupported_tf_json_config") {
		t.Fatalf("expected an iac.unsupported_tf_json_config gap naming grant.tf.json, got %+v", gaps)
	}
	sa := mustDecl(t, decls, "svc@example-project.iam.gserviceaccount.com")
	if sa.Policy.Complete {
		t.Errorf("expected the service account to be marked incomplete: a sibling .tf.json file's grants were never statically parsed")
	}
}

// TestNoTFJSONSiblingStaysComplete is the control for
// TestTFJSONSiblingGrantNeverSilentlyOmitted: a module directory with no
// ".tf.json" files must never be marked incomplete by this mechanism.
func TestNoTFJSONSiblingStaysComplete(t *testing.T) {
	repo := singleFileRepo(`
resource "google_service_account" "svc" {
  account_id = "svc"
  project    = "example-project"
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo, Project: "example-project"})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps with no .tf.json sibling present, got %+v", gaps)
	}
	sa := mustDecl(t, decls, "svc@example-project.iam.gserviceaccount.com")
	if !sa.Policy.Complete {
		t.Errorf("expected the service account to remain complete with no .tf.json sibling present")
	}
}

// TestDefaultGoogleProviderProjectFallback reproduces R14 finding 3: a
// google resource with no own `project` attribute, and no
// TerraformInput.Project supplied at all, must still resolve via the
// default (non-aliased) `provider "google" { project = ... }` block's own
// project. Pre-fix, no code ever consulted provider blocks, so this
// resource stayed unresolved (iac.unresolved_project) even though the
// project was in fact statically known from the provider configuration.
func TestDefaultGoogleProviderProjectFallback(t *testing.T) {
	repo := singleFileRepo(`
provider "google" {
  project = "example-project"
}

resource "google_service_account" "svc" {
  account_id = "svc"
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("expected no gaps: the default provider's project is statically known, got %+v", gaps)
	}
	sa := mustDecl(t, decls, "svc@example-project.iam.gserviceaccount.com")
	if !sa.Policy.Complete {
		t.Errorf("expected the service account to be complete via the default provider's project, gaps=%+v", gaps)
	}
}

// TestAliasedGoogleProviderNeverUsesDefaultProject is a control for
// TestDefaultGoogleProviderProjectFallback: a resource that explicitly
// selects an ALIASED provider (`provider = google.other`) must never fall
// back to the unrelated default provider's own project -- it stays an
// explicit unresolved gap exactly as before this fix, never a
// wrong/fabricated project.
func TestAliasedGoogleProviderNeverUsesDefaultProject(t *testing.T) {
	repo := singleFileRepo(`
provider "google" {
  project = "example-project"
}

provider "google" {
  alias   = "other"
  project = "other-project"
}

resource "google_service_account" "svc" {
  account_id = "svc"
  provider   = google.other
}
`)
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unresolved_project") {
		t.Fatalf("expected an iac.unresolved_project gap for the aliased-provider resource, got %+v", gaps)
	}
	for _, d := range decls {
		if d.Principal.ID == "svc@example-project.iam.gserviceaccount.com" || d.Principal.ID == "svc@other-project.iam.gserviceaccount.com" {
			t.Fatalf("expected no fabricated project from either provider block, got declaration %q", d.Principal.ID)
		}
	}
}

// TestChildModuleProviderMappingAmbiguityNeverUsesDefaultProject is a
// second control: a child module entered through a module call with an
// explicit `providers = {...}` mapping must never inherit the ROOT's
// default google provider project either -- that mapping could point the
// child's "google" provider at any aliased configuration, so the default
// lookup is skipped entirely and the resource stays an explicit unresolved
// gap, exactly as before this fix.
func TestChildModuleProviderMappingAmbiguityNeverUsesDefaultProject(t *testing.T) {
	repo := ci.Repository{
		Pin: ci.SourcePin{Repository: "test/repo", Revision: "fixture-rev", Exact: true},
		Files: []ci.SourceFile{
			{Path: "main.tf", Digest: "d1", Content: []byte(`
provider "google" {
  project = "root-project"
}

provider "google" {
  alias   = "other"
  project = "other-project"
}

module "svc" {
  source = "./modules/svc"
  providers = {
    google = google.other
  }
}
`)},
			{Path: "modules/svc/main.tf", Digest: "d2", Content: []byte(`
resource "google_service_account" "svc" {
  account_id = "svc"
}
`)},
		},
	}
	reader := NewDeclarationReader(nil)
	decls, gaps, err := reader.ReadDeclarations(context.Background(), ci.TerraformInput{Repository: repo})
	if err != nil {
		t.Fatalf("ReadDeclarations: %v", err)
	}
	if !hasGapCode(gaps, "iac.unresolved_project") {
		t.Fatalf("expected an iac.unresolved_project gap for the provider-mapping-ambiguous child module, got %+v", gaps)
	}
	for _, d := range decls {
		if d.Principal.ID == "svc@root-project.iam.gserviceaccount.com" || d.Principal.ID == "svc@other-project.iam.gserviceaccount.com" {
			t.Fatalf("expected no fabricated project through the ambiguous providers mapping, got declaration %q", d.Principal.ID)
		}
	}
}
