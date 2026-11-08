package cloudidentity

import "time"

// ScanPlan is private deployment configuration; it contains no credentials.
// All targets form one consumer inventory before any principal is assessed.
type ScanPlan struct {
	Scope    string           `json:"scope"`
	Targets  []ScanTarget     `json:"targets"`
	Services []ServiceMapping `json:"services"`
}

type ScanTarget struct {
	Name        string   `json:"name"`
	Environment string   `json:"environment"`
	Cluster     string   `json:"cluster"`
	Provider    Provider `json:"provider"`
	Account     string   `json:"account,omitempty"`
	Project     string   `json:"project,omitempty"`
	// Region is the cluster's cloud location (AWS region; GKE region or
	// zone). AWS targets require it so EKS reads use the cluster's own
	// regional endpoint rather than a reader-wide default.
	Region    string          `json:"region,omitempty"`
	Manifests []ManifestInput `json:"manifests"`
	Terraform []TerraformRoot `json:"terraform,omitempty"`
	// Services are target-scoped service mappings, appended AFTER the
	// plan's own Services for this target's own inventory passes only
	// (its provider pass and, for an AWS target with a Project, its
	// federated-GCP pass) -- never mutating the plan's own slice, and
	// never visible to any other target.
	Services []ServiceMapping `json:"services,omitempty"`
	// InputAssertions are verified once per run against their own pinned
	// repository (internal/cloudidentity/input_assertions.go). Each
	// failure becomes an inventory gap scoped to this target's own Name,
	// demoting Collection.InventoryComplete and, via
	// cohortMayBeAffectedByTargetGap, the ConsumerInventoryComplete of
	// cohorts related to this target.
	InputAssertions []InputAssertion `json:"input_assertions,omitempty"`
	// KnownGaps are coverage problems the plan generator already detected
	// in its own private inputs. Each becomes an inventory gap scoped to
	// this target's own Name; the supplied code is informational only and
	// is never used for gap scoping.
	KnownGaps []KnownGap `json:"known_gaps,omitempty"`
}

type ManifestInput struct {
	Source      SourcePin      `json:"source"`
	Paths       []string       `json:"paths,omitempty"`
	Chart       string         `json:"chart,omitempty"`
	ValuesFiles []string       `json:"values_files,omitempty"`
	Values      map[string]any `json:"values,omitempty"`
	Release     string         `json:"release,omitempty"`
	Namespace   string         `json:"namespace,omitempty"`
	// Applications scopes Argo CD expansion: when non-empty, only
	// Application/ApplicationSet documents with these metadata.name values
	// are expanded; other Argo documents are outside this plan and dropped.
	// A listed application that the rendered app-of-apps does not declare is
	// not deployed to the target and contributes nothing.
	Applications []string `json:"applications,omitempty"`
	// IgnoreMissingValueFiles mirrors Argo CD's real, documented
	// spec.source.helm.ignoreMissingValueFiles field: when true, a
	// ValuesFiles entry absent from the pinned repository is silently
	// skipped instead of becoming a gap. Set this for a plan entry whose
	// chart lists every possible per-environment/per-cluster values layer
	// unconditionally, the same way the deploying Argo CD Application
	// itself is configured.
	IgnoreMissingValueFiles bool `json:"ignore_missing_value_files,omitempty"`
	// UnresolvedValues names Terraform-contract value keys (for example
	// "ack.permissionsBoundaryArn", a key the real deploying Terraform
	// stack injects from remote state this scan does not evaluate) that
	// could not be bound from any proven read-only metadata source. Each
	// becomes one explicit, scoped gap instead of a silently incomplete
	// Values map, so a chart template's "required" failure on that key is
	// never mistaken for an unrelated render defect.
	UnresolvedValues []string `json:"unresolved_values,omitempty"`
}

type TerraformRoot struct {
	Source    SourcePin      `json:"source"`
	Root      string         `json:"root"`
	Variables map[string]any `json:"variables,omitempty"`
	Region    string         `json:"region,omitempty"`
	// VarFiles lists repository-relative paths to explicit Terraform
	// var-files, in the exact order the deploying CI passes them. Each is
	// evaluated like Terraform's own "-var-file" flag, applied in this
	// order after the root's auto-loaded *.tfvars/*.auto.tfvars files and
	// before Variables (the explicit, highest-precedence "-var" layer). A
	// path this scan's pinned Repository does not contain is a gap, never
	// silently skipped.
	VarFiles []string `json:"var_files,omitempty"`
	// MetadataBindings declares, for a reviewed root, which external value
	// traversals (for example
	// "data.terraform_remote_state.bootstrap.outputs.project_id") equal one of
	// the scan target's own metadata facts: "project_id", "project_number",
	// "region" or "account_id". The bound value always comes from scan inputs
	// (TerraformInput.Project/Account/Region or a resolved project number);
	// no state is read and unbound external values stay unresolved.
	MetadataBindings map[string]string `json:"metadata_bindings,omitempty"`
	// InputAssertions are verified once per run against their own pinned
	// repository. Each failure becomes a declaration gap scoped to this
	// root's own target Name, appended to that target's declaration gaps
	// the same way a Terraform evaluation gap is, so Declared.Complete is
	// false for cohorts consuming that target.
	InputAssertions []InputAssertion `json:"input_assertions,omitempty"`
}

// KnownGap is one coverage problem the plan generator already detected in
// its own private inputs before this collection ran. Its Code is
// informational only -- it is never used to scope the inventory gap it
// becomes -- so a generator-supplied code that happens to resemble a
// workload- or subject-scoped code never narrows the demoted scope.
type KnownGap struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// CollectionPorts are injected once per run, allowing provider adapters to reuse
// immutable repository materializations, tokens and request budgets.
type CollectionPorts struct {
	Repositories RepositoryReader
	Registry     RegistryReader
	Manifests    ManifestRenderer
	Declarations DeclarationReader
	Clouds       map[Provider]CloudReader
	Investigator RequirementInvestigator
}

// Collection is evidence, not a security assessment. Incomplete collections
// remain durable observations and must never reconcile previous findings clean.
type Collection struct {
	Scope             string     `json:"scope"`
	Evidence          []Evidence `json:"evidence"`
	Gaps              []Gap      `json:"gaps,omitempty"`
	CollectedAt       time.Time  `json:"collected_at"`
	InventoryComplete bool       `json:"inventory_complete"`
}
