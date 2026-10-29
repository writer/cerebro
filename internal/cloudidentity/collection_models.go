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
}

type TerraformRoot struct {
	Source    SourcePin      `json:"source"`
	Root      string         `json:"root"`
	Variables map[string]any `json:"variables,omitempty"`
	Region    string         `json:"region,omitempty"`
	// MetadataBindings declares, for a reviewed root, which external value
	// traversals (for example
	// "data.terraform_remote_state.bootstrap.outputs.project_id") equal one of
	// the scan target's own metadata facts: "project_id", "project_number",
	// "region" or "account_id". The bound value always comes from scan inputs
	// (TerraformInput.Project/Account/Region or a resolved project number);
	// no state is read and unbound external values stay unresolved.
	MetadataBindings map[string]string `json:"metadata_bindings,omitempty"`
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
