package cloudidentity

import "context"

// SourceFile is transient pinned input. Collectors must not persist the full
// repository or send credential/configuration secret files to investigators.
type SourceFile struct {
	Path    string
	Content []byte
	Digest  string
}

type Repository struct {
	Pin   SourcePin
	Files []SourceFile
	Gaps  []Gap
}

type RepositoryReader interface {
	ReadRepository(context.Context, SourcePin) (Repository, error)
}

type ImageProvenance struct {
	Image  string
	Digest string
	// DeploymentPinned reports that Digest is the digest named by the deployed
	// workload reference itself (a digest-qualified image reference whose
	// manifest digest was verified). Tag-only references are never pinned:
	// current registry tag-immutability settings say nothing about which
	// digest the tag named when the workload was deployed.
	DeploymentPinned bool
	Source           SourcePin
	References       []Reference
	Gaps             []Gap
}

type RegistryReader interface {
	ReadImage(context.Context, string) (ImageProvenance, error)
}

// ChartReference identifies an allowlisted Helm repository or OCI repository and
// an exact chart version. Digest, when supplied, is checked before extraction.
type ChartReference struct {
	Repository string
	Name       string
	Version    string
	Digest     string
}

type ChartReader interface {
	ReadChart(context.Context, ChartReference) (Repository, error)
}

// Manifest is a rendered Kubernetes document with its owning pinned location.
type Manifest struct {
	Object    map[string]any
	Reference Reference
}

type ManifestRequest struct {
	Repository  Repository
	Paths       []string
	Chart       string
	ValuesFiles []string
	Values      map[string]any
	Release     string
	Namespace   string
	Environment string
	Cluster     string
	// Applications mirrors ManifestInput.Applications: a non-empty list
	// restricts Argo CD expansion to these Application/ApplicationSet names.
	Applications []string
}

// ComposeRequest carries every manifest rendered for one scan target so
// Crossplane composite resources/claims are expanded with the target-wide
// Compositions, CompositeResourceDefinitions and EnvironmentConfigs, which
// are commonly deployed by a different chart than the claims themselves.
type ComposeRequest struct {
	Manifests   []Manifest
	Environment string
	Cluster     string
}

type ManifestRenderer interface {
	// Render renders one manifest input (raw YAML, Helm, Argo CD sources).
	// It does not expand Crossplane composites; Compose does, per target.
	Render(context.Context, ManifestRequest) ([]Manifest, []Gap, error)
	// Compose returns only the resources composed from Crossplane
	// composites/claims found among one target's aggregated manifests.
	Compose(context.Context, ComposeRequest) ([]Manifest, []Gap, error)
}

type Declaration struct {
	Principal Principal
	Policy    PolicyState
}

type TerraformInput struct {
	Repository          Repository
	Root                string
	Variables           map[string]any
	Account             string
	Project             string
	Region              string
	ResolvedIdentifiers map[string]string
	// MetadataBindings mirrors TerraformRoot.MetadataBindings.
	MetadataBindings map[string]string
}

type ModuleReader interface {
	ReadModule(context.Context, string, string) (Repository, error)
}

type DeclarationReader interface {
	ReadDeclarations(context.Context, TerraformInput) ([]Declaration, []Gap, error)
}

type InventoryRequest struct {
	Manifests   []Manifest
	Environment string
	Cluster     string
	Region      string
	Provider    Provider
	Project     string
	Account     string
	Services    []ServiceMapping
}

// ServiceMapping groups replicas and different workload types into one logical
// application. Image prefixes and repository routing are deployment config.
// Workloads optionally restricts the mapping to workloads (controller
// metadata.name) of these names, distinguishing logical services that share
// one image, such as separately deployed proxies.
type ServiceMapping struct {
	Service       string   `json:"service"`
	ImagePrefixes []string `json:"image_prefixes"`
	Workloads     []string `json:"workloads,omitempty"`
	Repository    string   `json:"repository"`
	SourceRoot    string   `json:"source_root,omitempty"`
}

type DefinitionRequest struct {
	AWSServices []string
	AWSPolicies []string
	GCPRoles    []string
}

type CloudRequest struct {
	Principal Principal
	Consumers []Workload
	Declared  PolicyState
}

type Observation struct {
	Policy              PolicyState
	Definitions         Definitions
	ResolvedIdentifiers map[string]string
	Gaps                []Gap
}

type CloudReader interface {
	Observe(context.Context, CloudRequest) (Observation, error)
	Define(context.Context, DefinitionRequest) (Definitions, error)
}

type InvestigationRequest struct {
	Workload    Workload
	Repository  Repository
	Definitions Definitions
}

type RequirementInvestigator interface {
	Investigate(context.Context, InvestigationRequest) (Investigation, error)
}
