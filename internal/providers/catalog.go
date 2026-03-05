package providers

import "sort"

// ProviderMaturity indicates provider implementation maturity.
type ProviderMaturity string

const (
	ProviderMaturityProductionReady ProviderMaturity = "production-ready"
	ProviderMaturityBeta            ProviderMaturity = "beta"
	ProviderMaturityStub            ProviderMaturity = "stub/incomplete"
)

// ProviderMetadata captures provider rollout metadata.
type ProviderMetadata struct {
	Name     string           `json:"name"`
	Maturity ProviderMaturity `json:"maturity"`
	Public   bool             `json:"public"`
}

var providerMetadata = map[string]ProviderMetadata{
	"auth0":            {Name: "auth0", Maturity: ProviderMaturityBeta, Public: true},
	"atlassian":        {Name: "atlassian", Maturity: ProviderMaturityBeta, Public: true},
	"bamboohr":         {Name: "bamboohr", Maturity: ProviderMaturityBeta, Public: true},
	"azure":            {Name: "azure", Maturity: ProviderMaturityProductionReady, Public: true},
	"cloudflare":       {Name: "cloudflare", Maturity: ProviderMaturityProductionReady, Public: true},
	"cloudtrail":       {Name: "cloudtrail", Maturity: ProviderMaturityBeta, Public: true},
	"crowdstrike":      {Name: "crowdstrike", Maturity: ProviderMaturityProductionReady, Public: true},
	"datadog":          {Name: "datadog", Maturity: ProviderMaturityProductionReady, Public: true},
	"duo":              {Name: "duo", Maturity: ProviderMaturityProductionReady, Public: true},
	"cyberark":         {Name: "cyberark", Maturity: ProviderMaturityProductionReady, Public: true},
	"entra_id":         {Name: "entra_id", Maturity: ProviderMaturityProductionReady, Public: true},
	"figma":            {Name: "figma", Maturity: ProviderMaturityBeta, Public: true},
	"forgerock":        {Name: "forgerock", Maturity: ProviderMaturityProductionReady, Public: true},
	"gong":             {Name: "gong", Maturity: ProviderMaturityBeta, Public: true},
	"github":           {Name: "github", Maturity: ProviderMaturityProductionReady, Public: true},
	"gitlab":           {Name: "gitlab", Maturity: ProviderMaturityProductionReady, Public: true},
	"google_workspace": {Name: "google_workspace", Maturity: ProviderMaturityProductionReady, Public: true},
	"intune":           {Name: "intune", Maturity: ProviderMaturityBeta, Public: true},
	"jamf":             {Name: "jamf", Maturity: ProviderMaturityBeta, Public: true},
	"jumpcloud":        {Name: "jumpcloud", Maturity: ProviderMaturityProductionReady, Public: true},
	"kandji":           {Name: "kandji", Maturity: ProviderMaturityBeta, Public: true},
	"kolide":           {Name: "kolide", Maturity: ProviderMaturityBeta, Public: true},
	"oracle_idcs":      {Name: "oracle_idcs", Maturity: ProviderMaturityProductionReady, Public: true},
	"onelogin":         {Name: "onelogin", Maturity: ProviderMaturityBeta, Public: true},
	"okta":             {Name: "okta", Maturity: ProviderMaturityProductionReady, Public: true},
	"panther":          {Name: "panther", Maturity: ProviderMaturityBeta, Public: true},
	"pingidentity":     {Name: "pingidentity", Maturity: ProviderMaturityProductionReady, Public: true},
	"qualys":           {Name: "qualys", Maturity: ProviderMaturityProductionReady, Public: true},
	"ramp":             {Name: "ramp", Maturity: ProviderMaturityBeta, Public: true},
	"rippling":         {Name: "rippling", Maturity: ProviderMaturityBeta, Public: true},
	"salesforce":       {Name: "salesforce", Maturity: ProviderMaturityBeta, Public: true},
	"s3":               {Name: "s3", Maturity: ProviderMaturityBeta, Public: true},
	"semgrep":          {Name: "semgrep", Maturity: ProviderMaturityBeta, Public: true},
	"servicenow":       {Name: "servicenow", Maturity: ProviderMaturityBeta, Public: true},
	"sentinelone":      {Name: "sentinelone", Maturity: ProviderMaturityProductionReady, Public: true},
	"sailpoint":        {Name: "sailpoint", Maturity: ProviderMaturityProductionReady, Public: true},
	"saviynt":          {Name: "saviynt", Maturity: ProviderMaturityProductionReady, Public: true},
	"slack":            {Name: "slack", Maturity: ProviderMaturityBeta, Public: true},
	"snyk":             {Name: "snyk", Maturity: ProviderMaturityProductionReady, Public: true},
	"socket":           {Name: "socket", Maturity: ProviderMaturityBeta, Public: true},
	"splunk":           {Name: "splunk", Maturity: ProviderMaturityBeta, Public: true},
	"tailscale":        {Name: "tailscale", Maturity: ProviderMaturityProductionReady, Public: true},
	"tenable":          {Name: "tenable", Maturity: ProviderMaturityProductionReady, Public: true},
	"terraform_cloud":  {Name: "terraform_cloud", Maturity: ProviderMaturityBeta, Public: true},
	"vanta":            {Name: "vanta", Maturity: ProviderMaturityBeta, Public: true},
	"vault":            {Name: "vault", Maturity: ProviderMaturityBeta, Public: true},
	"wiz":              {Name: "wiz", Maturity: ProviderMaturityBeta, Public: true},
	"workday":          {Name: "workday", Maturity: ProviderMaturityBeta, Public: true},
	"zoom":             {Name: "zoom", Maturity: ProviderMaturityBeta, Public: true},
}

// ProviderMetadataFor returns metadata for a provider name.
func ProviderMetadataFor(name string) ProviderMetadata {
	if metadata, ok := providerMetadata[name]; ok {
		return metadata
	}
	return ProviderMetadata{Name: name, Maturity: ProviderMaturityProductionReady, Public: true}
}

// IsProviderIncomplete returns true when a provider is marked as stub/incomplete.
func IsProviderIncomplete(name string) bool {
	return ProviderMetadataFor(name).Maturity == ProviderMaturityStub
}

// PublicProviderNames returns sorted provider names that are marked public.
func PublicProviderNames() []string {
	names := make([]string, 0, len(providerMetadata))
	for name, metadata := range providerMetadata {
		if metadata.Public {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// ImplementedProviderNames returns sorted provider names that are not marked stub/incomplete.
func ImplementedProviderNames() []string {
	names := make([]string, 0, len(providerMetadata))
	for name, metadata := range providerMetadata {
		if metadata.Maturity != ProviderMaturityStub {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
