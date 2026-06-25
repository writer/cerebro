package sourceregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestBuiltin(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	aurelius, ok := registry.Get("aurelius")
	if !ok {
		t.Fatal("Get(aurelius) = false, want true")
	}
	if aurelius.Spec().Name != "Aurelius" {
		t.Fatalf("aurelius Spec().Name = %q, want %q", aurelius.Spec().Name, "Aurelius")
	}
	auth0, ok := registry.Get("auth0")
	if !ok {
		t.Fatal("Get(auth0) = false, want true")
	}
	if auth0.Spec().Name != "Auth0" {
		t.Fatalf("auth0 Spec().Name = %q, want %q", auth0.Spec().Name, "Auth0")
	}
	aws, ok := registry.Get("aws")
	if !ok {
		t.Fatal("Get(aws) = false, want true")
	}
	if aws.Spec().Name != "AWS" {
		t.Fatalf("aws Spec().Name = %q, want %q", aws.Spec().Name, "AWS")
	}
	azure, ok := registry.Get("azure")
	if !ok {
		t.Fatal("Get(azure) = false, want true")
	}
	if azure.Spec().Name != "Azure" {
		t.Fatalf("azure Spec().Name = %q, want %q", azure.Spec().Name, "Azure")
	}
	backstage, ok := registry.Get("backstage")
	if !ok {
		t.Fatal("Get(backstage) = false, want true")
	}
	if backstage.Spec().Name != "Backstage" {
		t.Fatalf("backstage Spec().Name = %q, want %q", backstage.Spec().Name, "Backstage")
	}
	cerebro, ok := registry.Get("cerebro")
	if !ok {
		t.Fatal("Get(cerebro) = false, want true")
	}
	if cerebro.Spec().Name != "Cerebro" {
		t.Fatalf("cerebro Spec().Name = %q, want %q", cerebro.Spec().Name, "Cerebro")
	}
	cosmo, ok := registry.Get("cosmo")
	if !ok {
		t.Fatal("Get(cosmo) = false, want true")
	}
	if cosmo.Spec().Name != "Cosmo" {
		t.Fatalf("cosmo Spec().Name = %q, want %q", cosmo.Spec().Name, "Cosmo")
	}
	gcp, ok := registry.Get("gcp")
	if !ok {
		t.Fatal("Get(gcp) = false, want true")
	}
	if gcp.Spec().Name != "GCP" {
		t.Fatalf("gcp Spec().Name = %q, want %q", gcp.Spec().Name, "GCP")
	}
	github, ok := registry.Get("github")
	if !ok {
		t.Fatal("Get(github) = false, want true")
	}
	if github.Spec().Name != "GitHub" {
		t.Fatalf("github Spec().Name = %q, want %q", github.Spec().Name, "GitHub")
	}
	googleWorkspace, ok := registry.Get("google_workspace")
	if !ok {
		t.Fatal("Get(google_workspace) = false, want true")
	}
	if googleWorkspace.Spec().Name != "Google Workspace" {
		t.Fatalf("google_workspace Spec().Name = %q, want %q", googleWorkspace.Spec().Name, "Google Workspace")
	}
	grc, ok := registry.Get("grc")
	if !ok {
		t.Fatal("Get(grc) = false, want true")
	}
	if grc.Spec().Name != "GRC" {
		t.Fatalf("grc Spec().Name = %q, want %q", grc.Spec().Name, "GRC")
	}
	kandji, ok := registry.Get("kandji")
	if !ok {
		t.Fatal("Get(kandji) = false, want true")
	}
	if kandji.Spec().Name != "Kandji / Iru" {
		t.Fatalf("kandji Spec().Name = %q, want %q", kandji.Spec().Name, "Kandji / Iru")
	}
	kolide, ok := registry.Get("kolide")
	if !ok {
		t.Fatal("Get(kolide) = false, want true")
	}
	if kolide.Spec().Name != "Kolide" {
		t.Fatalf("kolide Spec().Name = %q, want %q", kolide.Spec().Name, "Kolide")
	}
	langchain, ok := registry.Get("langchain")
	if !ok {
		t.Fatal("Get(langchain) = false, want true")
	}
	if langchain.Spec().Name != "LangChain" {
		t.Fatalf("langchain Spec().Name = %q, want %q", langchain.Spec().Name, "LangChain")
	}
	langfuse, ok := registry.Get("langfuse")
	if !ok {
		t.Fatal("Get(langfuse) = false, want true")
	}
	if langfuse.Spec().Name != "Langfuse" {
		t.Fatalf("langfuse Spec().Name = %q, want %q", langfuse.Spec().Name, "Langfuse")
	}
	okta, ok := registry.Get("okta")
	if !ok {
		t.Fatal("Get(okta) = false, want true")
	}
	if okta.Spec().Name != "Okta" {
		t.Fatalf("okta Spec().Name = %q, want %q", okta.Spec().Name, "Okta")
	}
	panopticon, ok := registry.Get("panopticon")
	if !ok {
		t.Fatal("Get(panopticon) = false, want true")
	}
	if panopticon.Spec().Name != "Panopticon" {
		t.Fatalf("panopticon Spec().Name = %q, want %q", panopticon.Spec().Name, "Panopticon")
	}
	sdk, ok := registry.Get("sdk")
	if !ok {
		t.Fatal("Get(sdk) = false, want true")
	}
	if sdk.Spec().Name != "SDK Push Source" {
		t.Fatalf("sdk Spec().Name = %q, want %q", sdk.Spec().Name, "SDK Push Source")
	}
	sentinelone, ok := registry.Get("sentinelone")
	if !ok {
		t.Fatal("Get(sentinelone) = false, want true")
	}
	if sentinelone.Spec().Name != "SentinelOne" {
		t.Fatalf("sentinelone Spec().Name = %q, want %q", sentinelone.Spec().Name, "SentinelOne")
	}
	securityToolingMap, ok := registry.Get("security_tooling_map")
	if !ok {
		t.Fatal("Get(security_tooling_map) = false, want true")
	}
	if securityToolingMap.Spec().Name != "Security Tooling Map" {
		t.Fatalf("security_tooling_map Spec().Name = %q, want %q", securityToolingMap.Spec().Name, "Security Tooling Map")
	}
	trustedEndpoint, ok := registry.Get("trusted_endpoint")
	if !ok {
		t.Fatal("Get(trusted_endpoint) = false, want true")
	}
	if trustedEndpoint.Spec().Name != "Trusted Endpoint" {
		t.Fatalf("trusted_endpoint Spec().Name = %q, want %q", trustedEndpoint.Spec().Name, "Trusted Endpoint")
	}
}

func TestBuiltinRegistersGenerateableCatalogSources(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	for _, sourceID := range []string{"linear", "microsoft_teams", "wiz"} {
		source, ok := registry.Get(sourceID)
		if !ok {
			t.Fatalf("Get(%s) = false, want catalog runtime source", sourceID)
		}
		if source.Spec().Id != sourceID {
			t.Fatalf("%s Spec().Id = %q", sourceID, source.Spec().Id)
		}
	}
}

func TestBuiltinRegistersEveryGenerateableCatalogSource(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	catalog, err := connectorcatalog.Builtin()
	if err != nil {
		t.Fatalf("connectorcatalog.Builtin() error = %v", err)
	}
	for _, entry := range catalog.Entries {
		if entry.Status != connectorcatalog.StatusGenerateable {
			t.Fatalf("%s status = %q, want generateable", entry.Definition.SourceID, entry.Status)
		}
		if _, ok := registry.Get(entry.Definition.SourceID); !ok {
			t.Fatalf("registry missing generateable catalog source %s", entry.Definition.SourceID)
		}
	}
}

func TestDynamicDefinitionSourceRejectsBlockedDefinition(t *testing.T) {
	_, err := DynamicDefinitionSource(connectordefinitions.Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Runtime:     connectordefinitions.RuntimeJSONAPI,
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL: "${config.base_url}",
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:      "assets",
			Path:    "https://api.example.test/v1/assets",
			Method:  "POST",
			IDField: "id",
		}},
	})
	if err == nil {
		t.Fatal("DynamicDefinitionSource() error = nil, want blocked definition error")
	}
	if !errors.Is(err, connectordefinitions.ErrInvalidDefinition) {
		t.Fatalf("DynamicDefinitionSource() error = %v, want blocked definition error", err)
	}
}

func TestDynamicDefinitionSourceAcceptsDepositDefinitionWithoutPaths(t *testing.T) {
	source, err := DynamicDefinitionSource(connectordefinitions.Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example_deposit",
		DisplayName: "Example Deposit",
		Runtime:     connectordefinitions.RuntimeJSONAPI,
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Ingest: connectordefinitions.IngestSpec{
			Mode:    connectordefinitions.IngestModeDeposit,
			Deposit: &connectordefinitions.DepositIngestSpec{ResourceFamilies: []string{"assets"}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:         "assets",
			IDField:    "id",
			Event:      connectordefinitions.EventMappingSpec{Kind: "example_deposit.assets", SchemaRef: "example_deposit/assets/v1"},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
		}},
	})
	if err != nil {
		t.Fatalf("DynamicDefinitionSource() error = %v", err)
	}
	if source.Spec().Id != "example_deposit" {
		t.Fatalf("Spec().Id = %q, want example_deposit", source.Spec().Id)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant-a"})); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(nil), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("Read() events = %d, want 0 for deposit source", len(pull.Events))
	}
	provider, ok := source.(sourcecdk.EventContractProvider)
	if !ok {
		t.Fatalf("deposit source does not provide event contracts")
	}
	if contracts := provider.EventContracts(); len(contracts) != 1 || contracts[0].Kind != "example_deposit.assets" {
		t.Fatalf("EventContracts() = %#v, want example_deposit.assets", contracts)
	}
}
