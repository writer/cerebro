package sourceregistry

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	sourcecatalogs "github.com/writer/cerebro/sources"
)

func TestBuiltinWithCatalogOverridesUsesVerifiedDeepSeekCatalog(t *testing.T) {
	path := filepath.Join("..", "..", "contentpacks", "pilot", "connector-deepseek", "content", "source-catalog.yaml")
	payload, err := os.ReadFile(path) // #nosec G304 -- test reads a checked-in pilot fixture.
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	payload = []byte(strings.Replace(string(payload), `name: "DeepSeek"`, `name: "DeepSeek Pack"`, 1))
	registry, err := BuiltinWithCatalogOverrides(map[string][]byte{"deepseek": payload})
	if err != nil {
		t.Fatalf("BuiltinWithCatalogOverrides() error = %v", err)
	}
	source, ok := registry.Get("deepseek")
	if !ok {
		t.Fatal("Get(deepseek) = false")
	}
	if source.Spec().Name != "DeepSeek Pack" {
		t.Fatalf("deepseek Spec().Name = %q", source.Spec().Name)
	}
	assertMetadataOnlySourceFailsClosed(t, "deepseek", "model_catalog", source)
}

func TestBuiltinWithCatalogOverridesRejectsInvalidDeepSeekCatalog(t *testing.T) {
	if _, err := BuiltinWithCatalogOverrides(map[string][]byte{"deepseek": []byte("id: other\n")}); err == nil {
		t.Fatal("BuiltinWithCatalogOverrides() error = nil")
	}
}

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

func TestBuiltinLoadsDockerHubFromConnectorCatalog(t *testing.T) {
	for _, loader := range builtinSourceLoaders {
		if loader.name == "docker_hub" {
			t.Fatal("docker_hub still has a concrete source loader")
		}
	}
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	source, ok := registry.Get("docker_hub")
	if !ok {
		t.Fatal("Get(docker_hub) = false, want catalog-backed source")
	}
	if source.Spec().Name != "Docker Hub" {
		t.Fatalf("docker_hub Spec().Name = %q, want %q", source.Spec().Name, "Docker Hub")
	}
}

func TestBuiltinCatalogSourcesPreservePortableSourceContracts(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	analysis, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		t.Fatalf("connectorcatalog.BuiltinRuntime() error = %v", err)
	}
	static := make(map[string]struct{}, len(builtinSourceLoaders))
	for _, loader := range builtinSourceLoaders {
		static[loader.name] = struct{}{}
	}
	standardPlans, err := loadStandardSourcePlans()
	if err != nil {
		t.Fatalf("loadStandardSourcePlans() error = %v", err)
	}
	workerCatalog := make(map[string]struct{}, len(workerCatalogSourceIDs)+len(standardPlans))
	for _, sourceID := range workerCatalogSourceIDs {
		workerCatalog[sourceID] = struct{}{}
	}
	for sourceID := range standardPlans {
		workerCatalog[sourceID] = struct{}{}
	}
	var dynamicIDs []string
	for _, entry := range analysis.Entries {
		if entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
			continue
		}
		sourceID := entry.Definition.SourceID
		if _, ok := static[sourceID]; ok {
			continue
		}
		dynamicIDs = append(dynamicIDs, sourceID)
		source, ok := registry.Get(sourceID)
		if !ok {
			t.Errorf("Get(%s) = false", sourceID)
			continue
		}
		payload, err := sourcecatalogs.BuiltinCatalog(sourceID)
		if err != nil {
			t.Errorf("BuiltinCatalog(%s) error = %v", sourceID, err)
			continue
		}
		catalog, err := sourcecdk.LoadSourceCatalog(payload)
		if err != nil {
			t.Errorf("LoadSourceCatalog(%s) error = %v", sourceID, err)
			continue
		}
		if !reflect.DeepEqual(source.Spec(), catalog.Spec) {
			t.Errorf("%s source spec differs from portable catalog", sourceID)
		}
		portableFamilyIDs := portableCatalogFamilyIDs(catalog)
		if _, workerOwned := workerCatalog[sourceID]; !workerOwned && !slices.Equal(entry.ResourceFamilyIDs, portableFamilyIDs) {
			t.Errorf("%s portable families = %#v, want %#v", sourceID, entry.ResourceFamilyIDs, portableFamilyIDs)
		}
		coverageProvider, ok := source.(sourcecdk.CoverageContractProvider)
		if !ok || catalog.CoverageContract == nil || !reflect.DeepEqual(coverageProvider.CoverageContract(), *catalog.CoverageContract) {
			t.Errorf("%s coverage contract was not preserved", sourceID)
		}
		eventProvider, ok := source.(sourcecdk.EventContractProvider)
		if !ok || !reflect.DeepEqual(eventProvider.EventContracts(), catalog.EventContracts) {
			t.Errorf("%s event contracts were not preserved", sourceID)
		}
		lifecycleProvider, ok := source.(sourcecdk.LifecycleContractProvider)
		if !ok || catalog.LifecycleContract == nil || !reflect.DeepEqual(lifecycleProvider.LifecycleContract(), *catalog.LifecycleContract) {
			t.Errorf("%s lifecycle contract was not preserved", sourceID)
		}
	}
	if len(dynamicIDs) == 0 || !slices.IsSorted(dynamicIDs) {
		t.Fatalf("dynamic catalog source ids are empty or nondeterministic: %#v", dynamicIDs)
	}
	registrySpecs := registry.List()
	for index := 1; index < len(registrySpecs); index++ {
		if registrySpecs[index-1].Id >= registrySpecs[index].Id {
			t.Fatalf("registry source ids are not unique and deterministic at %q, %q", registrySpecs[index-1].Id, registrySpecs[index].Id)
		}
	}
}

func portableCatalogFamilyIDs(catalog *sourcecdk.SourceCatalog) []string {
	if catalog.ProviderAPI == nil {
		return catalog.RuntimeFamilies
	}
	providerFamilyIDs := make([]string, 0, len(catalog.ProviderAPI.Families))
	for _, family := range catalog.ProviderAPI.Families {
		if !slices.Contains(providerFamilyIDs, family.ID) {
			providerFamilyIDs = append(providerFamilyIDs, family.ID)
		}
	}
	for _, familyID := range catalog.RuntimeFamilies {
		if !slices.Contains(providerFamilyIDs, familyID) {
			return catalog.RuntimeFamilies
		}
	}
	return providerFamilyIDs
}

func TestBuiltinKeepsOnlyCatalogCompatibilityExceptionsAsStaticLoaders(t *testing.T) {
	compatibilityExceptions := map[string]bool{
		"anthropic":             true,
		"azure":                 true,
		"github":                true,
		"google_drive":          true,
		"kandji":                true,
		"kolide":                true,
		"kubernetes":            true,
		"langfuse":              true,
		"okta":                  true,
		"onelogin":              true,
		"sailpoint_identitynow": true,
		"snyk":                  true,
		"writer":                true,
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		t.Fatalf("connectorcatalog.BuiltinRuntime() error = %v", err)
	}
	entries := make(map[string]connectorcatalog.Entry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		entries[entry.Definition.SourceID] = entry
	}
	seenExceptions := make(map[string]bool, len(compatibilityExceptions))
	for _, loader := range builtinSourceLoaders {
		entry, ok := entries[loader.name]
		if !ok {
			continue
		}
		if compatibilityExceptions[loader.name] {
			seenExceptions[loader.name] = true
			continue
		}
		if entry.Report.Verdict == connectordefinitions.SupportVerdictSupported {
			t.Errorf("catalog-supported source %q has a redundant compile-time loader", loader.name)
		}
	}
	for sourceID := range compatibilityExceptions {
		if !seenExceptions[sourceID] {
			t.Errorf("catalog compatibility exception %q has no static loader", sourceID)
		}
	}
}

func TestBuiltinRetiresCoveredProviderGoLoaders(t *testing.T) {
	retired := []string{
		"abnormal_security",
		"activtrak",
		"acunetix",
		"ada_support",
		"addigy",
		"adobe_workfront",
		"aha",
		"aircall",
		"airfocus",
		"akeneo",
		"akeyless",
		"amplitude",
		"asana",
		"backstage",
		"beezup",
		"bitwarden",
		"box",
		"cloudflare",
		"conjur",
		"deepseek",
		"digitalocean",
		"discord",
		"doppler",
		"duo",
		"fivetran",
		"increase",
		"jira",
		"jumpcloud",
		"langchain",
		"openai",
		"pagerduty",
		"sentinelone",
		"tailscale",
		"twilio",
	}
	static := make(map[string]struct{}, len(builtinSourceLoaders))
	for _, loader := range builtinSourceLoaders {
		static[loader.name] = struct{}{}
	}
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	for _, sourceID := range retired {
		if _, ok := static[sourceID]; ok {
			t.Errorf("retired provider %q still has a static Go loader", sourceID)
		}
		if _, ok := registry.Get(sourceID); !ok {
			t.Errorf("retired provider %q is not registered through its current runtime", sourceID)
		}
	}
}

func TestRustOwnedCatalogSourcesKeepMetadataAndFailClosedWithoutWorkerRouting(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	standardPlans, err := loadStandardSourcePlans()
	if err != nil {
		t.Fatal(err)
	}
	for _, sourceID := range append(slices.Clone(workerCatalogSourceIDs), slices.Sorted(maps.Keys(standardPlans))...) {
		source, ok := registry.Get(sourceID)
		if !ok || source.Spec().GetId() != sourceID {
			t.Fatalf("Rust-owned source %q is missing its portable catalog metadata", sourceID)
		}
		family := map[string]string{"asana": "users", "digitalocean": "droplets", "discord": "audit_log", "pagerduty": "user", "sentinelone": "threat"}[sourceID]
		if plan, ok := standardPlans[sourceID]; ok {
			family = plan[0]
		}
		assertMetadataOnlySourceFailsClosed(t, sourceID, family, source)
	}
}

func assertMetadataOnlySourceFailsClosed(t *testing.T, sourceID, family string, source sourcecdk.Source) {
	t.Helper()
	ctx := context.Background()
	cfg := sourcecdk.NewConfig(map[string]string{"family": family})
	for operation, err := range map[string]error{
		"check":    func() error { return source.Check(ctx, cfg) }(),
		"discover": func() error { _, err := source.Discover(ctx, cfg); return err }(),
		"read":     func() error { _, err := source.Read(ctx, cfg, nil); return err }(),
	} {
		if !errors.Is(err, errAuthoritativeRuntimeRequired) {
			t.Fatalf("Rust-owned source %q direct %s error = %v, want authoritative runtime requirement", sourceID, operation, err)
		}
	}
	checkpointSource, ok := source.(sourcecdk.CheckpointAwareSource)
	if !ok {
		t.Fatalf("Rust-owned source %q is missing checkpoint compatibility", sourceID)
	}
	if _, err := checkpointSource.ReadWithCheckpoint(ctx, cfg, nil, nil); !errors.Is(err, errAuthoritativeRuntimeRequired) {
		t.Fatalf("Rust-owned source %q checkpoint read error = %v, want authoritative runtime requirement", sourceID, err)
	}
}

func TestTwilioCatalogRuntimeFixturesCoverEveryPortableFamily(t *testing.T) {
	payload, err := sourcecatalogs.BuiltinCatalog("twilio")
	if err != nil {
		t.Fatalf("BuiltinCatalog(twilio) error = %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(payload)
	if err != nil {
		t.Fatalf("LoadSourceCatalog(twilio) error = %v", err)
	}
	fixtureFS := os.DirFS(filepath.Join("..", "..", "sources", "twilio"))
	for _, family := range catalog.RuntimeFamilies {
		urns, err := sourcecdk.LoadFixtureURNs(fixtureFS, "testdata/discover_"+family+".json")
		if err != nil {
			t.Errorf("load %s discover fixture: %v", family, err)
		} else if len(urns) == 0 {
			t.Errorf("%s discover fixture is empty", family)
		}
		events, err := sourcecdk.LoadFixtureEventsWithContracts(fixtureFS, "testdata/read_"+family+".json", catalog.EventContracts)
		if err != nil {
			t.Errorf("load %s read fixture: %v", family, err)
		} else if len(events) == 0 {
			t.Errorf("%s read fixture is empty", family)
		}
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
			continue
		}
		if _, ok := registry.Get(entry.Definition.SourceID); !ok {
			t.Fatalf("registry missing generateable catalog source %s", entry.Definition.SourceID)
		}
	}
}

func TestBuiltinRegistersEverySupportedRuntimeCatalogSource(t *testing.T) {
	registry, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		t.Fatalf("connectorcatalog.BuiltinRuntime() error = %v", err)
	}
	supported := 0
	var missing []string
	for _, entry := range catalog.Entries {
		if entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
			continue
		}
		supported++
		sourceID := entry.Definition.SourceID
		source, ok := registry.Get(sourceID)
		if !ok {
			missing = append(missing, sourceID)
			continue
		}
		if source.Spec().Id != sourceID {
			t.Fatalf("%s Spec().Id = %q, want %q", sourceID, source.Spec().Id, sourceID)
		}
	}
	if len(missing) != 0 {
		t.Fatalf("registry missing supported runtime catalog sources: %#v", missing)
	}
	if got := len(registry.List()); got < supported {
		t.Fatalf("registry.List() len = %d, want at least %d supported runtime catalog sources", got, supported)
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
