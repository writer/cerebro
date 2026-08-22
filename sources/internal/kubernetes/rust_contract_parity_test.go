package kubernetesinternal

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

type rustContractParityFixture struct {
	SourceID string                     `json:"source_id"`
	Families []rustContractParityFamily `json:"families"`
}

type rustContractParityFamily struct {
	ID                    string   `json:"id"`
	EventKind             string   `json:"event_kind"`
	SchemaRef             string   `json:"schema_ref"`
	RequiredAttributes    []string `json:"required_attributes"`
	RequiredPayloadFields []string `json:"required_payload_fields"`
}

func TestRustContractParityFixtureMatchesGoOracle(t *testing.T) {
	fixtureBytes, err := readRustContractParityFixture()
	if err != nil {
		t.Fatal(err)
	}
	var fixture rustContractParityFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatalf("decode Rust contract parity fixture: %v", err)
	}
	catalogBytes, err := catalogFS.ReadFile("catalog.internal.yaml")
	if err != nil {
		t.Fatalf("read Go Kubernetes catalog: %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("compile Go Kubernetes catalog: %v", err)
	}
	if fixture.SourceID != catalog.Spec.GetId() {
		t.Fatalf("fixture source_id = %q, want %q", fixture.SourceID, catalog.Spec.GetId())
	}
	publicCatalogBytes, err := os.ReadFile("../../../sources/kubernetes/catalog.yaml")
	if err != nil {
		t.Fatalf("read public Kubernetes catalog: %v", err)
	}
	publicCatalog, err := sourcecdk.LoadSourceCatalog(publicCatalogBytes)
	if err != nil {
		t.Fatalf("compile public Kubernetes catalog: %v", err)
	}
	if len(fixture.Families) != len(catalog.EventContracts) {
		t.Fatalf("fixture families = %d, Go event contracts = %d", len(fixture.Families), len(catalog.EventContracts))
	}
	contracts := make(map[string]sourcecdk.EventContract, len(catalog.EventContracts))
	for _, contract := range catalog.EventContracts {
		contracts[contract.Kind] = contract
	}
	seen := map[string]struct{}{}
	for _, family := range fixture.Families {
		if !slices.Contains(publicCatalog.RuntimeFamilies, family.ID) {
			t.Fatalf("Rust family %q is absent from the public runtime catalog", family.ID)
		}
		if _, duplicate := seen[family.ID]; duplicate {
			t.Fatalf("duplicate Rust family %q", family.ID)
		}
		seen[family.ID] = struct{}{}
		contract, ok := contracts[family.EventKind]
		if !ok {
			t.Fatalf("Rust event kind %q is absent from the Go catalog", family.EventKind)
		}
		if contract.SchemaRef != family.SchemaRef ||
			!slices.Equal(contract.RequiredAttributes, family.RequiredAttributes) ||
			!slices.Equal(contract.RequiredPayloadFields, family.RequiredPayloadFields) {
			t.Fatalf("Rust family %q contract drift: fixture=%#v Go=%#v", family.ID, family, contract)
		}
	}
}

func readRustContractParityFixture() ([]byte, error) {
	return os.ReadFile("../../../crates/source-runtime-next/src/kubernetes/fixtures/go_oracle_contract.json")
}
