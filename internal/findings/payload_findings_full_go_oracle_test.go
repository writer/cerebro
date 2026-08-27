package findings

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestPayloadFindingFullGoOracle(t *testing.T) {
	rawFixture, err := os.ReadFile("testdata/rules/payload-findings-full-go-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(rawFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		rule    Rule
		runtime *cerebrov1.SourceRuntime
		event   *cerebrov1.EventEnvelope
	}{
		{
			name:    "aurelius",
			rule:    newAureliusPromotedVulnerabilityActiveRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "writer-aurelius-finding", SourceId: "aurelius", TenantId: "writer"},
			event:   aureliusPromotedVulnerabilityEvent("aurelius-vuln-open", nil, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)),
		},
		{
			name:    "cosmo",
			rule:    newCosmoCoordinationActiveRiskRule(),
			runtime: &cerebrov1.SourceRuntime{Id: "writer-cosmo-fact", SourceId: "cosmo", TenantId: "writer"},
			event:   cosmoCoordinationFactEvent("cosmo-risk-1", nil, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		},
	}
	for _, tc := range cases {
		records, err := tc.rule.Evaluate(context.Background(), tc.runtime, tc.event)
		if err != nil || len(records) != 1 {
			t.Fatalf("%s evaluate: len=%d err=%v", tc.name, len(records), err)
		}
		actual, err := json.Marshal(records[0])
		if err != nil {
			t.Fatal(err)
		}
		var actualValue, expectedValue any
		if err := json.Unmarshal(actual, &actualValue); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(fixture[tc.name], &expectedValue); err != nil {
			t.Fatal(err)
		}
		actualCanonical, _ := json.Marshal(actualValue)
		expectedCanonical, _ := json.Marshal(expectedValue)
		if string(actualCanonical) != string(expectedCanonical) {
			t.Fatalf("%s full FindingRecord drift\nactual: %s\nexpected: %s", tc.name, actualCanonical, expectedCanonical)
		}
	}
}
