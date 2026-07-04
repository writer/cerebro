package graphquery

import (
	"reflect"
	"testing"
)

func TestInventoryEntityTypesForFilterUsesSynthesizedCategoryID(t *testing.T) {
	got := inventoryEntityTypesForFilter("aws-lambda-function", "")
	want := []string{"aws.lambda.function"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventoryEntityTypesForFilterKeepsKnownGroupedCategory(t *testing.T) {
	got := inventoryEntityTypesForFilter("compute-instances", "")
	want := []string{"aws.ec2.instance", "gcp.compute.instance"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventoryEntityTypesForFilterEntityTypePrecedence(t *testing.T) {
	got := inventoryEntityTypesForFilter("compute-instances", "aws.lambda.function")
	want := []string{"aws.lambda.function"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventoryEntityTypesForFilter() = %v, want %v", got, want)
	}
}

func TestInventorySurfaceForEntityType(t *testing.T) {
	tests := []struct {
		name       string
		entityType string
		want       string
	}{
		{name: "reviewable asset", entityType: "sentinelone.agent", want: InventorySurfaceAsset},
		{name: "component", entityType: "sentinelone.installed_application", want: InventorySurfaceComponent},
		{name: "policy rule component", entityType: "policy.rule", want: InventorySurfaceComponent},
		{name: "evidence requirement component", entityType: "evidence.requirement", want: InventorySurfaceComponent},
		{name: "alias", entityType: "identifier.login", want: InventorySurfaceAlias},
		{name: "signal", entityType: "panopticon.alert", want: InventorySurfaceSignal},
		{name: "coverage gap signal", entityType: "coverage.gap", want: InventorySurfaceSignal},
		{name: "raw record", entityType: "okta.resource", want: InventorySurfaceRawRecord},
		{name: "known finding signal", entityType: "aws.securityhub.finding", want: InventorySurfaceSignal},
		{name: "unknown alert suffix", entityType: "custom_vendor.alert", want: InventorySurfaceAsset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InventorySurfaceForEntityType(tt.entityType); got != tt.want {
				t.Fatalf("InventorySurfaceForEntityType(%q) = %q, want %q", tt.entityType, got, tt.want)
			}
		})
	}
}

func TestNormalizeInventorySurfaceDefaultsToAll(t *testing.T) {
	if got := NormalizeInventorySurface(""); got != InventorySurfaceAll {
		t.Fatalf("NormalizeInventorySurface(\"\") = %q, want %q", got, InventorySurfaceAll)
	}
	if got := NormalizeInventorySurface("unknown"); got != InventorySurfaceAsset {
		t.Fatalf("NormalizeInventorySurface(\"unknown\") = %q, want %q", got, InventorySurfaceAsset)
	}
}

func TestInventorySurfaceParamsDefaultKeepsAllRecords(t *testing.T) {
	clause, params := inventorySurfaceParams("")
	if clause != "" {
		t.Fatalf("inventorySurfaceParams(\"\") clause = %q, want empty clause", clause)
	}
	if len(params) != 0 {
		t.Fatalf("inventorySurfaceParams(\"\") params = %v, want none", params)
	}
}

func TestInventorySurfaceParamsExcludeSupportingRecordsFromAssetSurface(t *testing.T) {
	_, params := inventorySurfaceParams(InventorySurfaceAsset)
	exact, _ := params["surface_excluded_entity_types"].([]string)
	prefixes, _ := params["surface_excluded_prefixes"].([]string)
	suffixes, _ := params["surface_excluded_suffixes"].([]string)
	if !inventoryTestContains(exact, "sentinelone.installed_application") {
		t.Fatalf("asset surface exclusions missing sentinelone.installed_application: %v", exact)
	}
	if !inventoryTestContains(prefixes, "identifier.") {
		t.Fatalf("asset surface prefix exclusions missing identifier.: %v", prefixes)
	}
	if !inventoryTestContains(exact, "aws.securityhub.finding") {
		t.Fatalf("asset surface exact exclusions missing aws.securityhub.finding: %v", exact)
	}
	if len(suffixes) != 0 {
		t.Fatalf("asset surface suffix exclusions = %v, want none", suffixes)
	}
}

func inventoryTestContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
