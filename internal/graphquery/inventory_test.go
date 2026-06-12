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
