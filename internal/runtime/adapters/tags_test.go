package adapters

import (
	"reflect"
	"testing"
)

func TestCompactTagsTrimsDeduplicatesAndPreservesOrder(t *testing.T) {
	got := CompactTags(" alpha ", "", "beta", "alpha", "beta", "gamma")
	want := []string{"alpha", "beta", "gamma"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CompactTags() = %v, want %v", got, want)
	}
}
