package setutil

import (
	"reflect"
	"testing"
)

func TestSortedStringsReturnsStableSortedSlice(t *testing.T) {
	got := SortedStrings(map[string]struct{}{
		"charlie": {},
		"alpha":   {},
		"bravo":   {},
	})
	want := []string{"alpha", "bravo", "charlie"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SortedStrings() = %v, want %v", got, want)
	}
}

func TestSortedStringsNilForEmptySet(t *testing.T) {
	if got := SortedStrings(nil); got != nil {
		t.Fatalf("SortedStrings(nil) = %v, want nil", got)
	}
}
