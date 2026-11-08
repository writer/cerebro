package sourcecdk

import (
	"reflect"
	"testing"
)

type versionedFixture struct {
	key     string
	version int
}

func TestKeepHighestVersionKeepsHighestPerKey(t *testing.T) {
	items := []versionedFixture{
		{key: "a", version: 1},
		{key: "a", version: 3},
		{key: "a", version: 2},
		{key: "b", version: 1},
	}
	got := KeepHighestVersion(items, func(v versionedFixture) string { return v.key },
		func(a, b versionedFixture) bool { return a.version > b.version })
	want := []versionedFixture{{key: "a", version: 3}, {key: "b", version: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got = %+v, want %+v", got, want)
	}
}

func TestKeepHighestVersionPreservesFirstSeenKeyOrder(t *testing.T) {
	items := []versionedFixture{
		{key: "b", version: 1},
		{key: "a", version: 1},
		{key: "b", version: 2},
	}
	got := KeepHighestVersion(items, func(v versionedFixture) string { return v.key },
		func(a, b versionedFixture) bool { return a.version > b.version })
	if len(got) != 2 || got[0].key != "b" || got[1].key != "a" {
		t.Fatalf("got = %+v, want order [b a]", got)
	}
}

func TestKeepHighestVersionDropsEmptyKeyItems(t *testing.T) {
	items := []versionedFixture{{key: "", version: 1}, {key: "a", version: 1}}
	got := KeepHighestVersion(items, func(v versionedFixture) string { return v.key },
		func(a, b versionedFixture) bool { return a.version > b.version })
	if len(got) != 1 || got[0].key != "a" {
		t.Fatalf("got = %+v, want only the non-empty key", got)
	}
}
