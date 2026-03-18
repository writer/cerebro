package graph

import "testing"

func TestEntitySearchTrigrams_UsesRunes(t *testing.T) {
	got := entitySearchTrigrams("über")
	want := []string{"übe", "ber"}
	if len(got) != len(want) {
		t.Fatalf("trigram count = %d, want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trigram[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
