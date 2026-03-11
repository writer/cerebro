package graph

import "testing"

func FuzzSlugForRuleID(f *testing.F) {
	f.Add("TC-AWS-001")
	f.Add("  Revenue Risk / Stripe  ")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		slug := slugForRuleID(raw)
		if slug == "" {
			t.Fatal("slug should never be empty")
		}
		for _, r := range slug {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			t.Fatalf("slug contains invalid character %q for input %q", r, raw)
		}
	})
}
