package projectionmeta

import (
	"encoding/json"
	"strings"
	"testing"
)

// DerivedEntityProperties must reproduce, exactly, the equality semantics of the
// rule Cypher predicates it replaces, evaluated against the same attributes_json
// blob the store writes. The oracle here builds that blob with encoding/json
// (the store's graphAttributesJSON marshals the same map[string]string) and
// applies the literal CONTAINS substring the rules use:
//   - internet_exposed: case-sensitive `"<key>":"true"`.
//   - privileged / mfa: lower-cased `"<key>":"true|false"` (the rules toLower
//     the whole user_attrs string before matching).
func TestDerivedEntityPropertiesMirrorRuleCypherSemantics(t *testing.T) {
	cases := []map[string]string{
		{},
		{"internet_exposed": "true"},
		{"external_exposure": "true"},
		{"public": "true"},
		{"internet_exposed": "false"},
		{"internet_exposed": "True"},  // case-sensitive predicate: no match
		{"public": "TRUE"},            // case-sensitive predicate: no match
		{"internet_exposed": " true"}, // whitespace breaks the substring: no match
		{"is_admin": "true"},
		{"is_admin": "True"}, // lower-cased predicate: matches
		{"is_delegated_admin": "true"},
		{"is_admin": "false"},
		{"is_admin": "yes"}, // broad Go truthy but Cypher wants "true": no match
		{"mfa_enrolled": "false"},
		{"mfa_enforced": "False"}, // lower-cased predicate: matches
		{"is_enrolled_in_2sv": "false"},
		{"is_enforced_in_2sv": "false"},
		{"mfa_enrolled": "true"},
		{"internet_exposed": "true", "is_admin": "true", "mfa_enrolled": "false"},
	}
	for _, attrs := range cases {
		blob := mustMarshalJSON(t, attrs)
		lower := strings.ToLower(blob)
		got := DerivedEntityProperties(attrs)

		wantExposed := strings.Contains(blob, `"internet_exposed":"true"`) ||
			strings.Contains(blob, `"external_exposure":"true"`) ||
			strings.Contains(blob, `"public":"true"`)
		if got.InternetExposed != wantExposed {
			t.Fatalf("InternetExposed for %v = %v, want %v", attrs, got.InternetExposed, wantExposed)
		}

		wantPrivileged := strings.Contains(lower, `"is_admin":"true"`) ||
			strings.Contains(lower, `"is_delegated_admin":"true"`)
		if got.PrivilegedIdentity != wantPrivileged {
			t.Fatalf("PrivilegedIdentity for %v = %v, want %v", attrs, got.PrivilegedIdentity, wantPrivileged)
		}

		wantMFADisabled := strings.Contains(lower, `"mfa_enrolled":"false"`) ||
			strings.Contains(lower, `"mfa_enforced":"false"`) ||
			strings.Contains(lower, `"is_enrolled_in_2sv":"false"`) ||
			strings.Contains(lower, `"is_enforced_in_2sv":"false"`)
		if got.MFADisabled != wantMFADisabled {
			t.Fatalf("MFADisabled for %v = %v, want %v", attrs, got.MFADisabled, wantMFADisabled)
		}
	}
}

func TestDerivedEntityPropertiesAlwaysPopulatesEveryProperty(t *testing.T) {
	props := DerivedEntityProperties(map[string]string{"unrelated": "value"})
	if props.InternetExposed || props.PrivilegedIdentity || props.MFADisabled {
		t.Fatalf("unrelated attributes derived a true property: %#v", props)
	}
}

func mustMarshalJSON(t *testing.T, attrs map[string]string) string {
	t.Helper()
	encoded, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	return string(encoded)
}
