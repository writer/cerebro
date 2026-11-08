package main

import "testing"

func TestCanonicalProjectionLocatorMatchesClosedCatalogGrammar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		baseURL string
		path    string
		want    string
		ok      bool
	}{
		{path: "/organization/groups/{group_id}/users", want: "/organization/groups/{}/users", ok: true},
		{baseURL: "https://api.example.com/v1", path: "/groups/${config.group_id}", want: "https://api.example.com/v1/groups/{}", ok: true},
		{baseURL: "http://api.example.com", path: "/users", want: "/users", ok: true},
		{path: "users", ok: false},
		{path: "/users/{bad.value}", ok: false},
		{path: "/users?cursor={cursor}", ok: false},
	}
	for _, test := range tests {
		got, ok := canonicalFamilyLocator(test.baseURL, test.path)
		if got != test.want || ok != test.ok {
			t.Errorf("canonicalFamilyLocator(%q, %q) = %q, %v; want %q, %v", test.baseURL, test.path, got, ok, test.want, test.ok)
		}
	}
}

func TestProjectionSourceLineCount(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]int{"": 0, "one": 1, "one\n": 1, "one\ntwo": 2, "one\ntwo\n": 2} {
		if got := sourceLineCount([]byte(input)); got != want {
			t.Errorf("sourceLineCount(%q) = %d, want %d", input, got, want)
		}
	}
}
