package sourcedeploy

import (
	"strings"
	"testing"
)

func TestRenderEmitsSecretsAndRuntimes(t *testing.T) {
	t.Parallel()
	manifests := []Manifest{
		{
			SourceID:   "okta",
			SecretKeys: []string{"OKTA_API_TOKEN", "OKTA_DOMAIN"},
			Runtimes: []RuntimeManifest{{
				LocalID: "audit",
				Config: map[string]string{
					"domain":   "env:OKTA_DOMAIN",
					"family":   "audit",
					"per_page": "200",
					"since":    "2026-05-01T00:00:00Z",
					"token":    "env:OKTA_API_TOKEN",
				},
			}},
		},
		{
			SourceID:   "sentinelone",
			SecretKeys: []string{"SENTINELONE_API_TOKEN", "SENTINELONE_BASE_URL"},
			Runtimes: []RuntimeManifest{{
				LocalID: "threat",
				Config: map[string]string{
					"base_url": "env:SENTINELONE_BASE_URL",
					"family":   "threat",
					"per_page": "200",
					"token":    "env:SENTINELONE_API_TOKEN",
				},
			}},
		},
	}

	frag, err := Render(manifests, RenderOptions{Environment: "dev", TenantID: "example"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	wantSecrets := []string{"OKTA_API_TOKEN", "OKTA_DOMAIN", "SENTINELONE_API_TOKEN", "SENTINELONE_BASE_URL"}
	if !equalStrings(frag.SourceSecretKeys, wantSecrets) {
		t.Fatalf("secret keys = %v, want %v", frag.SourceSecretKeys, wantSecrets)
	}
	if len(frag.SourceRuntimes) != 2 {
		t.Fatalf("expected 2 rendered runtimes, got %d", len(frag.SourceRuntimes))
	}
	if frag.SourceRuntimes[0].ID != "example-okta-audit" {
		t.Fatalf("runtime[0].id = %q", frag.SourceRuntimes[0].ID)
	}
	if frag.SourceRuntimes[1].ID != "example-sentinelone-threat" {
		t.Fatalf("runtime[1].id = %q", frag.SourceRuntimes[1].ID)
	}
}

func TestRenderRejectsBadOptions(t *testing.T) {
	t.Parallel()
	cases := []RenderOptions{
		{Environment: "dev"},
		{Environment: "dev", TenantID: "Example"},
		{TenantID: "example"},
	}
	for _, opt := range cases {
		if _, err := Render(nil, opt); err == nil {
			t.Fatalf("expected error for opts %#v", opt)
		}
	}
}

func TestFragmentMarshalsDeploymentKeys(t *testing.T) {
	t.Parallel()
	frag := Fragment{
		SourceSecretKeys: []string{"AAA"},
		SourceRuntimes: []RenderedRuntime{{
			ID: "example-source-live", SourceID: "example-source", TenantID: "example",
			Config: map[string]string{"family": "live", "per_page": "200"},
		}},
	}
	data, err := frag.MarshalYAML()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"cerebro:sourceSecretKeys",
		"cerebro:sourceRuntimes",
		"example-source-live",
		"family: live",
		`per_page: "200"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected output to contain %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "cerebro:orchestratorSchedules") {
		t.Fatalf("renderer must not emit cerebro:orchestratorSchedules; ops cadence belongs in deployment automation\n%s", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
