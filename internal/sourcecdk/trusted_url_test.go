package sourcecdk

import (
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/sourceconfig"
)

var errTestComponents = errors.New("invalid test url components")

func TestNormalizeTrustedURLRejectsHTTPWithoutLoopback(t *testing.T) {
	if _, err := NormalizeTrustedURL("test", "base_url", "http://example.test/api", false, errTestComponents); err == nil {
		t.Fatal("error = nil, want https requirement enforced")
	}
}

func TestNormalizeTrustedURLAllowsHTTPLoopback(t *testing.T) {
	got, err := NormalizeTrustedURL("test", "base_url", "http://127.0.0.1:9999/api/", true, errTestComponents)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if got != "http://127.0.0.1:9999/api" {
		t.Fatalf("got = %q, want trailing slash trimmed", got)
	}
}

func TestNormalizeTrustedURLRejectsFragmentWithSentinel(t *testing.T) {
	_, err := NormalizeTrustedURL("test", "base_url", "https://example.test/api#frag", false, errTestComponents)
	if !errors.Is(err, errTestComponents) {
		t.Fatalf("error = %v, want wrapped errTestComponents", err)
	}
}

func TestNormalizeTrustedURLRejectsUnsafeHost(t *testing.T) {
	if _, err := NormalizeTrustedURL("test", "base_url", "https://169.254.169.254/api", false, errTestComponents); err == nil {
		t.Fatal("error = nil, want unsafe host rejected")
	}
}

func TestNormalizeTrustedURLRejectsCustomPortWithoutLoopback(t *testing.T) {
	if _, err := NormalizeTrustedURL("test", "base_url", "https://example.test:8443/api", false, errTestComponents); err == nil {
		t.Fatal("error = nil, want custom port rejected")
	}
}

func TestRequireTrustedOriginAcceptsMatchingOrigin(t *testing.T) {
	if err := RequireTrustedOrigin("test", "base_url", "Test", "https://example.test/api", "https://example.test/api"); err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
}

func TestRequireTrustedOriginRejectsDifferentHost(t *testing.T) {
	err := RequireTrustedOrigin("test", "base_url", "Test", "https://attacker.example/api", "https://example.test/api")
	if err == nil {
		t.Fatal("error = nil, want untrusted origin rejected")
	}
}

func TestRequireIssuerTokenURLAcceptsDerivedEndpoint(t *testing.T) {
	err := RequireIssuerTokenURL("test", "issuer", "https://issuer.example", "/v1/token", "https://issuer.example/v1/token", false)
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
}

func TestRequireIssuerTokenURLRejectsMismatchedEndpoint(t *testing.T) {
	err := RequireIssuerTokenURL("test", "issuer", "https://issuer.example", "/v1/token", "https://attacker.example/token", false)
	if err == nil {
		t.Fatal("error = nil, want mismatched token_url rejected")
	}
}

func TestRequireTrustedOriginFromDeploymentAllowlistAcceptsConfiguredOrigin(t *testing.T) {
	cfg := NewConfig(map[string]string{
		sourceconfig.SourceTrustedOriginsKey: "test=https://vendor.example.test",
	})
	if err := RequireTrustedOriginFromDeploymentAllowlist(cfg, "test", "base_url", "Test", "https://vendor.example.test/api"); err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
}

func TestRequireTrustedOriginFromDeploymentAllowlistRejectsUntrustedOrigin(t *testing.T) {
	cfg := NewConfig(map[string]string{
		sourceconfig.SourceTrustedOriginsKey: "test=https://vendor.example.test",
	})
	if err := RequireTrustedOriginFromDeploymentAllowlist(cfg, "test", "base_url", "Test", "https://attacker.example/api"); err == nil {
		t.Fatal("error = nil, want untrusted origin rejected")
	}
}

func TestRequireTrustedOriginFromDeploymentAllowlistRejectsMissingAllowlist(t *testing.T) {
	cfg := NewConfig(map[string]string{})
	if err := RequireTrustedOriginFromDeploymentAllowlist(cfg, "test", "base_url", "Test", "https://vendor.example.test/api"); err == nil {
		t.Fatal("error = nil, want missing allowlist rejected")
	}
}
