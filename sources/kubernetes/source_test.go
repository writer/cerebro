package kubernetes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "kubernetes" {
		t.Fatalf("Spec().Id = %q, want kubernetes", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		"cluster",
		"container",
		"ingress",
		"namespace",
		"node",
		"pod",
		"rbac_binding",
		"rbac_role",
		"service",
		"service_account",
		"workload",
		"workload_identity_binding",
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	kubeconfig := []byte(`apiVersion: v1
kind: Config
clusters:
- name: unavailable
  cluster:
    server: ` + server.URL + `
contexts:
- name: unavailable
  context:
    cluster: unavailable
    user: unavailable
current-context: unavailable
users:
- name: unavailable
  user: {}
`)
	path := t.TempDir() + "/kubeconfig"
	if err := os.WriteFile(path, kubeconfig, 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family":          "cluster",
		"kubeconfig_path": path,
		"tenant_id":       "tenant",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "read kubernetes server version") {
		t.Fatalf("Read() error = %q, want server version provider error", got)
	}
}
