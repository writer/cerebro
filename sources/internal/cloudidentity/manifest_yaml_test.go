package cloudidentitysource

import "testing"

func TestManifestDecodeRawPathMultiDocument(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{
		"deploy/app.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n  namespace: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: img:v1\n",
	})
	manifests, gaps, err := manifestDecodeRawPath(repo, "deploy/app.yaml", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(manifests) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(manifests))
	}
	if manifests[0].Reference.Repository != "github.com/example/gitops" || manifests[0].Reference.Revision != "abc123" {
		t.Fatalf("unexpected reference provenance: %+v", manifests[0].Reference)
	}
	if manifests[0].Reference.Digest == "" {
		t.Fatalf("expected a content digest to be computed")
	}
}

func TestManifestDecodeRawPathNamespaceStamping(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{
		"deploy/app.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec: {}\n",
	})
	manifests, _, err := manifestDecodeRawPath(repo, "deploy/app.yaml", "payments")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 document, got %d", len(manifests))
	}
	meta, _ := manifestNestedMap(manifests[0].Object, "metadata")
	if meta["namespace"] != "payments" {
		t.Fatalf("expected namespace stamped to payments, got %+v", meta)
	}
}

func TestManifestDecodeRawPathClusterScopedNotStamped(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{
		"deploy/ns.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: payments\n",
	})
	manifests, _, err := manifestDecodeRawPath(repo, "deploy/ns.yaml", "some-other-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	meta, _ := manifestNestedMap(manifests[0].Object, "metadata")
	if _, ok := meta["namespace"]; ok {
		t.Fatalf("cluster-scoped kinds must never be stamped with a namespace, got %+v", meta)
	}
}

func TestManifestDecodeRawPathDirectoryWalksYAMLFilesOnly(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{
		"deploy/app.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: ns\n",
		"deploy/README.md":   "not yaml",
		"deploy/other/b.yml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n  namespace: ns\n",
	})
	manifests, _, err := manifestDecodeRawPath(repo, "deploy", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) != 2 {
		t.Fatalf("expected 2 yaml documents under deploy/, got %d: %+v", len(manifests), manifests)
	}
}

func TestManifestDecodeRawPathMalformedDocumentBecomesGap(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{
		"deploy/bad.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: [this, is, not, a, map]\n",
	})
	manifests, gaps, err := manifestDecodeRawPath(repo, "deploy/bad.yaml", "")
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(manifests) != 0 {
		t.Fatalf("expected no manifests from a malformed document, got %+v", manifests)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.document_malformed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected document_malformed gap, got %+v", gaps)
	}
}

func TestManifestDecodeRawPathMissingPathErrors(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", map[string]string{})
	_, _, err := manifestDecodeRawPath(repo, "does/not/exist.yaml", "")
	if err == nil {
		t.Fatalf("expected an error for a missing path")
	}
}

func TestManifestSafeRelativeRejectsEscape(t *testing.T) {
	if _, ok := manifestSafeRelative("charts/app", "charts/other/values.yaml"); ok {
		t.Fatalf("expected escape outside root to be rejected")
	}
	if rel, ok := manifestSafeRelative("charts/app", "charts/app/templates/deployment.yaml"); !ok || rel != "templates/deployment.yaml" {
		t.Fatalf("expected relative path within root, got %q ok=%v", rel, ok)
	}
}
