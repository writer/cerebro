// Package cloudidentitysource implements Source CDK adapters for the Cerebro
// Kubernetes cloud-identity scan. All provider/network I/O for cloud-identity
// collection lives here; internal/cloudidentity stays pure computation.
package cloudidentitysource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	goyaml "gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"
)

// manifestClusterScopedKinds lists built-in Kubernetes kinds that are never
// namespaced; a rendered object of one of these kinds is never stamped with
// a release/destination namespace.
var manifestClusterScopedKinds = map[string]bool{
	"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true,
	"CustomResourceDefinition": true, "PersistentVolume": true,
	"StorageClass": true, "Node": true, "APIService": true,
	"CompositeResourceDefinition": true, "Composition": true,
}

// manifestFindFile returns the repository file at exactly path, or ok=false.
func manifestFindFile(repo ci.Repository, filePath string) (ci.SourceFile, bool) {
	clean := path.Clean(strings.TrimPrefix(filePath, "/"))
	for _, f := range repo.Files {
		if path.Clean(strings.TrimPrefix(f.Path, "/")) == clean {
			return f, true
		}
	}
	return ci.SourceFile{}, false
}

// manifestFilesUnderRoot returns every repository file under root (a
// directory prefix), with Path left untouched (caller-relative trimming is
// context specific). Entries that resolve outside root after cleaning are
// excluded defensively even though Repository content is already pinned.
func manifestFilesUnderRoot(repo ci.Repository, root string) []ci.SourceFile {
	root = strings.TrimSuffix(strings.TrimPrefix(path.Clean(root), "/"), "/")
	var out []ci.SourceFile
	for _, f := range repo.Files {
		clean := path.Clean(strings.TrimPrefix(f.Path, "/"))
		if root == "" || root == "." {
			out = append(out, f)
			continue
		}
		if clean == root || strings.HasPrefix(clean, root+"/") {
			out = append(out, f)
		}
	}
	return out
}

// manifestSafeRelative returns full's path relative to root, rejecting any
// result that escapes root (e.g. via "../"), which pinned repository content
// should never produce but which we never trust blindly.
func manifestSafeRelative(root, full string) (string, bool) {
	root = strings.TrimSuffix(strings.TrimPrefix(path.Clean(root), "/"), "/")
	clean := path.Clean(strings.TrimPrefix(full, "/"))
	if root == "" || root == "." {
		if strings.HasPrefix(clean, "../") || clean == ".." {
			return "", false
		}
		return clean, true
	}
	if clean == root {
		return "", false
	}
	if !strings.HasPrefix(clean, root+"/") {
		return "", false
	}
	rel := strings.TrimPrefix(clean, root+"/")
	if strings.HasPrefix(rel, "../") || rel == ".." {
		return "", false
	}
	return rel, true
}

// manifestSplitYAMLDocuments splits raw multi-document YAML bytes into
// individual document byte slices, skipping empty documents.
func manifestSplitYAMLDocuments(data []byte) ([][]byte, error) {
	var docs [][]byte
	dec := goyaml.NewDecoder(bytes.NewReader(data))
	for {
		var node goyaml.Node
		err := dec.Decode(&node)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return docs, err
		}
		if node.Kind == 0 {
			continue
		}
		out, err := goyaml.Marshal(&node)
		if err != nil {
			return docs, err
		}
		if len(bytes.TrimSpace(out)) == 0 {
			continue
		}
		docs = append(docs, out)
	}
	return docs, nil
}

// manifestDecodeDocument decodes one YAML document into the generic
// map[string]any shape ci.Manifest.Object uses, stamping a default namespace
// onto namespaced objects that do not declare one, and computing a stable
// content digest for the Reference.
func manifestDecodeDocument(raw []byte, ref ci.Reference, defaultNamespace string) (ci.Manifest, bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ci.Manifest{}, false, nil
	}
	jsonBytes, err := k8syaml.YAMLToJSON(raw)
	if err != nil {
		return ci.Manifest{}, false, fmt.Errorf("decode manifest: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(jsonBytes), []byte("null")) {
		return ci.Manifest{}, false, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return ci.Manifest{}, false, fmt.Errorf("decode manifest: %w", err)
	}
	if obj["kind"] == nil {
		return ci.Manifest{}, false, nil
	}
	if metadata, exists := obj["metadata"]; exists && metadata != nil {
		if _, ok := metadata.(map[string]any); !ok {
			return ci.Manifest{}, false, fmt.Errorf("decode manifest: metadata must be an object")
		}
	}
	manifestStampNamespace(obj, defaultNamespace)
	ref.Digest = manifestContentDigest(obj)
	return ci.Manifest{Object: obj, Reference: ref}, true, nil
}

func manifestStampNamespace(obj map[string]any, namespace string) {
	if namespace == "" {
		return
	}
	kind, _ := obj["kind"].(string)
	if manifestClusterScopedKinds[kind] {
		return
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	if ns, ok := meta["namespace"].(string); ok && ns != "" {
		return
	}
	meta["namespace"] = namespace
}

// manifestContentDigest computes a stable sha256 over a canonical JSON
// encoding (Go's encoding/json sorts map keys) of the decoded object. It is
// local adapter provenance, unrelated to the core evidence digest.
func manifestContentDigest(obj map[string]any) string {
	canonical, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func manifestBytesDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// manifestDecodeRawPath decodes every YAML document in one repository file
// (or, when path names a directory prefix, every .yaml/.yml file under it)
// into manifests, with a Reference pinned to the owning repository/revision.
func manifestDecodeRawPath(repo ci.Repository, requestPath string, defaultNamespace string) ([]ci.Manifest, []ci.Gap, error) {
	if file, ok := manifestFindFile(repo, requestPath); ok {
		return manifestDecodeRawFile(repo, file, defaultNamespace)
	}
	files := manifestFilesUnderRoot(repo, requestPath)
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("path %q was not found in the pinned repository", requestPath)
	}
	var manifests []ci.Manifest
	var gaps []ci.Gap
	for _, f := range files {
		if !manifestIsYAMLFile(f.Path) {
			continue
		}
		m, g, err := manifestDecodeRawFile(repo, f, defaultNamespace)
		manifests = append(manifests, m...)
		gaps = append(gaps, g...)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.path_unreadable", Scope: f.Path, Message: err.Error()})
		}
	}
	return manifests, gaps, nil
}

func manifestIsYAMLFile(p string) bool {
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

func manifestDecodeRawFile(repo ci.Repository, file ci.SourceFile, defaultNamespace string) ([]ci.Manifest, []ci.Gap, error) {
	docs, err := manifestSplitYAMLDocuments(file.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("split %q: %w", file.Path, err)
	}
	var manifests []ci.Manifest
	var gaps []ci.Gap
	base := ci.Reference{Repository: repo.Pin.Repository, Revision: repo.Pin.Revision, Path: file.Path}
	for i, doc := range docs {
		ref := base
		if len(docs) > 1 {
			ref.Path = fmt.Sprintf("%s#%d", file.Path, i)
		}
		m, ok, err := manifestDecodeDocument(doc, ref, defaultNamespace)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.document_malformed", Scope: ref.Path, Message: err.Error()})
			continue
		}
		if !ok {
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, gaps, nil
}
