package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const projectionExclusionV1 = "cerebro.rustcarve.path-exclusions/v1"

type projectionPathExclusions struct {
	SchemaVersion string   `json:"schema_version"`
	Owner         string   `json:"owner"`
	Revision      string   `json:"revision"`
	Paths         []string `json:"paths"`
}

type projectionOwnershipRecord struct {
	Owner          string   `json:"owner,omitempty"`
	Revision       string   `json:"revision,omitempty"`
	ManifestPath   string   `json:"manifest_path,omitempty"`
	ManifestDigest string   `json:"manifest_digest_sha256,omitempty"`
	Paths          []string `json:"paths,omitempty"`
}

func secureRepositoryRoot(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve root symlinks: %w", err)
	}
	for _, required := range []string{"go.mod", "Cargo.toml", "internal/connectorcatalog/catalog", "internal/sourceprojection"} {
		if _, err := os.Stat(filepath.Join(root, required)); err != nil {
			return "", fmt.Errorf("repository root missing %s: %w", required, err)
		}
	}
	return root, nil
}

func loadProjectionExclusions(root, relative string) (map[string]struct{}, projectionOwnershipRecord, error) {
	set := make(map[string]struct{})
	if strings.TrimSpace(relative) == "" {
		return set, projectionOwnershipRecord{}, nil
	}
	relative, err := cleanRepositoryRelativePath(relative)
	if err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("exclusion manifest: %w", err)
	}
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative))) // #nosec G304 -- validated repository-relative operator input.
	if err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("read exclusion manifest: %w", err)
	}
	var manifest projectionPathExclusions
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, projectionOwnershipRecord{}, fmt.Errorf("decode exclusion manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, projectionOwnershipRecord{}, errors.New("decode exclusion manifest: trailing JSON value")
	}
	if manifest.SchemaVersion != projectionExclusionV1 || strings.TrimSpace(manifest.Owner) == "" || strings.TrimSpace(manifest.Revision) == "" {
		return nil, projectionOwnershipRecord{}, errors.New("exclusion manifest requires the current schema, owner, and revision")
	}
	for _, path := range manifest.Paths {
		path, err = cleanRepositoryRelativePath(path)
		if err != nil {
			return nil, projectionOwnershipRecord{}, fmt.Errorf("excluded path: %w", err)
		}
		if _, exists := set[path]; exists {
			return nil, projectionOwnershipRecord{}, fmt.Errorf("duplicate excluded path %s", path)
		}
		set[path] = struct{}{}
	}
	paths := sortedSet(set)
	return set, projectionOwnershipRecord{
		Owner: manifest.Owner, Revision: manifest.Revision, ManifestPath: relative,
		ManifestDigest: sha256Hex(payload), Paths: paths,
	}, nil
}

func cleanRepositoryRelativePath(path string) (string, error) {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	if path == "" || path == "." || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") {
		return "", fmt.Errorf("path must be repository-relative: %q", path)
	}
	return path, nil
}
