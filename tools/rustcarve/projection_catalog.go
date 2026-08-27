package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"gopkg.in/yaml.v3"
)

var authoritativeProjectionTemplates = map[string]struct{}{
	"alert": {}, "asset": {}, "audit_event": {}, "cloud_resource": {},
	"deployment": {}, "endpoint_device": {}, "evidence_cas_reference": {},
	"finding": {}, "group_membership": {}, "identity_app_assignment": {},
	"identity_application": {}, "identity_credential": {}, "identity_group": {},
	"identity_group_membership": {}, "identity_user": {}, "policy": {},
	"repository": {}, "secret": {}, "vulnerability": {},
}

type projectionProofManifest struct {
	ID              string                      `yaml:"id"`
	RuntimeFamilies []string                    `yaml:"runtime_families"`
	ProviderAPI     *projectionProviderAPIProof `yaml:"provider_api"`
}

type projectionProviderAPIProof struct {
	Status     string                  `yaml:"status"`
	Basis      string                  `yaml:"basis"`
	SpecURL    string                  `yaml:"spec_url"`
	References []string                `yaml:"references"`
	Families   []projectionFamilyProof `yaml:"families"`
}

type projectionFamilyProof struct {
	ID     string `yaml:"id"`
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

func loadProjectionProofs(root string) (map[string]projectionProofManifest, []string, error) {
	directories, err := os.ReadDir(filepath.Join(root, "sources"))
	if err != nil {
		return nil, nil, fmt.Errorf("read source manifests: %w", err)
	}
	proofs := make(map[string]projectionProofManifest)
	paths := make([]string, 0)
	for _, directory := range directories {
		if !directory.IsDir() || directory.Type()&fs.ModeSymlink != 0 {
			continue
		}
		relative := filepath.ToSlash(filepath.Join("sources", directory.Name(), "catalog.yaml"))
		path := filepath.Join(root, filepath.FromSlash(relative))
		payload, err := os.ReadFile(path) // #nosec G304 -- bounded repository catalog path.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", relative, err)
		}
		var proof projectionProofManifest
		if err := yaml.Unmarshal(payload, &proof); err != nil {
			return nil, nil, fmt.Errorf("decode %s: %w", relative, err)
		}
		proof.ID = strings.TrimSpace(proof.ID)
		if proof.ID == "" {
			return nil, nil, fmt.Errorf("%s has no source id", relative)
		}
		if _, exists := proofs[proof.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate source proof %s", proof.ID)
		}
		proofs[proof.ID] = proof
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	return proofs, paths, nil
}

func projectionReadyFamilies(definition connectordefinitions.Definition, proof projectionProofManifest) ([]string, []string, bool) {
	verified := verifiedProjectionProofs(proof)
	familyIDs := make([]string, 0, len(definition.ResourceFamilies))
	eventKinds := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		template := ""
		if family.Projection != nil {
			template = strings.TrimSpace(family.Projection.Template)
		}
		if _, supported := authoritativeProjectionTemplates[template]; !supported {
			return nil, nil, false
		}
		method := strings.TrimSpace(family.Method)
		if method == "" {
			method = "GET"
		}
		baseURL := ""
		if family.Config != nil {
			baseURL = family.Config.BaseURL
		}
		locator, ok := canonicalFamilyLocator(baseURL, family.Path)
		if !ok {
			return nil, nil, false
		}
		key := family.ID + "\x00" + method + "\x00" + locator
		if _, ok := verified[key]; !ok {
			return nil, nil, false
		}
		familyIDs = append(familyIDs, family.ID)
		kind := strings.TrimSpace(family.Event.Kind)
		if kind == "" {
			kind = strings.TrimSpace(family.EventKind)
		}
		if kind == "" || !strings.Contains(kind, ".") {
			kind = definition.SourceID + "." + family.ID
		}
		eventKinds = append(eventKinds, kind)
	}
	sort.Strings(familyIDs)
	sort.Strings(eventKinds)
	return familyIDs, eventKinds, len(familyIDs) != 0
}

func verifiedProjectionProofs(proof projectionProofManifest) map[string]struct{} {
	verified := make(map[string]struct{})
	api := proof.ProviderAPI
	if api == nil || strings.TrimSpace(api.Status) != "verified" || strings.TrimSpace(api.Basis) != "declared" || (strings.TrimSpace(api.SpecURL) == "" && len(api.References) == 0) {
		return verified
	}
	runtime := make(map[string]struct{}, len(proof.RuntimeFamilies))
	for _, family := range proof.RuntimeFamilies {
		runtime[family] = struct{}{}
	}
	for _, family := range api.Families {
		if _, ok := runtime[family.ID]; !ok || strings.TrimSpace(family.Path) == "" {
			continue
		}
		method := strings.TrimSpace(family.Method)
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "POST" {
			continue
		}
		path, ok := canonicalContractLocator(family.Path)
		if ok {
			verified[family.ID+"\x00"+method+"\x00"+path] = struct{}{}
		}
	}
	return verified
}

func canonicalFamilyLocator(baseURL, path string) (string, bool) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if strings.HasPrefix(baseURL, "https://") && !strings.Contains(baseURL, "${") {
		return canonicalContractLocator(baseURL + path)
	}
	return canonicalPathTemplate(path)
}

func canonicalContractLocator(locator string) (string, bool) {
	if strings.HasPrefix(locator, "/") {
		return canonicalPathTemplate(locator)
	}
	remainder, ok := strings.CutPrefix(locator, "https://")
	if !ok {
		return "", false
	}
	host, path, ok := strings.Cut(remainder, "/")
	if !ok || host == "" || strings.ContainsAny(host, "@?#\\") {
		return "", false
	}
	canonical, ok := canonicalPathTemplate("/" + path)
	if !ok {
		return "", false
	}
	return "https://" + host + canonical, true
}

func canonicalPathTemplate(path string) (string, bool) {
	pathPart, query, hasQuery := strings.Cut(path, "?")
	if !strings.HasPrefix(pathPart, "/") {
		return "", false
	}
	segments := strings.Split(pathPart, "/")
	for i, segment := range segments {
		if isPathParameter(segment) {
			segments[i] = "{}"
		} else if strings.ContainsAny(segment, "{}") {
			return "", false
		}
	}
	canonical := strings.Join(segments, "/")
	if hasQuery {
		if strings.ContainsAny(query, "{}") {
			return "", false
		}
		canonical += "?" + query
	}
	return canonical, true
}

func isPathParameter(segment string) bool {
	parameter := ""
	if strings.HasPrefix(segment, "${config.") && strings.HasSuffix(segment, "}") {
		parameter = strings.TrimSuffix(strings.TrimPrefix(segment, "${config."), "}")
	} else if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
		parameter = strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
	}
	if parameter == "" {
		return false
	}
	for _, character := range parameter {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
