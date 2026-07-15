package contentpacks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DeepSeekCatalogContentID = "source.deepseek.catalog"
	AIToolPolicyContentID    = "policy.ai-agent-tool-allowlist-required"
)

type RuntimeConfig struct {
	Root          string
	AllowlistPath string
	TenantID      string
	KernelVersion string
}

type ActivePack struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Kind    string `json:"kind"`
}

type RuntimeState struct {
	Enabled       bool         `json:"enabled"`
	Accepted      []ActivePack `json:"accepted,omitempty"`
	Rejected      []Rejection  `json:"rejected,omitempty"`
	FallbackKinds []string     `json:"fallback_kinds,omitempty"`
}

type RuntimeSelection struct {
	ConnectorCatalogs map[string][]byte
	PolicyRules       map[string][]byte
	State             RuntimeState
}

func LoadRuntime(config RuntimeConfig) RuntimeSelection {
	selection := RuntimeSelection{
		ConnectorCatalogs: map[string][]byte{},
		PolicyRules:       map[string][]byte{},
		State:             RuntimeState{FallbackKinds: []string{"connector", "policy-control"}},
	}
	if strings.TrimSpace(config.Root) == "" {
		return selection
	}
	selection.State.Enabled = true
	allowlist, err := ReadAllowlist(config.AllowlistPath)
	if err != nil {
		selection.State.Rejected = append(selection.State.Rejected, Rejection{Candidate: "allowlist", Reason: err.Error()})
		return selection
	}
	directories, err := DiscoverDirectories(config.Root)
	if err != nil {
		selection.State.Rejected = append(selection.State.Rejected, Rejection{Candidate: "content-pack-root", Reason: err.Error()})
		return selection
	}
	resolution, err := Resolve(nil, directories, config.KernelVersion, config.TenantID, allowlist)
	if err != nil {
		selection.State.Rejected = append(selection.State.Rejected, Rejection{Candidate: "content-pack-resolution", Reason: err.Error()})
		return selection
	}
	selection.State.Rejected = append(selection.State.Rejected, resolution.Rejected...)
	for _, pack := range resolution.Packs {
		if err := selection.accept(pack); err != nil {
			selection.State.Rejected = append(selection.State.Rejected, Rejection{Candidate: pack.Manifest.PackID, Reason: err.Error()})
		}
	}
	selection.refreshFallbackKinds()
	return selection
}

func DiscoverDirectories(root string) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("content-pack root must be a directory, not a symlink")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var directories []string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		manifestInfo, err := os.Lstat(filepath.Join(directory, "manifest.json"))
		if err == nil && manifestInfo.Mode().IsRegular() {
			directories = append(directories, directory)
		}
	}
	sort.Strings(directories)
	if len(directories) == 0 {
		return nil, fmt.Errorf("no content-pack manifests found")
	}
	return directories, nil
}

func (selection *RuntimeSelection) accept(pack VerifiedPack) error {
	if selection == nil {
		return fmt.Errorf("runtime selection is required")
	}
	if len(pack.Manifest.Contents) != 1 {
		return fmt.Errorf("pilot pack must contain exactly one declared asset")
	}
	content := pack.Manifest.Contents[0]
	payload := append([]byte(nil), pack.Files[content.ID]...)
	switch {
	case pack.Manifest.Kind == "connector" && content.ID == DeepSeekCatalogContentID:
		selection.ConnectorCatalogs["deepseek"] = payload
	case pack.Manifest.Kind == "policy-control" && content.ID == AIToolPolicyContentID:
		selection.PolicyRules["ai-agent-tool-allowlist-required"] = payload
	default:
		return fmt.Errorf("content %s is not supported by the pilot runtime", content.ID)
	}
	selection.State.Accepted = append(selection.State.Accepted, ActivePack{
		PackID:  pack.Manifest.PackID,
		Version: pack.Manifest.Version,
		Digest:  pack.Manifest.ManifestDigest,
		Kind:    pack.Manifest.Kind,
	})
	return nil
}

func (selection *RuntimeSelection) RejectKind(kind, reason string) {
	if selection == nil {
		return
	}
	kind = strings.TrimSpace(kind)
	for _, pack := range selection.State.Accepted {
		if pack.Kind == kind {
			selection.State.Rejected = append(selection.State.Rejected, Rejection{Candidate: pack.PackID, Reason: reason})
		}
	}
	selection.State.Accepted = filterActivePacks(selection.State.Accepted, kind)
	switch kind {
	case "connector":
		selection.ConnectorCatalogs = map[string][]byte{}
	case "policy-control":
		selection.PolicyRules = map[string][]byte{}
	}
	selection.refreshFallbackKinds()
}

func (selection *RuntimeSelection) refreshFallbackKinds() {
	acceptedKinds := map[string]struct{}{}
	for _, pack := range selection.State.Accepted {
		acceptedKinds[pack.Kind] = struct{}{}
	}
	selection.State.FallbackKinds = selection.State.FallbackKinds[:0]
	for _, kind := range []string{"connector", "policy-control"} {
		if _, accepted := acceptedKinds[kind]; !accepted {
			selection.State.FallbackKinds = append(selection.State.FallbackKinds, kind)
		}
	}
}

func filterActivePacks(packs []ActivePack, rejectedKind string) []ActivePack {
	filtered := packs[:0]
	for _, pack := range packs {
		if pack.Kind != rejectedKind {
			filtered = append(filtered, pack)
		}
	}
	return filtered
}
