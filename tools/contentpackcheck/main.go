package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/writer/cerebro/internal/contentpacks"
)

type report struct {
	KernelVersion        string        `json:"kernel_version"`
	PackCount            int           `json:"pack_count"`
	ContentFiles         int           `json:"content_files"`
	ContentBytes         int64         `json:"content_bytes"`
	ValidationDurationMS int64         `json:"validation_duration_ms"`
	Packs                []packSummary `json:"packs"`
}

type packSummary struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Kind    string `json:"kind"`
}

func main() {
	root := flag.String("root", "contentpacks/pilot", "directory containing pack directories")
	allowlistPath := flag.String("allowlist", "contentpacks/pilot/allowlist.json", "operator allowlist path")
	tenantID := flag.String("tenant", "content-pack-pilot", "tenant allowlist identifier")
	kernelVersion := flag.String("kernel-version", "1.0.0", "kernel version to test")
	flag.Parse()

	started := time.Now()
	allowlist, err := contentpacks.ReadAllowlist(*allowlistPath)
	if err != nil {
		fail("read allowlist: %v", err)
	}
	directories, err := packDirectories(*root)
	if err != nil {
		fail("discover packs: %v", err)
	}
	result := report{KernelVersion: *kernelVersion, Packs: make([]packSummary, 0, len(directories))}
	for _, directory := range directories {
		pack, err := contentpacks.VerifyDirectory(directory, *kernelVersion, *tenantID, allowlist)
		if err != nil {
			fail("validate %s: %v", filepath.Base(directory), err)
		}
		result.PackCount++
		result.ContentFiles += len(pack.Manifest.Contents)
		for _, content := range pack.Manifest.Contents {
			result.ContentBytes += content.Bytes
		}
		result.Packs = append(result.Packs, packSummary{ID: pack.Manifest.PackID, Version: pack.Manifest.Version, Digest: pack.Digest, Kind: pack.Manifest.Kind})
	}
	result.ValidationDurationMS = time.Since(started).Milliseconds()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fail("write report: %v", err)
	}
}

func packDirectories(root string) ([]string, error) {
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
		if info, err := os.Lstat(filepath.Join(directory, "manifest.json")); err == nil && info.Mode().IsRegular() {
			directories = append(directories, directory)
		}
	}
	sort.Strings(directories)
	if len(directories) == 0 {
		return nil, fmt.Errorf("no pack manifests found under %s", root)
	}
	return directories, nil
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
