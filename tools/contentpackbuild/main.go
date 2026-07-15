package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/contentpacks"
)

func main() {
	directory := flag.String("dir", "", "pack directory")
	privateKeyPath := flag.String("private-key", "", "base64 Ed25519 private key file")
	flag.Parse()
	if strings.TrimSpace(*directory) == "" || strings.TrimSpace(*privateKeyPath) == "" {
		fail("-dir and -private-key are required")
	}
	manifestPath := filepath.Join(*directory, "manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		fail("inspect manifest: %v", err)
	}
	if !manifestInfo.Mode().IsRegular() {
		fail("manifest must be a regular file")
	}
	// #nosec G304 -- the operator selects the pack directory and the manifest was checked as a regular file above.
	manifestPayload, err := os.ReadFile(manifestPath)
	if err != nil {
		fail("read manifest: %v", err)
	}
	var manifest contentpacks.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestPayload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		fail("decode manifest: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		fail("manifest must contain one JSON value")
	}
	manifest, err = contentpacks.FinalizeManifest(*directory, manifest)
	if err != nil {
		fail("finalize manifest: %v", err)
	}
	keyInfo, err := os.Lstat(*privateKeyPath)
	if err != nil {
		fail("inspect private key: %v", err)
	}
	if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o077 != 0 {
		fail("private key must be a regular file readable only by its owner")
	}
	encodedKey, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fail("read private key: %v", err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		fail("private key must contain a base64 Ed25519 private key")
	}
	signature, err := contentpacks.SignManifest(manifest, ed25519.PrivateKey(privateKey))
	if err != nil {
		fail("sign manifest: %v", err)
	}
	finalManifest, err := contentpacks.MarshalManifest(manifest)
	if err != nil {
		fail("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, finalManifest, 0o600); err != nil {
		fail("write manifest: %v", err)
	}
	// #nosec G703 -- the operator selects the pack directory and the fixed filename cannot escape it.
	if err := os.WriteFile(filepath.Join(*directory, "manifest.sig"), []byte(signature), 0o600); err != nil {
		fail("write signature: %v", err)
	}
	fmt.Printf("signed %s %s %s\n", manifest.PackID, manifest.Version, manifest.ManifestDigest)
}

func fail(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
