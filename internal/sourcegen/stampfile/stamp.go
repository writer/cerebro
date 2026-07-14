// Package stampfile provides input hashing for incremental codegen. Generators
// can compute a content hash of their inputs, compare it to a stored stamp, and
// skip regeneration when inputs haven't changed.
package stampfile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const stampDir = "tmp/codegen-stamps"

// Check returns true if the current input hash matches the stored stamp.
func Check(generatorName string, inputHash string) bool {
	stored, err := readStamp(generatorName)
	if err != nil {
		return false
	}
	return strings.TrimSpace(stored) == strings.TrimSpace(inputHash)
}

// Write stores the input hash as the stamp for a generator.
func Write(generatorName string, inputHash string) error {
	if err := os.MkdirAll(stampDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(stampPath(generatorName), []byte(strings.TrimSpace(inputHash)+"\n"), 0o600)
}

// HashFiles computes a deterministic SHA-256 hash of a list of file paths.
// Files are sorted before hashing to ensure deterministic output.
func HashFiles(paths []string) (string, error) {
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)

	h := sha256.New()
	for _, path := range sorted {
		payload, err := os.ReadFile(path) // #nosec G304 -- operator-controlled paths
		if err != nil {
			return "", fmt.Errorf("hash %s: %w", path, err)
		}
		if _, err := fmt.Fprintf(h, "%s\n%d\n", path, len(payload)); err != nil {
			return "", fmt.Errorf("hash header %s: %w", path, err)
		}
		h.Write(payload)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashDir computes a SHA-256 hash of all files in a directory matching an
// extension filter. Walks recursively and processes files in sorted order.
func HashDir(dir string, extensions []string) (string, error) {
	extSet := map[string]bool{}
	for _, ext := range extensions {
		extSet[strings.ToLower(ext)] = true
	}

	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if len(extSet) > 0 && !extSet[ext] {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	return HashFiles(paths)
}

// HashReader computes a SHA-256 hash of an io.Reader.
func HashReader(r io.Reader) (string, error) {
	h := sha256.New()
	// The input is generator content used for deterministic staleness checks, not a password or authentication secret.
	// codeql[go/weak-sensitive-data-hashing]
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readStamp(generatorName string) (string, error) {
	payload, err := os.ReadFile(stampPath(generatorName)) // #nosec G304
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func stampPath(generatorName string) string {
	return filepath.Join(stampDir, generatorName+".stamp")
}
