package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func buildProjectionCandidates(root string, batches []projectionBatch) ([]projectionFileCandidate, error) {
	type candidateState struct {
		class     string
		sourceIDs map[string]struct{}
	}
	states := make(map[string]*candidateState)
	for _, batch := range batches {
		for _, path := range batch.ImplementationFiles {
			if states[path] == nil {
				states[path] = &candidateState{class: "production", sourceIDs: make(map[string]struct{})}
			}
			states[path].sourceIDs[batch.SourceID] = struct{}{}
		}
		for _, path := range batch.TestFiles {
			if states[path] == nil {
				states[path] = &candidateState{class: "test", sourceIDs: make(map[string]struct{})}
			}
			states[path].sourceIDs[batch.SourceID] = struct{}{}
		}
	}
	paths := make([]string, 0, len(states))
	for path := range states {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	candidates := make([]projectionFileCandidate, 0, len(paths))
	for _, path := range paths {
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))) // #nosec G304 -- discovered repository path.
		if err != nil {
			return nil, fmt.Errorf("read deletion candidate %s: %w", path, err)
		}
		candidates = append(candidates, projectionFileCandidate{
			Path: path, Class: states[path].class, DigestSHA256: sha256Hex(payload),
			Lines: sourceLineCount(payload), SourceIDs: sortedSet(states[path].sourceIDs),
		})
	}
	return candidates, nil
}

func digestProjectionInputs(root string, paths []string) (string, error) {
	sort.Strings(paths)
	hash := sha256.New()
	previous := ""
	for _, path := range paths {
		if path == previous {
			continue
		}
		previous = path
		payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))) // #nosec G304 -- discovered repository input path.
		if err != nil {
			return "", fmt.Errorf("read planner input %s: %w", path, err)
		}
		_, _ = hash.Write([]byte(path))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(payload)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestProjectionPlan(plan projectionBatchPlan) (string, error) {
	plan.PlanDigestSHA256 = ""
	payload, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("marshal projection plan digest: %w", err)
	}
	return sha256Hex(payload), nil
}

func gitRevision(root string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "rev-parse", "HEAD") // #nosec G204 -- fixed command and arguments.
	command.Dir = root
	payload, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func sourceLineCount(payload []byte) int {
	if len(payload) == 0 {
		return 0
	}
	lines := bytes.Count(payload, []byte{'\n'})
	if payload[len(payload)-1] != '\n' {
		lines++
	}
	return lines
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func sortedSet[T ~string](set map[T]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, string(value))
	}
	sort.Strings(values)
	return values
}
