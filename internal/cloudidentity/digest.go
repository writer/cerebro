package cloudidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Digest returns a deterministic "sha256:<hex>" digest of a JSON-safe typed
// value. encoding/json marshals struct fields in declaration order and map
// keys in sorted order, so two semantically equal values always produce the
// same payload and therefore the same digest; this is why Digest only
// accepts JSON-safe typed models (per contract), never a raw map built from
// unordered iteration over something that isn't itself deterministic.
//
// Non-JSON values are programming errors, never content evidence. Reject them
// rather than returning a fabricated digest shared by unrelated invalid inputs.
func Digest(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("cloudidentity: digest non-JSON value: %v", err))
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// repositoryFileDigest is the canonical per-file entry RepositoryDigest
// hashes: Path paired with a digest always derived from the file's actual
// content bytes, never a possibly-wrong caller-supplied string.
type repositoryFileDigest struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// RepositoryDigest returns the canonical whole-repository content digest
// for a pinned, bounded file set: Digest over the sorted (path, digest)
// pairs, where each file's digest is Digest(file.Content) — computed from
// its actual bytes every time, never trusting a SourceFile.Digest value
// (e.g. a repository adapter's git blob SHA) as-is. Two callers that read
// the identical file set always produce the identical RepositoryDigest,
// and a corrupted/mismatched SourceFile.Digest can never hide inside it.
func RepositoryDigest(files []SourceFile) string {
	canonical := make([]repositoryFileDigest, len(files))
	for i, file := range files {
		canonical[i] = repositoryFileDigest{Path: file.Path, Digest: Digest(file.Content)}
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Path < canonical[j].Path })
	return Digest(canonical)
}
