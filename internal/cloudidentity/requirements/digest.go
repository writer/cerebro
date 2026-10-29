package requirements

import (
	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// requirementsFileDigest hashes a file's actual pinned content through the
// shared ci.DigestBytes helper. It deliberately ignores SourceFile.Digest
// (an adapter-claimed value in a different, non-comparable scheme such as
// "sha1:<git-blob-sha>"): a provided string is never proof by itself, only
// a digest independently recomputed over the bytes we actually hold is.
// Hashing byte content can never fail, so this is infallible by
// construction.
func requirementsFileDigest(file ci.SourceFile) string {
	return ci.DigestBytes(file.Content)
}

// requirementsResolveSourceDigest independently recomputes the pinned
// repository's content digest via the shared ci.RepositoryDigest helper
// (the same canonical algorithm the repository adapter and other
// consumers use) and compares it against the pin's claimed Digest. It
// always returns the independently computed value — a claimed digest is
// never trusted as proof by itself — and reports false when the claim
// disagrees with the actual content, so the caller can record that as a
// real validation failure rather than silently trusting whatever string
// was supplied. err is non-nil only when the content itself could not be
// digested (never expected for this JSON-safe typed model); callers must
// treat that the same as a confirmed mismatch, never as a trusted match.
func requirementsResolveSourceDigest(pin ci.SourcePin, files []ci.SourceFile) (digest string, matchesClaim bool, err error) {
	actual, err := ci.RepositoryDigest(files)
	if err != nil {
		return "", false, err
	}
	if pin.Digest == "" {
		return actual, true, nil
	}
	return actual, actual == pin.Digest, nil
}
