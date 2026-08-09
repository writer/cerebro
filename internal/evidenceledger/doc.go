// Package evidenceledger records immutable evidence versions and the scoped
// claims made about them.
//
// Artifact metadata names the logical evidence object. EvidenceVersion records
// immutable content, provenance, governance, subjects, and validity. An
// EvidenceClaim then states how one version supports one objective,
// implementation revision, and requirement for a bounded period and subject
// set. Review and invalidation update the claim aggregate; they never rewrite
// the underlying evidence version.
//
// Writes are append-first. The service appends a versioned workflow event and
// only then projects it into the ledger store. Callers must therefore treat an
// append failure as no accepted write and a projection failure as an accepted
// event that still needs replay or operational recovery. Validation is
// fail-closed across review state, quarantine, revocation, expiry, period,
// subject coverage, and conflicting claims.
package evidenceledger
