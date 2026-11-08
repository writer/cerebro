package requirements

import (
	"fmt"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// requirementsServiceMatches reports whether a candidate service string (an
// extracted import-path segment, a boto3 service slug, or a model-supplied
// name) identifies the same service as def — either its canonical Service
// name or one of its SDKServices namespace aliases, since those can differ
// (e.g. a canonical "Amazon S3" vs. the Go SDK package alias "s3").
func requirementsServiceMatches(def ci.OperationDefinition, service string) bool {
	if def.Service == service {
		return true
	}
	for _, alias := range def.SDKServices {
		if alias == service {
			return true
		}
	}
	return false
}

// requirementsFindOperation maps a model-claimed provider/service/operation
// onto a known OperationDefinition. Operation matching is exact
// (case-sensitive): the model is instructed to use Definitions' vocabulary
// verbatim, so a mismatch is treated as a genuinely unknown operation rather
// than fuzzy-matched away. Service matching allows either the canonical
// Service name or a listed SDKServices alias.
func requirementsFindOperation(defs ci.Definitions, provider ci.Provider, service, operation string) (ci.OperationDefinition, bool) {
	for _, def := range defs.Operations {
		if def.Provider == provider && requirementsServiceMatches(def, service) && def.Operation == operation {
			return def, true
		}
	}
	return ci.OperationDefinition{}, false
}

// requirementsFindOperationByToken maps an independently-extracted static
// call-site token (a Go method name, a boto3 snake_case method name, or an
// AWS SDK v3 `XCommand` class name) onto a known OperationDefinition. It
// accepts either the PascalCase-normalized token matching def.Operation, or
// the raw/normalized token appearing literally in def.SDKMethods — the
// authoritative real SDK identifiers, not a guessed IAM action name.
func requirementsFindOperationByToken(defs ci.Definitions, provider ci.Provider, service, rawToken string) (ci.OperationDefinition, bool) {
	normalized := requirementsNormalizeToken(rawToken)
	for _, def := range defs.Operations {
		if def.Provider != provider || !requirementsServiceMatches(def, service) {
			continue
		}
		if def.Operation == normalized {
			return def, true
		}
		for _, method := range def.SDKMethods {
			if method == rawToken || method == normalized {
				return def, true
			}
		}
	}
	return ci.OperationDefinition{}, false
}

func requirementsStaticReference(op StaticOperation, files map[string]ci.SourceFile) ci.Reference {
	digest := ""
	if file, ok := files[op.Path]; ok {
		digest = requirementsFileDigest(file)
	} else {
		digest = ci.DigestBytes([]byte(op.Quote))
	}
	return ci.Reference{Path: op.Path, StartLine: op.StartLine, EndLine: op.EndLine, Digest: digest}
}

// requirementsVerifyCitations re-reads the pinned file content at each cited
// location and requires the content to equal the claimed quote byte-for-
// byte. Any single invalid citation rejects the whole claim: a model that
// gets one pointer wrong (or fabricates one) cannot ride along on others
// that happen to be real.
func requirementsVerifyCitations(citations []ClaimCitation, files map[string]ci.SourceFile) ([]ci.Reference, string) {
	if len(citations) == 0 {
		return nil, "claim has no citations"
	}
	refs := make([]ci.Reference, 0, len(citations))
	for _, citation := range citations {
		file, ok := files[citation.Path]
		if !ok {
			return nil, fmt.Sprintf("citation references %q which is not in the pinned repository", citation.Path)
		}
		lines := requirementsFileLines(file.Content)
		actual, ok := requirementsQuoteLines(lines, citation.StartLine, citation.EndLine)
		if !ok {
			return nil, fmt.Sprintf("citation at %s:%d-%d is out of bounds for the pinned file", citation.Path, citation.StartLine, citation.EndLine)
		}
		if actual != citation.Quote {
			return nil, fmt.Sprintf("citation quote at %s:%d-%d does not match the pinned source content", citation.Path, citation.StartLine, citation.EndLine)
		}
		digest := requirementsFileDigest(file)
		refs = append(refs, ci.Reference{
			Path: citation.Path, StartLine: citation.StartLine, EndLine: citation.EndLine,
			Digest: digest,
		})
	}
	return refs, ""
}

// requirementsClaimOverlapsStatic reports whether at least one of the
// claim's (already citation-verified) citations lands on the same file and
// an overlapping line range as an independently-extracted static finding
// that resolves, through Definitions, to the very same operation the claim
// resolved to (resolved). Matching through the resolved definitions —
// rather than comparing raw service strings directly — means a canonical
// Service name and an SDKServices alias used on either side still line up.
// This is what actually defeats a claim that quotes real, unrelated source
// text (a comment, a docstring) to fabricate support for an operation that
// is not really called there.
func requirementsClaimOverlapsStatic(claim ModelClaim, staticOps []StaticOperation, defs ci.Definitions, resolved ci.OperationDefinition) bool {
	for _, citation := range claim.Citations {
		for _, op := range staticOps {
			if op.Path != citation.Path {
				continue
			}
			opDef, found := requirementsFindOperationByToken(defs, op.Provider, op.Service, op.Token)
			if !found || opDef.Provider != resolved.Provider || opDef.Service != resolved.Service || opDef.Operation != resolved.Operation {
				continue
			}
			if citation.StartLine <= op.EndLine && citation.EndLine >= op.StartLine {
				return true
			}
		}
	}
	return false
}

func requirementsClaimScope(claim ModelClaim) string {
	if len(claim.Citations) > 0 {
		return claim.Citations[0].Path
	}
	return string(claim.Provider) + "/" + claim.Service
}
