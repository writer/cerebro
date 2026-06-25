package graphquery

import (
	"strings"

	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// LegacyEntityImpactFallbackURNs returns current graph root candidates for
// legacy impact URLs that were minted before GitHub entity kinds stabilized.
func LegacyEntityImpactFallbackURNs(entityURN string) []string {
	parsed, err := cerebrourn.Parse(entityURN)
	if err != nil {
		return nil
	}
	var candidates []string
	addCandidate := func(kind string, parts ...string) {
		candidate, err := cerebrourn.Mint(parsed.TenantID, kind, parts...)
		if err != nil || candidate == "" || candidate == entityURN {
			return
		}
		for _, existing := range candidates {
			if existing == candidate {
				return
			}
		}
		candidates = append(candidates, candidate)
	}
	switch parsed.Kind {
	case "github_repo", "github_repository", "repo":
		addCandidate("github_code_repository", parsed.Parts...)
		if len(parsed.Parts) > 1 {
			addCandidate("github_code_repository", strings.Join(parsed.Parts, "/"))
		}
		if len(parsed.Parts) == 1 && !strings.Contains(parsed.Parts[0], "/") {
			login := parsed.Parts[0]
			addCandidate("github_user", login)
			addCandidate("identity", "login", login)
			addCandidate("identifier", "login", login)
			addCandidate("github_resource", "team", login)
			addCandidate("github_resource", "org", login)
		}
	}
	return candidates
}
