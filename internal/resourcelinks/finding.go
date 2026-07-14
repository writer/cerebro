package resourcelinks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/fabriccontract"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// FindingInput is the authorization-safe subset of a finding needed to build
// additive navigation links. TenantID is used only to reject cross-tenant graph
// targets; the input contains no sensitive attribute data.
type FindingInput struct {
	ID           string
	TenantID     string
	RuntimeID    string
	ResourceURNs []string
}

// FindingLinks builds deterministic links only from the already-authorized
// finding record. It does not load or imply authorization to any target.
func FindingLinks(input FindingInput) ([]ResourceLink, error) {
	findingID := strings.TrimSpace(input.ID)
	tenantID := strings.TrimSpace(input.TenantID)
	runtimeID := strings.TrimSpace(input.RuntimeID)
	if findingID == "" || tenantID == "" || runtimeID == "" {
		return nil, fmt.Errorf("%w: finding id, tenant id, and runtime id are required", ErrInvalidLink)
	}
	resourceURNs, err := normalizedGraphURNs(tenantID, input.ResourceURNs)
	if err != nil {
		return nil, err
	}

	type linkInput struct {
		relation  string
		target    ResourceRef
		authority Authority
	}
	references := make([]linkInput, 0, 4+len(resourceURNs))
	appendID := func(relation string, kind fabriccontract.ResourceKind, id string, authority Authority) error {
		target, buildErr := NewID(kind, id)
		if buildErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidLink, buildErr)
		}
		references = append(references, linkInput{relation: relation, target: target, authority: authority})
		return nil
	}
	if err := appendID(fabriccontract.RelationSelf, fabriccontract.ResourceKindFinding, findingID, AuthorityCanonicalRecord); err != nil {
		return nil, err
	}
	if err := appendID(fabriccontract.RelationHasContext, fabriccontract.ResourceKindFindingInvestigation, findingID, AuthorityDerivedRecord); err != nil {
		return nil, err
	}
	if err := appendID(fabriccontract.RelationHasEvidence, fabriccontract.ResourceKindFindingEvidenceCollection, findingID, AuthorityDerivedRecord); err != nil {
		return nil, err
	}
	if err := appendID(fabriccontract.RelationObservedOn, fabriccontract.ResourceKindSourceRuntime, runtimeID, AuthorityDerivedRecord); err != nil {
		return nil, err
	}
	for _, resourceURN := range resourceURNs {
		target, buildErr := NewURN(fabriccontract.ResourceKindGraphEntity, resourceURN)
		if buildErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidLink, buildErr)
		}
		references = append(references, linkInput{
			relation:  fabriccontract.RelationAffects,
			target:    target,
			authority: AuthorityDerivedRecord,
		})
	}

	links := make([]ResourceLink, 0, len(references))
	for _, reference := range references {
		link, err := NewLink(fabriccontract.ResourceKindFinding, reference.relation, reference.target, reference.authority, CompletenessComplete)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].Relation != links[j].Relation {
			return links[i].Relation < links[j].Relation
		}
		if links[i].Target.Kind != links[j].Target.Kind {
			return links[i].Target.Kind < links[j].Target.Kind
		}
		return links[i].Target.Identifier() < links[j].Target.Identifier()
	})
	return links, nil
}

func normalizedGraphURNs(tenantID string, values []string) ([]string, error) {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !strings.HasPrefix(value, cerebrourn.Prefix) {
			continue
		}
		parsed, err := cerebrourn.Parse(value)
		if err != nil || len(parsed.Parts) == 0 || parsed.TenantID != tenantID {
			return nil, fmt.Errorf("%w: affected resource urn is invalid or outside the finding tenant", ErrInvalidLink)
		}
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}
