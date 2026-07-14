package resourcelinks

import (
	"fmt"
	"net/url"
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

	references := []struct {
		relation  string
		target    ResourceRef
		authority Authority
	}{
		{
			relation: fabriccontract.RelationSelf,
			target: ResourceRef{
				Kind:    KindFinding,
				ID:      findingID,
				APIPath: "/findings/" + url.PathEscape(findingID),
				MCPURI:  "cerebro://finding/" + url.PathEscape(findingID),
				State:   StateCurrent,
			},
			authority: AuthorityCanonicalRecord,
		},
		{
			relation: fabriccontract.RelationHasContext,
			target: ResourceRef{
				Kind:   KindFindingInvestigation,
				ID:     findingID,
				MCPURI: "cerebro://investigation/finding/" + url.PathEscape(findingID),
				State:  StateCurrent,
			},
			authority: AuthorityDerivedRecord,
		},
		{
			relation: fabriccontract.RelationHasEvidence,
			target: ResourceRef{
				Kind:    KindFindingEvidenceCollection,
				ID:      findingID,
				APIPath: evidenceCollectionPath(runtimeID, findingID),
				State:   StateCurrent,
			},
			authority: AuthorityDerivedRecord,
		},
		{
			relation: fabriccontract.RelationObservedOn,
			target: ResourceRef{
				Kind:    KindSourceRuntime,
				ID:      runtimeID,
				APIPath: "/source-runtimes/" + url.PathEscape(runtimeID),
				MCPURI:  "cerebro://runtime/" + url.PathEscape(runtimeID),
				State:   StateCurrent,
			},
			authority: AuthorityDerivedRecord,
		},
	}

	for _, resourceURN := range resourceURNs {
		query := url.Values{"root_urn": []string{resourceURN}}
		references = append(references, struct {
			relation  string
			target    ResourceRef
			authority Authority
		}{
			relation: fabriccontract.RelationAffects,
			target: ResourceRef{
				Kind:    KindGraphEntity,
				ID:      resourceURN,
				APIPath: "/platform/graph/neighborhood?" + query.Encode(),
				MCPURI:  "cerebro://asset/" + url.PathEscape(resourceURN),
				State:   StateCurrent,
			},
			authority: AuthorityDerivedRecord,
		})
	}

	links := make([]ResourceLink, 0, len(references))
	for _, reference := range references {
		link, err := NewLink(KindFinding, reference.relation, reference.target, reference.authority, CompletenessComplete)
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
		return links[i].Target.ID < links[j].Target.ID
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

func evidenceCollectionPath(runtimeID, findingID string) string {
	query := url.Values{"finding_id": []string{findingID}}
	return "/source-runtimes/" + url.PathEscape(runtimeID) + "/finding-evidence?" + query.Encode()
}
