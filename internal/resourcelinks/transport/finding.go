// Package transport adapts resource-link domain records to public protobuf
// responses while keeping transport mapping out of bootstrap.
package transport

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcelinks"
)

// FindingResponse adds deterministic links to one already-authorized finding
// response. Invalid stored link inputs omit the additive link field rather than
// weakening the existing finding-read contract.
func FindingResponse(message *cerebrov1.Finding, finding *ports.FindingRecord) *cerebrov1.GetFindingResponse {
	response := &cerebrov1.GetFindingResponse{Finding: message}
	if finding == nil {
		return response
	}
	links, err := resourcelinks.FindingLinks(resourcelinks.FindingInput{
		ID:           finding.ID,
		TenantID:     finding.TenantID,
		RuntimeID:    finding.RuntimeID,
		ResourceURNs: finding.ResourceURNs,
	})
	if err != nil {
		return response
	}
	response.Links = linkMessages(links)
	return response
}

func linkMessages(links []resourcelinks.ResourceLink) []*cerebrov1.ResourceLink {
	messages := make([]*cerebrov1.ResourceLink, 0, len(links))
	for _, link := range links {
		messages = append(messages, &cerebrov1.ResourceLink{
			Rel: link.Relation,
			Target: &cerebrov1.ResourceRef{
				Kind:     string(link.Target.Kind),
				Id:       link.Target.ID,
				Revision: link.Target.Revision,
				ApiPath:  link.Target.APIPath,
				McpUri:   link.Target.MCPURI,
				State:    string(link.Target.State),
			},
			Authority:    string(link.Authority),
			Completeness: string(link.Completeness),
		})
	}
	return messages
}
