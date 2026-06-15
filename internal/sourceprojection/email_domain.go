package sourceprojection

import (
	"encoding/json"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type emailDomainHealthIssue struct {
	ID             string `json:"id"`
	Protocol       string `json:"protocol"`
	Severity       string `json:"severity"`
	Code           string `json:"code"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

type emailDomainHealthDKIM struct {
	Selector string `json:"selector"`
	Status   string `json:"status"`
	KeyBits  int    `json:"key_bits"`
	Record   string `json:"record"`
}

type emailDomainHealthPayload struct {
	Domain         string                   `json:"domain"`
	Status         string                   `json:"status"`
	Score          int                      `json:"score"`
	SPFStatus      string                   `json:"spf_status"`
	DKIMStatus     string                   `json:"dkim_status"`
	DMARCStatus    string                   `json:"dmarc_status"`
	SPFRecords     []string                 `json:"spf_records"`
	SPFPolicy      string                   `json:"spf_policy"`
	SPFLookupCount int                      `json:"spf_lookup_count"`
	DMARCRecords   []string                 `json:"dmarc_records"`
	DMARCPolicy    string                   `json:"dmarc_policy"`
	DMARCPct       int                      `json:"dmarc_pct"`
	DMARCRua       []string                 `json:"dmarc_rua"`
	MXRecords      []string                 `json:"mx_records"`
	DKIMSelectors  []emailDomainHealthDKIM  `json:"dkim_selectors"`
	RelatedRecords []string                 `json:"related_records"`
	Issues         []emailDomainHealthIssue `json:"issues"`
}

func emailDomainHealthProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	domain := strings.TrimSpace(attrs["domain"])
	if domain == "" {
		return nil, nil, fmt.Errorf("event %q missing domain attribute", event.GetId())
	}
	domain = strings.ToLower(domain)
	var payload emailDomainHealthPayload
	if len(event.GetPayload()) != 0 {
		_ = json.Unmarshal(event.GetPayload(), &payload)
	}
	if strings.TrimSpace(payload.Domain) == "" {
		payload.Domain = domain
	}
	domainURN := projectionURN(tenantID, "email_domain", domain)
	if domainURN == "" {
		return nil, nil, nil
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        domainURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "email.domain",
		Label:      domain,
		Attributes: emailDomainEntityAttributes(event, attrs, payload),
	})

	internetDomainURN, internetDomainLabel := internetDomainURN(tenantID, domain)
	if internetDomainURN != "" {
		addInternetDomainEntity(entities, tenantID, event.GetSourceId(), internetDomainURN, internetDomainLabel)
		addLink(links, projectedLink(tenantID, event.GetSourceId(), domainURN, internetDomainURN, relationBelongsTo, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "email_domain_belongs_to_internet_domain",
		}))
	}

	for _, selector := range payload.DKIMSelectors {
		selectorName := strings.TrimSpace(selector.Selector)
		if selectorName == "" {
			continue
		}
		selectorURN := projectionURN(tenantID, "email_dkim_selector", domain, selectorName)
		if selectorURN == "" {
			continue
		}
		selectorAttributes := map[string]string{
			"selector": selectorName,
			"domain":   domain,
			"status":   strings.TrimSpace(selector.Status),
			"key_bits": fmt.Sprintf("%d", selector.KeyBits),
			"record":   strings.TrimSpace(selector.Record),
		}
		trimEmptyProjectionAttributes(selectorAttributes)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        selectorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "email.dkim_selector",
			Label:      selectorName + "@" + domain,
			Attributes: selectorAttributes,
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), domainURN, selectorURN, relationContains, map[string]string{
			"event_id":   event.GetId(),
			"at":         eventObservedAt(event),
			"match_type": "email_domain_dkim_selector",
			"selector":   selectorName,
		}))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func emailDomainEntityAttributes(event *cerebrov1.EventEnvelope, attrs map[string]string, payload emailDomainHealthPayload) map[string]string {
	out := map[string]string{
		"domain":              payload.Domain,
		"status":              strings.TrimSpace(payload.Status),
		"score":               fmt.Sprintf("%d", payload.Score),
		"spf_status":          strings.TrimSpace(payload.SPFStatus),
		"dkim_status":         strings.TrimSpace(payload.DKIMStatus),
		"dmarc_status":        strings.TrimSpace(payload.DMARCStatus),
		"spf_policy":          strings.TrimSpace(payload.SPFPolicy),
		"spf_lookup_count":    fmt.Sprintf("%d", payload.SPFLookupCount),
		"dmarc_policy":        strings.TrimSpace(payload.DMARCPolicy),
		"dmarc_pct":           fmt.Sprintf("%d", payload.DMARCPct),
		"issue_count":         fmt.Sprintf("%d", len(payload.Issues)),
		"failing_issue_count": strings.TrimSpace(attrs["failing_issue_count"]),
		"highest_severity":    strings.TrimSpace(attrs["highest_severity"]),
		"observed_at":         eventObservedAt(event),
		"event_id":            event.GetId(),
	}
	if codes := strings.TrimSpace(attrs["issue_codes"]); codes != "" {
		out["issue_codes"] = codes
	}
	if codes := strings.TrimSpace(attrs["failing_issue_codes"]); codes != "" {
		out["failing_issue_codes"] = codes
	}
	if data, err := json.Marshal(payload.Issues); err == nil && len(payload.Issues) != 0 {
		out["issues_json"] = string(data)
	}
	if len(payload.SPFRecords) != 0 {
		out["spf_records"] = strings.Join(payload.SPFRecords, "\n")
	}
	if len(payload.DMARCRecords) != 0 {
		out["dmarc_records"] = strings.Join(payload.DMARCRecords, "\n")
	}
	if len(payload.MXRecords) != 0 {
		out["mx_records"] = strings.Join(payload.MXRecords, "\n")
	}
	if len(payload.DMARCRua) != 0 {
		out["dmarc_rua"] = strings.Join(payload.DMARCRua, ",")
	}
	if len(payload.RelatedRecords) != 0 {
		out["related_records"] = strings.Join(payload.RelatedRecords, "\n")
	}
	trimEmptyProjectionAttributes(out)
	return out
}

func trimEmptyProjectionAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}
