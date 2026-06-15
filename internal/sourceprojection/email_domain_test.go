package sourceprojection

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectEmailDomainHealthEntitiesAndLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	payload := emailDomainHealthPayload{
		Domain:      "example.com",
		Status:      "FAILING",
		Score:       40,
		SPFStatus:   "FAILING",
		DKIMStatus:  "FAILING",
		DMARCStatus: "FAILING",
		SPFRecords:  []string{"v=spf1 +all"},
		SPFPolicy:   "+all",
		DKIMSelectors: []emailDomainHealthDKIM{
			{Selector: "default", Status: "FAILING", KeyBits: 512, Record: "v=DKIM1; p=AAAA"},
		},
		Issues: []emailDomainHealthIssue{
			{ID: "SPF:spf_permissive_all", Protocol: "SPF", Severity: "CRITICAL", Code: "spf_permissive_all", Title: "SPF allows all senders", Detail: "+all", Recommendation: "use -all"},
			{ID: "DMARC:dmarc_missing", Protocol: "DMARC", Severity: "HIGH", Code: "dmarc_missing", Title: "DMARC missing"},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "email-domain-health-writer-example.com-deadbeef",
		TenantId:   "writer",
		SourceId:   "email_domain_health",
		Kind:       "email_domain_health.health",
		OccurredAt: timestamppb.New(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		SchemaRef:  "email_domain_health/health/v1",
		Payload:    data,
		Attributes: map[string]string{
			"domain":              "example.com",
			"status":              "FAILING",
			"score":               "40",
			"spf_status":          "FAILING",
			"dkim_status":         "FAILING",
			"dmarc_status":        "FAILING",
			"failing_issue_count": "2",
			"highest_severity":    "CRITICAL",
			"issue_codes":         "dmarc_missing,spf_permissive_all",
			"failing_issue_codes": "dmarc_missing,spf_permissive_all",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	domainURN := "urn:cerebro:writer:email_domain:example.com"
	internetDomainURN := "urn:cerebro:writer:internet_domain:example.com"
	selectorURN := "urn:cerebro:writer:email_dkim_selector:example.com:default"

	domainEntity := state.entities[domainURN]
	if domainEntity == nil || domainEntity.EntityType != "email.domain" {
		t.Fatalf("email.domain entity missing or wrong: %#v", domainEntity)
	}
	if got := domainEntity.Attributes["status"]; got != "FAILING" {
		t.Fatalf("email.domain status = %q, want FAILING", got)
	}
	if got := domainEntity.Attributes["spf_policy"]; got != "+all" {
		t.Fatalf("email.domain spf_policy = %q", got)
	}
	if got := domainEntity.Attributes["highest_severity"]; got != "CRITICAL" {
		t.Fatalf("email.domain highest_severity = %q", got)
	}
	if domainEntity.Attributes["issues_json"] == "" {
		t.Fatalf("email.domain issues_json is empty")
	}

	if entity := state.entities[internetDomainURN]; entity == nil || entity.EntityType != "internet.domain" {
		t.Fatalf("internet.domain entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, domainURN, relationBelongsTo, internetDomainURN)

	selector := state.entities[selectorURN]
	if selector == nil || selector.EntityType != "email.dkim_selector" {
		t.Fatalf("email.dkim_selector entity missing or wrong: %#v", selector)
	}
	if got := selector.Attributes["selector"]; got != "default" {
		t.Fatalf("dkim selector attribute = %q", got)
	}
	assertProjectedLink(t, state, domainURN, relationContains, selectorURN)
}

func TestProjectEmailDomainHealthRequiresDomainAttribute(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:         "email-domain-health-writer-missing",
		TenantId:   "writer",
		SourceId:   "email_domain_health",
		Kind:       "email_domain_health.health",
		OccurredAt: timestamppb.New(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		SchemaRef:  "email_domain_health/health/v1",
		Payload:    []byte(`{}`),
		Attributes: map[string]string{},
	}
	if _, err := service.Project(context.Background(), event); err == nil {
		t.Fatalf("Project() expected error for missing domain attribute")
	}
}
