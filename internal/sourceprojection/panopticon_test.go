package sourceprojection

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectPanopticonCaseBuildsLinkedGraphAndEvidencePointers(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 8, 12, 0, 0, 0, time.UTC)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "panopticon-case-event-1",
		TenantId:   "writer",
		SourceId:   "panopticon",
		Kind:       "panopticon.case",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"case_id": "case-1",
			"status":  "investigating",
			"title":   "Credential exposure investigation",
		},
		Payload: mustJSON(t, map[string]any{
			"case_id": "case-1",
			"status":  "investigating",
			"title":   "Credential exposure investigation",
			"alerts": []map[string]any{{
				"alert_id": "alert-1",
				"title":    "Suspicious token use",
				"severity": "high",
				"status":   "open",
			}},
			"iocs": []map[string]any{{
				"ioc_id":   "ioc-1",
				"ioc_type": "domain",
				"value":    "evil.example",
			}},
			"assets": []map[string]any{{
				"asset_id":   "asset-1",
				"asset_type": "host",
				"name":       "prod-host-1",
			}},
			"evidence": []map[string]any{{
				"evidence_id":         "evidence-1",
				"evidence_cas":        "cas://objects/evidence-1",
				"sha256":              "abc123",
				"content_type":        "application/json",
				"inline_bytes":        "must-not-be-projected",
				"chain_of_custody":    []map[string]any{{"step": "captured", "actor": "panopticon"}},
				"chain_of_custody_id": "chain-1",
			}},
			"timeline": []map[string]any{{
				"event_id": "timeline-1",
				"title":    "Analyst opened case",
			}},
		}),
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected == 0 || result.LinksProjected == 0 {
		t.Fatalf("expected linked case projection, got entities=%d links=%d", result.EntitiesProjected, result.LinksProjected)
	}

	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	alertURN := "urn:cerebro:writer:panopticon_alert:alert-1"
	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-1"
	assetURN := "urn:cerebro:writer:panopticon_asset:asset-1"
	evidenceURN := "urn:cerebro:writer:evidence_cas_pointer:evidence-1"

	if entity := state.entities[caseURN]; entity == nil || entity.EntityType != "panopticon.case" {
		t.Fatalf("case entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[alertURN]; entity == nil || entity.EntityType != "panopticon.alert" {
		t.Fatalf("linked alert entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[iocURN]; entity == nil || entity.EntityType != "panopticon.ioc" {
		t.Fatalf("linked IOC entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[assetURN]; entity == nil || entity.EntityType != "panopticon.asset" {
		t.Fatalf("linked asset entity missing or wrong type: %#v", entity)
	}
	evidence := state.entities[evidenceURN]
	if evidence == nil || evidence.EntityType != "evidence.cas.pointer" {
		t.Fatalf("EvidenceCAS pointer entity missing or wrong type: %#v", evidence)
	}
	if got := evidence.Attributes["evidence_cas"]; got != "cas://objects/evidence-1" {
		t.Fatalf("EvidenceCAS pointer = %q, want cas://objects/evidence-1", got)
	}
	if got := evidence.Attributes["sha256"]; got != "abc123" {
		t.Fatalf("EvidenceCAS sha256 = %q, want abc123", got)
	}
	if got := evidence.Attributes["chain_of_custody_present"]; got != "true" {
		t.Fatalf("EvidenceCAS chain_of_custody_present = %q, want true", got)
	}
	for key, value := range evidence.Attributes {
		if strings.Contains(key, "bytes") || strings.Contains(value, "must-not-be-projected") {
			t.Fatalf("EvidenceCAS projected inline evidence bytes in %q=%q", key, value)
		}
	}

	assertProjectedLink(t, state, caseURN, relationContains, alertURN)
	assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, caseURN, relationHasEvidence, iocURN)
	assertProjectedLink(t, state, caseURN, relationContains, assetURN)
	assertProjectedLink(t, state, caseURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationBelongsTo, caseURN)

	for urn, entity := range state.entities {
		if strings.Contains(strings.ToLower(entity.EntityType), "finding") || strings.Contains(strings.ToLower(urn), ":finding") || strings.Contains(strings.ToLower(urn), "timeline") {
			t.Fatalf("raw Panopticon temporal data should not be promoted into findings/timeline entities: %s %#v", urn, entity)
		}
	}
}

func TestProjectPanopticonAlertAndIOCLinkToCasesAssetsAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-alert-event-1",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.alert",
		Attributes: map[string]string{
			"alert_id": "alert-1",
			"case_id":  "case-1",
			"severity": "critical",
			"status":   "open",
			"title":    "Suspicious domain observed",
		},
		Payload: mustJSON(t, map[string]any{
			"alert_id": "alert-1",
			"case_id":  "case-1",
			"severity": "critical",
			"status":   "open",
			"title":    "Suspicious domain observed",
			"iocs": []map[string]any{{
				"ioc_id":   "ioc-1",
				"ioc_type": "domain",
				"value":    "evil.example",
			}},
			"assets": []map[string]any{{
				"asset_id":   "asset-1",
				"asset_type": "host",
				"name":       "prod-host-1",
			}},
		}),
	})
	if err != nil {
		t.Fatalf("Project(alert) error = %v", err)
	}
	_, err = service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "panopticon-ioc-event-1",
		TenantId: "writer",
		SourceId: "panopticon",
		Kind:     "panopticon.ioc",
		Attributes: map[string]string{
			"ioc_id":   "ioc-1",
			"ioc_type": "domain",
			"value":    "evil.example",
			"case_id":  "case-1",
			"alert_id": "alert-1",
		},
		Payload: mustJSON(t, map[string]any{
			"ioc_id":   "ioc-1",
			"ioc_type": "domain",
			"value":    "evil.example",
			"case_id":  "case-1",
			"alert_id": "alert-1",
		}),
	})
	if err != nil {
		t.Fatalf("Project(ioc) error = %v", err)
	}

	alertURN := "urn:cerebro:writer:panopticon_alert:alert-1"
	caseURN := "urn:cerebro:writer:panopticon_case:case-1"
	iocURN := "urn:cerebro:writer:panopticon_ioc:ioc-1"
	assetURN := "urn:cerebro:writer:panopticon_asset:asset-1"

	assertProjectedLink(t, state, alertURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
	assertProjectedLink(t, state, alertURN, relationObservedOn, assetURN)
	assertProjectedLink(t, state, iocURN, relationBelongsTo, caseURN)
	assertProjectedLink(t, state, alertURN, relationHasEvidence, iocURN)
}
