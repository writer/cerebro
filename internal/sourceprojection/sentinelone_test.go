package sourceprojection

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProjectSentinelOneAgentBuildsAgentEntity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.April, 23, 1, 0, 0, 0, time.UTC)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "s1-agent-1",
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       "sentinelone.agent",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"agent_id":             "agent-1",
			"computer_name":        "host-1",
			"os_name":              "macOS",
			"os_type":              "macos",
			"is_active":            "true",
			"is_decommissioned":    "false",
			"is_pending_uninstall": "false",
			"is_up_to_date":        "true",
			"infected":             "false",
			"firewall_enabled":     "false",
			"active_threats":       "0",
			"hostname":             "host-1",
			"external_ip":          "203.0.113.10",
			"last_active_date":     "2026-04-23T01:00:00Z",
			"site_id":              "site-1",
			"site_name":            "Production",
			"group_id":             "group-1",
			"group_name":           "Default",
			"tenant_host":          "writer.sentinelone.example",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 5 {
		t.Fatalf("EntitiesProjected = %d, want 5", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("LinksProjected = %d, want 4", result.LinksProjected)
	}

	agentURN := "urn:cerebro:writer:sentinelone_agent:agent-1"
	siteURN := "urn:cerebro:writer:sentinelone_site:site-1"
	groupURN := "urn:cerebro:writer:sentinelone_group:group-1"
	ipURN := "urn:cerebro:writer:internet_ip:203.0.113.10"
	hostIdentifierURN := "urn:cerebro:writer:endpoint_identifier:hostname:host-1"
	if state.entities[agentURN] == nil {
		t.Fatalf("agent entity missing: %#v", state.entities)
	}
	if state.entities[agentURN].EntityType != "sentinelone.agent" {
		t.Fatalf("agent entity type = %q, want sentinelone.agent", state.entities[agentURN].EntityType)
	}
	if state.entities[agentURN].Attributes["computer_name"] != "host-1" {
		t.Fatalf("agent computer_name = %q, want host-1", state.entities[agentURN].Attributes["computer_name"])
	}
	if got := state.entities[agentURN].Attributes["hostname"]; got != "host-1" {
		t.Fatalf("agent hostname = %q, want host-1", got)
	}
	if got := state.entities[agentURN].Attributes["control_type"]; got != "firewall" {
		t.Fatalf("agent control_type = %q, want firewall", got)
	}
	if got := state.entities[agentURN].Attributes["control_state"]; got != "disabled" {
		t.Fatalf("agent control_state = %q, want disabled", got)
	}
	if got := state.entities[agentURN].Attributes["is_pending_uninstall"]; got != "false" {
		t.Fatalf("agent is_pending_uninstall = %q, want false", got)
	}
	if entity := state.entities[ipURN]; entity == nil || entity.EntityType != "internet.ip" {
		t.Fatalf("internet ip entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, agentURN, relationBelongsTo, siteURN)
	assertProjectedLink(t, state, agentURN, relationMemberOf, groupURN)
	assertProjectedLink(t, state, agentURN, relationHasIdentifier, ipURN)
	assertProjectedLink(t, state, agentURN, relationHasIdentifier, hostIdentifierURN)
	if got := state.links[agentURN+"|"+relationHasIdentifier+"|"+ipURN].Attributes["at"]; got != occurred.Format(time.RFC3339) {
		t.Fatalf("identifier link at = %q, want %q", got, occurred.Format(time.RFC3339))
	}
}

func TestProjectSentinelOneAgentSkipsWhenAgentIDMissing(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "s1-agent-empty",
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       "sentinelone.agent",
		Attributes: map[string]string{},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 0 || result.LinksProjected != 0 {
		t.Fatalf("expected empty projection, got entities=%d links=%d", result.EntitiesProjected, result.LinksProjected)
	}
}

func TestProjectSentinelOneThreatLinksThreatToAgent(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.April, 24, 2, 0, 0, 0, time.UTC)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "s1-threat-1",
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       "sentinelone.threat",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"threat_id":              "threat-1",
			"agent_id":               "agent-1",
			"agent_name":             "host-1",
			"computer_name":          "host-1",
			"hostname":               "host-1",
			"agent_ip_v6":            "2001:db8::20",
			"external_ip":            "203.0.113.20",
			"ip_addresses":           "203.0.113.20,2001:db8::20",
			"classification":         "Malware",
			"classification_norm":    "malware",
			"classification_source":  "Engine",
			"analyst_verdict":        "true_positive",
			"analyst_verdict_norm":   "true_positive",
			"automatically_resolved": "false",
			"incident_status":        "unresolved",
			"incident_status_norm":   "unresolved",
			"mitigation_status":      "not_mitigated",
			"mitigation_status_norm": "not_mitigated",
			"confidence_level":       "malicious",
			"site_id":                "site-1",
			"group_id":               "group-1",
			"mitre_tactics":          "Execution",
			"mitre_techniques":       "Native API",
			"is_active":              "true",
			"is_fileless":            "false",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	threatURN := "urn:cerebro:writer:sentinelone_threat:threat-1"
	agentURN := "urn:cerebro:writer:sentinelone_agent:agent-1"
	ipURN := "urn:cerebro:writer:internet_ip:203.0.113.20"
	ipv6URN := "urn:cerebro:writer:internet_ip:2001:db8::20"
	hostIdentifierURN := "urn:cerebro:writer:endpoint_identifier:hostname:host-1"
	siteURN := "urn:cerebro:writer:sentinelone_site:site-1"
	groupURN := "urn:cerebro:writer:sentinelone_group:group-1"

	if state.entities[threatURN] == nil {
		t.Fatalf("threat entity missing")
	}
	if state.entities[agentURN] == nil {
		t.Fatalf("agent entity missing")
	}
	assertProjectedLink(t, state, agentURN, relationAffectedBy, threatURN)
	assertProjectedLink(t, state, agentURN, relationHasIdentifier, ipURN)
	assertProjectedLink(t, state, agentURN, relationHasIdentifier, ipv6URN)
	assertProjectedLink(t, state, agentURN, relationHasIdentifier, hostIdentifierURN)
	if got := state.links[agentURN+"|"+relationHasIdentifier+"|"+ipURN].Attributes["at"]; got != occurred.Format(time.RFC3339) {
		t.Fatalf("identifier link at = %q, want %q", got, occurred.Format(time.RFC3339))
	}
	assertProjectedLink(t, state, threatURN, relationBelongsTo, siteURN)
	assertProjectedLink(t, state, threatURN, relationMemberOf, groupURN)
	if got := state.entities[threatURN].Attributes["classification"]; got != "Malware" {
		t.Fatalf("threat classification = %q, want Malware", got)
	}
	if got := state.entities[threatURN].Attributes["mitigation_status_norm"]; got != "not_mitigated" {
		t.Fatalf("threat mitigation_status_norm = %q, want not_mitigated", got)
	}
	if got := state.entities[threatURN].Attributes["mitre_tactics"]; got != "Execution" {
		t.Fatalf("threat mitre_tactics = %q, want Execution", got)
	}
	_ = result
}

func TestProjectSentinelOneSiteAccountLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "s1-site-1",
		TenantId: "writer",
		SourceId: "sentinelone",
		Kind:     "sentinelone.site",
		Attributes: map[string]string{
			"site_id":      "site-1",
			"site_name":    "Production",
			"account_id":   "account-1",
			"account_name": "Writer",
			"is_default":   "true",
		},
	}); err != nil {
		t.Fatalf("Project(site) error = %v", err)
	}
	siteURN := "urn:cerebro:writer:sentinelone_site:site-1"
	accountURN := "urn:cerebro:writer:sentinelone_account:account-1"
	if state.entities[siteURN] == nil {
		t.Fatal("site entity missing")
	}
	if state.entities[accountURN] == nil {
		t.Fatal("account entity missing")
	}
	assertProjectedLink(t, state, siteURN, relationBelongsTo, accountURN)
}

func TestProjectSentinelOneGroupSiteLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "s1-group-1",
		TenantId: "writer",
		SourceId: "sentinelone",
		Kind:     "sentinelone.group",
		Attributes: map[string]string{
			"group_id":     "group-1",
			"group_name":   "Default",
			"site_id":      "site-1",
			"site_name":    "Production",
			"total_agents": "5",
		},
	}); err != nil {
		t.Fatalf("Project(group) error = %v", err)
	}
	groupURN := "urn:cerebro:writer:sentinelone_group:group-1"
	siteURN := "urn:cerebro:writer:sentinelone_site:site-1"
	if state.entities[groupURN] == nil {
		t.Fatal("group entity missing")
	}
	assertProjectedLink(t, state, groupURN, relationBelongsTo, siteURN)
}

func TestProjectSentinelOneActivityLinksAgentAndThreat(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "s1-activity-1",
		TenantId: "writer",
		SourceId: "sentinelone",
		Kind:     "sentinelone.activity",
		Attributes: map[string]string{
			"activity_id":         "activity-1",
			"activity_type":       "27",
			"primary_description": "User logged in",
			"agent_id":            "agent-1",
			"threat_id":           "threat-1",
			"site_id":             "site-1",
		},
	}); err != nil {
		t.Fatalf("Project(activity) error = %v", err)
	}
	activityURN := "urn:cerebro:writer:sentinelone_activity:activity-1"
	agentURN := "urn:cerebro:writer:sentinelone_agent:agent-1"
	threatURN := "urn:cerebro:writer:sentinelone_threat:threat-1"
	if state.entities[activityURN] == nil {
		t.Fatal("activity entity missing")
	}
	assertProjectedLink(t, state, activityURN, relationObservedOn, agentURN)
	assertProjectedLink(t, state, activityURN, relationActedOn, threatURN)
}

func TestProjectSentinelOneApplicationInventoryContainedByAgent(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "s1-app-1",
		TenantId: "writer",
		SourceId: "sentinelone",
		Kind:     "sentinelone.application_inventory",
		Attributes: map[string]string{
			"agent_id":         "agent-1",
			"application_name": "Example App",
			"publisher":        "Example Inc",
			"version":          "1.0.0",
			"installed_date":   "2026-04-20T00:00:00Z",
		},
	}); err != nil {
		t.Fatalf("Project(app) error = %v", err)
	}
	appURN := "urn:cerebro:writer:sentinelone_installed_app:agent-1:example inc|example app|1.0.0"
	agentURN := "urn:cerebro:writer:sentinelone_agent:agent-1"
	if state.entities[appURN] == nil {
		t.Fatalf("application entity missing; got entities=%v", state.entities)
	}
	assertProjectedLink(t, state, agentURN, relationContains, appURN)
}

func TestProjectSentinelOneExclusion(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "s1-exclusion-1",
		TenantId: "writer",
		SourceId: "sentinelone",
		Kind:     "sentinelone.exclusion",
		Attributes: map[string]string{
			"exclusion_id":   "exclusion-1",
			"exclusion_type": "path",
			"mode":           "suppress_alerts",
			"os_type":        "macos",
			"scope":          "site",
			"value":          "/Applications/Approved.app",
		},
	}); err != nil {
		t.Fatalf("Project(exclusion) error = %v", err)
	}
	exclusionURN := "urn:cerebro:writer:sentinelone_exclusion:exclusion-1"
	if state.entities[exclusionURN] == nil {
		t.Fatal("exclusion entity missing")
	}
	if got := state.entities[exclusionURN].Attributes["scope"]; got != "site" {
		t.Fatalf("exclusion scope = %q, want site", got)
	}
}
