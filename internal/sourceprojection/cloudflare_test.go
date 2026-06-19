package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func cloudflareTestEvent(id string, kind string, attrs map[string]string, payload string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "cloudflare",
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		Attributes: attrs,
		Payload:    []byte(payload),
	}
}

func TestProjectCloudflareInventoryEntitiesAndLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	ctx := context.Background()

	// The in-memory test recorder replaces entities on upsert (the production
	// store merges), so events that emit stub endpoints are projected before the
	// rich event for the same entity to keep this assertion deterministic.
	events := []*cerebrov1.EventEnvelope{
		cloudflareTestEvent("cf-dns-1", "cloudflare.dns_record", map[string]string{
			"record_id": "dns-1", "zone_id": "zone-1", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "proxied": "true",
		}, `{"id":"dns-1","name":"www.example.com"}`),
		cloudflareTestEvent("cf-member-1", "cloudflare.member", map[string]string{
			"member_id": "member-1", "account_id": "acct-1", "email": "alice@example.com", "status": "accepted",
		}, `{"id":"member-1","roles":[{"id":"role-1","name":"Administrator"}]}`),
		cloudflareTestEvent("cf-zone-1", "cloudflare.zone", map[string]string{
			"zone_id": "zone-1", "account_id": "acct-1", "name": "example.com", "status": "active", "paused": "false",
		}, `{"id":"zone-1","name":"example.com"}`),
		cloudflareTestEvent("cf-role-1", "cloudflare.role", map[string]string{
			"role_id": "role-1", "account_id": "acct-1", "name": "Administrator",
		}, `{"id":"role-1","name":"Administrator"}`),
		cloudflareTestEvent("cf-account-1", "cloudflare.account", map[string]string{
			"account_id": "acct-1", "name": "Writer", "type": "enterprise",
		}, `{"id":"acct-1","name":"Writer"}`),
	}
	for _, event := range events {
		if _, err := service.Project(ctx, event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	accountURN := "urn:cerebro:writer:cloudflare_account:acct-1"
	emailURN := "urn:cerebro:writer:identifier:email:alice@example.com"
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	roleURN := "urn:cerebro:writer:cloudflare_role:role-1"
	memberURN := "urn:cerebro:writer:cloudflare_member:member-1"
	zoneURN := "urn:cerebro:writer:cloudflare_zone:zone-1"
	recordURN := "urn:cerebro:writer:cloudflare_dns_record:dns-1"

	if entity := state.entities[accountURN]; entity == nil || entity.EntityType != "cloudflare.account" {
		t.Fatalf("cloudflare.account entity missing or wrong: %#v", entity)
	}
	member := state.entities[memberURN]
	if member == nil || member.EntityType != "cloudflare.member" {
		t.Fatalf("cloudflare.member entity missing or wrong: %#v", member)
	}
	if got := member.Attributes["email"]; got != "alice@example.com" {
		t.Fatalf("member email attribute = %q", got)
	}
	if entity := state.entities[zoneURN]; entity == nil || entity.Attributes["paused"] != "false" {
		t.Fatalf("cloudflare.zone entity missing or paused attr wrong: %#v", entity)
	}
	record := state.entities[recordURN]
	if record == nil || record.Attributes["proxied"] != "true" {
		t.Fatalf("cloudflare.dns_record entity missing or proxied attr wrong: %#v", record)
	}

	assertProjectedLink(t, state, memberURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, memberURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, memberURN, relationHasIdentifier, emailURN)
	assertProjectedLink(t, state, memberURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, roleURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, zoneURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, recordURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, zoneURN, relationHasDNSRecord, recordURN)
}

func TestRegistryRoutesCloudflareCoreKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		payload    string
		entityType string
	}{
		{"cloudflare.account", map[string]string{"account_id": "acct-1", "name": "Writer"}, `{"id":"acct-1"}`, "cloudflare.account"},
		{"cloudflare.member", map[string]string{"member_id": "member-1", "account_id": "acct-1"}, `{"id":"member-1"}`, "cloudflare.member"},
		{"cloudflare.role", map[string]string{"role_id": "role-1", "account_id": "acct-1"}, `{"id":"role-1"}`, "cloudflare.role"},
		{"cloudflare.zone", map[string]string{"zone_id": "zone-1", "account_id": "acct-1"}, `{"id":"zone-1"}`, "cloudflare.zone"},
		{"cloudflare.dns_record", map[string]string{"record_id": "dns-1", "zone_id": "zone-1"}, `{"id":"dns-1"}`, "cloudflare.dns_record"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			entities, _, err := BuiltinRegistry().Project(cloudflareTestEvent("cf-"+tc.kind, tc.kind, tc.attrs, tc.payload))
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to dedicated projector; entities=%#v", tc.kind, entities)
			}
		})
	}
}

func TestProjectCloudflareScopedInventoryLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	ctx := context.Background()

	events := []*cerebrov1.EventEnvelope{
		cloudflareTestEvent("cf-access-app", "cloudflare.access_application", map[string]string{
			"application_id": "app-1", "account_id": "acct-1", "name": "Admin App",
		}, `{"id":"app-1"}`),
		cloudflareTestEvent("cf-account-ruleset", "cloudflare.account_ruleset", map[string]string{
			"ruleset_id": "ruleset-1", "account_id": "acct-1", "name": "Account WAF",
		}, `{"id":"ruleset-1"}`),
		cloudflareTestEvent("cf-pool", "cloudflare.load_balancer_pool", map[string]string{
			"pool_id": "pool-1", "account_id": "acct-1", "name": "Primary Pool",
		}, `{"id":"pool-1"}`),
		cloudflareTestEvent("cf-zone-access-group", "cloudflare.zone_access_group", map[string]string{
			"group_id": "group-1", "zone_id": "zone-1", "name": "Employees",
		}, `{"id":"group-1"}`),
		cloudflareTestEvent("cf-zone-ruleset", "cloudflare.zone_ruleset", map[string]string{
			"ruleset_id": "zone-ruleset-1", "zone_id": "zone-1", "name": "Zone WAF",
		}, `{"id":"zone-ruleset-1"}`),
		cloudflareTestEvent("cf-lb", "cloudflare.load_balancer", map[string]string{
			"load_balancer_id": "lb-1", "zone_id": "zone-1", "name": "www.example.com", "fallback_pool": "pool-1", "default_pools": "pool-2,pool-1",
		}, `{"id":"lb-1"}`),
		cloudflareTestEvent("cf-audit", "cloudflare.audit_log", map[string]string{
			"audit_id": "audit-1", "account_id": "acct-1", "zone_id": "zone-1", "actor_email": "admin@example.com",
		}, `{"id":"audit-1"}`),
	}
	for _, event := range events {
		if _, err := service.Project(ctx, event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	accountURN := "urn:cerebro:writer:cloudflare_account:acct-1"
	zoneURN := "urn:cerebro:writer:cloudflare_zone:zone-1"
	accessAppURN := "urn:cerebro:writer:cloudflare_access_application:app-1"
	accountRulesetURN := "urn:cerebro:writer:cloudflare_account_ruleset:ruleset-1"
	poolURN := "urn:cerebro:writer:cloudflare_load_balancer_pool:pool-1"
	defaultPoolURN := "urn:cerebro:writer:cloudflare_load_balancer_pool:pool-2"
	zoneAccessGroupURN := "urn:cerebro:writer:cloudflare_zone_access_group:group-1"
	zoneRulesetURN := "urn:cerebro:writer:cloudflare_zone_ruleset:zone-ruleset-1"
	loadBalancerURN := "urn:cerebro:writer:cloudflare_load_balancer:lb-1"
	auditURN := "urn:cerebro:writer:cloudflare_audit_log:audit-1"

	for _, urn := range []string{accessAppURN, accountRulesetURN, poolURN, zoneAccessGroupURN, zoneRulesetURN, loadBalancerURN, auditURN} {
		if entity := state.entities[urn]; entity == nil {
			t.Fatalf("expected entity %s; entities=%#v", urn, state.entities)
		}
	}
	assertProjectedLink(t, state, accessAppURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, accountRulesetURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, poolURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, zoneAccessGroupURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, zoneRulesetURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, loadBalancerURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, loadBalancerURN, relationDependsOn, poolURN)
	assertProjectedLink(t, state, loadBalancerURN, relationDependsOn, defaultPoolURN)
}

func TestProjectCloudflareDNSRecordZoneReassignmentRetraction(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := cloudflareTestEvent("cf-dns-reassigned", "cloudflare.dns_record", map[string]string{
		"record_id":        "dns-1",
		"zone_id":          "zone-2",
		"previous_zone_id": "zone-1",
		"name":             "www.example.com",
	}, `{"id":"dns-1"}`)

	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	recordURN := "urn:cerebro:writer:cloudflare_dns_record:dns-1"
	previousZoneURN := "urn:cerebro:writer:cloudflare_zone:zone-1"
	currentZoneURN := "urn:cerebro:writer:cloudflare_zone:zone-2"

	belongsRetracted := false
	hasRecordRetracted := false
	for _, link := range links {
		if link.FromURN == currentZoneURN || link.ToURN == currentZoneURN {
			t.Fatalf("retraction unexpectedly targeted current zone: %#v", link)
		}
		if link.FromURN == recordURN && link.ToURN == previousZoneURN && link.Relation == relationBelongsTo {
			belongsRetracted = true
		}
		if link.FromURN == previousZoneURN && link.ToURN == recordURN && link.Relation == relationHasDNSRecord {
			hasRecordRetracted = true
		}
	}
	if !belongsRetracted || !hasRecordRetracted {
		t.Fatalf("expected record<->previous-zone links retracted; links=%#v", links)
	}
}

func TestProjectCloudflareDNSRecordNoRetractionWithoutReassignment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := cloudflareTestEvent("cf-dns-stable", "cloudflare.dns_record", map[string]string{
		"record_id": "dns-1",
		"zone_id":   "zone-1",
	}, `{"id":"dns-1"}`)

	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("expected no retractions without zone reassignment; got %#v", links)
	}
}
