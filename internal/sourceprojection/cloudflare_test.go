package sourceprojection

import (
	"context"
	"fmt"
	"strings"
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
		cloudflareTestEvent("cf-worker-script", "cloudflare.worker_script", map[string]string{
			"script_id": "api", "account_id": "acct-1", "name": "api",
		}, `{"id":"api"}`),
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
	accessAppURN := "urn:cerebro:writer:cloudflare_access_application:acct-1%7Capp-1"
	accountRulesetURN := "urn:cerebro:writer:cloudflare_account_ruleset:acct-1%7Cruleset-1"
	workerScriptURN := "urn:cerebro:writer:cloudflare_worker_script:acct-1%7Capi"
	poolURN := "urn:cerebro:writer:cloudflare_load_balancer_pool:pool-1"
	defaultPoolURN := "urn:cerebro:writer:cloudflare_load_balancer_pool:pool-2"
	zoneAccessGroupURN := "urn:cerebro:writer:cloudflare_zone_access_group:zone-1%7Cgroup-1"
	zoneRulesetURN := "urn:cerebro:writer:cloudflare_zone_ruleset:zone-1%7Czone-ruleset-1"
	loadBalancerURN := "urn:cerebro:writer:cloudflare_load_balancer:zone-1%7Clb-1"
	auditURN := "urn:cerebro:writer:cloudflare_audit_log:audit-1"

	for _, urn := range []string{accessAppURN, accountRulesetURN, workerScriptURN, poolURN, zoneAccessGroupURN, zoneRulesetURN, loadBalancerURN, auditURN} {
		if entity := state.entities[urn]; entity == nil {
			t.Fatalf("expected entity %s; entities=%#v", urn, state.entities)
		}
	}
	assertProjectedLink(t, state, accessAppURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, accountRulesetURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, workerScriptURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, poolURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, zoneAccessGroupURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, zoneRulesetURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, loadBalancerURN, relationBelongsTo, zoneURN)
	assertProjectedLink(t, state, loadBalancerURN, relationDependsOn, poolURN)
	assertProjectedLink(t, state, loadBalancerURN, relationDependsOn, defaultPoolURN)
}

func TestProjectCloudflareWorkerScriptRequiresAccountScopedIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := cloudflareTestEvent("cf-worker-missing-account", "cloudflare.worker_script", map[string]string{
		"script_id": "api",
		"name":      "api",
	}, `{"id":"api"}`)
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	nameOnlyURN := "urn:cerebro:writer:cloudflare_worker_script:api"
	if entity := state.entities[nameOnlyURN]; entity != nil {
		t.Fatalf("worker script without account must not use script name alone: %#v", entity)
	}
	eventURN := "urn:cerebro:writer:cloudflare_worker_script:cf-worker-missing-account"
	if entity := state.entities[eventURN]; entity == nil || entity.EntityType != "cloudflare.worker_script" {
		t.Fatalf("worker script fallback entity missing or wrong: %#v", entity)
	}
}

func TestProjectCloudflareLoadBalancerDoesNotUseZoneAsIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := cloudflareTestEvent("cf-lb-missing-id", "cloudflare.load_balancer", map[string]string{
		"zone_id": "zone-1",
		"name":    "www.example.com",
	}, `{"name":"www.example.com"}`)
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	zoneDerivedURN := "urn:cerebro:writer:cloudflare_load_balancer:zone-1"
	if entity := state.entities[zoneDerivedURN]; entity != nil {
		t.Fatalf("load balancer without id must not use zone as identity: %#v", entity)
	}
	eventURN := "urn:cerebro:writer:cloudflare_load_balancer:cf-lb-missing-id"
	if entity := state.entities[eventURN]; entity == nil || entity.EntityType != "cloudflare.load_balancer" {
		t.Fatalf("load balancer fallback entity missing or wrong: %#v", entity)
	}
}

func TestProjectCloudflareScopedResourcesRequireScopeKey(t *testing.T) {
	tests := []struct {
		name     string
		eventID  string
		kind     string
		attrs    map[string]string
		entityID string
	}{
		{
			name:     "access_application without account_id",
			eventID:  "cf-app-no-account",
			kind:     "cloudflare.access_application",
			attrs:    map[string]string{"application_id": "app-1", "name": "Admin App"},
			entityID: "app-1",
		},
		{
			name:     "zone_access_group without zone_id",
			eventID:  "cf-group-no-zone",
			kind:     "cloudflare.zone_access_group",
			attrs:    map[string]string{"group_id": "group-1", "name": "Employees"},
			entityID: "group-1",
		},
		{
			name:     "account_ruleset without account_id",
			eventID:  "cf-ruleset-no-account",
			kind:     "cloudflare.account_ruleset",
			attrs:    map[string]string{"ruleset_id": "ruleset-1", "name": "WAF"},
			entityID: "ruleset-1",
		},
		{
			name:     "gateway_rule without account_id",
			eventID:  "cf-gw-rule-no-account",
			kind:     "cloudflare.gateway_rule",
			attrs:    map[string]string{"rule_id": "rule-1", "name": "Block bad traffic"},
			entityID: "rule-1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)

			event := cloudflareTestEvent(tc.eventID, tc.kind, tc.attrs, `{"id":"`+tc.entityID+`"}`)
			if _, err := service.Project(context.Background(), event); err != nil {
				t.Fatalf("Project() error = %v", err)
			}

			family := strings.ReplaceAll(tc.kind, ".", "_")
			unscopedURN := fmt.Sprintf("urn:cerebro:writer:%s:%s", family, tc.entityID)
			if entity := state.entities[unscopedURN]; entity != nil {
				t.Fatalf("unscoped entity %s must not exist: %#v", unscopedURN, entity)
			}
			eventURN := fmt.Sprintf("urn:cerebro:writer:%s:%s", family, tc.eventID)
			if entity := state.entities[eventURN]; entity == nil || entity.EntityType != tc.kind {
				t.Fatalf("fallback entity %s missing or wrong: %#v", eventURN, entity)
			}
		})
	}
}

func TestProjectCloudflareScopedResourcesStayDistinctAcrossScopes(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		idKey    string
		idValue  string
		scopeKey string
		scopeA   string
		scopeB   string
	}{
		{
			name:     "access_application across accounts",
			kind:     "cloudflare.access_application",
			idKey:    "application_id",
			idValue:  "app-1",
			scopeKey: "account_id",
			scopeA:   "acct-1",
			scopeB:   "acct-2",
		},
		{
			name:     "zone_access_group across zones",
			kind:     "cloudflare.zone_access_group",
			idKey:    "group_id",
			idValue:  "group-1",
			scopeKey: "zone_id",
			scopeA:   "zone-1",
			scopeB:   "zone-2",
		},
		{
			name:     "load_balancer across zones",
			kind:     "cloudflare.load_balancer",
			idKey:    "load_balancer_id",
			idValue:  "lb-1",
			scopeKey: "zone_id",
			scopeA:   "zone-1",
			scopeB:   "zone-2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)

			for i, scope := range []string{tc.scopeA, tc.scopeB} {
				event := cloudflareTestEvent(
					fmt.Sprintf("cf-%s-%d", tc.idValue, i),
					tc.kind,
					map[string]string{tc.idKey: tc.idValue, tc.scopeKey: scope, "name": "test"},
					`{"id":"`+tc.idValue+`"}`,
				)
				if _, err := service.Project(context.Background(), event); err != nil {
					t.Fatalf("Project() error = %v", err)
				}
			}

			family := strings.ReplaceAll(tc.kind, ".", "_")
			urnA := fmt.Sprintf("urn:cerebro:writer:%s:%s%%7C%s", family, tc.scopeA, tc.idValue)
			urnB := fmt.Sprintf("urn:cerebro:writer:%s:%s%%7C%s", family, tc.scopeB, tc.idValue)
			if urnA == urnB {
				t.Fatalf("URNs must differ across scopes: %s", urnA)
			}
			for _, urn := range []string{urnA, urnB} {
				if entity := state.entities[urn]; entity == nil {
					t.Fatalf("expected entity %s; entities=%#v", urn, state.entities)
				}
			}
		})
	}
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
