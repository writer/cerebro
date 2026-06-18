package sourceprojection

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func tailscaleTestEvent(id string, kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "tailscale",
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)),
		Attributes: attrs,
	}
}

func TestProjectTailscaleInventoryEntitiesAndLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	ctx := context.Background()

	events := []*cerebrov1.EventEnvelope{
		tailscaleTestEvent("ts-tailnet-1", "tailscale.tailnet", map[string]string{
			"tailnet": "writer.com", "devices_approval_on": "true", "users_approval_on": "false", "network_flow_logging_on": "true",
		}),
		tailscaleTestEvent("ts-user-1", "tailscale.user", map[string]string{
			"user_id": "user-1", "login_name": "alice@writer.com", "email": "alice@writer.com", "role": "admin", "status": "active",
		}),
		tailscaleTestEvent("ts-device-1", "tailscale.device", map[string]string{
			"device_id": "device-1", "node_id": "node-1", "name": "laptop", "os": "macOS", "user_id": "user-1", "authorized": "true",
		}),
		tailscaleTestEvent("ts-group-1", "tailscale.group", map[string]string{
			"group_id": "group:eng", "name": "group:eng", "members": "alice@writer.com,bob@writer.com",
		}),
		tailscaleTestEvent("ts-tag-1", "tailscale.tag", map[string]string{
			"tag_id": "tag:prod", "name": "tag:prod", "owners": "group:eng",
		}),
		tailscaleTestEvent("ts-service-1", "tailscale.service", map[string]string{
			"service_id": "service-1", "name": "api", "tags": "tag:prod",
		}),
		tailscaleTestEvent("ts-grant-1", "tailscale.grant", map[string]string{
			"grant_id": "grant-1", "sources": "group:eng", "destinations": "tag:prod:443",
		}),
	}
	for _, event := range events {
		if _, err := service.Project(ctx, event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	tailnetURN := "urn:cerebro:writer:tailscale_tailnet:writer.com"
	userURN := "urn:cerebro:writer:tailscale_user:user-1"
	deviceURN := "urn:cerebro:writer:tailscale_device:device-1"
	groupURN := "urn:cerebro:writer:tailscale_group:group:eng"
	tagURN := "urn:cerebro:writer:tailscale_tag:tag:prod"
	serviceURN := "urn:cerebro:writer:tailscale_service:service-1"
	grantURN := "urn:cerebro:writer:tailscale_grant:grant-1"
	memberURN := "urn:cerebro:writer:tailscale_user:alice@writer.com"
	destinationURN := "urn:cerebro:writer:tailscale_destination:tag:prod:443"

	if entity := state.entities[tailnetURN]; entity == nil || entity.Attributes["devices_approval_on"] != "true" {
		t.Fatalf("tailscale.tailnet entity missing or approval attr wrong: %#v", entity)
	}
	if entity := state.entities[userURN]; entity == nil || entity.EntityType != "tailscale.user" {
		t.Fatalf("tailscale.user entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[deviceURN]; entity == nil || entity.Attributes["authorized"] != "true" {
		t.Fatalf("tailscale.device entity missing or authorized attr wrong: %#v", entity)
	}
	if entity := state.entities[grantURN]; entity == nil || entity.EntityType != "tailscale.grant" {
		t.Fatalf("tailscale.grant entity missing or wrong: %#v", entity)
	}

	assertProjectedLink(t, state, deviceURN, relationOwnedBy, userURN)
	assertProjectedLink(t, state, userURN, relationCanReach, deviceURN)
	assertProjectedLink(t, state, groupURN, relationContains, memberURN)
	assertProjectedLink(t, state, memberURN, relationMemberOf, groupURN)
	assertProjectedLink(t, state, tagURN, relationOwnedBy, groupURN)
	assertProjectedLink(t, state, serviceURN, relationTaggedAs, tagURN)
	assertProjectedLink(t, state, grantURN, relationGrantsEntitlement, groupURN)
	assertProjectedLink(t, state, grantURN, relationCanReach, destinationURN)
}

func TestRegistryRoutesTailscaleCoreKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"tailscale.tailnet", map[string]string{"tailnet": "writer.com"}, "tailscale.tailnet"},
		{"tailscale.user", map[string]string{"user_id": "user-1", "login_name": "alice@writer.com"}, "tailscale.user"},
		{"tailscale.device", map[string]string{"device_id": "device-1"}, "tailscale.device"},
		{"tailscale.group", map[string]string{"group_id": "group:eng"}, "tailscale.group"},
		{"tailscale.tag", map[string]string{"tag_id": "tag:prod"}, "tailscale.tag"},
		{"tailscale.service", map[string]string{"service_id": "service-1"}, "tailscale.service"},
		{"tailscale.grant", map[string]string{"grant_id": "grant-1"}, "tailscale.grant"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			entities, _, err := BuiltinRegistry().Project(tailscaleTestEvent("ts-"+tc.kind, tc.kind, tc.attrs))
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

func TestProjectTailscaleDeviceDeauthorizationRetraction(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := tailscaleTestEvent("ts-device-deauth", "tailscale.device", map[string]string{
		"device_id": "device-1", "user_id": "user-1", "authorized": "false",
	})
	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	deviceURN := "urn:cerebro:writer:tailscale_device:device-1"
	userURN := "urn:cerebro:writer:tailscale_user:user-1"
	retracted := false
	for _, link := range links {
		if link.FromURN == userURN && link.ToURN == deviceURN && link.Relation == relationCanReach {
			retracted = true
		}
	}
	if !retracted {
		t.Fatalf("expected user->device can_reach retracted; links=%#v", links)
	}
}

func TestProjectTailscaleDeviceBlocksIncomingRetraction(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := tailscaleTestEvent("ts-device-blocks-incoming", "tailscale.device", map[string]string{
		"device_id": "device-1", "user_id": "user-1", "authorized": "true", "blocks_incoming_connections": "true",
	})
	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	deviceURN := "urn:cerebro:writer:tailscale_device:device-1"
	userURN := "urn:cerebro:writer:tailscale_user:user-1"
	var retracted *struct{ reason string }
	for _, link := range links {
		if link.FromURN == userURN && link.ToURN == deviceURN && link.Relation == relationCanReach {
			retracted = &struct{ reason string }{reason: link.Attributes["retraction"]}
		}
	}
	if retracted == nil {
		t.Fatalf("expected user->device can_reach retracted; links=%#v", links)
	}
	if retracted.reason != "tailscale_device_blocks_incoming" {
		t.Fatalf("retraction reason = %q, want tailscale_device_blocks_incoming", retracted.reason)
	}
	if got := projectionRetractionReason(links); got != "tailscale_device_blocks_incoming" {
		t.Fatalf("projectionRetractionReason() = %q, want tailscale_device_blocks_incoming", got)
	}

	entities, projectedLinks, err := BuiltinRegistry().Project(event)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatalf("expected device entity to project; entities=%#v", entities)
	}
	for _, link := range projectedLinks {
		if link.FromURN == userURN && link.ToURN == deviceURN && link.Relation == relationCanReach {
			t.Fatalf("expected no owner can_reach edge for device blocking incoming connections; links=%#v", projectedLinks)
		}
	}
}

func TestProjectTailscaleGrantDisabledRetraction(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := tailscaleTestEvent("ts-grant-disabled", "tailscale.grant", map[string]string{
		"grant_id": "grant-1", "sources": "group:eng", "destinations": "tag:prod:443", "disabled": "true",
	})
	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	grantURN := "urn:cerebro:writer:tailscale_grant:grant-1"
	groupURN := "urn:cerebro:writer:tailscale_group:group:eng"
	destinationURN := "urn:cerebro:writer:tailscale_destination:tag:prod:443"
	sourceRetracted := false
	destinationRetracted := false
	for _, link := range links {
		if link.FromURN == grantURN && link.ToURN == groupURN && link.Relation == relationGrantsEntitlement {
			sourceRetracted = true
		}
		if link.FromURN == grantURN && link.ToURN == destinationURN && link.Relation == relationCanReach {
			destinationRetracted = true
		}
	}
	if !sourceRetracted || !destinationRetracted {
		t.Fatalf("expected grant source and destination edges retracted; links=%#v", links)
	}
}

func TestProjectTailscaleGrantNoRetractionWhenEnabled(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := tailscaleTestEvent("ts-grant-enabled", "tailscale.grant", map[string]string{
		"grant_id": "grant-1", "sources": "group:eng", "destinations": "tag:prod:443",
	})
	links, err := service.ProjectRetractions(event)
	if err != nil {
		t.Fatalf("ProjectRetractions() error = %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("expected no retractions for enabled grant; got %#v", links)
	}
}
