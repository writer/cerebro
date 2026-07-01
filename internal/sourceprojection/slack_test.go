package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func slackEvent(kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "slack-" + kind,
		TenantId:   "writer",
		SourceId:   "slack",
		Kind:       kind,
		Attributes: attrs,
	}
}

func projectedEntitiesByURN(entities []*ports.ProjectedEntity) map[string]*ports.ProjectedEntity {
	byURN := make(map[string]*ports.ProjectedEntity, len(entities))
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		byURN[entity.URN] = entity
	}
	return byURN
}

func TestProjectSlackUserPostureAndTeamContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := slackEvent("slack.user", map[string]string{
		"user_id":  "U1",
		"team_id":  "T1",
		"name":     "alice",
		"email":    "alice@writer.com",
		"is_admin": "true",
		"has_2fa":  "false",
		"deleted":  "false",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:slack_user:U1"
	teamURN := "urn:cerebro:writer:slack_team:T1"
	emailURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"

	user := state.entities[userURN]
	if user == nil || user.EntityType != "slack.user" {
		t.Fatalf("slack.user entity missing or wrong: %#v", user)
	}
	for key, want := range map[string]string{
		"privileged":   "true",
		"has_mfa":      "false",
		"mfa_enrolled": "false",
		"active":       "true",
	} {
		if got := user.Attributes[key]; got != want {
			t.Fatalf("user posture attribute %q = %q, want %q", key, got, want)
		}
	}
	if got, ok := user.Attributes["mfa_enforced"]; ok {
		t.Fatalf("Slack user projection must not derive workspace MFA enforcement from user 2FA enrollment; got mfa_enforced=%q", got)
	}

	team := state.entities[teamURN]
	if team == nil || team.EntityType != "slack.team" {
		t.Fatalf("slack.team context entity missing or wrong: %#v", team)
	}
	assertProjectedLink(t, state, userURN, relationBelongsTo, teamURN)
	assertProjectedLink(t, state, teamURN, relationContains, userURN)
	assertProjectedLink(t, state, userURN, relationHasIdentifier, emailURN)
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
}

func TestProjectSlackChannelAndUserGroupTeamContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	channel := slackEvent("slack.channel", map[string]string{
		"channel_id": "C1",
		"team_id":    "T1",
		"creator":    "U1",
		"name":       "general",
	})
	group := slackEvent("slack.user_group", map[string]string{
		"group_id": "S1",
		"team_id":  "T1",
		"name":     "Engineering",
	})
	for _, event := range []*cerebrov1.EventEnvelope{channel, group} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetKind(), err)
		}
	}

	channelURN := "urn:cerebro:writer:slack_channel:C1"
	creatorURN := "urn:cerebro:writer:slack_user:U1"
	groupURN := "urn:cerebro:writer:slack_user_group:S1"
	teamURN := "urn:cerebro:writer:slack_team:T1"

	if entity := state.entities[channelURN]; entity == nil || entity.EntityType != "slack.channel" {
		t.Fatalf("slack.channel entity missing or wrong: %#v", entity)
	}
	if entity := state.entities[groupURN]; entity == nil || entity.EntityType != "slack.user_group" {
		t.Fatalf("slack.user_group entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, channelURN, relationBelongsTo, teamURN)
	assertProjectedLink(t, state, teamURN, relationContains, channelURN)
	assertProjectedLink(t, state, creatorURN, relationAuthored, channelURN)
	assertProjectedLink(t, state, groupURN, relationBelongsTo, teamURN)
	assertProjectedLink(t, state, teamURN, relationContains, groupURN)
}

func TestProjectSlackRelationshipStubsDoNotOverwriteLabels(t *testing.T) {
	channel := slackEvent("slack.channel", map[string]string{
		"channel_id": "C1",
		"team_id":    "T1",
		"creator":    "U1",
		"name":       "general",
	})
	member := slackEvent("slack.channel_member", map[string]string{
		"channel_id": "C1",
		"user_id":    "U1",
		"username":   "alice",
		"name":       "general",
	})
	channelEntities, _, err := BuiltinRegistry().Project(channel)
	if err != nil {
		t.Fatalf("Project(%q) error = %v", channel.GetKind(), err)
	}
	memberEntities, _, err := BuiltinRegistry().Project(member)
	if err != nil {
		t.Fatalf("Project(%q) error = %v", member.GetKind(), err)
	}

	channelByURN := projectedEntitiesByURN(channelEntities)
	for urn, entityType := range map[string]string{
		"urn:cerebro:writer:slack_user:U1": "slack.user",
		"urn:cerebro:writer:slack_team:T1": "slack.team",
	} {
		entity := channelByURN[urn]
		if entity == nil || entity.EntityType != entityType {
			t.Fatalf("stub entity %q missing or wrong: %#v", urn, entity)
		}
		if entity.Label != "" {
			t.Fatalf("stub entity %q label = %q, want empty label", urn, entity.Label)
		}
	}
	if channelEntity := channelByURN["urn:cerebro:writer:slack_channel:C1"]; channelEntity == nil || channelEntity.Label != "general" {
		t.Fatalf("primary channel label = %#v, want general", channelEntity)
	}

	memberByURN := projectedEntitiesByURN(memberEntities)
	for urn, entityType := range map[string]string{
		"urn:cerebro:writer:slack_user:U1":    "slack.user",
		"urn:cerebro:writer:slack_channel:C1": "slack.channel",
	} {
		entity := memberByURN[urn]
		if entity == nil || entity.EntityType != entityType {
			t.Fatalf("membership stub entity %q missing or wrong: %#v", urn, entity)
		}
		if entity.Label != "" {
			t.Fatalf("membership stub entity %q label = %q, want empty label", urn, entity.Label)
		}
	}
}

func TestProjectSlackSharedChannelLinksEachRealTeam(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	channel := slackEvent("slack.channel", map[string]string{
		"channel_id":      "C9",
		"shared_team_ids": "T1,T2",
		"name":            "connect",
	})
	if _, err := service.Project(context.Background(), channel); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	channelURN := "urn:cerebro:writer:slack_channel:C9"
	syntheticURN := "urn:cerebro:writer:slack_team:T1,T2"

	for _, teamURN := range []string{
		"urn:cerebro:writer:slack_team:T1",
		"urn:cerebro:writer:slack_team:T2",
	} {
		if entity := state.entities[teamURN]; entity == nil || entity.EntityType != "slack.team" {
			t.Fatalf("expected slack.team context entity for %q, got %#v", teamURN, entity)
		}
		assertProjectedLink(t, state, channelURN, relationBelongsTo, teamURN)
		assertProjectedLink(t, state, teamURN, relationContains, channelURN)
	}

	if entity := state.entities[syntheticURN]; entity != nil {
		t.Fatalf("comma-joined synthetic team URN must not be projected: %#v", entity)
	}
	assertProjectedLinkMissing(t, state, channelURN, relationBelongsTo, syntheticURN)
	assertProjectedLinkMissing(t, state, syntheticURN, relationContains, channelURN)
}

func TestProjectSlackMembershipsAndAuditEvents(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		slackEvent("slack.channel_member", map[string]string{"channel_id": "C1", "user_id": "U1"}),
		slackEvent("slack.user_group_member", map[string]string{"usergroup_id": "S1", "user_id": "U2"}),
		slackEvent("slack.audit_log", map[string]string{"event_type": "user_login", "actor_id": "U1", "actor_name": "alice", "resource_id": "U2", "resource_type": "user"}),
		slackEvent("slack.access_log", map[string]string{"event_type": "team_access", "actor_id": "U1", "actor_name": "alice", "ip_address": "203.0.113.10"}),
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	channelURN := "urn:cerebro:writer:slack_channel:C1"
	groupURN := "urn:cerebro:writer:slack_user_group:S1"
	user1URN := "urn:cerebro:writer:slack_user:U1"
	user2URN := "urn:cerebro:writer:slack_user:U2"

	assertProjectedLink(t, state, user1URN, relationMemberOf, channelURN)
	assertProjectedLink(t, state, channelURN, relationContains, user1URN)
	assertProjectedLink(t, state, user2URN, relationMemberOf, groupURN)
	assertProjectedLink(t, state, groupURN, relationContains, user2URN)
	if actor := state.entities[user1URN]; actor == nil || actor.EntityType != "slack.user" {
		t.Fatalf("slack audit/access actor missing or wrong: %#v", actor)
	}
}

func TestRegistryRoutesSlackDeclaredKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"slack.team", map[string]string{"team_id": "T1", "name": "Writer"}, "slack.team"},
		{"slack.user", map[string]string{"user_id": "U1", "team_id": "T1", "is_admin": "true", "has_2fa": "false"}, "slack.user"},
		{"slack.access_log", map[string]string{"event_type": "team_access", "actor_id": "U1"}, "slack.user"},
		{"slack.audit_log", map[string]string{"event_type": "user_login", "actor_id": "U1", "resource_id": "U2", "resource_type": "user"}, "slack.user"},
		{"slack.channel", map[string]string{"channel_id": "C1", "team_id": "T1"}, "slack.channel"},
		{"slack.channel_member", map[string]string{"channel_id": "C1", "user_id": "U1"}, "slack.user"},
		{"slack.user_group", map[string]string{"group_id": "S1", "team_id": "T1"}, "slack.user_group"},
		{"slack.user_group_member", map[string]string{"usergroup_id": "S1", "user_id": "U1"}, "slack.user"},
	}
	registered := make(map[string]struct{})
	for _, kind := range BuiltinRegistry().Kinds() {
		registered[kind] = struct{}{}
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if _, ok := registered[tc.kind]; !ok {
				t.Fatalf("declared Slack kind %q is not routed in the projection registry", tc.kind)
			}
			entities, _, err := BuiltinRegistry().Project(slackEvent(tc.kind, tc.attrs))
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
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}

func TestSlackRuntimeKindLiteralsProjectThroughRegistry(t *testing.T) {
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "slack-team-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.team",
			Attributes: map[string]string{
				"team_id": "T1",
				"name":    "Writer",
			},
		},
		{
			Id:       "slack-user-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.user",
			Attributes: map[string]string{
				"user_id":  "U1",
				"team_id":  "T1",
				"email":    "alice@writer.com",
				"is_admin": "true",
				"has_2fa":  "false",
			},
		},
		{
			Id:       "slack-channel-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.channel",
			Attributes: map[string]string{
				"channel_id": "C1",
				"team_id":    "T1",
				"creator":    "U1",
			},
		},
		{
			Id:       "slack-user-group-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.user_group",
			Attributes: map[string]string{
				"group_id": "S1",
				"team_id":  "T1",
				"handle":   "eng",
			},
		},
		{
			Id:       "slack-channel-member-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.channel_member",
			Attributes: map[string]string{
				"channel_id": "C1",
				"user_id":    "U1",
			},
		},
		{
			Id:       "slack-user-group-member-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.user_group_member",
			Attributes: map[string]string{
				"usergroup_id": "S1",
				"user_id":      "U1",
			},
		},
		{
			Id:       "slack-audit-log-literal",
			TenantId: "writer",
			SourceId: "slack",
			Kind:     "slack.audit_log",
			Attributes: map[string]string{
				"actor_id":      "U1",
				"event_type":    "user_login",
				"resource_id":   "U2",
				"resource_type": "user",
			},
		},
	}
	for _, event := range events {
		t.Run(event.GetKind(), func(t *testing.T) {
			entities, _, err := BuiltinRegistry().Project(event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
			}
			if len(entities) == 0 {
				t.Fatalf("Project(%s) emitted no entities", event.GetKind())
			}
		})
	}
}
