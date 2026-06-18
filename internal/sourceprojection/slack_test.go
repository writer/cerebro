package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
}

func TestProjectSlackChannelAndUserGroupTeamContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	channel := slackEvent("slack.channel", map[string]string{
		"channel_id": "C1",
		"team_id":    "T1",
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
	assertProjectedLink(t, state, groupURN, relationBelongsTo, teamURN)
	assertProjectedLink(t, state, teamURN, relationContains, groupURN)
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

func TestRegistryRoutesSlackDeclaredKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"slack.team", map[string]string{"team_id": "T1", "name": "Writer"}, "slack.team"},
		{"slack.user", map[string]string{"user_id": "U1", "team_id": "T1", "is_admin": "true", "has_2fa": "false"}, "slack.user"},
		{"slack.channel", map[string]string{"channel_id": "C1", "team_id": "T1"}, "slack.channel"},
		{"slack.user_group", map[string]string{"group_id": "S1", "team_id": "T1"}, "slack.user_group"},
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
