package stream

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
)

type InteractionEventPlan struct {
	Channel         string
	InteractionType string
	OccurredAt      time.Time
	Duration        time.Duration
	Weight          float64
	Participants    []InteractionParticipant
}

func BuildTapInteractionEventPlan(eventType string, evt events.CloudEvent) (*InteractionEventPlan, bool) {
	channel, interactionType := ParseTapInteractionType(eventType)
	if channel == "" {
		return nil, false
	}

	interactionType = CoalesceString(
		interactionType,
		strings.ToLower(strings.TrimSpace(AnyToString(FirstPresent(evt.Data, "interaction_type", "type", "action", "snapshot.interaction_type", "snapshot.type", "snapshot.action")))),
		"interaction",
	)

	occurredAt := evt.Time.UTC()
	if ts, ok := ParseTimeValue(FirstPresent(evt.Data, "timestamp", "event_time", "occurred_at", "provider_timestamp", "snapshot.timestamp", "snapshot.event_time", "snapshot.occurred_at", "snapshot.provider_timestamp")); ok {
		occurredAt = ts.UTC()
	}

	participants := parseTapInteractionParticipants(evt.Data)
	if len(participants) < 2 {
		return nil, false
	}

	duration := parseTapInteractionDuration(evt.Data)
	return &InteractionEventPlan{
		Channel:         channel,
		InteractionType: interactionType,
		OccurredAt:      occurredAt,
		Duration:        duration,
		Weight:          parseTapInteractionWeight(evt.Data, duration),
		Participants:    participants,
	}, true
}

func ParseTapInteractionParticipants(data map[string]any) []InteractionParticipant {
	return parseTapInteractionParticipants(data)
}

func parseTapInteractionParticipants(data map[string]any) []InteractionParticipant {
	participants := make([]InteractionParticipant, 0)
	seen := make(map[string]struct{})

	addParticipant := func(raw any) {
		participant, ok := parseTapInteractionParticipant(raw)
		if !ok {
			return
		}
		participant.ID = NormalizeTapInteractionPersonID(participant.ID)
		if participant.ID == "" {
			return
		}
		if _, ok := seen[participant.ID]; ok {
			return
		}
		if strings.TrimSpace(participant.Name) == "" {
			participant.Name = strings.TrimPrefix(participant.ID, "person:")
		}
		participants = append(participants, participant)
		seen[participant.ID] = struct{}{}
	}

	addMany := func(raw any) {
		switch typed := raw.(type) {
		case []any:
			for _, value := range typed {
				addParticipant(value)
			}
		case []string:
			for _, value := range typed {
				addParticipant(value)
			}
		default:
			addParticipant(raw)
		}
	}

	addParticipant(FirstPresent(data,
		"source_person_id", "source_person_email", "source_id", "source_email",
		"actor_id", "actor_email", "user_id", "user_email",
		"snapshot.source_person_id", "snapshot.source_person_email", "snapshot.source_id", "snapshot.source_email",
		"snapshot.actor_id", "snapshot.actor_email", "snapshot.user_id", "snapshot.user_email",
	))
	addParticipant(FirstPresent(data,
		"target_person_id", "target_person_email", "target_id", "target_email",
		"counterparty_id", "counterparty_email", "peer_id", "peer_email",
		"reviewed_id", "reviewed_email",
		"snapshot.target_person_id", "snapshot.target_person_email", "snapshot.target_id", "snapshot.target_email",
		"snapshot.counterparty_id", "snapshot.counterparty_email", "snapshot.peer_id", "snapshot.peer_email",
	))
	addParticipant(FirstPresent(data, "actor", "source", "target", "user", "snapshot.actor", "snapshot.source", "snapshot.target", "snapshot.user"))

	for _, key := range []string{
		"participants", "participant_ids", "participant_emails", "people", "users", "members", "attendees", "reviewers", "assignees", "collaborators",
		"snapshot.participants", "snapshot.participant_ids", "snapshot.participant_emails",
		"snapshot.people", "snapshot.users", "snapshot.members", "snapshot.attendees", "snapshot.reviewers", "snapshot.assignees", "snapshot.collaborators",
		"interaction.participants", "interaction.users", "snapshot.interaction.participants", "snapshot.interaction.users",
	} {
		addMany(FirstPresent(data, key))
	}

	return participants
}

func parseTapInteractionParticipant(raw any) (InteractionParticipant, bool) {
	switch typed := raw.(type) {
	case string:
		id := strings.TrimSpace(typed)
		if id == "" {
			return InteractionParticipant{}, false
		}
		return InteractionParticipant{ID: id}, true
	case map[string]any:
		id := strings.TrimSpace(AnyToString(FirstPresent(typed,
			"person_id", "person", "id", "user_id", "user", "email",
			"actor_id", "actor_email", "source_person_id", "target_person_id",
		)))
		if id == "" {
			if person, ok := typed["person"].(map[string]any); ok {
				return parseTapInteractionParticipant(person)
			}
			return InteractionParticipant{}, false
		}
		name := strings.TrimSpace(AnyToString(FirstPresent(typed, "name", "display_name", "full_name", "username")))
		return InteractionParticipant{ID: id, Name: name}, true
	default:
		return InteractionParticipant{}, false
	}
}

func NormalizeTapInteractionPersonID(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "person:") {
		return normalized
	}
	normalized = strings.TrimPrefix(normalized, "user:")
	if strings.Contains(normalized, ":") {
		return normalized
	}
	return "person:" + normalized
}

func parseTapInteractionDuration(data map[string]any) time.Duration {
	if seconds := ToFloat64(FirstPresent(data, "duration_seconds", "duration_sec", "duration_s", "metadata.duration_seconds", "snapshot.duration_seconds", "snapshot.metadata.duration_seconds")); seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if minutes := ToFloat64(FirstPresent(data, "duration_minutes", "metadata.duration_minutes", "snapshot.duration_minutes", "snapshot.metadata.duration_minutes")); minutes > 0 {
		return time.Duration(minutes * float64(time.Minute))
	}
	if millis := ToFloat64(FirstPresent(data, "duration_ms", "metadata.duration_ms", "snapshot.duration_ms", "snapshot.metadata.duration_ms")); millis > 0 {
		return time.Duration(millis * float64(time.Millisecond))
	}

	rawDuration := strings.TrimSpace(AnyToString(FirstPresent(data, "duration", "metadata.duration", "snapshot.duration", "snapshot.metadata.duration")))
	if rawDuration == "" {
		return 0
	}
	if parsed, err := time.ParseDuration(rawDuration); err == nil && parsed > 0 {
		return parsed
	}
	if seconds, err := strconv.ParseFloat(rawDuration, 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	return 0
}

func parseTapInteractionWeight(data map[string]any, duration time.Duration) float64 {
	if explicit := ToFloat64(FirstPresent(data, "weight", "interaction_weight", "score", "metadata.weight", "snapshot.weight", "snapshot.metadata.weight")); explicit > 0 {
		return explicit
	}
	if duration <= 0 {
		return 1
	}
	weight := 1 + math.Log1p(duration.Minutes()/30.0)
	if weight < 1 {
		return 1
	}
	return weight
}

func StringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(AnyToString(item))
			if text == "" {
				continue
			}
			values = append(values, text)
		}
		return values
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	default:
		return nil
	}
}
