package aiegresspolicy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrInvalidInput = errors.New("invalid AI egress policy input")

// Evaluate produces one deterministic decision. Registry failure is closed:
// unavailable, stale, disabled, or invalid registries never produce allow.
func Evaluate(input *cerebrov1.AIEgressPolicyInput) (*cerebrov1.AIEgressPolicyDecision, error) {
	if input == nil || input.GetDestination() == nil || input.GetEvaluatedAt() == nil {
		return nil, fmt.Errorf("%w: destination and evaluated_at are required", ErrInvalidInput)
	}
	if strings.TrimSpace(input.GetTenantId()) == "" || input.GetSubjectRef() == nil || strings.TrimSpace(input.GetSubjectRef().GetId()) == "" {
		return nil, fmt.Errorf("%w: tenant_id and subject_ref.id are required", ErrInvalidInput)
	}
	if input.GetDestination().GetPort() == 0 || input.GetDestination().GetPort() > 65535 || input.GetDestination().GetTransport() == cerebrov1.AIEgressTransport_AI_EGRESS_TRANSPORT_UNSPECIFIED {
		return nil, fmt.Errorf("%w: destination requires a valid port and transport", ErrInvalidInput)
	}
	if input.GetEnforcementLayer() == cerebrov1.AIEgressEnforcementLayer_AI_EGRESS_ENFORCEMENT_LAYER_UNSPECIFIED {
		return nil, fmt.Errorf("%w: enforcement_layer is required", ErrInvalidInput)
	}
	if err := input.GetEvaluatedAt().CheckValid(); err != nil {
		return nil, fmt.Errorf("%w: evaluated_at: %w", ErrInvalidInput, err)
	}
	evaluatedAt := input.GetEvaluatedAt().AsTime()
	hostname, err := canonicalHostname(input.GetDestination().GetHostname())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	decision := baseDecision(input, hostname)
	registry := input.GetRegistry()
	if registry == nil {
		decision.Reason = cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_UNAVAILABLE
		return decision, nil
	}
	decision.RegistryId = registry.GetRegistryId()
	decision.RegistryRevision = registry.GetRevision()
	decision.RegistryDigest = registry.GetDigest()
	decision.EvidenceClaimRefs = append(decision.EvidenceClaimRefs, registry.GetEvidenceClaimRefs()...)
	if err := validateRegistry(registry); err != nil {
		return nil, err
	}
	if registry.GetMode() == cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_DISABLED {
		decision.Reason = cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_DISABLED
		return decision, nil
	}
	if evaluatedAt.Before(registry.GetPublishedAt().AsTime()) || evaluatedAt.After(registry.GetValidUntil().AsTime()) {
		decision.Reason = cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_REGISTRY_STALE
		return decision, nil
	}
	if !input.GetEnforcementEnabled() {
		decision.Reason = cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_ENFORCEMENT_DISABLED
		return decision, nil
	}

	reason := cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_DESTINATION_NOT_APPROVED
	for _, entry := range registry.GetEntries() {
		matched, mismatch := entryMatches(entry, input, hostname, evaluatedAt)
		if matched {
			decision.Action = cerebrov1.AIEgressAction_AI_EGRESS_ACTION_ALLOW
			decision.Reason = cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_APPROVED_DESTINATION
			decision.MatchedEntryId = entry.GetId()
			decision.EvidenceClaimRefs = append(decision.EvidenceClaimRefs, entry.GetEvidenceClaimRefs()...)
			return decision, nil
		}
		if mismatch != cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_DESTINATION_NOT_APPROVED {
			reason = mismatch
		}
	}
	decision.Reason = reason
	if registry.GetMode() == cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_AUDIT {
		decision.Action = cerebrov1.AIEgressAction_AI_EGRESS_ACTION_AUDIT
	}
	return decision, nil
}

func baseDecision(input *cerebrov1.AIEgressPolicyInput, hostname string) *cerebrov1.AIEgressPolicyDecision {
	return &cerebrov1.AIEgressPolicyDecision{
		Action:            cerebrov1.AIEgressAction_AI_EGRESS_ACTION_BLOCK,
		CanonicalHostname: hostname,
		EvaluatedAt:       timestamppb.New(input.GetEvaluatedAt().AsTime()),
		Enforceable:       input.GetEnforcementEnabled(),
	}
}

func validateRegistry(registry *cerebrov1.AIEgressRegistrySnapshot) error {
	if strings.TrimSpace(registry.GetRegistryId()) == "" || strings.TrimSpace(registry.GetRevision()) == "" || strings.TrimSpace(registry.GetDigest()) == "" {
		return fmt.Errorf("%w: registry identity, revision, and digest are required", ErrInvalidInput)
	}
	if registry.GetMode() == cerebrov1.AIEgressRegistryMode_AI_EGRESS_REGISTRY_MODE_UNSPECIFIED {
		return fmt.Errorf("%w: registry mode is required", ErrInvalidInput)
	}
	if registry.GetDefaultAction() != cerebrov1.AIEgressAction_AI_EGRESS_ACTION_BLOCK {
		return fmt.Errorf("%w: registry default_action must be block", ErrInvalidInput)
	}
	if registry.GetPublishedAt() == nil || registry.GetValidUntil() == nil {
		return fmt.Errorf("%w: registry published_at and valid_until are required", ErrInvalidInput)
	}
	if err := registry.GetPublishedAt().CheckValid(); err != nil {
		return fmt.Errorf("%w: registry published_at: %w", ErrInvalidInput, err)
	}
	if err := registry.GetValidUntil().CheckValid(); err != nil {
		return fmt.Errorf("%w: registry valid_until: %w", ErrInvalidInput, err)
	}
	if !registry.GetValidUntil().AsTime().After(registry.GetPublishedAt().AsTime()) {
		return fmt.Errorf("%w: registry valid_until must follow published_at", ErrInvalidInput)
	}
	seen := make(map[string]struct{}, len(registry.GetEntries()))
	for _, entry := range registry.GetEntries() {
		if entry == nil || strings.TrimSpace(entry.GetId()) == "" {
			return fmt.Errorf("%w: registry entry id is required", ErrInvalidInput)
		}
		if _, exists := seen[entry.GetId()]; exists {
			return fmt.Errorf("%w: duplicate registry entry %q", ErrInvalidInput, entry.GetId())
		}
		seen[entry.GetId()] = struct{}{}
		if len(entry.GetExactHostnames()) == 0 || len(entry.GetPorts()) == 0 || len(entry.GetTransports()) == 0 {
			return fmt.Errorf("%w: registry entry %q requires hostnames, ports, and transports", ErrInvalidInput, entry.GetId())
		}
		for _, hostname := range entry.GetExactHostnames() {
			if _, err := canonicalHostname(hostname); err != nil {
				return fmt.Errorf("%w: registry entry %q: %w", ErrInvalidInput, entry.GetId(), err)
			}
		}
		for _, port := range entry.GetPorts() {
			if port == 0 || port > 65535 {
				return fmt.Errorf("%w: registry entry %q has invalid port", ErrInvalidInput, entry.GetId())
			}
		}
		for _, transport := range entry.GetTransports() {
			if transport == cerebrov1.AIEgressTransport_AI_EGRESS_TRANSPORT_UNSPECIFIED {
				return fmt.Errorf("%w: registry entry %q has unspecified transport", ErrInvalidInput, entry.GetId())
			}
		}
		if entry.GetValidFrom() != nil {
			if err := entry.GetValidFrom().CheckValid(); err != nil {
				return fmt.Errorf("%w: registry entry %q valid_from: %w", ErrInvalidInput, entry.GetId(), err)
			}
		}
		if entry.GetValidUntil() != nil {
			if err := entry.GetValidUntil().CheckValid(); err != nil {
				return fmt.Errorf("%w: registry entry %q valid_until: %w", ErrInvalidInput, entry.GetId(), err)
			}
		}
		if entry.GetValidFrom() != nil && entry.GetValidUntil() != nil && !entry.GetValidUntil().AsTime().After(entry.GetValidFrom().AsTime()) {
			return fmt.Errorf("%w: registry entry %q valid_until must follow valid_from", ErrInvalidInput, entry.GetId())
		}
	}
	return nil
}

func entryMatches(entry *cerebrov1.AIEgressRegistryEntry, input *cerebrov1.AIEgressPolicyInput, hostname string, evaluatedAt time.Time) (bool, cerebrov1.AIEgressDecisionReason) {
	if entry == nil || !entry.GetEnabled() || !withinWindow(entry, evaluatedAt) || !containsHostname(entry.GetExactHostnames(), hostname) {
		return false, cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_DESTINATION_NOT_APPROVED
	}
	if !containsPort(entry.GetPorts(), input.GetDestination().GetPort()) {
		return false, cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_PORT_NOT_APPROVED
	}
	if !containsTransport(entry.GetTransports(), input.GetDestination().GetTransport()) {
		return false, cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_TRANSPORT_NOT_APPROVED
	}
	if len(entry.GetActorUrns()) > 0 && !containsString(entry.GetActorUrns(), input.GetActorRef().GetId()) {
		return false, cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_IDENTITY_NOT_APPROVED
	}
	return true, cerebrov1.AIEgressDecisionReason_AI_EGRESS_DECISION_REASON_APPROVED_DESTINATION
}

func withinWindow(entry *cerebrov1.AIEgressRegistryEntry, evaluatedAt time.Time) bool {
	if entry.GetValidFrom() != nil && evaluatedAt.Before(entry.GetValidFrom().AsTime()) {
		return false
	}
	return entry.GetValidUntil() == nil || !evaluatedAt.After(entry.GetValidUntil().AsTime())
}

func canonicalHostname(value string) (string, error) {
	hostname := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if hostname == "" || strings.ContainsAny(hostname, "*/") || net.ParseIP(hostname) != nil {
		return "", errors.New("hostname must be an exact DNS name")
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("hostname must be an exact DNS name")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("hostname must be an exact DNS name")
			}
		}
	}
	return hostname, nil
}

func containsHostname(values []string, expected string) bool {
	for _, value := range values {
		canonical, err := canonicalHostname(value)
		if err == nil && canonical == expected {
			return true
		}
	}
	return false
}

func containsPort(values []uint32, expected uint32) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsTransport(values []cerebrov1.AIEgressTransport, expected cerebrov1.AIEgressTransport) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
