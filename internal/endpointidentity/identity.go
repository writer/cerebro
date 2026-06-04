package endpointidentity

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	AliasDeviceID               = "device_id"
	AliasHardwareUUID           = "hardware_uuid"
	AliasSerialNumber           = "serial_number"
	AliasHostname               = "hostname"
	AliasTrustedEndpointAgentID = "trusted_endpoint_agent_id"
)

// AliasesFromDevice builds durable aliases from device-auth enrollment state.
func AliasesFromDevice(tenantID string, deviceID string, hardwareUUID string, serialNumber string, hostname string, observedAt time.Time) []ports.EndpointIdentityAlias {
	return compactAliases([]ports.EndpointIdentityAlias{
		alias(tenantID, deviceID, AliasDeviceID, deviceID, "deviceauth", 1.0, observedAt),
		alias(tenantID, deviceID, AliasHardwareUUID, hardwareUUID, "deviceauth", 0.98, observedAt),
		alias(tenantID, deviceID, AliasSerialNumber, serialNumber, "deviceauth", 0.95, observedAt),
		alias(tenantID, deviceID, AliasHostname, hostname, "deviceauth", 0.60, observedAt),
	})
}

// AliasesFromTrustedEndpoint builds aliases observed through Trusted Endpoint telemetry.
func AliasesFromTrustedEndpoint(tenantID string, canonicalDeviceID string, agentID string, hardwareUUID string, serialNumber string, hostname string, observedAt time.Time) []ports.EndpointIdentityAlias {
	if strings.TrimSpace(canonicalDeviceID) == "" {
		canonicalDeviceID = firstNonEmpty(agentID, hardwareUUID, serialNumber, hostname)
	}
	return compactAliases([]ports.EndpointIdentityAlias{
		alias(tenantID, canonicalDeviceID, AliasDeviceID, canonicalDeviceID, "trusted_endpoint", 1.0, observedAt),
		alias(tenantID, canonicalDeviceID, AliasTrustedEndpointAgentID, agentID, "trusted_endpoint", 0.90, observedAt),
		alias(tenantID, canonicalDeviceID, AliasHardwareUUID, hardwareUUID, "trusted_endpoint", 0.98, observedAt),
		alias(tenantID, canonicalDeviceID, AliasSerialNumber, serialNumber, "trusted_endpoint", 0.95, observedAt),
		alias(tenantID, canonicalDeviceID, AliasHostname, hostname, "trusted_endpoint", 0.60, observedAt),
	})
}

func alias(tenantID string, deviceID string, aliasType string, value string, sourceID string, confidence float64, observedAt time.Time) ports.EndpointIdentityAlias {
	return ports.EndpointIdentityAlias{
		TenantID:          strings.TrimSpace(tenantID),
		CanonicalDeviceID: strings.TrimSpace(deviceID),
		AliasType:         strings.TrimSpace(aliasType),
		AliasValue:        strings.TrimSpace(value),
		SourceID:          strings.TrimSpace(sourceID),
		Confidence:        confidence,
		ObservedAt:        observedAt.UTC(),
	}
}

func compactAliases(aliases []ports.EndpointIdentityAlias) []ports.EndpointIdentityAlias {
	out := make([]ports.EndpointIdentityAlias, 0, len(aliases))
	seen := map[string]struct{}{}
	for _, candidate := range aliases {
		candidate.TenantID = strings.TrimSpace(candidate.TenantID)
		candidate.CanonicalDeviceID = strings.TrimSpace(candidate.CanonicalDeviceID)
		candidate.AliasType = strings.TrimSpace(candidate.AliasType)
		candidate.AliasValue = strings.TrimSpace(candidate.AliasValue)
		if candidate.TenantID == "" || candidate.CanonicalDeviceID == "" || candidate.AliasType == "" || candidate.AliasValue == "" {
			continue
		}
		key := candidate.TenantID + "\x00" + candidate.AliasType + "\x00" + strings.ToLower(candidate.AliasValue)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// MemoryStore is a test implementation of ports.EndpointIdentityStore.
type MemoryStore struct {
	mu      sync.Mutex
	aliases map[string]ports.EndpointIdentityAlias
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{aliases: map[string]ports.EndpointIdentityAlias{}}
}

func (s *MemoryStore) UpsertEndpointIdentityAliases(_ context.Context, aliases []ports.EndpointIdentityAlias) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aliases == nil {
		s.aliases = map[string]ports.EndpointIdentityAlias{}
	}
	for _, candidate := range compactAliases(aliases) {
		key := aliasKey(candidate)
		if existing, ok := s.aliases[key]; ok {
			if existing.ObservedAt.After(candidate.ObservedAt) {
				candidate.ObservedAt = existing.ObservedAt
			}
			if existing.Confidence > candidate.Confidence {
				candidate.Confidence = existing.Confidence
			}
		}
		s.aliases[key] = candidate
	}
	return nil
}

func (s *MemoryStore) ResolveEndpointIdentity(_ context.Context, request ports.EndpointIdentityResolveRequest) (ports.EndpointIdentityResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := []ports.EndpointIdentityAlias{}
	for _, candidate := range request.Aliases {
		candidate.TenantID = strings.TrimSpace(candidate.TenantID)
		candidate.AliasType = strings.TrimSpace(candidate.AliasType)
		candidate.AliasValue = strings.TrimSpace(candidate.AliasValue)
		if candidate.TenantID == "" || candidate.AliasType == "" || candidate.AliasValue == "" {
			continue
		}
		for _, stored := range s.aliases {
			if stored.TenantID == candidate.TenantID && stored.AliasType == candidate.AliasType && strings.EqualFold(stored.AliasValue, candidate.AliasValue) {
				matches = append(matches, stored)
			}
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].ObservedAt.After(matches[j].ObservedAt)
	})
	candidates := candidateDeviceIDs(matches)
	resolution := ports.EndpointIdentityResolution{
		TenantID:           strings.TrimSpace(request.TenantID),
		MatchedAliases:     matches,
		CandidateDeviceIDs: candidates,
		Ambiguous:          len(candidates) > 1,
	}
	if len(candidates) > 0 {
		resolution.CanonicalDeviceID = candidates[0]
	}
	return resolution, nil
}

func aliasKey(alias ports.EndpointIdentityAlias) string {
	return alias.TenantID + "\x00" + alias.AliasType + "\x00" + strings.ToLower(strings.TrimSpace(alias.AliasValue)) + "\x00" + alias.CanonicalDeviceID
}

func candidateDeviceIDs(matches []ports.EndpointIdentityAlias) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, match := range matches {
		id := strings.TrimSpace(match.CanonicalDeviceID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

var _ ports.EndpointIdentityStore = (*MemoryStore)(nil)
