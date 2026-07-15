package decisionpacket

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrInvalidBudget = errors.New("invalid decision packet budget")

var budgetDefaults = Budgets{Evidence: 50, Contradictions: 10, CoverageGaps: 10, Affected: 50, Controls: 50, AuditPackets: 10, Actions: 5, GraphRows: 25, GraphDepth: 2}
var budgetMaximums = Budgets{Evidence: 100, Contradictions: 25, CoverageGaps: 25, Affected: 100, Controls: 100, AuditPackets: 25, Actions: 10, GraphRows: 100, GraphDepth: 3}

func NormalizeRequest(request Request) (Request, error) {
	request.Workflow = strings.ToLower(strings.TrimSpace(request.Workflow))
	request.Question = strings.TrimSpace(request.Question)
	request.ScopeURN = strings.TrimSpace(request.ScopeURN)
	request.RequestedAction = strings.TrimSpace(request.RequestedAction)
	request.FindingIDs = normalizeStrings(request.FindingIDs)
	request.ClaimIDs = normalizeStrings(request.ClaimIDs)
	request.EvidenceURNs = normalizeStrings(request.EvidenceURNs)
	request.AuditPacketIDs = normalizeStrings(request.AuditPacketIDs)
	request.RequiredSources = normalizeStrings(request.RequiredSources)
	budgets, err := normalizeBudgets(request.Budgets)
	if err != nil {
		return Request{}, err
	}
	request.Budgets = budgets
	return request, nil
}

func CanonicalizePacket(packet Packet) (Packet, []byte, error) {
	packet = normalizePacket(packet)
	packet.ID = ""
	hashInput, err := json.Marshal(packet)
	if err != nil {
		return Packet{}, nil, fmt.Errorf("marshal decision packet hash input: %w", err)
	}
	digest := sha256.Sum256(hashInput)
	packet.ID = fmt.Sprintf("dpr_%x", digest[:16])
	canonical, err := json.Marshal(packet)
	if err != nil {
		return Packet{}, nil, fmt.Errorf("marshal decision packet: %w", err)
	}
	return packet, canonical, nil
}

func normalizePacket(packet Packet) Packet {
	packet.SchemaVersion = strings.TrimSpace(packet.SchemaVersion)
	if packet.SchemaVersion == "" {
		packet.SchemaVersion = SchemaVersion
	}
	packet.GeneratedAt = packet.GeneratedAt.UTC()
	packet.Workflow.ID = strings.ToLower(strings.TrimSpace(packet.Workflow.ID))
	packet.Workflow.Question = strings.TrimSpace(packet.Workflow.Question)
	packet.Scope.TenantID = strings.TrimSpace(packet.Scope.TenantID)
	packet.Scope.ActorID = strings.TrimSpace(packet.Scope.ActorID)
	packet.Scope.URN = strings.TrimSpace(packet.Scope.URN)
	packet.Decision.State = strings.ToLower(strings.TrimSpace(packet.Decision.State))
	packet.Decision.Rationale = strings.TrimSpace(packet.Decision.Rationale)
	packet.Decision.Reasons = normalizeStrings(packet.Decision.Reasons)
	packet.Confidence.Level = strings.ToLower(strings.TrimSpace(packet.Confidence.Level))
	packet.Confidence.Basis = normalizeStrings(packet.Confidence.Basis)
	packet.Freshness.State = strings.ToLower(strings.TrimSpace(packet.Freshness.State))
	packet.Freshness.OldestObservedAt = packet.Freshness.OldestObservedAt.UTC()
	packet.Freshness.NewestObservedAt = packet.Freshness.NewestObservedAt.UTC()
	packet.Provenance.ResolverIDs = normalizeStrings(packet.Provenance.ResolverIDs)
	packet.Provenance.SourceIDs = normalizeStrings(packet.Provenance.SourceIDs)
	for index := range packet.Evidence {
		packet.Evidence[index] = normalizeEvidenceReference(packet.Evidence[index])
	}
	packet.Evidence = dedupeEvidence(packet.Evidence)
	for index := range packet.Contradictions {
		packet.Contradictions[index].Left = normalizeEvidenceReference(packet.Contradictions[index].Left)
		packet.Contradictions[index].Right = normalizeEvidenceReference(packet.Contradictions[index].Right)
	}
	for index := range packet.Actions {
		packet.Actions[index].TargetURNs = normalizeStrings(packet.Actions[index].TargetURNs)
		packet.Actions[index].ApprovalRequirements = normalizeStrings(packet.Actions[index].ApprovalRequirements)
	}
	for index := range packet.AuditPackets {
		packet.AuditPackets[index].GeneratedAt = packet.AuditPackets[index].GeneratedAt.UTC()
	}
	sort.Slice(packet.Contradictions, func(i, j int) bool { return packet.Contradictions[i].ID < packet.Contradictions[j].ID })
	sort.Slice(packet.CoverageGaps, func(i, j int) bool { return packet.CoverageGaps[i].ID < packet.CoverageGaps[j].ID })
	sort.Slice(packet.Affected, func(i, j int) bool { return packet.Affected[i].URN < packet.Affected[j].URN })
	sort.Slice(packet.Controls, func(i, j int) bool { return packet.Controls[i].ID < packet.Controls[j].ID })
	sort.Slice(packet.AuditPackets, func(i, j int) bool { return packet.AuditPackets[i].ID < packet.AuditPackets[j].ID })
	sort.Slice(packet.Actions, func(i, j int) bool { return packet.Actions[i].ID < packet.Actions[j].ID })
	return packet
}

func normalizeEvidenceReference(value EvidenceReference) EvidenceReference {
	value.ID = strings.TrimSpace(value.ID)
	value.URN = strings.TrimSpace(value.URN)
	value.Kind = strings.ToLower(strings.TrimSpace(value.Kind))
	value.SourceID = strings.TrimSpace(value.SourceID)
	value.SubjectURN = strings.TrimSpace(value.SubjectURN)
	value.Predicate = strings.ToLower(strings.TrimSpace(value.Predicate))
	value.Value = strings.TrimSpace(value.Value)
	value.Digest = strings.TrimSpace(value.Digest)
	value.ObservedAt = value.ObservedAt.UTC()
	value.ValidFrom = value.ValidFrom.UTC()
	value.ValidTo = value.ValidTo.UTC()
	return value
}

func dedupeEvidence(values []EvidenceReference) []EvidenceReference {
	byKey := make(map[string]EvidenceReference, len(values))
	for _, value := range values {
		key := value.Kind + "\x00" + value.ID
		if _, found := byKey[key]; !found {
			byKey[key] = value
		}
	}
	result := make([]EvidenceReference, 0, len(byKey))
	for _, value := range byKey {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Kind+"\x00"+result[i].ID < result[j].Kind+"\x00"+result[j].ID
	})
	return result
}

func normalizeBudgets(value Budgets) (Budgets, error) {
	values := []*int{&value.Evidence, &value.Contradictions, &value.CoverageGaps, &value.Affected, &value.Controls, &value.AuditPackets, &value.Actions, &value.GraphRows, &value.GraphDepth}
	defaults := []int{budgetDefaults.Evidence, budgetDefaults.Contradictions, budgetDefaults.CoverageGaps, budgetDefaults.Affected, budgetDefaults.Controls, budgetDefaults.AuditPackets, budgetDefaults.Actions, budgetDefaults.GraphRows, budgetDefaults.GraphDepth}
	maximums := []int{budgetMaximums.Evidence, budgetMaximums.Contradictions, budgetMaximums.CoverageGaps, budgetMaximums.Affected, budgetMaximums.Controls, budgetMaximums.AuditPackets, budgetMaximums.Actions, budgetMaximums.GraphRows, budgetMaximums.GraphDepth}
	for index, item := range values {
		if *item < 0 || *item > maximums[index] {
			return Budgets{}, fmt.Errorf("%w: value %d exceeds range 0..%d", ErrInvalidBudget, *item, maximums[index])
		}
		if *item == 0 {
			*item = defaults[index]
		}
	}
	return value, nil
}

func normalizeStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueSortedStrings(values []string) []string { return normalizeStrings(values) }
