package decisionpacket

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	normalizeEmbeddedCanonicalValue(&packet.Guardrails)
	normalizeEmbeddedCanonicalValue(&packet.Claim)
	packet.Guardrails.Readiness.State = strings.ToLower(packet.Guardrails.Readiness.State)
	for index := range packet.Guardrails.VerifierResults {
		packet.Guardrails.VerifierResults[index].Status = strings.ToLower(packet.Guardrails.VerifierResults[index].Status)
	}
	for index := range packet.Guardrails.ActionLadder {
		packet.Guardrails.ActionLadder[index].Status = strings.ToLower(packet.Guardrails.ActionLadder[index].Status)
	}
	for index := range packet.Guardrails.ConnectorToolGates {
		packet.Guardrails.ConnectorToolGates[index].Status = strings.ToLower(packet.Guardrails.ConnectorToolGates[index].Status)
	}
	packet.Claim.Verdict = strings.ToLower(packet.Claim.Verdict)
	packet.Claim.AllowedNextStage = strings.ToLower(packet.Claim.AllowedNextStage)
	packet.Claim.RequestedActionStage = strings.ToLower(packet.Claim.RequestedActionStage)
	packet.Claim.FreshnessState = strings.ToLower(packet.Claim.FreshnessState)
	for index := range packet.Claim.SupportingEvidence {
		packet.Claim.SupportingEvidence[index].Kind = strings.ToLower(packet.Claim.SupportingEvidence[index].Kind)
		packet.Claim.SupportingEvidence[index].CitationStatus = strings.ToLower(packet.Claim.SupportingEvidence[index].CitationStatus)
	}
	for index := range packet.Claim.CounterEvidence {
		packet.Claim.CounterEvidence[index].Kind = strings.ToLower(packet.Claim.CounterEvidence[index].Kind)
		packet.Claim.CounterEvidence[index].CitationStatus = strings.ToLower(packet.Claim.CounterEvidence[index].CitationStatus)
	}
	for index := range packet.Claim.VerifierResults {
		packet.Claim.VerifierResults[index].Status = strings.ToLower(packet.Claim.VerifierResults[index].Status)
	}
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
	packet.Provenance.TraceID = strings.TrimSpace(packet.Provenance.TraceID)
	packet.Provenance.EvidenceDigest = strings.TrimSpace(packet.Provenance.EvidenceDigest)
	packet.Provenance.CoverageDigest = strings.TrimSpace(packet.Provenance.CoverageDigest)
	for index := range packet.Evidence {
		packet.Evidence[index] = normalizeEvidenceReference(packet.Evidence[index])
	}
	packet.Evidence = dedupeEvidence(packet.Evidence)
	for index := range packet.Contradictions {
		packet.Contradictions[index].ID = strings.TrimSpace(packet.Contradictions[index].ID)
		packet.Contradictions[index].SubjectURN = strings.TrimSpace(packet.Contradictions[index].SubjectURN)
		packet.Contradictions[index].Predicate = strings.ToLower(strings.TrimSpace(packet.Contradictions[index].Predicate))
		packet.Contradictions[index].ResolutionState = strings.ToLower(strings.TrimSpace(packet.Contradictions[index].ResolutionState))
		packet.Contradictions[index].Left = normalizeEvidenceReference(packet.Contradictions[index].Left)
		packet.Contradictions[index].Right = normalizeEvidenceReference(packet.Contradictions[index].Right)
	}
	for index := range packet.CoverageGaps {
		packet.CoverageGaps[index].ID = strings.TrimSpace(packet.CoverageGaps[index].ID)
		packet.CoverageGaps[index].SourceID = strings.TrimSpace(packet.CoverageGaps[index].SourceID)
		packet.CoverageGaps[index].Dimension = strings.ToLower(strings.TrimSpace(packet.CoverageGaps[index].Dimension))
		packet.CoverageGaps[index].State = strings.ToLower(strings.TrimSpace(packet.CoverageGaps[index].State))
		packet.CoverageGaps[index].Reason = strings.TrimSpace(packet.CoverageGaps[index].Reason)
	}
	for index := range packet.Affected {
		packet.Affected[index].URN = strings.TrimSpace(packet.Affected[index].URN)
		packet.Affected[index].Kind = strings.ToLower(strings.TrimSpace(packet.Affected[index].Kind))
		packet.Affected[index].Name = strings.TrimSpace(packet.Affected[index].Name)
	}
	for index := range packet.Controls {
		packet.Controls[index].ID = strings.TrimSpace(packet.Controls[index].ID)
		packet.Controls[index].Framework = strings.TrimSpace(packet.Controls[index].Framework)
		packet.Controls[index].Applicability = strings.ToLower(strings.TrimSpace(packet.Controls[index].Applicability))
	}
	for index := range packet.Actions {
		packet.Actions[index].ID = strings.TrimSpace(packet.Actions[index].ID)
		packet.Actions[index].ActionID = strings.TrimSpace(packet.Actions[index].ActionID)
		packet.Actions[index].State = strings.ToLower(strings.TrimSpace(packet.Actions[index].State))
		packet.Actions[index].Rationale = strings.TrimSpace(packet.Actions[index].Rationale)
		packet.Actions[index].CatalogVersion = strings.TrimSpace(packet.Actions[index].CatalogVersion)
		packet.Actions[index].ProposalDigest = strings.TrimSpace(packet.Actions[index].ProposalDigest)
		packet.Actions[index].TargetURNs = normalizeStrings(packet.Actions[index].TargetURNs)
		packet.Actions[index].ApprovalRequirements = normalizeStrings(packet.Actions[index].ApprovalRequirements)
	}
	for index := range packet.AuditPackets {
		packet.AuditPackets[index].ID = strings.TrimSpace(packet.AuditPackets[index].ID)
		packet.AuditPackets[index].ScopeURN = strings.TrimSpace(packet.AuditPackets[index].ScopeURN)
		packet.AuditPackets[index].Digest = strings.TrimSpace(packet.AuditPackets[index].Digest)
		packet.AuditPackets[index].Freshness = strings.ToLower(strings.TrimSpace(packet.AuditPackets[index].Freshness))
		packet.AuditPackets[index].GeneratedAt = packet.AuditPackets[index].GeneratedAt.UTC()
	}
	packet.Contradictions = nonNilSlice(packet.Contradictions)
	packet.CoverageGaps = nonNilSlice(packet.CoverageGaps)
	packet.Affected = nonNilSlice(packet.Affected)
	packet.Controls = nonNilSlice(packet.Controls)
	packet.AuditPackets = nonNilSlice(packet.AuditPackets)
	packet.Actions = nonNilSlice(packet.Actions)
	sort.Slice(packet.Contradictions, func(i, j int) bool {
		return canonicalSortKey(packet.Contradictions[i]) < canonicalSortKey(packet.Contradictions[j])
	})
	sort.Slice(packet.CoverageGaps, func(i, j int) bool {
		return canonicalSortKey(packet.CoverageGaps[i]) < canonicalSortKey(packet.CoverageGaps[j])
	})
	sort.Slice(packet.Affected, func(i, j int) bool {
		return canonicalSortKey(packet.Affected[i]) < canonicalSortKey(packet.Affected[j])
	})
	sort.Slice(packet.Controls, func(i, j int) bool {
		return canonicalSortKey(packet.Controls[i]) < canonicalSortKey(packet.Controls[j])
	})
	sort.Slice(packet.AuditPackets, func(i, j int) bool {
		return canonicalSortKey(packet.AuditPackets[i]) < canonicalSortKey(packet.AuditPackets[j])
	})
	sort.Slice(packet.Actions, func(i, j int) bool { return canonicalSortKey(packet.Actions[i]) < canonicalSortKey(packet.Actions[j]) })
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
		current, found := byKey[key]
		if !found || canonicalSortKey(value) < canonicalSortKey(current) {
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

func nonNilSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func canonicalSortKey(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%#v", value)
	}
	return string(raw)
}

// normalizeEmbeddedCanonicalValue keeps imported, typed agent contracts stable
// under whitespace and nil-versus-empty representation differences.
func normalizeEmbeddedCanonicalValue(value any) {
	normalizeCanonicalReflectValue(reflect.ValueOf(value))
}

func normalizeCanonicalReflectValue(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}
		normalizeCanonicalReflectValue(value.Elem())
		return
	}
	switch value.Kind() {
	case reflect.String:
		if value.CanSet() {
			value.SetString(strings.TrimSpace(value.String()))
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			normalizeCanonicalReflectValue(field)
			if field.Kind() == reflect.String && field.CanSet() && canonicalLowercaseField(value.Type().Field(index).Name) {
				field.SetString(strings.ToLower(field.String()))
			}
		}
	case reflect.Slice:
		if value.IsNil() && value.CanSet() {
			value.Set(reflect.MakeSlice(value.Type(), 0, 0))
		}
		for index := 0; index < value.Len(); index++ {
			normalizeCanonicalReflectValue(value.Index(index))
		}
		if value.Type().Elem().Kind() == reflect.String && value.CanSet() {
			stringsValue := make([]string, value.Len())
			for index := 0; index < value.Len(); index++ {
				stringsValue[index] = value.Index(index).String()
			}
			stringsValue = normalizeStrings(stringsValue)
			normalized := reflect.MakeSlice(value.Type(), len(stringsValue), len(stringsValue))
			for index := range stringsValue {
				normalized.Index(index).SetString(stringsValue[index])
			}
			value.Set(normalized)
		}
	case reflect.Map:
		if value.IsNil() && value.CanSet() {
			value.Set(reflect.MakeMap(value.Type()))
		}
		iterator := value.MapRange()
		for iterator.Next() {
			item := reflect.New(value.Type().Elem()).Elem()
			item.Set(iterator.Value())
			normalizeCanonicalReflectValue(item)
			value.SetMapIndex(iterator.Key(), item)
		}
	}
}

func canonicalLowercaseField(name string) bool {
	switch name {
	case "ActionStage", "AllowedNextStage", "Applicability", "CitationStatus", "ClaimType", "CredentialBoundary", "DimensionType", "FreshnessState", "Kind", "Level", "MaxActionStage", "MCPSurface", "Mode", "OAuthSurface", "QueryMode", "Readiness", "ReasoningSurface", "RequestedActionStage", "Stage", "State", "Status", "SupportLevel", "TokenOwner", "Type", "Verdict", "WritePolicy":
		return true
	default:
		return false
	}
}

func uniqueSortedStrings(values []string) []string { return normalizeStrings(values) }
