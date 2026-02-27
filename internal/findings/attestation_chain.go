package findings

import (
	"context"
	"strings"
	"time"
)

func upsertAttestationEvent(existing bool, previousStatus string, attestReobserved bool) FindingAttestationEventType {
	if !existing {
		return FindingAttestationCreated
	}
	if normalizeStatus(previousStatus) == "RESOLVED" {
		return FindingAttestationReopened
	}
	if attestReobserved {
		return FindingAttestationReobserved
	}
	return ""
}

func attestFindingEvent(ctx context.Context, attestor FindingAttestor, finding *Finding, eventType FindingAttestationEventType, observedAt time.Time) error {
	if attestor == nil || finding == nil || strings.TrimSpace(string(eventType)) == "" {
		return nil
	}

	event := FindingAttestationEvent{
		Type:         eventType,
		ObservedAt:   observedAt,
		PreviousHash: latestAttestationHash(finding.Evidence),
		Finding:      snapshotFindingForAttestation(finding),
	}

	result, err := attestor.Attest(ctx, event)
	appendAttestationEvidence(finding, result, err)
	if !observedAt.IsZero() {
		finding.UpdatedAt = observedAt
	}
	return err
}

func snapshotFindingForAttestation(f *Finding) FindingAttestationSnapshot {
	if f == nil {
		return FindingAttestationSnapshot{}
	}

	copyResource := make(map[string]interface{}, len(f.Resource))
	for key, value := range f.Resource {
		copyResource[key] = value
	}

	return FindingAttestationSnapshot{
		ID:             f.ID,
		PolicyID:       f.PolicyID,
		PolicyName:     f.PolicyName,
		ControlID:      f.ControlID,
		Title:          f.Title,
		Description:    f.Description,
		Severity:       f.Severity,
		Status:         normalizeStatus(f.Status),
		ResourceID:     f.ResourceID,
		ResourceName:   f.ResourceName,
		ResourceType:   f.ResourceType,
		RiskCategories: append([]string(nil), f.RiskCategories...),
		Resource:       copyResource,
		FirstSeen:      f.FirstSeen,
		LastSeen:       f.LastSeen,
	}
}

func latestAttestationHash(evidence []Evidence) string {
	for i := len(evidence) - 1; i >= 0; i-- {
		ev := evidence[i]
		if ev.Type != AttestationEvidenceType || ev.Data == nil {
			continue
		}
		if hash := valueToString(ev.Data["statement_hash"]); strings.TrimSpace(hash) != "" {
			return strings.TrimSpace(hash)
		}
	}
	return ""
}

func appendAttestationEvidence(f *Finding, result *FindingAttestationResult, attestErr error) {
	if f == nil {
		return
	}

	entry := Evidence{
		Type:        AttestationEvidenceType,
		Description: "Signed finding attestation chain entry",
		Data: map[string]interface{}{
			"status": defaultAttestationEvidenceStatusOK,
		},
	}

	if result != nil {
		entry.Data["schema"] = result.Schema
		entry.Data["event_type"] = string(result.EventType)
		if !result.ObservedAt.IsZero() {
			entry.Data["observed_at"] = result.ObservedAt.UTC().Format(time.RFC3339Nano)
		}
		entry.Data["statement_hash"] = result.StatementHash
		if strings.TrimSpace(result.PreviousHash) != "" {
			entry.Data["previous_hash"] = strings.TrimSpace(result.PreviousHash)
		}
		entry.Data["payload_type"] = result.PayloadType
		entry.Data["signature_key_id"] = result.SignatureKeyID
		entry.Data["public_key"] = result.PublicKey
		entry.Data["envelope"] = result.EnvelopeJSON

		logData := map[string]interface{}{}
		if strings.TrimSpace(result.LogURL) != "" {
			logData["url"] = strings.TrimSpace(result.LogURL)
		}
		if strings.TrimSpace(result.LogEntryID) != "" {
			logData["entry_id"] = strings.TrimSpace(result.LogEntryID)
		}
		if result.LogIndex != nil {
			logData["log_index"] = *result.LogIndex
		}
		if result.IntegratedTime != nil {
			logData["integrated_time"] = result.IntegratedTime.UTC().Format(time.RFC3339Nano)
		}
		if strings.TrimSpace(result.Checkpoint) != "" {
			logData["checkpoint"] = strings.TrimSpace(result.Checkpoint)
		}
		if len(result.InclusionProof) > 0 {
			logData["inclusion_proof"] = result.InclusionProof
		}
		if len(result.LogRawResponse) > 0 {
			logData["raw_response"] = result.LogRawResponse
		}
		if len(logData) > 0 {
			entry.Data["transparency_log"] = logData
		}
	}

	if attestErr != nil {
		entry.Description = "Signed finding attestation created but transparency log upload failed"
		entry.Data["status"] = "upload_error"
		entry.Data["error"] = attestErr.Error()
	}

	f.Evidence = append(f.Evidence, entry)
}

func valueToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}
