package grcauditverify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcauditpacket"
)

// Verify performs a complete preflight using only the supplied submission. It
// does not consult a provider, state store, graph, clock, or mutable registry.
func Verify(submission Submission) Result {
	return verifyWithKeys(submission, nil)
}

// VerifyWithTrust checks optional signatures against caller-controlled keys.
func VerifyWithTrust(submission Submission, trust TrustBundle) Result {
	return verifyWithKeys(submission, trust.SigningKeys)
}

func verifyWithKeys(submission Submission, trustedKeys map[string]string) Result {
	started := time.Now()
	defects := verifySubmission(submission, trustedKeys)
	sort.SliceStable(defects, func(i, j int) bool {
		if defects[i].Code == defects[j].Code {
			return defects[i].Path < defects[j].Path
		}
		return defects[i].Code < defects[j].Code
	})
	ready := len(defects) == 0
	code := ResultResubmissionNeeded
	if ready {
		code = ResultFirstPassReady
	}
	return Result{
		Ready: ready, Code: code, Defects: defects,
		Metrics: VerificationMetrics{
			FirstPassReady: ready, ResubmissionDefects: len(defects), VerifyDuration: time.Since(started),
		},
	}
}

// VerifyJSON is the standalone serialization surface for offline tools.
func VerifyJSON(payload []byte) (Result, error) {
	return VerifyJSONWithTrust(payload, TrustBundle{})
}

// VerifyJSONWithTrust is the signed standalone serialization surface.
func VerifyJSONWithTrust(payload []byte, trust TrustBundle) (Result, error) {
	var submission Submission
	if err := json.Unmarshal(payload, &submission); err != nil {
		return Result{}, fmt.Errorf("decode audit submission: %w", err)
	}
	return VerifyWithTrust(submission, trust), nil
}

func verifySubmission(submission Submission, trustedKeys map[string]string) []Defect {
	defects := []Defect{}
	request := submission.Request
	if request.SchemaVersion != RequestSchemaVersion {
		defects = append(defects, defect("request_schema_unsupported", "request.schema_version", "The audit request manifest schema is not supported."))
	}
	requestDigest, err := DigestRequest(request)
	if err != nil || request.Digest == "" || request.Digest != requestDigest {
		defects = append(defects, defect("request_digest_invalid", "request.digest", "The audit request digest does not match its contents."))
	}
	if err := verifySignature(request.Signature, request.Digest, trustedKeys); err != nil {
		defects = append(defects, defect("request_signature_invalid", "request.signature", err.Error()))
	}
	if request.ID == "" || request.TenantID == "" || request.CreatedAt.IsZero() || !validWindow(request.Period) {
		defects = append(defects, defect("request_manifest_invalid", "request", "The request must identify its tenant, creation time, and ordered audit period."))
	}
	if request.SupersededBy != nil {
		defects = append(defects, defect("request_superseded", "request.superseded_by", "A superseded request is not eligible for submission."))
	}
	if submission.VerifiedAt.IsZero() {
		defects = append(defects, defect("verification_time_missing", "verified_at", "The standalone verification time is required."))
	}
	if request.Recipient.RecipientID == "" || request.Recipient.ExpiresAt.IsZero() || submission.VerifiedAt.After(request.Recipient.ExpiresAt) {
		defects = append(defects, defect("recipient_grant_invalid", "request.recipient", "The recipient grant is missing or expired at verification time."))
	}

	packet := grcauditpacket.Packet{}
	if err := json.Unmarshal(submission.PacketJSON, &packet); err != nil {
		defects = append(defects, defect("packet_decode_failed", "packet_json", "The immutable audit packet could not be decoded."))
	} else {
		if err := grcauditpacket.Verify(packet); err != nil {
			defects = append(defects, defect("packet_verification_failed", "packet_json", err.Error()))
		}
		for _, gap := range packet.Gaps {
			switch gap.Code {
			case "evidence_snapshot_truncated", "evidence_total_unavailable":
				defects = append(defects, defect("packet_evidence_incomplete", "packet_json.gaps", "The immutable packet does not contain a complete evidence snapshot."))
			}
		}
		if packet.TenantID != request.TenantID {
			defects = append(defects, defect("packet_tenant_mismatch", "packet_json", "The packet tenant does not match the audit request."))
		}
		packetScope := packetScopeReferences(packet)
		for _, scope := range normalized(request.ScopeReferences) {
			if !packetScope[scope] {
				defects = append(defects, defect("packet_scope_mismatch", "request.scope_references", "The packet does not contain requested scope "+scope+"."))
			}
		}
		defects = append(defects, verifyPacketSupersession(packet, submission.SupersededPackets)...)
	}

	defects = append(defects, verifyRequestSupersession(request, submission.PriorRequests)...)
	citations, citationDefects := verifyCitations(request, submission.Citations, submission.Population, submission.Sample)
	defects = append(defects, citationDefects...)
	defects = append(defects, verifyDisclosure(request, submission.Disclosure, submission.ExternalFields, citations, trustedKeys)...)

	if (submission.Population == nil) != (submission.Sample == nil) {
		defects = append(defects, defect("sample_bundle_incomplete", "sample", "Population and sample manifests must be submitted together."))
	}
	if submission.Population != nil && submission.Sample != nil {
		defects = append(defects, verifySample(*submission.Population, *submission.Sample, trustedKeys)...)
	}
	return defects
}

func verifyCitations(request RequestManifest, citations []Citation, population *PopulationManifest, sample *SampleManifest) (map[string]Citation, []Defect) {
	defects := []Defect{}
	byID := map[string]Citation{}
	scopeCovered := map[string]bool{}
	for _, citation := range citations {
		if citation.ID == "" || byID[citation.ID].ID != "" {
			defects = append(defects, defect("citation_id_invalid", "citations", "Citation IDs must be present and unique."))
			continue
		}
		byID[citation.ID] = citation
		if len(citation.Payload) == 0 {
			defects = append(defects, defect("citation_payload_missing", "citations."+citation.ID, "The citation must include the cited evidence payload."))
		}
		if citation.Digest == "" || citation.Digest != DigestCitation(citation) {
			defects = append(defects, defect("citation_digest_invalid", "citations."+citation.ID, "The citation digest does not match its payload."))
		}
		if !windowContains(citation.Period, request.Period) {
			defects = append(defects, defect("citation_period_mismatch", "citations."+citation.ID, "The citation period does not cover the requested audit period."))
		}
		for _, scope := range normalized(citation.ScopeReferences) {
			if !contains(request.ScopeReferences, scope) {
				defects = append(defects, defect("citation_scope_unauthorized", "citations."+citation.ID, "The citation includes scope outside the request."))
			} else {
				scopeCovered[scope] = true
			}
		}
		if citation.SampleID != "" && (sample == nil || population == nil || citation.SampleID != sample.ID) {
			defects = append(defects, defect("citation_sample_missing", "citations."+citation.ID, "The citation names a sample that is not included in the submission."))
		}
	}
	for _, required := range normalized(request.RequiredCitationIDs) {
		if byID[required].ID == "" {
			defects = append(defects, defect("required_citation_missing", "request.required_citation_ids", "Required citation "+required+" is missing."))
		}
	}
	for _, scope := range normalized(request.ScopeReferences) {
		if !scopeCovered[scope] {
			defects = append(defects, defect("scope_citation_missing", "request.scope_references", "No citation covers requested scope "+scope+"."))
		}
	}
	return byID, defects
}

func verifyDisclosure(request RequestManifest, disclosure DisclosureManifest, externalFields map[string]json.RawMessage, citations map[string]Citation, trustedKeys map[string]string) []Defect {
	defects := []Defect{}
	if disclosure.SchemaVersion != DisclosureSchemaVersion {
		defects = append(defects, defect("disclosure_schema_unsupported", "disclosure.schema_version", "The disclosure manifest schema is not supported."))
	}
	digest, err := DigestDisclosure(disclosure)
	if err != nil || disclosure.Digest == "" || disclosure.Digest != digest {
		defects = append(defects, defect("disclosure_digest_invalid", "disclosure.digest", "The disclosure manifest digest does not match its contents."))
	}
	if err := verifySignature(disclosure.Signature, disclosure.Digest, trustedKeys); err != nil {
		defects = append(defects, defect("disclosure_signature_invalid", "disclosure.signature", err.Error()))
	}
	if disclosure.ID == "" || disclosure.RequestID != request.ID || disclosure.RecipientID != request.Recipient.RecipientID || disclosure.CreatedAt.IsZero() {
		defects = append(defects, defect("disclosure_binding_invalid", "disclosure", "The disclosure must identify the request, recipient, and creation time."))
	}

	expected := normalized(request.ExternalFields)
	allowed := stringSet(request.Recipient.AllowedFields)
	seen := map[string]bool{}
	for _, field := range disclosure.Fields {
		if field.Path == "" || seen[field.Path] || !contains(expected, field.Path) {
			defects = append(defects, defect("disclosure_field_unexpected", "disclosure.fields", "Disclosure fields must cover each requested external field exactly once."))
			continue
		}
		seen[field.Path] = true
		switch field.State {
		case "included":
			if !allowed[field.Path] {
				defects = append(defects, defect("disclosure_field_unauthorized", "disclosure.fields."+field.Path, "The recipient is not authorized to receive this field."))
			}
			payload, supplied := externalFields[field.Path]
			if !supplied || !validSHA256Digest(field.Digest) || field.Digest != DigestExternalField(payload) || field.CitationID == "" || citations[field.CitationID].ID == "" || field.Reason != "" {
				defects = append(defects, defect("disclosure_included_field_invalid", "disclosure.fields."+field.Path, "An included field requires a content digest and valid citation."))
			}
		case "redacted":
			_, supplied := externalFields[field.Path]
			if strings.TrimSpace(field.Reason) == "" || field.Digest != "" || field.CitationID != "" || supplied {
				defects = append(defects, defect("disclosure_redaction_invalid", "disclosure.fields."+field.Path, "A redacted field requires a reason and cannot expose a digest or citation."))
			}
		default:
			defects = append(defects, defect("disclosure_state_invalid", "disclosure.fields."+field.Path, "Disclosure state must be included or redacted."))
		}
	}
	for _, field := range expected {
		if !seen[field] {
			defects = append(defects, defect("disclosure_field_missing", "disclosure.fields", "External field "+field+" is missing from the disclosure manifest."))
		}
	}
	for field := range externalFields {
		if !seen[field] {
			defects = append(defects, defect("external_field_unmanifested", "external_fields."+field, "Every supplied external field must be covered by the disclosure manifest."))
		}
	}
	return defects
}

func verifyRequestSupersession(request RequestManifest, prior []RequestManifest) []Defect {
	defects := []Defect{}
	byID := map[string]RequestManifest{}
	for _, manifest := range prior {
		byID[manifest.ID] = manifest
	}
	for _, reference := range request.Supersedes {
		manifest := byID[reference.ID]
		digest, err := DigestRequest(manifest)
		if reference.ID == request.ID || manifest.ID == "" || err != nil || manifest.Digest != digest || reference.Digest != manifest.Digest || manifest.TenantID != request.TenantID {
			defects = append(defects, defect("request_supersession_invalid", "request.supersedes", "Each superseded request must be supplied with a matching digest and tenant."))
		}
	}
	return defects
}

func verifyPacketSupersession(packet grcauditpacket.Packet, supplied [][]byte) []Defect {
	defects := []Defect{}
	byID := map[string]grcauditpacket.Packet{}
	for _, payload := range supplied {
		var prior grcauditpacket.Packet
		if json.Unmarshal(payload, &prior) == nil && grcauditpacket.Verify(prior) == nil {
			byID[prior.ID] = prior
		}
	}
	for _, packetID := range packet.Supersedes {
		prior := byID[packetID]
		if packetID == packet.ID || prior.ID == "" || prior.TenantID != packet.TenantID {
			defects = append(defects, defect("packet_supersession_invalid", "packet.supersedes", "Each superseded packet must be supplied and independently verifiable."))
		}
	}
	return defects
}

func packetScopeReferences(packet grcauditpacket.Packet) map[string]bool {
	result := map[string]bool{"finding:" + packet.FindingReference.ID: true}
	for _, control := range packet.ControlReferences {
		result["control:"+control.FrameworkID+":"+control.ControlID] = true
	}
	for _, runtime := range packet.SourceRuntimes {
		result["source-runtime:"+runtime.ID] = true
	}
	for _, root := range packet.GraphReferences.RootURNs {
		result["graph-root:"+root] = true
	}
	return result
}

func defect(code, path, message string) Defect {
	return Defect{Code: code, Path: path, Message: message}
}

func validWindow(window Window) bool {
	return !window.Start.IsZero() && !window.End.IsZero() && !window.End.Before(window.Start)
}

func sameWindow(left, right Window) bool {
	return left.Start.Equal(right.Start) && left.End.Equal(right.End)
}

func windowContains(outer, inner Window) bool {
	return validWindow(outer) && validWindow(inner) && !outer.Start.After(inner.Start) && !outer.End.Before(inner.End)
}

func normalized(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range normalized(values) {
		result[value] = true
	}
	return result
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
