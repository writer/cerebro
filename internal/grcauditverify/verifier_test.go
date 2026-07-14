package grcauditverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/grcauditpacket"
)

func TestVerifyAcceptsSelfContainedFirstPassSubmission(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	result := Verify(submission)
	if !result.Ready || result.Code != ResultFirstPassReady || len(result.Defects) != 0 {
		t.Fatalf("result = %#v", result)
	}
	if !result.Metrics.FirstPassReady || result.Metrics.ResubmissionDefects != 0 || result.Metrics.VerifyDuration <= 0 {
		t.Fatalf("metrics = %#v", result.Metrics)
	}
	payload, err := json.Marshal(submission)
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := VerifyJSON(payload)
	if err != nil || !standalone.Ready {
		t.Fatalf("VerifyJSON() result = %#v, err = %v", standalone, err)
	}
}

func TestVerifyRejectsTamperedPacket(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	var packet grcauditpacket.Packet
	if err := json.Unmarshal(submission.PacketJSON, &packet); err != nil {
		t.Fatal(err)
	}
	packet.RecommendedAction = "changed after freezing"
	submission.PacketJSON = marshal(t, packet)
	assertDefect(t, Verify(submission), "packet_verification_failed")
}

func TestVerifyRejectsIncompleteOrLateChangedPopulation(t *testing.T) {
	t.Parallel()
	incomplete := validSubmission(t)
	incomplete.Population.Complete = false
	incomplete.Population.Digest = mustPopulationDigest(t, *incomplete.Population)
	incomplete.Sample.PopulationDigest = incomplete.Population.Digest
	incomplete.Sample.Digest = mustSampleDigest(t, *incomplete.Sample)
	assertDefect(t, Verify(incomplete), "population_incomplete")

	late := validSubmission(t)
	late.Population.Members = append(late.Population.Members, PopulationMember{
		ID: "member-late", Digest: digestLiteral('d'), ObservedAt: late.Population.Window.End.Add(-time.Hour), ArrivedAt: late.Population.Window.End.Add(time.Minute),
	})
	// The unchanged digest proves that the population changed after sampling.
	assertDefect(t, Verify(late), "population_digest_invalid")

	unrecorded := validSubmission(t)
	unrecorded.Population.Members = append(unrecorded.Population.Members, PopulationMember{
		ID: "member-late", Digest: digestLiteral('d'), ObservedAt: unrecorded.Population.Window.End.Add(-time.Hour), ArrivedAt: unrecorded.Population.Window.End.Add(time.Minute),
	})
	unrecorded.Population.Digest = mustPopulationDigest(t, *unrecorded.Population)
	unrecorded.Sample.PopulationDigest = unrecorded.Population.Digest
	unrecorded.Sample.Exclusions = []SampleExclusion{{MemberID: "member-late", Reason: "received after the sampling window"}}
	unrecorded.Sample.Digest = mustSampleDigest(t, *unrecorded.Sample)
	assertDefect(t, Verify(unrecorded), "late_arrival_unrecorded")
}

func TestVerifyRejectsUnauthorizedExternalField(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	submission.Request.Recipient.AllowedFields = nil
	submission.Request.Digest = mustRequestDigest(t, submission.Request)
	assertDefect(t, Verify(submission), "disclosure_field_unauthorized")
}

func TestVerifyRejectsTamperedExternalField(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	submission.ExternalFields["finding.summary"] = json.RawMessage(`"changed after disclosure"`)
	assertDefect(t, Verify(submission), "disclosure_included_field_invalid")
}

func TestVerifyChecksOptionalManifestSignature(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	submission.Request.Signature = &ManifestSignature{
		Algorithm: SignatureAlgorithmEd25519, KeyID: "request-key-1",
		SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(submission.Request.Digest))),
		SignedDigest:    submission.Request.Digest,
	}
	trust := TrustBundle{SigningKeys: map[string]string{"request-key-1": base64.StdEncoding.EncodeToString(publicKey)}}
	if result := VerifyWithTrust(submission, trust); !result.Ready {
		t.Fatalf("signed result = %#v", result)
	}
	delete(trust.SigningKeys, "request-key-1")
	assertDefect(t, Verify(submission), "request_signature_invalid")
	trust.SigningKeys["request-key-1"] = base64.StdEncoding.EncodeToString(publicKey)
	submission.Request.Signature.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	assertDefect(t, VerifyWithTrust(submission, trust), "request_signature_invalid")
}

func TestVerifyRejectsUnrecordedRedactionAndInvalidReplacement(t *testing.T) {
	t.Parallel()
	submission := validSubmission(t)
	submission.Disclosure.Fields[0] = DisclosureField{Path: "finding.summary", State: "redacted"}
	delete(submission.ExternalFields, "finding.summary")
	submission.Disclosure.Digest = mustDisclosureDigest(t, submission.Disclosure)
	assertDefect(t, Verify(submission), "disclosure_redaction_invalid")

	replacement := validSubmission(t)
	replacement.Sample.Replacements = []SampleReplacement{{RemovedID: replacement.Sample.SelectedIDs[0], AddedID: replacement.Sample.SelectedIDs[1], Reason: "duplicate evidence"}}
	replacement.Sample.Digest = mustSampleDigest(t, *replacement.Sample)
	assertDefect(t, Verify(replacement), "sample_replacement_invalid")
}

func validSubmission(t *testing.T) Submission {
	t.Helper()
	period := Window{Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)}
	packet := grcauditpacket.Packet{
		ID: "audit-packet-one", SchemaVersion: grcauditpacket.SchemaVersion, ResourceState: "immutable",
		TenantID: "tenant-one", FindingReference: grcauditpacket.FindingReference{ID: "finding-one", Status: "open", StatusRevision: period.End},
		Gaps: []grcauditpacket.Gap{}, Supersedes: []string{}, GeneratedAt: period.End,
	}
	packet.Digest = mustPacketDigest(t, packet)
	population := PopulationManifest{
		SchemaVersion: PopulationSchemaVersion, ID: "population-one", Complete: true, Window: period, CreatedAt: period.End,
		Members: []PopulationMember{
			{ID: "member-one", Digest: digestLiteral('1'), ObservedAt: period.Start.Add(time.Hour), ArrivedAt: period.Start.Add(2 * time.Hour)},
			{ID: "member-two", Digest: digestLiteral('2'), ObservedAt: period.Start.Add(2 * time.Hour), ArrivedAt: period.Start.Add(3 * time.Hour)},
			{ID: "member-three", Digest: digestLiteral('3'), ObservedAt: period.Start.Add(3 * time.Hour), ArrivedAt: period.Start.Add(4 * time.Hour)},
		},
	}
	population.Digest = mustPopulationDigest(t, population)
	sample := SampleManifest{
		SchemaVersion: SampleSchemaVersion, ID: "sample-one", PopulationID: population.ID, PopulationDigest: population.Digest,
		Window: period, Algorithm: SampleAlgorithmDeterministicSHA256V1, AlgorithmVersion: "1", Seed: "quarter-one-seed",
		Rationale: "Select two deterministic population members for operating-effectiveness testing.", SampleSize: 2, CreatedAt: period.End,
	}
	ranked := append([]PopulationMember(nil), population.Members...)
	sort.Slice(ranked, func(i, j int) bool { return sampleRank(sample.Seed, ranked[i]) < sampleRank(sample.Seed, ranked[j]) })
	sample.SelectedIDs = []string{ranked[0].ID, ranked[1].ID}
	sample.Digest = mustSampleDigest(t, sample)
	citation := Citation{
		ID: "citation-one", Period: period, ScopeReferences: []string{"finding:finding-one"}, SampleID: sample.ID,
		Payload: []byte("immutable cited evidence"),
	}
	citation.Digest = DigestCitation(citation)
	request := RequestManifest{
		SchemaVersion: RequestSchemaVersion, ID: "request-one", TenantID: "tenant-one", Period: period,
		ScopeReferences: []string{"finding:finding-one"}, RequiredCitationIDs: []string{citation.ID}, ExternalFields: []string{"finding.summary"},
		Recipient: RecipientGrant{RecipientID: "recipient-one", AllowedFields: []string{"finding.summary"}, ExpiresAt: period.End.Add(30 * 24 * time.Hour)},
		CreatedAt: period.End,
	}
	request.Digest = mustRequestDigest(t, request)
	externalFields := map[string]json.RawMessage{"finding.summary": json.RawMessage(`"A current finding"`)}
	disclosure := DisclosureManifest{
		SchemaVersion: DisclosureSchemaVersion, ID: "disclosure-one", RequestID: request.ID, RecipientID: request.Recipient.RecipientID,
		Fields: []DisclosureField{{Path: "finding.summary", State: "included", Digest: DigestExternalField(externalFields["finding.summary"]), CitationID: citation.ID}}, CreatedAt: period.End,
	}
	disclosure.Digest = mustDisclosureDigest(t, disclosure)
	return Submission{
		Request: request, PacketJSON: marshal(t, packet), Disclosure: disclosure, ExternalFields: externalFields, Citations: []Citation{citation},
		Population: &population, Sample: &sample, VerifiedAt: period.End.Add(time.Hour),
	}
}

func assertDefect(t *testing.T, result Result, code string) {
	t.Helper()
	if result.Ready || result.Code != ResultResubmissionNeeded {
		t.Fatalf("result = %#v", result)
	}
	for _, item := range result.Defects {
		if item.Code == code {
			return
		}
	}
	t.Fatalf("defects = %#v, want %q", result.Defects, code)
}

func mustPacketDigest(t *testing.T, packet grcauditpacket.Packet) string {
	t.Helper()
	digest, err := grcauditpacket.Digest(packet)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustRequestDigest(t *testing.T, manifest RequestManifest) string {
	t.Helper()
	digest, err := DigestRequest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustDisclosureDigest(t *testing.T, manifest DisclosureManifest) string {
	t.Helper()
	digest, err := DigestDisclosure(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustPopulationDigest(t *testing.T, manifest PopulationManifest) string {
	t.Helper()
	digest, err := DigestPopulation(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustSampleDigest(t *testing.T, manifest SampleManifest) string {
	t.Helper()
	digest, err := DigestSample(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func digestLiteral(character byte) string {
	value := make([]byte, 64)
	for i := range value {
		value[i] = character
	}
	return "sha256:" + string(value)
}
