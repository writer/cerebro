package sourceruntime

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSourceRuntimeProtocolContract(t *testing.T) {
	valid := []SourceRuntimeEnvelope{
		validProtocolEnvelope(sourceRuntimeDescribePlan),
		validProtocolEnvelope(sourceRuntimeCheck),
		validProtocolEnvelope(sourceRuntimeDiscover),
		validProtocolEnvelope(sourceRuntimeReadPage),
	}
	for _, envelope := range valid {
		if err := ValidateSourceRuntimeEnvelope(envelope); err != nil {
			t.Fatalf("%s valid envelope rejected: %v", envelope.Operation, err)
		}
	}

	invalid := map[string]SourceRuntimeEnvelope{
		"unknown_revision":     withProtocolRevision(validProtocolEnvelope(sourceRuntimeReadPage), 99),
		"missing_tenant":       withoutProtocolIdentity(validProtocolEnvelope(sourceRuntimeReadPage), "tenant_id"),
		"missing_runtime":      withoutProtocolIdentity(validProtocolEnvelope(sourceRuntimeReadPage), "runtime_id"),
		"missing_source":       withoutProtocolIdentity(validProtocolEnvelope(sourceRuntimeReadPage), "source_id"),
		"missing_family":       withoutProtocolIdentity(validProtocolEnvelope(sourceRuntimeReadPage), "family_id"),
		"missing_attempt":      withoutProtocolIdentity(validProtocolEnvelope(sourceRuntimeReadPage), "attempt_id"),
		"worker_sync_rejected": withProtocolOperation(validProtocolEnvelope(sourceRuntimeReadPage), "Sync"),
		"unknown_operation":    withProtocolOperation(validProtocolEnvelope(sourceRuntimeReadPage), "Commit"),
	}
	for id, envelope := range invalid {
		if err := ValidateSourceRuntimeEnvelope(envelope); !errors.Is(err, errProtocolInvalid) {
			t.Fatalf("%s accepted or returned wrong error: %v", id, err)
		}
	}
	t.Logf("source-runtime protocol accepted=%v rejected=%v raw_secret_fields=[]", protocolCaseIDs(valid), sortedProtocolCaseIDs(invalid))
}

func TestSourceRuntimeProtocolRejectsRawCredentials(t *testing.T) {
	for _, field := range rawSecretSentinelFieldNames() {
		for surface, mutate := range map[string]func(SourceRuntimeEnvelope) SourceRuntimeEnvelope{
			"public_config": func(envelope SourceRuntimeEnvelope) SourceRuntimeEnvelope {
				envelope.PublicConfig[field] = "sentinel"
				return envelope
			},
			"result_diagnostics": func(envelope SourceRuntimeEnvelope) SourceRuntimeEnvelope {
				envelope.Result.Diagnostics[field] = "sentinel"
				return envelope
			},
			"error_diagnostics": func(envelope SourceRuntimeEnvelope) SourceRuntimeEnvelope {
				envelope.Error.Diagnostics[field] = "sentinel"
				return envelope
			},
		} {
			name := surface + "." + field
			if err := ValidateSourceRuntimeEnvelope(mutate(validProtocolEnvelope(sourceRuntimeReadPage))); !errors.Is(err, errProtocolSecretField) {
				t.Fatalf("%s accepted or returned wrong error: %v", name, err)
			}
		}
	}
}

func TestSourceRuntimeProtocolRejectsRawCredentialAliases(t *testing.T) {
	for _, field := range []string{
		"apiKey",
		"API-SECRET-KEY",
		"Authorization",
		"bearerToken",
		"access-token",
		"setCookie",
		"rawProviderRequest",
		"providerResponseBody",
		"provider-error-body",
	} {
		envelope := validProtocolEnvelope(sourceRuntimeReadPage)
		envelope.PublicConfig[field] = "sentinel"
		if err := ValidateSourceRuntimeEnvelope(envelope); !errors.Is(err, errProtocolSecretField) {
			t.Fatalf("%s accepted or returned wrong error: %v", field, err)
		}
	}
}

func TestCanonicalSourceRuntimeDigests(t *testing.T) {
	vectors, err := CanonicalSourceRuntimeDigestVectors()
	if err != nil {
		t.Fatal(err)
	}
	permuted, err := CanonicalSourceRuntimeDigest(map[string]any{
		"source_id": "fixture",
		"public_config": map[string]any{
			"org":      "writer",
			"base_url": "https://provider.example.invalid",
		},
		"operation": "ReadPage",
		"limits": map[string]any{
			"page_size":   100,
			"event_limit": 250,
		},
		"family_id": "identity_user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if vectors["plan"] != permuted {
		t.Fatalf("plan digest changed under map key permutation: %s != %s", vectors["plan"], permuted)
	}
	repeated, err := CanonicalSourceRuntimeDigestVectors()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vectors, repeated) {
		t.Fatalf("digest vectors are nondeterministic:\nfirst=%v\nsecond=%v", vectors, repeated)
	}
	t.Logf("canonical source-runtime digest vectors: %s", formatDigestVectors(vectors))
}

func TestRequestIntentDigestVectors(t *testing.T) {
	vectors, err := CanonicalSourceRuntimeDigestVectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"plan",
		"request_intent",
		"scanned_events",
		"accepted_events",
		"logical_result",
		"worker_receipt",
	} {
		if got := vectors[name]; len(got) != 64 {
			t.Fatalf("%s digest = %q, want SHA-256 hex", name, got)
		}
	}
}

func TestSourceFamilyAuthorityReadiness(t *testing.T) {
	complete := SourceFamilyAuthorityEvidence{
		PlanDigest:                 strings.Repeat("a", 64),
		FixtureCorpusRevision:      "fixture-corpus:v1",
		SupportedAuthModes:         []string{"api_key"},
		SupportedPaginationGrammar: []string{"cursor"},
		SupportedProviderErrors:    []string{"401", "429", "5xx"},
		EgressAllowlist:            []string{"https://provider.example.invalid"},
		ResponseLimits:             "body=1048576,decompression=4x",
		CredentialLeaseMode:        "one_operation",
		ProjectionDependency:       "go_projection_dependency",
		RollbackReceipt:            "rollback:test",
		ParityStatus:               "passed",
		CanonicalDigestVectors:     []string{"plan", "request_intent", "worker_receipt"},
		ConfigSafetyProof:          "config:redacted",
		CursorCheckpointProof:      "cursor:go-compatible",
		FencingRecoveryProof:       "fence:rejected-stale",
		WorkerBuildID:              "source-runtime-next:test",
		PromotionReceipt:           "sig:promotion:test",
	}
	if err := ValidateSourceFamilyAuthorityEvidence(complete); err != nil {
		t.Fatalf("complete evidence rejected: %v", err)
	}

	incomplete := complete
	incomplete.RollbackReceipt = ""
	incomplete.EgressAllowlist = nil
	err := ValidateSourceFamilyAuthorityEvidence(incomplete)
	if !errors.Is(err, errAuthorityEvidenceMissing) {
		t.Fatalf("incomplete evidence accepted or wrong error: %v", err)
	}
	t.Logf("authority readiness requires complete provider proof fields")
}

func TestAuthorityPromotionRequiresEvidence(t *testing.T) {
	if err := ValidateSourceFamilyAuthorityEvidence(SourceFamilyAuthorityEvidence{}); !errors.Is(err, errAuthorityEvidenceMissing) {
		t.Fatalf("empty evidence accepted or wrong error: %v", err)
	}
}

func TestAuthorityEvidenceRejectsMalformedDigestAndUnsignedPromotionReceipt(t *testing.T) {
	evidence := SourceFamilyAuthorityEvidence{
		PlanDigest:                 strings.Repeat("a", 64),
		FixtureCorpusRevision:      "fixture-corpus:v1",
		SupportedAuthModes:         []string{"api_key"},
		SupportedPaginationGrammar: []string{"cursor"},
		SupportedProviderErrors:    []string{"401", "429", "5xx"},
		EgressAllowlist:            []string{"https://provider.example.invalid"},
		ResponseLimits:             "body=1048576,decompression=4x",
		CredentialLeaseMode:        "one_operation",
		ProjectionDependency:       "go_projection_dependency",
		RollbackReceipt:            "rollback:test",
		ParityStatus:               "passed",
		CanonicalDigestVectors:     []string{"plan", "request_intent", "worker_receipt"},
		ConfigSafetyProof:          "config:redacted",
		CursorCheckpointProof:      "cursor:go-compatible",
		FencingRecoveryProof:       "fence:rejected-stale",
		WorkerBuildID:              "source-runtime-next:test",
		PromotionReceipt:           "sig:promotion:test",
	}
	badDigest := evidence
	badDigest.PlanDigest = "not-a-sha256"
	if err := ValidateSourceFamilyAuthorityEvidence(badDigest); !errors.Is(err, errAuthorityEvidenceMissing) {
		t.Fatalf("bad digest error = %v, want SHA-256 rejection", err)
	}
	unsigned := evidence
	unsigned.PromotionReceipt = "promotion:test"
	if err := ValidateSourceFamilyAuthorityEvidence(unsigned); !errors.Is(err, errAuthorityEvidenceMissing) {
		t.Fatalf("unsigned promotion error = %v, want auth rejection", err)
	}
}

func validProtocolEnvelope(operation sourceRuntimeOperation) SourceRuntimeEnvelope {
	return SourceRuntimeEnvelope{
		Revision:  sourceRuntimeProtocolRevision,
		Operation: operation,
		TenantID:  "tenant-a",
		RuntimeID: "runtime-a",
		SourceID:  "fixture",
		FamilyID:  "identity_user",
		AttemptID: "attempt-0001",
		PublicConfig: map[string]string{
			"base_url": "https://provider.example.invalid",
			"org":      "writer",
		},
		Cursor:     "cursor-1",
		Checkpoint: "checkpoint-1",
		Limit:      100,
		Result: &SourceRuntimeResult{
			EventsScanned:  2,
			EventsAccepted: 1,
			NextCursor:     "cursor-2",
			Diagnostics: map[string]string{
				"redaction": "provider diagnostics redacted",
			},
		},
		Receipt: &SourceRuntimeReceipt{
			PlanDigestSHA256:      strings.Repeat("1", 64),
			RequestDigestSHA256:   strings.Repeat("2", 64),
			ScannedDigestSHA256:   strings.Repeat("3", 64),
			AcceptedDigestSHA256:  strings.Repeat("4", 64),
			ResultDigestSHA256:    strings.Repeat("5", 64),
			ReceiptDigestSHA256:   strings.Repeat("6", 64),
			WorkerBuildID:         "source-runtime-next:test",
			RuntimeFamilyProofRev: "fixture-corpus:v1",
		},
		Error: &SourceRuntimeErrorShape{
			Code:      "not_modified",
			Category:  "short_circuit",
			Retryable: false,
			Diagnostics: map[string]string{
				"detail": "redacted",
			},
		},
	}
}

func withProtocolRevision(envelope SourceRuntimeEnvelope, revision int) SourceRuntimeEnvelope {
	envelope.Revision = revision
	return envelope
}

func withProtocolOperation(envelope SourceRuntimeEnvelope, operation sourceRuntimeOperation) SourceRuntimeEnvelope {
	envelope.Operation = operation
	return envelope
}

func withoutProtocolIdentity(envelope SourceRuntimeEnvelope, field string) SourceRuntimeEnvelope {
	switch field {
	case "tenant_id":
		envelope.TenantID = ""
	case "runtime_id":
		envelope.RuntimeID = ""
	case "source_id":
		envelope.SourceID = ""
	case "family_id":
		envelope.FamilyID = ""
	case "attempt_id":
		envelope.AttemptID = ""
	default:
		panic(field)
	}
	return envelope
}

func protocolCaseIDs(envelopes []SourceRuntimeEnvelope) []string {
	ids := make([]string, 0, len(envelopes))
	for _, envelope := range envelopes {
		ids = append(ids, string(envelope.Operation))
	}
	sort.Strings(ids)
	return ids
}

func sortedProtocolCaseIDs(values map[string]SourceRuntimeEnvelope) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func formatDigestVectors(vectors map[string]string) string {
	keys := make([]string, 0, len(vectors))
	for key := range vectors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, vectors[key]))
	}
	return strings.Join(parts, " ")
}

func rawSecretSentinelFieldNames() []string {
	return []string{
		"api_key",
		"api_secret_key",
		"password",
		"authorization",
		"bearer_token",
		"access_token",
		"refresh_token",
		"api_token",
		"client_secret",
		"cookie",
		"set_cookie",
		"raw_provider_request",
		"raw_provider_response",
		"raw_provider_error",
		"raw_provider_payload",
		"provider_payload",
		"provider_request_body",
		"provider_response_body",
		"provider_error_body",
	}
}
