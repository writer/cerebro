package sourceruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehealth"
)

// #nosec G101 -- synthetic test sentinel, not credential material.
const depositSecretIdempotencyForTest = "SECRET-SENTINEL-IDEMPOTENCY-KEY-DO-NOT-PERSIST"

type depositDefinitionStore struct {
	records []*ports.ConnectorDefinitionRecord
}

func (s *depositDefinitionStore) Ping(context.Context) error { return nil }

func (s *depositDefinitionStore) PutConnectorDefinition(_ context.Context, record *ports.ConnectorDefinitionRecord) (*ports.ConnectorDefinitionRecord, error) {
	s.records = append(s.records, record)
	return record, nil
}

func (s *depositDefinitionStore) GetConnectorDefinition(context.Context, string) (*ports.ConnectorDefinitionRecord, error) {
	return nil, ports.ErrConnectorDefinitionNotFound
}

func (s *depositDefinitionStore) ListConnectorDefinitions(_ context.Context, filter ports.ConnectorDefinitionFilter) ([]*ports.ConnectorDefinitionRecord, error) {
	out := make([]*ports.ConnectorDefinitionRecord, 0, len(s.records))
	for _, record := range s.records {
		if filter.TenantID != "" && record.TenantID != filter.TenantID {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *depositDefinitionStore) ListConnectorDefinitionVersions(context.Context, string) ([]*ports.ConnectorDefinitionVersionRecord, error) {
	return nil, nil
}

func TestDepositIngestProducesLedgerReceiptAndStableIdempotency(t *testing.T) {
	definition := depositTestDefinition(t, "tenant-a")
	definitionJSON, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	store := &ledgerRuntimeStore{
		runtimeStore: runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"runtime-deposit": {
				Id:       "runtime-deposit",
				SourceId: "custom_deposit",
				TenantId: "tenant-a",
				Config:   map[string]string{},
			},
		}},
		authorityEvidence: []sourcehealth.AuthorityEvidenceRecord{depositAuthorityEvidence(t)},
	}
	definitions := &depositDefinitionStore{records: []*ports.ConnectorDefinitionRecord{{
		ID:             definition.ID,
		TenantID:       definition.TenantID,
		SourceID:       definition.SourceID,
		DisplayName:    definition.DisplayName,
		Runtime:        definition.Runtime,
		Stage:          definition.Stage,
		DefinitionJSON: definitionJSON,
	}}}
	appendLog := &appendLog{}
	projector := &projector{result: ports.ProjectionResult{EntitiesProjected: 1}}
	service := New(nil, store, appendLog, projector).WithConnectorDefinitionStore(definitions)
	request := DepositRequest{
		RuntimeID:      "runtime-deposit",
		SourceID:       "custom_deposit",
		TenantID:       "tenant-a",
		FamilyID:       "assets",
		BatchID:        "batch-1",
		IdempotencyKey: "request-1",
		OccurredAt:     time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
		Records:        []json.RawMessage{json.RawMessage(`{"id":"asset-1","name":"Asset One"}`)},
	}
	response, err := service.Deposit(context.Background(), request)
	if err != nil {
		t.Fatalf("Deposit() error = %v", err)
	}
	if response.Receipt.ReceiptID == "" || response.Receipt.AppendReceiptID == "" || response.Receipt.ProjectionReceiptID == "" || len(response.Receipt.ReceiptDigestSHA256) != 64 || len(response.Receipt.IdempotencyKeyDigest) != 64 {
		t.Fatalf("deposit receipt = %#v, want durable receipt ids and digests", response.Receipt)
	}
	if got, want := store.calls, []string{"begin", "appended", "projected", "committed"}; len(got) != len(want) {
		t.Fatalf("ledger calls = %#v, want %#v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ledger calls = %#v, want %#v", got, want)
			}
		}
	}
	if len(store.attempts) != 1 {
		t.Fatalf("ledger attempts = %d, want 1", len(store.attempts))
	}
	attempt := store.attempts[0]
	if attempt.TenantID != "tenant-a" || attempt.SourceID != "custom_deposit" || attempt.RuntimeID != "runtime-deposit" || attempt.Admission.Kernel != "deposit_ingest" {
		t.Fatalf("ledger attempt = %#v, want tenant-scoped deposit receipt", attempt)
	}
	if attempt.Admission.Accepted != 1 || attempt.Admission.Scanned != 1 || attempt.Admission.ContractsSHA256 == "" || attempt.Admission.ResultSHA256 == "" {
		t.Fatalf("ledger admission = %#v, want receipt semantics", attempt.Admission)
	}
	if attempt.Authority.DecisionID != response.Receipt.AuthorityDecisionID || attempt.Authority.Epoch != 7 {
		t.Fatalf("ledger authority = %#v, receipt = %#v", attempt.Authority, response.Receipt)
	}
	if response.Receipt.AuthorityDecisionID != "decision-deposit-authority" || response.Receipt.AuthorityEvidenceRef != "authority-evidence:decision-deposit-authority:7" {
		t.Fatalf("authority receipt refs = %#v, want durable authority evidence cross-reference", response.Receipt)
	}
}

func TestDepositIngestRedactsCallerIdempotencyFromDurableOutputs(t *testing.T) {
	definition := depositTestDefinition(t, "tenant-a")
	definitionJSON, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	store := &ledgerRuntimeStore{
		runtimeStore: runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			"runtime-deposit": {
				Id:       "runtime-deposit",
				SourceId: "custom_deposit",
				TenantId: "tenant-a",
				Config:   map[string]string{},
			},
		}},
		authorityEvidence: []sourcehealth.AuthorityEvidenceRecord{depositAuthorityEvidence(t)},
	}
	definitions := &depositDefinitionStore{records: []*ports.ConnectorDefinitionRecord{{
		ID:             definition.ID,
		TenantID:       definition.TenantID,
		SourceID:       definition.SourceID,
		DisplayName:    definition.DisplayName,
		Runtime:        definition.Runtime,
		Stage:          definition.Stage,
		DefinitionJSON: definitionJSON,
	}}}
	appendLog := &appendLog{}
	projector := &projector{result: ports.ProjectionResult{EntitiesProjected: 1}}
	service := New(nil, store, appendLog, projector).WithConnectorDefinitionStore(definitions)
	response, err := service.Deposit(context.Background(), DepositRequest{
		RuntimeID:      "runtime-deposit",
		SourceID:       "custom_deposit",
		TenantID:       "tenant-a",
		FamilyID:       "assets",
		BatchID:        "batch-secret-sentinel",
		IdempotencyKey: depositSecretIdempotencyForTest,
		OccurredAt:     time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
		Records:        []json.RawMessage{json.RawMessage(`{"id":"asset-1","name":"Asset One"}`)},
	})
	if err != nil {
		t.Fatalf("Deposit() error = %v", err)
	}
	if response.Receipt.IdempotencyKeyDigest == "" || strings.Contains(response.Receipt.ReceiptID, depositSecretIdempotencyForTest) {
		t.Fatalf("receipt id/digest = %#v, want redacted idempotency identity", response.Receipt)
	}
	assertDepositOutputOmits(t, "receipt", response.Receipt)
	assertDepositOutputOmits(t, "append log events", appendLog.events)
	assertDepositOutputOmits(t, "ledger attempts", store.attempts)
	assertDepositOutputOmits(t, "projected events", projector.events)
	assertDepositOutputOmits(t, "runtime state", store.runtimes)
	for _, event := range appendLog.events {
		if strings.Contains(event.GetId(), depositSecretIdempotencyForTest) || strings.Contains(event.GetAttributes()["source_event_id"], depositSecretIdempotencyForTest) {
			t.Fatalf("event identifiers leaked idempotency key: id=%q attrs=%#v", event.GetId(), event.GetAttributes())
		}
		if !strings.Contains(event.GetId(), "idempotency-sha256-") {
			t.Fatalf("event id = %q, want deterministic redacted idempotency digest", event.GetId())
		}
	}
}

func TestDepositIngestFailsClosedWhenAuthorityEvidenceMissingOrMutated(t *testing.T) {
	definition := depositTestDefinition(t, "tenant-a")
	definitionJSON, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	definitions := &depositDefinitionStore{records: []*ports.ConnectorDefinitionRecord{{
		ID:             definition.ID,
		TenantID:       definition.TenantID,
		SourceID:       definition.SourceID,
		DisplayName:    definition.DisplayName,
		Runtime:        definition.Runtime,
		Stage:          definition.Stage,
		DefinitionJSON: definitionJSON,
	}}}
	for _, tt := range []struct {
		name     string
		evidence []sourcehealth.AuthorityEvidenceRecord
	}{
		{name: "missing evidence"},
		{name: "mutated evidence", evidence: []sourcehealth.AuthorityEvidenceRecord{mutatedDepositAuthorityEvidence(t)}},
		{name: "unsigned promotion evidence", evidence: []sourcehealth.AuthorityEvidenceRecord{unsignedDepositAuthorityEvidence(t)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &ledgerRuntimeStore{
				runtimeStore: runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
					"runtime-deposit": {
						Id:       "runtime-deposit",
						SourceId: "custom_deposit",
						TenantId: "tenant-a",
						Config:   map[string]string{},
					},
				}},
				authorityEvidence: tt.evidence,
			}
			appendLog := &appendLog{}
			projector := &projector{result: ports.ProjectionResult{EntitiesProjected: 1}}
			service := New(nil, store, appendLog, projector).WithConnectorDefinitionStore(definitions)
			_, err := service.Deposit(context.Background(), DepositRequest{
				RuntimeID:      "runtime-deposit",
				SourceID:       "custom_deposit",
				TenantID:       "tenant-a",
				FamilyID:       "assets",
				IdempotencyKey: "request-1",
				OccurredAt:     time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
				Records:        []json.RawMessage{json.RawMessage(`{"id":"asset-1","name":"Asset One"}`)},
			})
			if !errors.Is(err, ErrRuntimeUnavailable) {
				t.Fatalf("Deposit() error = %v, want fail-closed runtime unavailable", err)
			}
			if len(appendLog.events) != 0 || len(projector.events) != 0 || len(store.calls) != 0 {
				t.Fatalf("deposit advanced without authority evidence: appends=%d projections=%d calls=%#v", len(appendLog.events), len(projector.events), store.calls)
			}
		})
	}
}

func depositTestDefinition(t *testing.T, tenantID string) connectordefinitions.Definition {
	t.Helper()
	definition, err := connectordefinitions.Normalize(connectordefinitions.Definition{
		TenantID:    tenantID,
		SourceID:    "custom_deposit",
		DisplayName: "Custom Deposit",
		Runtime:     connectordefinitions.RuntimeJSONAPI,
		Auth:        connectordefinitions.AuthSpec{Model: "none"},
		Ingest: connectordefinitions.IngestSpec{
			Mode: connectordefinitions.IngestModeDeposit,
			Deposit: &connectordefinitions.DepositIngestSpec{
				ResourceFamilies: []string{"assets"},
			},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:         "assets",
			Label:      "Assets",
			IDField:    "id",
			NameField:  "name",
			Event:      connectordefinitions.EventMappingSpec{Kind: "custom_deposit.assets", SchemaRef: "custom_deposit/assets/v1"},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	return definition
}

func (s *ledgerRuntimeStore) LatestSourceRuntimeAuthorityEvidence(_ context.Context, tenantID, sourceID, familyID string) (sourcehealth.AuthorityEvidenceRecord, error) {
	for i := len(s.authorityEvidence) - 1; i >= 0; i-- {
		record := s.authorityEvidence[i]
		if record.TenantID == tenantID && record.SourceID == sourceID && record.FamilyID == familyID {
			return record, nil
		}
	}
	return sourcehealth.AuthorityEvidenceRecord{}, sourcehealth.ErrAuthorityEvidenceInvalid
}

func depositAuthorityEvidence(t *testing.T) sourcehealth.AuthorityEvidenceRecord {
	t.Helper()
	stream := sourcehealth.NewAuthorityEvidenceStream()
	record, err := stream.Append(sourcehealth.AuthorityEvidenceRecord{
		TenantID:                  "tenant-a",
		SourceID:                  "custom_deposit",
		FamilyID:                  "assets",
		AuthorityEpoch:            7,
		DecisionID:                "decision-deposit-authority",
		DecisionKind:              sourcehealth.AuthorityDecisionPromote,
		InputEvidenceDigestSHA256: strings.Repeat("a", 64),
		ActorID:                   "system:cutover",
		Timestamp:                 time.Date(2026, 8, 19, 11, 55, 0, 0, time.UTC),
		ReasonCode:                "provider_proof_complete",
		AuthenticatedReceiptID:    "receipt:promotion",
	})
	if err != nil {
		t.Fatalf("append authority evidence fixture: %v", err)
	}
	return record
}

func mutatedDepositAuthorityEvidence(t *testing.T) sourcehealth.AuthorityEvidenceRecord {
	t.Helper()
	record := depositAuthorityEvidence(t)
	record.ReasonCode = "mutated_after_append"
	return record
}

func unsignedDepositAuthorityEvidence(t *testing.T) sourcehealth.AuthorityEvidenceRecord {
	t.Helper()
	record := depositAuthorityEvidence(t)
	record.AuthenticatedReceiptID = ""
	record.ReceiptSignature = ""
	record.RecordDigestSHA256 = strings.Repeat("b", 64)
	return record
}

func assertDepositOutputOmits(t *testing.T, label string, value any) {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", label, err)
	}
	if strings.Contains(string(bytes), depositSecretIdempotencyForTest) {
		t.Fatalf("%s leaked sentinel idempotency key: %s", label, string(bytes))
	}
}
