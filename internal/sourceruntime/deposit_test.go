package sourceruntime

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
)

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
