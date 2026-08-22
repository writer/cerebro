package sourceruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehealth"
	"github.com/writer/cerebro/internal/sourceops"
)

const maxDepositRecords = 100

type DepositRequest struct {
	RuntimeID       string
	SourceID        string
	TenantID        string
	FamilyID        string
	BatchID         string
	IdempotencyKey  string
	OccurredAt      time.Time
	Records         []json.RawMessage
	FullStateMarker bool
}

type DepositResponse struct {
	Runtime           *cerebrov1.SourceRuntime
	SourceID          string
	RuntimeID         string
	TenantID          string
	FamilyID          string
	Receipt           DepositReceipt
	RecordsAccepted   uint32
	RecordsRejected   uint32
	EventsAppended    uint32
	EntitiesProjected uint32
	LinksProjected    uint32
	Errors            []DepositRecordError
	authorityEvidence ports.SourceRuntimeAuthorityEvidenceRef
}

type DepositReceipt struct {
	ReceiptID            string   `json:"receipt_id"`
	AppendReceiptID      string   `json:"append_receipt_id"`
	ProjectionReceiptID  string   `json:"projection_receipt_id"`
	RecordsScanned       uint32   `json:"records_scanned"`
	RecordsAccepted      uint32   `json:"records_accepted"`
	RecordsRejected      uint32   `json:"records_rejected"`
	EventsAppended       uint32   `json:"events_appended"`
	EntitiesProjected    uint32   `json:"entities_projected"`
	LinksProjected       uint32   `json:"links_projected"`
	IdempotencyKeyDigest string   `json:"idempotency_key_digest,omitempty"`
	AuthorityDecisionID  string   `json:"authority_decision_id,omitempty"`
	AuthorityEvidenceRef string   `json:"authority_evidence_ref,omitempty"`
	ReceiptDigestSHA256  string   `json:"receipt_digest_sha256"`
	QuarantineSummary    []string `json:"quarantine_summary,omitempty"`
}

type DepositRecordError struct {
	Index         int
	SourceEventID string
	Detail        string
}

type depositAuthorityEvidenceReader interface {
	LatestSourceRuntimeAuthorityEvidence(ctx context.Context, tenantID, sourceID, familyID string) (sourcehealth.AuthorityEvidenceRecord, error)
}

func (s *Service) Deposit(ctx context.Context, req DepositRequest) (*DepositResponse, error) {
	if s == nil || s.store == nil || s.appendLog == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(req.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: runtime_id is required", ErrInvalidRequest)
	}
	runtime, err := s.lookupRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	if sourceID := strings.TrimSpace(req.SourceID); sourceID != "" && sourceID != runtime.GetSourceId() {
		return nil, fmt.Errorf("%w: source_id does not match runtime", ErrInvalidRequest)
	}
	if tenantID := strings.TrimSpace(req.TenantID); tenantID != "" && tenantID != runtime.GetTenantId() {
		return nil, fmt.Errorf("%w: tenant_id does not match runtime", ErrInvalidRequest)
	}
	if sourcehealth.RuntimeEnabledState(runtime) == "disabled" {
		return nil, fmt.Errorf("%w: source runtime is disabled", ErrInvalidRequest)
	}
	definition, err := s.lookupConnectorDefinition(ctx, runtime.GetSourceId(), runtime.GetTenantId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(definition.Ingest.Mode) != connectordefinitions.IngestModeDeposit {
		return nil, fmt.Errorf("%w: connector does not accept deposit ingest", ErrInvalidRequest)
	}
	family, err := depositDefinitionFamily(definition, req.FamilyID)
	if err != nil {
		return nil, err
	}
	records := normalizeDepositRecords(req.Records)
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: at least one deposit record is required", ErrInvalidRequest)
	}
	if len(records) > maxDepositRecords {
		return nil, fmt.Errorf("%w: deposit records must not exceed %d records", ErrInvalidRequest, maxDepositRecords)
	}
	if registrar, ok := s.projector.(connectorDefinitionProjectorRegistrar); ok {
		registrar.RegisterConnectorDefinition(definition)
	}

	response := &DepositResponse{
		Runtime:   redactRuntime(runtime),
		SourceID:  runtime.GetSourceId(),
		RuntimeID: runtime.GetId(),
		TenantID:  runtime.GetTenantId(),
		FamilyID:  family.ID,
	}
	seen := map[string]struct{}{}
	events := make([]*cerebrov1.EventEnvelope, 0, len(records))
	occurredAt := req.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	for index, record := range records {
		event, err := depositEventEnvelope(runtime, definition, family, record, depositEventOptions{
			BatchID:        req.BatchID,
			IdempotencyKey: req.IdempotencyKey,
			Index:          index,
			OccurredAt:     occurredAt,
			FullState:      req.FullStateMarker,
		})
		if err != nil {
			response.RecordsRejected++
			response.Errors = append(response.Errors, DepositRecordError{Index: index, Detail: err.Error()})
			continue
		}
		if _, duplicate := seen[event.GetId()]; duplicate {
			response.RecordsRejected++
			response.Errors = append(response.Errors, DepositRecordError{Index: index, SourceEventID: event.GetId(), Detail: "duplicate source_event_id in deposit batch"})
			continue
		}
		seen[event.GetId()] = struct{}{}
		contract := depositEventContract(definition, family)
		if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, contract); err != nil {
			response.RecordsRejected++
			response.Errors = append(response.Errors, DepositRecordError{Index: index, SourceEventID: event.GetId(), Detail: err.Error()})
			continue
		}
		events = append(events, event)
	}
	if len(events) > 0 {
		authority, err := s.depositAuthorityEvidence(ctx, runtime, family)
		if err != nil {
			return nil, err
		}
		response.Receipt.AuthorityDecisionID = authority.DecisionID
		response.Receipt.AuthorityEvidenceRef = sourcehealth.AuthorityEvidenceReceiptRef(authority)
		response.authorityEvidence = ports.SourceRuntimeAuthorityEvidenceRef{
			DecisionID: authority.DecisionID,
			Epoch:      authority.AuthorityEpoch,
		}
	}
	if batcher, ok := s.appendLog.(ports.AppendLogBatcher); ok {
		if err := s.beginDepositPageAttempt(ctx, runtime, family, events, response, req); err != nil {
			return nil, err
		}
		if err := batcher.AppendBatch(ctx, events); err != nil {
			_ = s.recordDepositRuntimeFailure(context.WithoutCancel(ctx), runtime, response, boundedUint32(len(events))+response.RecordsRejected, req.FullStateMarker, err)
			return nil, fmt.Errorf("append deposit source event batch: %w", err)
		}
		response.EventsAppended += boundedUint32(len(events))
		if err := s.markDepositPageAppended(ctx, response); err != nil {
			return nil, err
		}
	} else {
		if err := s.beginDepositPageAttempt(ctx, runtime, family, events, response, req); err != nil {
			return nil, err
		}
		for _, event := range events {
			if err := s.appendLog.Append(ctx, event); err != nil {
				_ = s.recordDepositRuntimeFailure(context.WithoutCancel(ctx), runtime, response, boundedUint32(len(events))+response.RecordsRejected, req.FullStateMarker, err)
				return nil, fmt.Errorf("append deposit source event %q: %w", event.GetId(), err)
			}
			response.EventsAppended++
		}
		if err := s.markDepositPageAppended(ctx, response); err != nil {
			return nil, err
		}
	}
	if s.projector != nil {
		for _, event := range events {
			result, err := s.projector.Project(ctx, event)
			if err != nil {
				_ = s.recordDepositRuntimeFailure(context.WithoutCancel(ctx), runtime, response, boundedUint32(len(events))+response.RecordsRejected, req.FullStateMarker, err)
				return nil, fmt.Errorf("project deposit source event %q: %w", event.GetId(), err)
			}
			response.EntitiesProjected += result.EntitiesProjected
			response.LinksProjected += result.LinksProjected
		}
	}
	if err := s.markDepositPageProjected(ctx, response); err != nil {
		return nil, err
	}
	response.RecordsAccepted = response.EventsAppended
	receipt, err := buildDepositReceipt(runtime, family, req, response)
	if err != nil {
		return nil, err
	}
	response.Receipt = receipt
	runtime.LastSyncedAt = timestamppb.Now()
	if runtime.Config == nil {
		runtime.Config = map[string]string{}
	}
	updateRuntimeSyncStatus(runtime, runtimeSyncStatus{
		Status:               "completed",
		RecordsScanned:       response.RecordsAccepted + response.RecordsRejected,
		RecordsAccepted:      response.RecordsAccepted,
		RecordsRejected:      response.RecordsRejected,
		EntitiesProjected:    response.EntitiesProjected,
		LinksProjected:       response.LinksProjected,
		CompletedAt:          runtime.GetLastSyncedAt().AsTime().UTC(),
		ContractConfigured:   true,
		ShortCircuitReason:   "deposit_ingest",
		ReconciliationReason: depositReconciliationReason(req.FullStateMarker),
	})
	if ledger, ok := s.store.(ports.SourceRuntimePageLedgerStore); ok && response.Receipt.ReceiptID != "" {
		if err := ledger.CommitSourceRuntimePage(ctx, response.Receipt.ReceiptID, runtime); err != nil {
			return nil, err
		}
	} else if err := s.store.PutSourceRuntime(ctx, runtime); err != nil {
		return nil, err
	}
	response.Runtime = redactRuntime(runtime)
	return response, nil
}

func (s *Service) beginDepositPageAttempt(ctx context.Context, runtime *cerebrov1.SourceRuntime, family connectordefinitions.ResourceFamily, events []*cerebrov1.EventEnvelope, response *DepositResponse, req DepositRequest) error {
	ledger, ok := s.store.(ports.SourceRuntimePageLedgerStore)
	if !ok || len(events) == 0 || response == nil {
		return nil
	}
	receiptID := depositReceiptID(runtime, family, req, events)
	response.Receipt.ReceiptID = receiptID
	response.Receipt.AppendReceiptID = "append:" + receiptID
	response.Receipt.ProjectionReceiptID = "projection:" + receiptID
	admission := depositPageAdmission(events, response.RecordsRejected)
	if err := ledger.BeginSourceRuntimePage(ctx, ports.SourceRuntimePageAttempt{
		AttemptID:      receiptID,
		RuntimeID:      runtime.GetId(),
		SourceID:       runtime.GetSourceId(),
		TenantID:       runtime.GetTenantId(),
		PageNumber:     1,
		RecordsScanned: boundedUint32(len(events)) + response.RecordsRejected,
		Events:         events,
		Admission:      admission,
		Authority:      response.authorityEvidence,
	}); err != nil {
		return err
	}
	return nil
}

func (s *Service) depositAuthorityEvidence(ctx context.Context, runtime *cerebrov1.SourceRuntime, family connectordefinitions.ResourceFamily) (sourcehealth.AuthorityEvidenceRecord, error) {
	reader, ok := s.store.(depositAuthorityEvidenceReader)
	if !ok {
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("%w: durable authority evidence store is required for deposit ingest", ErrRuntimeUnavailable)
	}
	record, err := reader.LatestSourceRuntimeAuthorityEvidence(ctx, runtime.GetTenantId(), runtime.GetSourceId(), family.ID)
	if err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("%w: durable authority evidence is required for deposit ingest: %w", ErrRuntimeUnavailable, err)
	}
	if err := sourcehealth.VerifyAuthorityEvidenceRecord(record); err != nil {
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("%w: durable authority evidence is invalid for deposit ingest: %w", ErrRuntimeUnavailable, err)
	}
	if sourcehealth.AuthorityEvidenceReceiptRef(record) == "" {
		return sourcehealth.AuthorityEvidenceRecord{}, fmt.Errorf("%w: durable authority evidence reference is required for deposit ingest", ErrRuntimeUnavailable)
	}
	return record, nil
}

func (s *Service) markDepositPageAppended(ctx context.Context, response *DepositResponse) error {
	ledger, ok := s.store.(ports.SourceRuntimePageLedgerStore)
	if !ok || response == nil || response.Receipt.ReceiptID == "" {
		return nil
	}
	return ledger.MarkSourceRuntimePageAppended(ctx, response.Receipt.ReceiptID)
}

func (s *Service) markDepositPageProjected(ctx context.Context, response *DepositResponse) error {
	ledger, ok := s.store.(ports.SourceRuntimePageLedgerStore)
	if !ok || response == nil || response.Receipt.ReceiptID == "" {
		return nil
	}
	return ledger.MarkSourceRuntimePageProjected(ctx, response.Receipt.ReceiptID, ports.SourceRuntimePageProjection{
		EntitiesProjected: response.EntitiesProjected,
		LinksProjected:    response.LinksProjected,
	})
}

func buildDepositReceipt(runtime *cerebrov1.SourceRuntime, family connectordefinitions.ResourceFamily, req DepositRequest, response *DepositResponse) (DepositReceipt, error) {
	if response == nil {
		return DepositReceipt{}, nil
	}
	receipt := response.Receipt
	if receipt.ReceiptID == "" {
		receipt.ReceiptID = depositReceiptID(runtime, family, req, nil)
		receipt.AppendReceiptID = "append:" + receipt.ReceiptID
		receipt.ProjectionReceiptID = "projection:" + receipt.ReceiptID
	}
	if response.EventsAppended > 0 && (strings.TrimSpace(receipt.AuthorityDecisionID) == "" || strings.TrimSpace(receipt.AuthorityEvidenceRef) == "") {
		return DepositReceipt{}, fmt.Errorf("%w: deposit receipt is missing durable authority evidence", ErrRuntimeUnavailable)
	}
	receipt.RecordsScanned = response.RecordsAccepted + response.RecordsRejected
	receipt.RecordsAccepted = response.RecordsAccepted
	receipt.RecordsRejected = response.RecordsRejected
	receipt.EventsAppended = response.EventsAppended
	receipt.EntitiesProjected = response.EntitiesProjected
	receipt.LinksProjected = response.LinksProjected
	receipt.QuarantineSummary = depositQuarantineSummary(response.Errors)
	receipt.IdempotencyKeyDigest = depositRawDigest(req.IdempotencyKey)
	receipt.ReceiptDigestSHA256 = ""
	digest, err := CanonicalSourceRuntimeDigest(receipt)
	if err == nil {
		receipt.ReceiptDigestSHA256 = digest
	}
	return receipt, nil
}

func depositReceiptID(runtime *cerebrov1.SourceRuntime, family connectordefinitions.ResourceFamily, req DepositRequest, events []*cerebrov1.EventEnvelope) string {
	eventIDs := make([]string, 0, len(events))
	for _, event := range events {
		if event != nil {
			eventIDs = append(eventIDs, event.GetId())
		}
	}
	sort.Strings(eventIDs)
	payload := map[string]any{
		"tenant_id":              runtime.GetTenantId(),
		"source_id":              runtime.GetSourceId(),
		"runtime_id":             runtime.GetId(),
		"family_id":              family.ID,
		"batch_id_digest":        depositRawDigest(req.BatchID),
		"idempotency_key_digest": depositRawDigest(req.IdempotencyKey),
		"full_state":             req.FullStateMarker,
		"event_ids":              eventIDs,
	}
	digest, err := CanonicalSourceRuntimeDigest(payload)
	if err != nil {
		sum := sha256.Sum256([]byte(strings.Join(eventIDs, ",")))
		digest = hex.EncodeToString(sum[:])
	}
	return "deposit:" + digest
}

func depositPageAdmission(events []*cerebrov1.EventEnvelope, rejected uint32) ports.SourceRuntimePageAdmission {
	eventIDs := make([]string, 0, len(events))
	for _, event := range events {
		if event != nil {
			eventIDs = append(eventIDs, event.GetId())
		}
	}
	sort.Strings(eventIDs)
	scanned := boundedUint32(len(events)) + rejected
	return ports.SourceRuntimePageAdmission{
		Kernel:          "deposit_ingest",
		ABIVersion:      1,
		Scanned:         scanned,
		Accepted:        boundedUint32(len(events)),
		Quarantined:     rejected,
		Duplicates:      0,
		ContractsSHA256: depositDigest(map[string]any{"kernel": "deposit_ingest", "version": 1}),
		ScannedSHA256:   depositDigest(map[string]any{"events": eventIDs, "rejected": rejected}),
		AcceptedSHA256:  depositDigest(eventIDs),
		ResultSHA256:    depositDigest(map[string]any{"accepted": len(events), "rejected": rejected}),
	}
}

func depositDigest(value any) string {
	digest, err := CanonicalSourceRuntimeDigest(value)
	if err != nil {
		return ""
	}
	return "sha256:" + digest
}

func depositRawDigest(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func depositQuarantineSummary(errors []DepositRecordError) []string {
	if len(errors) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, record := range errors {
		reason := "invalid_record"
		detail := strings.ToLower(record.Detail)
		switch {
		case strings.Contains(detail, "duplicate"):
			reason = "duplicate"
		case strings.Contains(detail, "required"):
			reason = "missing_required_field"
		case strings.Contains(detail, "json"):
			reason = "invalid_json"
		}
		counts[reason]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return out
}

func (s *Service) recordDepositRuntimeFailure(ctx context.Context, runtime *cerebrov1.SourceRuntime, response *DepositResponse, recordsScanned uint32, fullStateMarker bool, cause error) error {
	if s == nil || s.store == nil || runtime == nil || response == nil || cause == nil {
		return nil
	}
	if runtime.Config == nil {
		runtime.Config = map[string]string{}
	}
	updateRuntimeSyncStatus(runtime, runtimeSyncStatus{
		Status:               "failed",
		RecordsScanned:       recordsScanned,
		RecordsAccepted:      response.EventsAppended,
		RecordsRejected:      response.RecordsRejected,
		EntitiesProjected:    response.EntitiesProjected,
		LinksProjected:       response.LinksProjected,
		CompletedAt:          time.Now().UTC(),
		ContractConfigured:   true,
		ShortCircuitReason:   "deposit_ingest",
		ReconciliationReason: depositReconciliationReason(fullStateMarker),
	})
	setRuntimeConfig(runtime.Config, runtimeLastFailureCategoryConfigKey, sourceRuntimeFailureCategory(cause))
	setRuntimeConfig(runtime.Config, runtimeContractProbeStateConfigKey, contractProbeStateForRuntime(runtime, runtime.Config[runtimeLastFailureCategoryConfigKey], true))
	return s.store.PutSourceRuntime(ctx, runtime)
}

func (s *Service) lookupConnectorDefinition(ctx context.Context, sourceID string, tenantID string) (connectordefinitions.Definition, error) {
	if s == nil || s.definitionStore == nil || strings.TrimSpace(tenantID) == "" {
		return connectordefinitions.Definition{}, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, sourceID)
	}
	records, err := s.definitionStore.ListConnectorDefinitions(ctx, ports.ConnectorDefinitionFilter{TenantID: strings.TrimSpace(tenantID), Limit: 500})
	if err != nil {
		return connectordefinitions.Definition{}, err
	}
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.SourceID) != strings.TrimSpace(sourceID) {
			continue
		}
		definition := connectordefinitions.Definition{}
		if err := json.Unmarshal(record.DefinitionJSON, &definition); err != nil {
			return connectordefinitions.Definition{}, fmt.Errorf("%w: decode connector definition %q: %w", ErrInvalidRequest, record.ID, err)
		}
		definition.ID = record.ID
		definition.TenantID = record.TenantID
		definition.SourceID = record.SourceID
		definition.DisplayName = record.DisplayName
		definition.Runtime = record.Runtime
		definition.Stage = record.Stage
		return connectordefinitions.Normalize(definition)
	}
	return connectordefinitions.Definition{}, fmt.Errorf("%w: %s", sourceops.ErrSourceNotFound, sourceID)
}

func depositDefinitionFamily(definition connectordefinitions.Definition, familyID string) (connectordefinitions.ResourceFamily, error) {
	familyID = strings.TrimSpace(familyID)
	if familyID == "" && definition.Ingest.Deposit != nil && len(definition.Ingest.Deposit.ResourceFamilies) == 1 {
		familyID = definition.Ingest.Deposit.ResourceFamilies[0]
	}
	if familyID == "" && len(definition.ResourceFamilies) == 1 {
		familyID = definition.ResourceFamilies[0].ID
	}
	if familyID == "" {
		return connectordefinitions.ResourceFamily{}, fmt.Errorf("%w: family_id is required", ErrInvalidRequest)
	}
	allowed := map[string]struct{}{}
	if definition.Ingest.Deposit != nil {
		for _, value := range definition.Ingest.Deposit.ResourceFamilies {
			allowed[strings.TrimSpace(value)] = struct{}{}
		}
	}
	for _, family := range definition.ResourceFamilies {
		if strings.TrimSpace(family.ID) != familyID {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[familyID]; !ok {
				return connectordefinitions.ResourceFamily{}, fmt.Errorf("%w: family_id is not enabled for deposit ingest", ErrInvalidRequest)
			}
		}
		return family, nil
	}
	return connectordefinitions.ResourceFamily{}, fmt.Errorf("%w: family_id is not modeled by connector definition", ErrInvalidRequest)
}

type depositEventOptions struct {
	BatchID        string
	IdempotencyKey string
	Index          int
	OccurredAt     time.Time
	FullState      bool
}

func depositEventEnvelope(runtime *cerebrov1.SourceRuntime, definition connectordefinitions.Definition, family connectordefinitions.ResourceFamily, payload json.RawMessage, options depositEventOptions) (*cerebrov1.EventEnvelope, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: record payload is required", sourcecdk.ErrInvalidEventEnvelope)
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("%w: record payload must be valid JSON", sourcecdk.ErrInvalidEventEnvelope)
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("%w: decode record payload: %w", sourcecdk.ErrInvalidEventEnvelope, err)
	}
	if decoded == nil {
		return nil, fmt.Errorf("%w: record payload must be a JSON object, not null", sourcecdk.ErrInvalidEventEnvelope)
	}
	if _, ok := decoded.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: record payload must be a JSON object", sourcecdk.ErrInvalidEventEnvelope)
	}
	attributes := depositRecordAttributes(runtime, definition, family, decoded)
	if options.FullState {
		attributes["full_state_sync"] = "true"
	}
	eventID := depositEventID(runtime, family, decoded, payload, options)
	attributes["source_event_id"] = eventID
	occurredAt := options.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return &cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   runtime.GetTenantId(),
		SourceId:   runtime.GetSourceId(),
		Kind:       depositEventKind(definition.SourceID, family),
		SchemaRef:  depositSchemaRef(definition.SourceID, family),
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		Payload:    append([]byte(nil), payload...),
		Attributes: attributes,
	}, nil
}

func depositRecordAttributes(runtime *cerebrov1.SourceRuntime, definition connectordefinitions.Definition, family connectordefinitions.ResourceFamily, payload any) map[string]string {
	class := depositProjectionClass(family)
	attributes := map[string]string{
		"tenant_id":                         runtime.GetTenantId(),
		"source_system":                     definition.SourceID,
		"record_class":                      class,
		"family":                            family.ID,
		ports.EventAttributeSourceRuntimeID: runtime.GetId(),
		"resource_type":                     firstNonEmptyString(family.ID, class),
	}
	resourceID := depositPayloadFirstString(payload, family.IDField, "resource_id", "id", "uid", "key", "name")
	resourceName := depositPayloadFirstString(payload, family.NameField, "resource_name", "name", "display_name", "title", "email")
	if resourceID != "" {
		attributes["resource_id"] = resourceID
		attributes["id"] = resourceID
	}
	if resourceName != "" {
		attributes["resource_name"] = resourceName
		attributes["name"] = resourceName
	}
	if observedAt := depositPayloadFirstString(payload, family.UpdatedAtField, "observed_at", "updated_at", "last_seen_at", "created_at", "timestamp"); observedAt != "" {
		attributes["observed_at"] = observedAt
	}
	switch class {
	case "finding", "vulnerability":
		depositSetAttribute(attributes, "finding_id", depositPayloadFirstString(payload, "finding_id", family.IDField, "id"))
		depositSetAttribute(attributes, "severity", depositPayloadFirstString(payload, "severity", "risk", "priority"))
		depositSetAttribute(attributes, "status", depositPayloadFirstString(payload, "status", "state"))
		depositSetAttribute(attributes, "title", depositPayloadFirstString(payload, "title", "name", "summary"))
	case "identity_user":
		depositSetAttribute(attributes, "user_id", depositPayloadFirstString(payload, "user_id", family.IDField, "id", "uid"))
		depositSetAttribute(attributes, "email", depositPayloadFirstString(payload, "email", "primary_email", "profile.email"))
		depositSetAttribute(attributes, "display_name", depositPayloadFirstString(payload, "display_name", "name", "profile.display_name", "profile.name"))
		depositSetAttribute(attributes, "status", depositPayloadFirstString(payload, "status", "state", "lifecycle_state"))
	case "identity_group":
		depositSetAttribute(attributes, "group_id", depositPayloadFirstString(payload, "group_id", family.IDField, "id"))
		depositSetAttribute(attributes, "group_email", depositPayloadFirstString(payload, "group_email", "email"))
		depositSetAttribute(attributes, "group_name", depositPayloadFirstString(payload, "group_name", "name", "display_name"))
	case "group_membership":
		depositSetAttribute(attributes, "group_id", depositPayloadFirstString(payload, "group_id", "group.id", "groupId"))
		depositSetAttribute(attributes, "member_id", depositPayloadFirstString(payload, "member_id", "member.id", "user_id", "user.id", "id"))
		depositSetAttribute(attributes, "member_email", depositPayloadFirstString(payload, "member_email", "user_email", "email", "member.email", "user.email"))
	case "audit_event":
		depositSetAttribute(attributes, "event_type", depositPayloadFirstString(payload, "event_type", "event_name", "action", "type"))
		depositSetAttribute(attributes, "actor_id", depositPayloadFirstString(payload, "actor_id", "actor.id", "actorId", "user_id", "user.id"))
		depositSetAttribute(attributes, "actor_email", depositPayloadFirstString(payload, "actor_email", "actor.email", "email", "user.email"))
	case "secret":
		depositSetAttribute(attributes, "secret_id", depositPayloadFirstString(payload, "secret_id", family.IDField, "id", "key", "sid", "name"))
		depositSetAttribute(attributes, "secret_name", depositPayloadFirstString(payload, "secret_name", "name", "display_name", "label", "title"))
		depositSetAttribute(attributes, "secret_status", depositPayloadFirstString(payload, "secret_status", "status", "state"))
	case "policy":
		depositSetAttribute(attributes, "policy_id", depositPayloadFirstString(payload, "policy_id", family.IDField, "id", "control_id", "key", "sid"))
		depositSetAttribute(attributes, "policy_name", depositPayloadFirstString(payload, "policy_name", "name", "display_name", "title", "label"))
		depositSetAttribute(attributes, "policy_status", depositPayloadFirstString(payload, "policy_status", "status", "state", "enabled"))
	case "deployment":
		depositSetAttribute(attributes, "deployment_id", depositPayloadFirstString(payload, "deployment_id", family.IDField, "id", "name", "uid"))
		depositSetAttribute(attributes, "deployment_name", depositPayloadFirstString(payload, "deployment_name", "name", "display_name", "title", "label"))
		depositSetAttribute(attributes, "deployment_status", depositPayloadFirstString(payload, "deployment_status", "status", "state", "ready"))
	case "alert":
		depositSetAttribute(attributes, "alert_id", depositPayloadFirstString(payload, "alert_id", family.IDField, "id", "sid", "incident_id", "uuid"))
		depositSetAttribute(attributes, "alert_name", depositPayloadFirstString(payload, "alert_name", "name", "title", "summary", "subject"))
		depositSetAttribute(attributes, "alert_severity", depositPayloadFirstString(payload, "severity", "priority", "level", "risk"))
		depositSetAttribute(attributes, "alert_status", depositPayloadFirstString(payload, "status", "state", "resolved", "acknowledged"))
	}
	if family.Projection != nil {
		keys := make([]string, 0, len(family.Projection.Fields))
		for key := range family.Projection.Fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			depositSetAttribute(attributes, key, depositPayloadFirstString(payload, family.Projection.Fields[key]))
		}
	}
	return attributes
}

func depositEventContract(definition connectordefinitions.Definition, family connectordefinitions.ResourceFamily) []sourcecdk.EventContract {
	requiredAttributes := append([]string(nil), family.Event.RequiredAttributes...)
	if len(requiredAttributes) == 0 && len(family.Event.RequiredPayloadFields) == 0 {
		requiredAttributes = []string{"tenant_id", "source_event_id", "record_class", ports.EventAttributeSourceRuntimeID}
	}
	return []sourcecdk.EventContract{{
		Kind:                  depositEventKind(definition.SourceID, family),
		SchemaRef:             depositSchemaRef(definition.SourceID, family),
		RequiredAttributes:    requiredAttributes,
		RequiredPayloadFields: family.Event.RequiredPayloadFields,
	}}
}

func depositEventKind(sourceID string, family connectordefinitions.ResourceFamily) string {
	if kind := strings.TrimSpace(family.Event.Kind); kind != "" {
		return kind
	}
	if kind := strings.TrimSpace(family.EventKind); kind != "" {
		return kind
	}
	return strings.TrimSpace(sourceID) + "." + strings.TrimSpace(family.ID)
}

func depositSchemaRef(sourceID string, family connectordefinitions.ResourceFamily) string {
	if schemaRef := strings.TrimSpace(family.Event.SchemaRef); schemaRef != "" {
		return schemaRef
	}
	return strings.TrimSpace(sourceID) + "/" + strings.TrimSpace(family.ID) + "/v1"
}

func depositProjectionClass(family connectordefinitions.ResourceFamily) string {
	if family.Projection == nil {
		return "asset"
	}
	switch strings.TrimSpace(family.Projection.Template) {
	case "finding", "vulnerability", "secret", "policy", "deployment", "alert", "identity_user", "identity_group", "group_membership", "audit_event", "evidence_cas_reference":
		return strings.TrimSpace(family.Projection.Template)
	default:
		return "asset"
	}
}

func depositEventID(runtime *cerebrov1.SourceRuntime, family connectordefinitions.ResourceFamily, decoded any, payload json.RawMessage, options depositEventOptions) string {
	hash := sha256.Sum256(payload)
	stable := depositSafeCallerToken("idempotency", options.IdempotencyKey)
	if stable == "" {
		stable = depositSafeCallerToken("batch", options.BatchID)
	}
	if stable == "" {
		stable = depositPayloadFirstString(decoded, "source_event_id", "event_id")
	}
	if stable == "" {
		stable = hex.EncodeToString(hash[:12])
	}
	if options.IdempotencyKey != "" || options.BatchID != "" {
		stable = fmt.Sprintf("%s-%d", stable, options.Index)
	}
	return strings.Join([]string{
		strings.TrimSpace(runtime.GetSourceId()),
		strings.TrimSpace(runtime.GetId()),
		strings.TrimSpace(family.ID),
		sanitizeDepositEventIDSegment(stable),
	}, ":")
}

func depositSafeCallerToken(label string, value string) string {
	digest := depositRawDigest(value)
	if digest == "" {
		return ""
	}
	return strings.TrimSpace(label) + "-sha256-" + digest
}

func sanitizeDepositEventIDSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "record"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_' || r == '-' || r == '.' || r == ':':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "record"
	}
	return result
}

func depositPayloadFirstString(payload any, paths ...string) string {
	for _, rawPath := range paths {
		for _, path := range strings.Split(rawPath, "|") {
			value := depositPayloadString(payload, strings.TrimSpace(path))
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func depositPayloadString(payload any, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, ".")
	current := payload
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return ""
		}
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		next, ok := object[part]
		if !ok {
			return ""
		}
		current = next
	}
	switch value := current.(type) {
	case string:
		return strings.TrimSpace(value)
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	case bool:
		return fmt.Sprintf("%t", value)
	default:
		return ""
	}
}

func depositSetAttribute(attributes map[string]string, key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key != "" && value != "" {
		attributes[key] = value
	}
}

func normalizeDepositRecords(records []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(records))
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		out = append(out, append(json.RawMessage(nil), record...))
	}
	return out
}

func depositReconciliationReason(fullState bool) string {
	if fullState {
		return "deposit_full_state"
	}
	return "deposit_delta"
}
