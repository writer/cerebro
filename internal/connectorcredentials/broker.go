package connectorcredentials

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	AuditEventStored    = "stored"
	AuditEventRotated   = "rotated"
	AuditEventRevoked   = "revoked"
	AuditEventUsed      = "used"
	AuditEventValidated = "validated"
)

type Broker struct {
	vault   *Vault
	transit *TransitKey
	now     func() time.Time
}

type StoreEncryptedRequest struct {
	SourceID             string
	TenantID             string
	RuntimeID            string
	CredentialStoreID    string
	AuthMethod           string
	Actor                string
	IdempotencyKey       string
	PreviousCredentialID string
	EncryptedCredentials EncryptedPayload
	ValidateFields       func(map[string]string) error
}

type StoreEncryptedResult struct {
	Record     *ports.ConnectorCredentialRecord
	References map[string]string
	Created    bool
}

type RevokeRequest struct {
	CredentialID string
	SourceID     string
	TenantID     string
	RuntimeID    string
	Actor        string
	Detail       string
}

type ValidateRequest struct {
	CredentialID string
	SourceID     string
	TenantID     string
	RuntimeID    string
	Actor        string
}

func NewBroker(vault *Vault, transit *TransitKey) *Broker {
	return &Broker{
		vault:   vault,
		transit: transit,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func (b *Broker) StoreEncrypted(ctx context.Context, request StoreEncryptedRequest) (StoreEncryptedResult, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return StoreEncryptedResult{}, ErrUnavailable
	}
	sourceID := strings.TrimSpace(request.SourceID)
	tenantID := strings.TrimSpace(request.TenantID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	credentialStoreID := strings.TrimSpace(request.CredentialStoreID)
	authMethod := strings.TrimSpace(request.AuthMethod)
	actor := strings.TrimSpace(request.Actor)
	idempotencyKey := strings.TrimSpace(request.IdempotencyKey)
	previousCredentialID := strings.TrimSpace(request.PreviousCredentialID)
	if sourceID == "" {
		return StoreEncryptedResult{}, fmt.Errorf("%w: source_id is required", ErrInvalidRequest)
	}
	if tenantID == "" {
		return StoreEncryptedResult{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if runtimeID == "" {
		return StoreEncryptedResult{}, fmt.Errorf("%w: runtime_id is required", ErrInvalidRequest)
	}
	if credentialStoreID == "" {
		credentialStoreID = "cerebro_vault"
	}
	if authMethod == "" {
		authMethod = "encrypted_submission"
	}
	if idempotencyKey != "" {
		existing, err := b.vault.store.ListConnectorCredentials(ctx, ports.ConnectorCredentialFilter{
			TenantID:       tenantID,
			SourceID:       sourceID,
			RuntimeID:      runtimeID,
			IdempotencyKey: idempotencyKey,
			Limit:          1,
		})
		if err != nil {
			return StoreEncryptedResult{}, err
		}
		if len(existing) > 0 {
			record := existing[0]
			if err := authorizeRecord(record, sourceID, tenantID, runtimeID); err != nil {
				return StoreEncryptedResult{}, err
			}
			if err := authorizeRecordStatus(record); err != nil {
				return StoreEncryptedResult{}, err
			}
			return StoreEncryptedResult{
				Record:     record,
				References: referencesForFields(record.ID, record.Fields),
				Created:    false,
			}, nil
		}
	}
	if !encryptedPayloadPresent(request.EncryptedCredentials) {
		return StoreEncryptedResult{}, fmt.Errorf("%w: encrypted_credentials is required", ErrInvalidRequest)
	}
	if b.transit == nil {
		return StoreEncryptedResult{}, ErrUnavailable
	}
	if previousCredentialID != "" {
		previous, err := b.vault.store.GetConnectorCredential(ctx, previousCredentialID)
		if err != nil {
			return StoreEncryptedResult{}, err
		}
		if err := authorizeRecord(previous, sourceID, tenantID, runtimeID); err != nil {
			return StoreEncryptedResult{}, err
		}
		if err := authorizeRecordStatus(previous); err != nil {
			return StoreEncryptedResult{}, err
		}
	}
	decrypted, err := b.transit.DecryptWithExactAdditionalData(
		request.EncryptedCredentials,
		TransitAdditionalData(request.EncryptedCredentials.KeyID, sourceID, tenantID, runtimeID, credentialStoreID),
	)
	if err != nil {
		return StoreEncryptedResult{}, err
	}
	fields, err := ParseCredentialFields(decrypted)
	if err != nil {
		return StoreEncryptedResult{}, err
	}
	if request.ValidateFields != nil {
		if err := request.ValidateFields(fields); err != nil {
			return StoreEncryptedResult{}, err
		}
	}
	record, err := b.vault.Put(ctx, PlainCredential{
		TenantID:             tenantID,
		SourceID:             sourceID,
		RuntimeID:            runtimeID,
		CredentialStoreID:    credentialStoreID,
		AuthMethod:           authMethod,
		Status:               StatusValid,
		Fields:               fields,
		CreatedBy:            actor,
		UpdatedBy:            actor,
		IdempotencyKey:       idempotencyKey,
		PreviousCredentialID: previousCredentialID,
	})
	if err != nil {
		return StoreEncryptedResult{}, err
	}
	eventType := AuditEventStored
	if previousCredentialID != "" {
		eventType = AuditEventRotated
	}
	if err := b.appendAudit(ctx, record, eventType, actor, ""); err != nil {
		return StoreEncryptedResult{}, err
	}
	return StoreEncryptedResult{
		Record:     record,
		References: referencesForFields(record.ID, SortedFieldNames(fields)),
		Created:    true,
	}, nil
}

func (b *Broker) List(ctx context.Context, filter ports.ConnectorCredentialFilter) ([]*ports.ConnectorCredentialRecord, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	return b.vault.store.ListConnectorCredentials(ctx, filter)
}

func (b *Broker) Get(ctx context.Context, credentialID string) (*ports.ConnectorCredentialRecord, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	return b.vault.store.GetConnectorCredential(ctx, credentialID)
}

func (b *Broker) Revoke(ctx context.Context, request RevokeRequest) (*ports.ConnectorCredentialRecord, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	credentialID := strings.TrimSpace(request.CredentialID)
	if credentialID == "" {
		return nil, fmt.Errorf("%w: credential_id is required", ErrInvalidRequest)
	}
	record, err := b.vault.store.GetConnectorCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if err := authorizeRecord(record, request.SourceID, request.TenantID, request.RuntimeID); err != nil {
		return nil, err
	}
	now := b.now()
	updated, err := b.vault.store.UpdateConnectorCredentialMetadata(ctx, credentialID, ports.ConnectorCredentialMetadataUpdate{
		Status:    StatusRevoked,
		UpdatedBy: strings.TrimSpace(request.Actor),
		RevokedBy: strings.TrimSpace(request.Actor),
		RevokedAt: &now,
	})
	if err != nil {
		return nil, err
	}
	if err := b.appendAudit(ctx, updated, AuditEventRevoked, request.Actor, request.Detail); err != nil {
		return nil, err
	}
	return updated, nil
}

func (b *Broker) MarkValidated(ctx context.Context, request ValidateRequest) (*ports.ConnectorCredentialRecord, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	credentialID := strings.TrimSpace(request.CredentialID)
	if credentialID == "" {
		return nil, fmt.Errorf("%w: credential_id is required", ErrInvalidRequest)
	}
	record, err := b.vault.store.GetConnectorCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if err := authorizeRecord(record, request.SourceID, request.TenantID, request.RuntimeID); err != nil {
		return nil, err
	}
	if err := authorizeRecordStatus(record); err != nil {
		return nil, err
	}
	now := b.now()
	updated, err := b.vault.store.UpdateConnectorCredentialMetadata(ctx, credentialID, ports.ConnectorCredentialMetadataUpdate{
		Status:          StatusValid,
		UpdatedBy:       strings.TrimSpace(request.Actor),
		LastValidatedAt: &now,
	})
	if err != nil {
		return nil, err
	}
	if err := b.appendAudit(ctx, updated, AuditEventValidated, request.Actor, ""); err != nil {
		return nil, err
	}
	return updated, nil
}

func (b *Broker) ResolveReferences(ctx context.Context, sourceID string, tenantID string, runtimeID string, values map[string]string) (map[string]string, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	credentialIDs := credentialIDsFromValues(values)
	resolved, err := b.vault.ResolveReferences(ctx, sourceID, tenantID, runtimeID, values)
	if err != nil {
		return nil, err
	}
	for _, credentialID := range credentialIDs {
		record, err := b.vault.store.GetConnectorCredential(ctx, credentialID)
		if err != nil {
			continue
		}
		if err := b.appendAudit(ctx, record, AuditEventUsed, "", ""); err != nil {
			continue
		}
	}
	return resolved, nil
}

func (b *Broker) AuditEvents(ctx context.Context, credentialID string, limit int) ([]*ports.ConnectorCredentialAuditRecord, error) {
	if b == nil || b.vault == nil || b.vault.store == nil {
		return nil, ErrUnavailable
	}
	return b.vault.store.ListConnectorCredentialAuditEvents(ctx, credentialID, limit)
}

func (b *Broker) appendAudit(ctx context.Context, record *ports.ConnectorCredentialRecord, eventType string, actor string, detail string) error {
	if record == nil {
		return ports.ErrConnectorCredentialNotFound
	}
	return b.vault.store.AppendConnectorCredentialAuditEvent(ctx, &ports.ConnectorCredentialAuditRecord{
		ID:           randomAuditID(),
		CredentialID: record.ID,
		TenantID:     record.TenantID,
		SourceID:     record.SourceID,
		RuntimeID:    record.RuntimeID,
		EventType:    strings.TrimSpace(eventType),
		Actor:        strings.TrimSpace(actor),
		Status:       strings.TrimSpace(record.Status),
		Detail:       strings.TrimSpace(detail),
		CreatedAt:    b.now(),
	})
}

func referencesForFields(credentialID string, fields []string) map[string]string {
	references := make(map[string]string, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			references[field] = Reference(credentialID, field)
		}
	}
	return references
}

func encryptedPayloadPresent(payload EncryptedPayload) bool {
	return strings.TrimSpace(payload.KeyID) != "" ||
		strings.TrimSpace(payload.Algorithm) != "" ||
		strings.TrimSpace(payload.WrappedKey) != "" ||
		strings.TrimSpace(payload.Nonce) != "" ||
		strings.TrimSpace(payload.Ciphertext) != ""
}

func credentialIDsFromValues(values map[string]string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		credentialID, _, ok := sourceconfig.CredentialReference(value)
		if !ok {
			continue
		}
		credentialID = strings.TrimSpace(credentialID)
		if credentialID == "" {
			continue
		}
		seen[credentialID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids
}

func randomAuditID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("credential-audit-%d", time.Now().UnixNano())
	}
	return "credential-audit-" + base64.RawURLEncoding.EncodeToString(raw[:])
}
