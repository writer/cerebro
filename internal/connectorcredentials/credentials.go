package connectorcredentials

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	transitAlgorithm = "RSA-OAEP-256+A256GCM"
	rsaOAEPAlgorithm = "RSA-OAEP-256"
	sealedAlgorithm  = "AES-256-GCM"

	StatusPending  = "pending"
	StatusValid    = "valid"
	StatusInvalid  = "invalid"
	StatusRevoked  = "revoked"
	StatusRotating = "rotating"

	credentialUseTrackingInterval = time.Hour
)

var (
	ErrUnavailable    = errors.New("connector credentials are unavailable")
	ErrInvalidRequest = errors.New("invalid connector credential request")
)

type EncryptedPayload struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	WrappedKey string `json:"wrapped_key,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Ciphertext string `json:"ciphertext"`
}

type PublicKey struct {
	KeyID     string         `json:"key_id"`
	Algorithm string         `json:"algorithm"`
	JWK       map[string]any `json:"jwk"`
}

type TransitKey struct {
	keyID   string
	private *rsa.PrivateKey
}

type Vault struct {
	store ports.ConnectorCredentialStore
	key   []byte
	keyID string
}

type PlainCredential struct {
	ID                   string
	TenantID             string
	SourceID             string
	RuntimeID            string
	CredentialStoreID    string
	AuthMethod           string
	Status               string
	CreatedBy            string
	UpdatedBy            string
	IdempotencyKey       string
	PreviousCredentialID string
	Fields               map[string]string
}

type sealedCredential struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type credentialPlaintext struct {
	Fields map[string]string `json:"fields"`
}

func NewTransitKey() (*TransitKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("%w: generate transit key: %w", ErrUnavailable, err)
	}
	return newTransitKey(private)
}

func NewTransitKeyFromPEM(keyMaterial string) (*TransitKey, error) {
	private, err := parseTransitPrivateKey([]byte(strings.TrimSpace(keyMaterial)))
	if err != nil {
		return nil, err
	}
	return newTransitKey(private)
}

func newTransitKey(private *rsa.PrivateKey) (*TransitKey, error) {
	if private == nil {
		return nil, fmt.Errorf("%w: connector credential transit key is required", ErrUnavailable)
	}
	if private.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%w: connector credential transit key must be at least 2048 bits", ErrUnavailable)
	}
	if err := private.Validate(); err != nil {
		return nil, fmt.Errorf("%w: invalid connector credential transit key", ErrUnavailable)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal transit key: %w", ErrUnavailable, err)
	}
	sum := sha256.Sum256(der)
	return &TransitKey{
		keyID:   "connector-transit-" + hex.EncodeToString(sum[:8]),
		private: private,
	}, nil
}

func parseTransitPrivateKey(material []byte) (*rsa.PrivateKey, error) {
	material = bytes.TrimSpace(material)
	if len(material) == 0 {
		return nil, fmt.Errorf("%w: CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY is required", ErrUnavailable)
	}
	if !bytes.Contains(material, []byte("-----BEGIN ")) {
		if decoded, ok := decodeTransitKeyMaterial(material); ok {
			material = bytes.TrimSpace(decoded)
		}
	}
	block, _ := pem.Decode(material)
	if block == nil {
		return nil, fmt.Errorf("%w: parse connector credential transit private key", ErrUnavailable)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse connector credential transit private key", ErrUnavailable)
		}
		return private, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse connector credential transit private key", ErrUnavailable)
		}
		private, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: connector credential transit private key must be RSA", ErrUnavailable)
		}
		return private, nil
	default:
		return nil, fmt.Errorf("%w: connector credential transit private key must be RSA PEM", ErrUnavailable)
	}
}

func decodeTransitKeyMaterial(material []byte) ([]byte, bool) {
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(string(material))
		if err == nil && bytes.Contains(decoded, []byte("-----BEGIN ")) {
			return decoded, true
		}
	}
	return nil, false
}

func (k *TransitKey) PublicKey() PublicKey {
	if k == nil || k.private == nil {
		return PublicKey{Algorithm: transitAlgorithm}
	}
	return PublicKey{
		KeyID:     k.keyID,
		Algorithm: transitAlgorithm,
		JWK: map[string]any{
			"kty":     "RSA",
			"kid":     k.keyID,
			"alg":     rsaOAEPAlgorithm,
			"use":     "enc",
			"key_ops": []string{"encrypt"},
			"ext":     true,
			"n":       base64.RawURLEncoding.EncodeToString(k.private.N.Bytes()),
			"e":       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.private.PublicKey.E)).Bytes()),
		},
	}
}

func (k *TransitKey) Decrypt(payload EncryptedPayload) ([]byte, error) {
	return k.DecryptWithAdditionalData(payload, nil)
}

func (k *TransitKey) DecryptWithAdditionalData(payload EncryptedPayload, additionalData []byte) ([]byte, error) {
	return k.decryptWithAdditionalData(payload, additionalData)
}

func (k *TransitKey) DecryptWithExactAdditionalData(payload EncryptedPayload, additionalData []byte) ([]byte, error) {
	if len(additionalData) == 0 {
		return nil, fmt.Errorf("%w: credential payload context is required", ErrInvalidRequest)
	}
	return k.decryptWithAdditionalData(payload, additionalData)
}

func (k *TransitKey) decryptWithAdditionalData(payload EncryptedPayload, additionalData []byte) ([]byte, error) {
	if k == nil || k.private == nil {
		return nil, fmt.Errorf("%w: transit key is not configured", ErrUnavailable)
	}
	if strings.TrimSpace(payload.KeyID) != k.keyID {
		return nil, fmt.Errorf("%w: unknown transit key", ErrInvalidRequest)
	}
	algorithm := strings.TrimSpace(payload.Algorithm)
	if strings.EqualFold(algorithm, transitAlgorithm) {
		if len(additionalData) == 0 {
			return nil, fmt.Errorf("%w: credential payload context is required", ErrInvalidRequest)
		}
		return k.decryptHybrid(payload, additionalData)
	}
	return nil, fmt.Errorf("%w: unsupported credential transport algorithm", ErrInvalidRequest)
}

func (k *TransitKey) decryptHybrid(payload EncryptedPayload, additionalData []byte) ([]byte, error) {
	wrappedKey, err := decodeBase64(payload.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode wrapped credential key: %w", ErrInvalidRequest, err)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k.private, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap credential key", ErrInvalidRequest)
	}
	nonce, err := decodeBase64(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: decode credential nonce: %w", ErrInvalidRequest, err)
	}
	ciphertext, err := decodeBase64(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: decode credential ciphertext: %w", ErrInvalidRequest, err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize credential payload cipher: %w", ErrInvalidRequest, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize credential payload cipher: %w", ErrInvalidRequest, err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt credential payload", ErrInvalidRequest)
	}
	return plaintext, nil
}

func NewVault(store ports.ConnectorCredentialStore, keyMaterial string) (*Vault, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: credential store is not configured", ErrUnavailable)
	}
	keyMaterial = strings.TrimSpace(keyMaterial)
	if keyMaterial == "" {
		return nil, fmt.Errorf("%w: CEREBRO_CONNECTOR_CREDENTIAL_KEY is required", ErrUnavailable)
	}
	key := normalizeVaultKey(keyMaterial)
	sum := sha256.Sum256([]byte(keyMaterial))
	return &Vault{
		store: store,
		key:   key,
		keyID: "connector-vault-" + hex.EncodeToString(sum[:8]),
	}, nil
}

func (v *Vault) Put(ctx context.Context, credential PlainCredential) (*ports.ConnectorCredentialRecord, error) {
	if v == nil || v.store == nil {
		return nil, ErrUnavailable
	}
	normalized, err := normalizeCredential(credential)
	if err != nil {
		return nil, err
	}
	sealed, err := v.seal(normalized)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	record := &ports.ConnectorCredentialRecord{
		ID:                   normalized.ID,
		TenantID:             normalized.TenantID,
		SourceID:             normalized.SourceID,
		RuntimeID:            normalized.RuntimeID,
		CredentialStoreID:    normalized.CredentialStoreID,
		AuthMethod:           normalized.AuthMethod,
		Status:               normalized.Status,
		KeyID:                v.keyID,
		Fields:               SortedFieldNames(normalized.Fields),
		Sealed:               sealed,
		CreatedBy:            normalized.CreatedBy,
		UpdatedBy:            normalized.UpdatedBy,
		IdempotencyKey:       normalized.IdempotencyKey,
		PreviousCredentialID: normalized.PreviousCredentialID,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := v.store.PutConnectorCredential(ctx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (v *Vault) ResolveReferences(ctx context.Context, sourceID string, tenantID string, runtimeID string, values map[string]string) (map[string]string, error) {
	if values == nil {
		return map[string]string{}, nil
	}
	resolved := make(map[string]string, len(values))
	for key, value := range values {
		resolved[key] = value
	}
	cache := map[string]map[string]string{}
	for key, value := range values {
		credentialID, field, ok := sourceconfig.CredentialReference(value)
		if !ok {
			continue
		}
		fields, ok := cache[credentialID]
		if !ok {
			record, err := v.store.GetConnectorCredential(ctx, credentialID)
			if err != nil {
				return nil, err
			}
			if err := authorizeRecord(record, sourceID, tenantID, runtimeID); err != nil {
				return nil, err
			}
			if err := authorizeRecordStatus(record); err != nil {
				return nil, err
			}
			fields, err = v.open(record)
			if err != nil {
				return nil, err
			}
			cache[credentialID] = fields
		}
		secret, ok := fields[field]
		if !ok {
			return nil, fmt.Errorf("%w: connector credential field %q is missing", ErrInvalidRequest, field)
		}
		resolved[key] = secret
	}
	return resolved, nil
}

func Reference(id string, field string) string {
	return sourceconfig.CredentialReferenceValue(id, field)
}

func TransitAdditionalData(keyID string, sourceID string, tenantID string, runtimeID string, credentialStoreID string) []byte {
	parts := []string{
		"connector-credential",
		"v1",
		strings.TrimSpace(keyID),
		strings.TrimSpace(sourceID),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(credentialStoreID),
	}
	return []byte(strings.Join(parts, "\x00"))
}

func ParseCredentialFields(data []byte) (map[string]string, error) {
	var wrapped struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Fields) > 0 {
		return normalizeFields(wrapped.Fields)
	}
	var direct map[string]string
	if err := json.Unmarshal(data, &direct); err != nil {
		return nil, fmt.Errorf("%w: decode credential payload: %w", ErrInvalidRequest, err)
	}
	return normalizeFields(direct)
}

func SortedFieldNames(fields map[string]string) []string {
	names := make([]string, 0, len(fields))
	for key := range fields {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}

func normalizeCredential(input PlainCredential) (PlainCredential, error) {
	credential := PlainCredential{
		ID:                   strings.TrimSpace(input.ID),
		TenantID:             strings.TrimSpace(input.TenantID),
		SourceID:             strings.TrimSpace(input.SourceID),
		RuntimeID:            strings.TrimSpace(input.RuntimeID),
		CredentialStoreID:    strings.TrimSpace(input.CredentialStoreID),
		AuthMethod:           strings.TrimSpace(input.AuthMethod),
		Status:               strings.TrimSpace(input.Status),
		CreatedBy:            strings.TrimSpace(input.CreatedBy),
		UpdatedBy:            strings.TrimSpace(input.UpdatedBy),
		IdempotencyKey:       strings.TrimSpace(input.IdempotencyKey),
		PreviousCredentialID: strings.TrimSpace(input.PreviousCredentialID),
	}
	if credential.ID == "" {
		id, err := randomCredentialID()
		if err != nil {
			return PlainCredential{}, err
		}
		credential.ID = id
	}
	if !validReferencePart(credential.ID) {
		return PlainCredential{}, fmt.Errorf("%w: connector credential id is invalid", ErrInvalidRequest)
	}
	if credential.TenantID == "" {
		return PlainCredential{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if credential.SourceID == "" {
		return PlainCredential{}, fmt.Errorf("%w: source_id is required", ErrInvalidRequest)
	}
	if credential.RuntimeID == "" {
		return PlainCredential{}, fmt.Errorf("%w: runtime_id is required", ErrInvalidRequest)
	}
	if credential.CredentialStoreID == "" {
		credential.CredentialStoreID = "cerebro_vault"
	}
	if credential.AuthMethod == "" {
		credential.AuthMethod = "encrypted_submission"
	}
	if credential.Status == "" {
		credential.Status = StatusValid
	}
	if !validCredentialStatus(credential.Status) {
		return PlainCredential{}, fmt.Errorf("%w: connector credential status is invalid", ErrInvalidRequest)
	}
	if credential.UpdatedBy == "" {
		credential.UpdatedBy = credential.CreatedBy
	}
	fields, err := normalizeFields(input.Fields)
	if err != nil {
		return PlainCredential{}, err
	}
	credential.Fields = fields
	return credential, nil
}

func validCredentialStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case StatusPending, StatusValid, StatusInvalid, StatusRevoked, StatusRotating:
		return true
	default:
		return false
	}
}

func normalizeFields(input map[string]string) (map[string]string, error) {
	fields := make(map[string]string, len(input))
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if !validReferencePart(trimmedKey) {
			return nil, fmt.Errorf("%w: connector credential field %q is invalid", ErrInvalidRequest, trimmedKey)
		}
		if strings.TrimSpace(value) == "" && sourceconfig.SensitiveKey(trimmedKey) {
			return nil, fmt.Errorf("%w: connector credential field %q is empty", ErrInvalidRequest, trimmedKey)
		}
		fields[trimmedKey] = value
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: at least one credential field is required", ErrInvalidRequest)
	}
	return fields, nil
}

func validReferencePart(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_' || char == '-' || char == '.':
		default:
			return false
		}
	}
	return true
}

func randomCredentialID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("%w: generate credential id: %w", ErrUnavailable, err)
	}
	return "cred_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func normalizeVaultKey(raw string) []byte {
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func (v *Vault) seal(credential PlainCredential) ([]byte, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize connector credential vault: %w", ErrUnavailable, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize connector credential vault: %w", ErrUnavailable, err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: generate connector credential nonce: %w", ErrUnavailable, err)
	}
	plaintext, err := json.Marshal(credentialPlaintext{Fields: credential.Fields})
	if err != nil {
		return nil, fmt.Errorf("%w: encode connector credential fields: %w", ErrInvalidRequest, err)
	}
	aad := credentialAAD(credential.ID, credential.TenantID, credential.SourceID, credential.RuntimeID, v.keyID)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return json.Marshal(sealedCredential{
		Algorithm:  sealedAlgorithm,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func (v *Vault) open(record *ports.ConnectorCredentialRecord) (map[string]string, error) {
	if v == nil {
		return nil, ErrUnavailable
	}
	if record == nil {
		return nil, ports.ErrConnectorCredentialNotFound
	}
	if strings.TrimSpace(record.KeyID) != v.keyID {
		return nil, fmt.Errorf("%w: connector credential key is unavailable", ErrUnavailable)
	}
	var sealed sealedCredential
	if err := json.Unmarshal(record.Sealed, &sealed); err != nil {
		return nil, fmt.Errorf("%w: decode connector credential envelope: %w", ErrUnavailable, err)
	}
	if sealed.Algorithm != sealedAlgorithm {
		return nil, fmt.Errorf("%w: unsupported connector credential envelope", ErrUnavailable)
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: decode connector credential nonce: %w", ErrUnavailable, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: decode connector credential ciphertext: %w", ErrUnavailable, err)
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize connector credential vault: %w", ErrUnavailable, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize connector credential vault: %w", ErrUnavailable, err)
	}
	aad := credentialAAD(record.ID, record.TenantID, record.SourceID, record.RuntimeID, record.KeyID)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: open connector credential", ErrUnavailable)
	}
	var decoded credentialPlaintext
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		return nil, fmt.Errorf("%w: decode connector credential fields: %w", ErrUnavailable, err)
	}
	return normalizeFields(decoded.Fields)
}

func authorizeRecord(record *ports.ConnectorCredentialRecord, sourceID string, tenantID string, runtimeID string) error {
	if record == nil {
		return ports.ErrConnectorCredentialNotFound
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" && strings.TrimSpace(record.TenantID) != tenantID {
		return fmt.Errorf("%w: connector credential tenant mismatch", ErrInvalidRequest)
	}
	if sourceID = strings.TrimSpace(sourceID); sourceID != "" && strings.TrimSpace(record.SourceID) != sourceID {
		return fmt.Errorf("%w: connector credential source mismatch", ErrInvalidRequest)
	}
	if runtimeID = strings.TrimSpace(runtimeID); runtimeID != "" && strings.TrimSpace(record.RuntimeID) != runtimeID {
		return fmt.Errorf("%w: connector credential runtime mismatch", ErrInvalidRequest)
	}
	return nil
}

func authorizeRecordStatus(record *ports.ConnectorCredentialRecord) error {
	if record == nil {
		return ports.ErrConnectorCredentialNotFound
	}
	switch strings.TrimSpace(record.Status) {
	case "", StatusValid, StatusRotating:
		return nil
	case StatusRevoked:
		return fmt.Errorf("%w: connector credential is revoked", ErrInvalidRequest)
	default:
		return fmt.Errorf("%w: connector credential is not usable", ErrInvalidRequest)
	}
}

func credentialAAD(id string, tenantID string, sourceID string, runtimeID string, keyID string) []byte {
	return []byte(strings.Join([]string{
		strings.TrimSpace(id),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(sourceID),
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(keyID),
	}, "\x00"))
}

func decodeBase64(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func TimestampOrZero(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
