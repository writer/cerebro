package identitysso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// BootstrapActor is recorded as updatedBy on connections and policies written
// from stack configuration.
const BootstrapActor = "bootstrap"

// ErrBootstrapManaged marks admin writes refused because stack configuration
// owns the connection or policy setting. It maps to HTTP 409.
var ErrBootstrapManaged = errors.New("bootstrap_managed")

// Bootstrap is a validated stack-configured SSO connection, and optionally
// policy, seeded into the identity store at startup so the console can sign
// in before any admin has configured SSO.
type Bootstrap struct {
	TenantID   string
	Connection ports.SSOConnection
	Policy     *BootstrapPolicy
}

// BootstrapPolicy holds the policy fields stack configuration sets. Nil fields
// keep the stored (or default) value.
type BootstrapPolicy struct {
	Enforced                  *bool `json:"enforced"`
	SessionMaxLifetimeMinutes *int  `json:"sessionMaxLifetimeMinutes"`
	SessionIdleTimeoutMinutes *int  `json:"sessionIdleTimeoutMinutes"`
}

type bootstrapDocument struct {
	TenantID   string                  `json:"tenantId"`
	Connection *bootstrapConnectionDoc `json:"connection"`
	Policy     *BootstrapPolicy        `json:"policy"`
}

type bootstrapConnectionDoc struct {
	ID string `json:"id"`
	ConnectionInput
}

// ParseBootstrap decodes and validates a bootstrap document. The connection
// goes through the same normalization as the admin API, so only secret
// references are accepted and roles must be known Cerebro roles. Unknown
// fields are rejected so a misspelled key (for example a raw clientSecret)
// fails loudly instead of being ignored.
func ParseBootstrap(raw []byte) (*Bootstrap, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc bootstrapDocument
	if err := decoder.Decode(&doc); err != nil {
		return nil, invalid("bootstrap must be a single JSON object: %v", err)
	}
	if decoder.More() {
		return nil, invalid("bootstrap must be a single JSON object")
	}
	tenantID := strings.TrimSpace(doc.TenantID)
	if err := checkToken("tenantId", tenantID, maxNameLength); err != nil {
		return nil, err
	}
	if doc.Connection == nil {
		return nil, invalid("connection is required")
	}
	id := strings.TrimSpace(doc.Connection.ID)
	if !ValidResourceID(id) {
		return nil, invalid("connection.id must be 1 to 64 characters of letters, digits, '_' or '-'")
	}
	switch strings.ToLower(strings.TrimSpace(doc.Connection.Status)) {
	case "", StatusActive:
	default:
		return nil, invalid("connection.status must be omitted or active; bootstrap connections are always active")
	}
	input := doc.Connection.ConnectionInput
	input.Status = StatusActive
	input.UpdatedBy = BootstrapActor
	conn, err := NormalizeConnectionInput(input)
	if err != nil {
		return nil, err
	}
	conn.TenantID = tenantID
	conn.ID = id
	bootstrap := &Bootstrap{TenantID: tenantID, Connection: conn, Policy: doc.Policy}
	if doc.Policy != nil {
		if _, err := bootstrap.applyPolicy(DefaultPolicy()); err != nil {
			return nil, err
		}
	}
	return bootstrap, nil
}

// ManagesConnection reports whether stack configuration owns the connection.
func (b *Bootstrap) ManagesConnection(tenantID string, connectionID string) bool {
	return b != nil && b.TenantID == tenantID && b.Connection.ID == connectionID
}

// EnforcesPolicy reports whether stack configuration requires the tenant
// policy to stay enforced.
func (b *Bootstrap) EnforcesPolicy(tenantID string) bool {
	return b != nil && b.TenantID == tenantID && b.Policy != nil && b.Policy.Enforced != nil && *b.Policy.Enforced
}

func (b *Bootstrap) applyPolicy(current ports.SSOPolicy) (ports.SSOPolicy, error) {
	next := current
	if b.Policy.Enforced != nil {
		next.Enforced = *b.Policy.Enforced
	}
	if b.Policy.SessionMaxLifetimeMinutes != nil {
		next.SessionMaxLifetimeMinutes = *b.Policy.SessionMaxLifetimeMinutes
	}
	if b.Policy.SessionIdleTimeoutMinutes != nil {
		next.SessionIdleTimeoutMinutes = *b.Policy.SessionIdleTimeoutMinutes
	}
	for _, field := range []struct {
		name  string
		value *int
	}{
		{"policy.sessionMaxLifetimeMinutes", b.Policy.SessionMaxLifetimeMinutes},
		{"policy.sessionIdleTimeoutMinutes", b.Policy.SessionIdleTimeoutMinutes},
	} {
		if field.value != nil && *field.value == 0 {
			return next, invalid("%s must not be 0; omit it to keep the current value", field.name)
		}
	}
	next.UpdatedBy = BootstrapActor
	return NormalizePolicy(next)
}

// SeedBootstrap writes the bootstrap connection as active and, when present,
// the bootstrap policy. Stack configuration is the source of truth, so the
// connection's configured fields are overwritten on every call while
// createdAt, sessions, SCIM tokens, and directory records are preserved. It is
// safe to run concurrently from several processes: the store serializes
// connection writes per tenant and every writer converges on the same values.
func SeedBootstrap(ctx context.Context, store ports.SSOConnectionStore, bootstrap *Bootstrap, now time.Time) error {
	if bootstrap == nil {
		return nil
	}
	if store == nil {
		return errors.New("identity sso bootstrap requires an identity sso state store")
	}
	now = now.UTC()
	desired := bootstrap.Connection
	desired.TenantID = bootstrap.TenantID
	desired.Status = StatusActive
	desired.UpdatedBy = BootstrapActor
	desired.CreatedAt = now
	desired.UpdatedAt = now
	desired.LastTest = nil
	existing, err := store.GetSSOConnection(ctx, bootstrap.TenantID, desired.ID)
	if err != nil && !errors.Is(err, ports.ErrSSOConnectionNotFound) {
		return fmt.Errorf("load bootstrap sso connection %q: %w", desired.ID, err)
	}
	write := true
	if existing != nil {
		desired.CreatedAt = existing.CreatedAt
		if !ProtocolChanged(*existing, desired) {
			desired.LastTest = existing.LastTest
		}
		unchanged := desired
		unchanged.UpdatedAt = existing.UpdatedAt
		write = !reflect.DeepEqual(unchanged, *existing)
	}
	if write {
		if err := store.PutSSOConnection(ctx, &desired, MaxConnections); err != nil {
			return bootstrapWriteError(desired.ID, err)
		}
	}
	if bootstrap.Policy == nil {
		return nil
	}
	current := DefaultPolicy()
	stored, err := store.GetSSOPolicy(ctx, bootstrap.TenantID)
	switch {
	case errors.Is(err, ports.ErrSSOPolicyNotFound):
	case err != nil:
		return fmt.Errorf("load bootstrap sso policy: %w", err)
	default:
		current = *stored
	}
	policy, err := bootstrap.applyPolicy(current)
	if err != nil {
		return fmt.Errorf("apply bootstrap sso policy to stored policy: %w", err)
	}
	policy.TenantID = bootstrap.TenantID
	if stored != nil && policy.Enforced == stored.Enforced &&
		policy.SessionMaxLifetimeMinutes == stored.SessionMaxLifetimeMinutes &&
		policy.SessionIdleTimeoutMinutes == stored.SessionIdleTimeoutMinutes {
		return nil
	}
	policy.UpdatedAt = now
	if err := store.PutSSOPolicy(ctx, &policy); err != nil {
		return fmt.Errorf("write bootstrap sso policy: %w", err)
	}
	return nil
}

// SeedConfiguredBootstrap seeds the bootstrap before the server accepts
// requests, so the console can sign in without an admin having configured SSO.
// Any failure stops startup rather than serving a console nobody can log in to.
func SeedConfiguredBootstrap(ctx context.Context, stateStore any, bootstrap *Bootstrap) error {
	if bootstrap == nil {
		return nil
	}
	store, ok := stateStore.(ports.SSOConnectionStore)
	if value := reflect.ValueOf(store); !ok || store == nil || (value.Kind() == reflect.Pointer && value.IsNil()) {
		return errors.New("identity sso bootstrap: CEREBRO_IDENTITY_SSO_BOOTSTRAP_JSON is set but no identity sso capable state store is configured")
	}
	if ctx == nil {
		return errors.New("identity sso bootstrap requires a bootstrap context")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := SeedBootstrap(ctx, store, bootstrap, time.Now()); err != nil {
		return fmt.Errorf("identity sso bootstrap: %w", err)
	}
	return nil
}

func bootstrapWriteError(connectionID string, err error) error {
	switch {
	case errors.Is(err, ports.ErrSSODomainConflict):
		return fmt.Errorf("bootstrap sso connection %q conflicts with an existing connection; remove the domain from the other connection or from the bootstrap config: %w", connectionID, err)
	case errors.Is(err, ports.ErrSSOConnectionLimit):
		return fmt.Errorf("bootstrap sso connection %q cannot be created because the tenant already has %d connections: %w", connectionID, MaxConnections, err)
	default:
		return fmt.Errorf("write bootstrap sso connection %q: %w", connectionID, err)
	}
}
