package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/mcpoauth"
)

func TestMCPOAuthSchemaIncludesReplaySafeState(t *testing.T) {
	joined := strings.Join(ensureMCPOAuthStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS mcp_oauth_clients",
		"CREATE TABLE IF NOT EXISTS mcp_oauth_login_states",
		"CREATE TABLE IF NOT EXISTS mcp_oauth_authorization_codes",
		"CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens",
		"state_hash BYTEA PRIMARY KEY",
		"code_hash BYTEA PRIMARY KEY",
		"token_hash BYTEA PRIMARY KEY",
		"resource TEXT NOT NULL",
		"roles_json JSONB NOT NULL DEFAULT '[]'::jsonb",
		"scopes_explicit BOOLEAN NOT NULL DEFAULT FALSE",
		"consumed_at TIMESTAMPTZ",
		"family_revoked BOOLEAN NOT NULL DEFAULT FALSE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("MCP OAuth schema missing %q:\n%s", want, joined)
		}
	}
}

func TestMCPOAuthRefreshFamilyLockKeysAreStable(t *testing.T) {
	left, right := mcpOAuthRefreshFamilyLockKeys("family-1")
	leftAgain, rightAgain := mcpOAuthRefreshFamilyLockKeys(" family-1 ")
	if left != leftAgain || right != rightAgain {
		t.Fatalf("lock keys changed after trimming: (%d,%d) vs (%d,%d)", left, right, leftAgain, rightAgain)
	}
	otherLeft, otherRight := mcpOAuthRefreshFamilyLockKeys("family-2")
	if left == otherLeft && right == otherRight {
		t.Fatalf("different refresh families share advisory lock keys: (%d,%d)", left, right)
	}
}

func TestConsumeOAuthRefreshTokenReplayRevokesFamilyIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run MCP OAuth refresh replay integration test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC().Truncate(time.Microsecond)
	familyID := "test-mcp-oauth-replay-" + now.Format("20060102150405.000000000")
	defer func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`, familyID)
	}()
	firstHash := mcpoauth.HashToken(familyID + "-refresh-1")
	secondHash := mcpoauth.HashToken(familyID + "-refresh-2")
	base := mcpoauth.RefreshToken{
		ClientID:  "droid",
		Resource:  "https://cerebro.example/api/v1/mcp",
		Subject:   "user@example.com",
		TenantID:  "writer",
		Scopes:    []string{mcpoauth.ScopeSecurityRead},
		Groups:    []string{"security"},
		FamilyID:  familyID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	first := base
	first.TokenHash = firstHash
	first.Generation = 0
	if err := store.SaveOAuthRefreshToken(ctx, first); err != nil {
		t.Fatalf("save first refresh token: %v", err)
	}
	second := base
	second.TokenHash = secondHash
	second.Generation = 1
	if err := store.SaveOAuthRefreshToken(ctx, second); err != nil {
		t.Fatalf("save second refresh token: %v", err)
	}
	if _, err := store.ConsumeOAuthRefreshToken(ctx, firstHash, now.Add(time.Minute)); err != nil {
		t.Fatalf("consume first refresh token: %v", err)
	}
	if _, err := store.ConsumeOAuthRefreshToken(ctx, firstHash, now.Add(2*time.Minute)); !errors.Is(err, mcpoauth.ErrReplay) {
		t.Fatalf("replay first refresh token error = %v, want ErrReplay", err)
	}
	if _, err := store.ConsumeOAuthRefreshToken(ctx, secondHash, now.Add(3*time.Minute)); !errors.Is(err, mcpoauth.ErrReplay) {
		t.Fatalf("consume second token after family replay error = %v, want ErrReplay", err)
	}
}

func TestSaveOAuthRefreshTokenInheritsFamilyRevocationIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run MCP OAuth refresh replay integration test")
	}
	ctx := context.Background()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC().Truncate(time.Microsecond)
	familyID := "test-mcp-oauth-revoked-save-" + now.Format("20060102150405.000000000")
	defer func() {
		_, _ = store.db.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE family_id = $1`, familyID)
	}()
	firstHash := mcpoauth.HashToken(familyID + "-refresh-1")
	secondHash := mcpoauth.HashToken(familyID + "-refresh-2")
	base := mcpoauth.RefreshToken{
		ClientID:  "droid",
		Resource:  "https://cerebro.example/api/v1/mcp",
		Subject:   "user@example.com",
		TenantID:  "writer",
		Scopes:    []string{mcpoauth.ScopeSecurityRead},
		Groups:    []string{"security"},
		FamilyID:  familyID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	first := base
	first.TokenHash = firstHash
	if err := store.SaveOAuthRefreshToken(ctx, first); err != nil {
		t.Fatalf("save first refresh token: %v", err)
	}
	if _, err := store.ConsumeOAuthRefreshToken(ctx, firstHash, now.Add(time.Minute)); err != nil {
		t.Fatalf("consume first refresh token: %v", err)
	}
	if err := store.RevokeOAuthRefreshFamily(ctx, familyID); err != nil {
		t.Fatalf("revoke refresh family: %v", err)
	}

	second := base
	second.TokenHash = secondHash
	second.Generation = 1
	if err := store.SaveOAuthRefreshToken(ctx, second); err != nil {
		t.Fatalf("save successor refresh token: %v", err)
	}
	if _, err := store.ConsumeOAuthRefreshToken(ctx, secondHash, now.Add(2*time.Minute)); !errors.Is(err, mcpoauth.ErrReplay) {
		t.Fatalf("consume successor after family revocation error = %v, want ErrReplay", err)
	}
}
