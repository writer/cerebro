package deviceauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemStoreBootstrapTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	plaintext, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatalf("GenerateOpaqueToken: %v", err)
	}
	hash := HashToken(plaintext)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	token := BootstrapToken{
		TokenID:      "btk-1",
		TokenHash:    hash,
		HardwareUUID: "hw-1",
		TenantID:     "writer",
		Scopes:       []string{"platform.devices.enroll"},
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
	}
	if err := store.CreateBootstrapToken(ctx, token); err != nil {
		t.Fatalf("CreateBootstrapToken: %v", err)
	}

	consumed, err := store.ConsumeBootstrapToken(ctx, hash, "hw-1", now.Add(time.Minute), "agent")
	if err != nil {
		t.Fatalf("first ConsumeBootstrapToken: %v", err)
	}
	if consumed.TokenID != "btk-1" {
		t.Errorf("token id = %q, want btk-1", consumed.TokenID)
	}

	if _, err := store.ConsumeBootstrapToken(ctx, hash, "hw-1", now.Add(2*time.Minute), "agent"); !errors.Is(err, ErrBootstrapTokenConsumed) {
		t.Fatalf("second ConsumeBootstrapToken err = %v, want ErrBootstrapTokenConsumed", err)
	}
}

func TestMemStoreBootstrapTokenRejectsExpired(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	plaintext, _ := GenerateOpaqueToken()
	hash := HashToken(plaintext)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	_ = store.CreateBootstrapToken(ctx, BootstrapToken{
		TokenID: "btk-1", TokenHash: hash, HardwareUUID: "hw-1", TenantID: "writer",
		CreatedAt: now, ExpiresAt: now.Add(-time.Minute),
	})
	if _, err := store.ConsumeBootstrapToken(ctx, hash, "hw-1", now, "agent"); !errors.Is(err, ErrBootstrapTokenExpired) {
		t.Fatalf("ConsumeBootstrapToken err = %v, want ErrBootstrapTokenExpired", err)
	}
}

func TestMemStoreBootstrapTokenRejectsHardwareMismatch(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	plaintext, _ := GenerateOpaqueToken()
	hash := HashToken(plaintext)
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	_ = store.CreateBootstrapToken(ctx, BootstrapToken{
		TokenID: "btk-1", TokenHash: hash, HardwareUUID: "hw-1", TenantID: "writer",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := store.ConsumeBootstrapToken(ctx, hash, "hw-DIFFERENT", now, "agent"); !errors.Is(err, ErrBootstrapTokenMismatch) {
		t.Fatalf("ConsumeBootstrapToken err = %v, want ErrBootstrapTokenMismatch", err)
	}
}

func TestMemStoreRefreshRotation(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	if _, err := store.EnrollDevice(ctx, DeviceRecord{
		DeviceID: "dev-1", HardwareUUID: "hw-1", TenantID: "writer",
		Status: "active", EnrolledAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatalf("EnrollDevice: %v", err)
	}

	plaintext1, _ := GenerateOpaqueToken()
	hash1 := HashToken(plaintext1)
	familyID, _ := NewFamilyID()
	if err := store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash:  hash1,
		DeviceID:   "dev-1",
		FamilyID:   familyID,
		Generation: 1,
		Scopes:     []string{"platform.telemetry.ingest"},
		CreatedAt:  now,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	consumed, err := store.ConsumeRefreshToken(ctx, hash1, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("first ConsumeRefreshToken: %v", err)
	}
	if consumed.Generation != 1 {
		t.Errorf("generation = %d, want 1", consumed.Generation)
	}

	plaintext2, _ := GenerateOpaqueToken()
	hash2 := HashToken(plaintext2)
	if err := store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash:  hash2,
		DeviceID:   "dev-1",
		FamilyID:   familyID,
		Generation: consumed.Generation + 1,
		CreatedAt:  now.Add(time.Hour),
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("IssueRefreshToken gen 2: %v", err)
	}

	if _, err := store.ConsumeRefreshToken(ctx, hash2, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("ConsumeRefreshToken gen 2: %v", err)
	}
}

func TestMemStoreRefreshReplayRevokesFamily(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	_, _ = store.EnrollDevice(ctx, DeviceRecord{
		DeviceID: "dev-1", TenantID: "writer", Status: "active", EnrolledAt: now, LastSeenAt: now,
	})

	familyID, _ := NewFamilyID()
	plaintext1, _ := GenerateOpaqueToken()
	hash1 := HashToken(plaintext1)
	plaintext2, _ := GenerateOpaqueToken()
	hash2 := HashToken(plaintext2)

	_ = store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash: hash1, DeviceID: "dev-1", FamilyID: familyID, Generation: 1,
		CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	})
	_ = store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash: hash2, DeviceID: "dev-1", FamilyID: familyID, Generation: 2,
		CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	})

	if _, err := store.ConsumeRefreshToken(ctx, hash1, now.Add(time.Hour)); err != nil {
		t.Fatalf("first consume gen 1: %v", err)
	}
	if _, err := store.ConsumeRefreshToken(ctx, hash1, now.Add(2*time.Hour)); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("replay of gen 1 err = %v, want ErrRefreshReplay", err)
	}
	if _, err := store.ConsumeRefreshToken(ctx, hash2, now.Add(3*time.Hour)); !errors.Is(err, ErrRefreshReplay) {
		t.Fatalf("post-replay consume of gen 2 err = %v, want ErrRefreshReplay (family revoked)", err)
	}
}

func TestMemStoreRefreshRejectsRevokedDevice(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	_, _ = store.EnrollDevice(ctx, DeviceRecord{
		DeviceID: "dev-1", TenantID: "writer", Status: "active", EnrolledAt: now, LastSeenAt: now,
	})
	plaintext, _ := GenerateOpaqueToken()
	hash := HashToken(plaintext)
	familyID, _ := NewFamilyID()
	_ = store.IssueRefreshToken(ctx, RefreshToken{
		TokenHash: hash, DeviceID: "dev-1", FamilyID: familyID, Generation: 1,
		CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	})
	if err := store.RevokeDevice(ctx, "dev-1", now.Add(time.Minute), "test"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := store.ConsumeRefreshToken(ctx, hash, now.Add(time.Hour)); !errors.Is(err, ErrDeviceInactive) {
		t.Fatalf("ConsumeRefreshToken on revoked device err = %v, want ErrDeviceInactive", err)
	}
}

func TestMemStoreIdempotency(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })
	body := []byte(`{"ok":true}`)
	bodyHash := HashToken("request-body-1")

	if cached, status, err := store.CheckIdempotency(ctx, "key-1", bodyHash); err != nil || cached != nil || status != 0 {
		t.Fatalf("first check returned cached=%v status=%d err=%v; want all zero", cached, status, err)
	}
	if err := store.PutIdempotency(ctx, "key-1", bodyHash, 200, body, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("PutIdempotency: %v", err)
	}
	cached, status, err := store.CheckIdempotency(ctx, "key-1", bodyHash)
	if err != nil {
		t.Fatalf("CheckIdempotency: %v", err)
	}
	if status != 200 || string(cached) != `{"ok":true}` {
		t.Fatalf("CheckIdempotency = (%q, %d), want (%q, 200)", cached, status, body)
	}

	otherHash := HashToken("request-body-2")
	if _, _, err := store.CheckIdempotency(ctx, "key-1", otherHash); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("CheckIdempotency mismatched err = %v, want ErrIdempotencyConflict", err)
	}
}
