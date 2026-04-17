package deviceauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "device_auth_state.json")
}

func TestCreateAndConsumeBootstrapToken(t *testing.T) {
	store := NewStore(tempStorePath(t))

	bt, raw, err := store.CreateBootstrapToken(BootstrapTokenSpec{
		HardwareUUID: "AAAA-BBBB-CCCC-DDDD",
		OrgID:        "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bt.TokenID == "" || raw == "" {
		t.Fatal("expected non-empty token id and raw token")
	}

	consumed, err := store.ConsumeBootstrapToken(raw, "AAAA-BBBB-CCCC-DDDD")
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("expected consumed_at to be set")
	}
}

func TestBootstrapTokenSingleUse(t *testing.T) {
	store := NewStore(tempStorePath(t))

	_, raw, err := store.CreateBootstrapToken(BootstrapTokenSpec{
		HardwareUUID: "AAAA-BBBB-CCCC-DDDD",
		OrgID:        "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.ConsumeBootstrapToken(raw, "AAAA-BBBB-CCCC-DDDD")
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.ConsumeBootstrapToken(raw, "AAAA-BBBB-CCCC-DDDD")
	if err == nil {
		t.Fatal("expected error on second consumption")
	}
}

func TestBootstrapTokenHardwareUUIDMismatch(t *testing.T) {
	store := NewStore(tempStorePath(t))

	_, raw, err := store.CreateBootstrapToken(BootstrapTokenSpec{
		HardwareUUID: "AAAA-BBBB-CCCC-DDDD",
		OrgID:        "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.ConsumeBootstrapToken(raw, "WRONG-UUID")
	if err == nil {
		t.Fatal("expected error on hardware uuid mismatch")
	}
}

func TestBootstrapTokenExpired(t *testing.T) {
	store := NewStore(tempStorePath(t))

	_, raw, err := store.CreateBootstrapToken(BootstrapTokenSpec{
		HardwareUUID: "AAAA-BBBB-CCCC-DDDD",
		OrgID:        "org-1",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.ConsumeBootstrapToken(raw, "AAAA-BBBB-CCCC-DDDD")
	if err == nil {
		t.Fatal("expected error on expired token")
	}
}

func TestRegisterDevice(t *testing.T) {
	store := NewStore(tempStorePath(t))

	device, err := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-1234",
		Hostname:     "dev-mac.local",
		OrgID:        "org-1",
		OSType:       "darwin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceID == "" || device.Status != "active" {
		t.Fatal("expected active device with an id")
	}

	got, ok := store.GetDevice(device.DeviceID)
	if !ok {
		t.Fatal("device not found after registration")
	}
	if got.HardwareUUID != "HW-1234" {
		t.Fatalf("unexpected hardware uuid: %s", got.HardwareUUID)
	}
}

func TestGetDeviceByHardwareUUID(t *testing.T) {
	store := NewStore(tempStorePath(t))

	_, err := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-LOOKUP",
		Hostname:     "test.local",
		OrgID:        "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := store.GetDeviceByHardwareUUID("HW-LOOKUP")
	if !ok {
		t.Fatal("device not found by hardware uuid")
	}
	if got.Hostname != "test.local" {
		t.Fatalf("unexpected hostname: %s", got.Hostname)
	}
}

func TestRevokeDevice(t *testing.T) {
	store := NewStore(tempStorePath(t))

	device, _ := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-REV",
		OrgID:        "org-1",
	})

	rawRT, record, _ := (&DeviceJWTIssuer{signingKey: []byte("test-key-32-bytes-long-enough!!")}).IssueRefreshToken(device, "")
	_ = rawRT
	_ = store.StoreRefreshToken(record)

	err := store.RevokeDevice(device.DeviceID, "compromised")
	if err != nil {
		t.Fatal(err)
	}

	got, _ := store.GetDevice(device.DeviceID)
	if got.Status != "revoked" {
		t.Fatalf("expected revoked, got %s", got.Status)
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	store := NewStore(tempStorePath(t))

	device, _ := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-ROT",
		OrgID:        "org-1",
	})

	issuer, _ := NewDeviceJWTIssuer([]byte("test-key-32-bytes-long-enough!!"), "", "")
	rawRT, record, _ := issuer.IssueRefreshToken(device, "")
	_ = store.StoreRefreshToken(record)

	consumed, err := store.ConsumeRefreshToken(rawRT)
	if err != nil {
		t.Fatal(err)
	}
	if !consumed.Consumed {
		t.Fatal("expected consumed to be true")
	}
}

func TestRefreshTokenReplayDetection(t *testing.T) {
	store := NewStore(tempStorePath(t))

	device, _ := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-REPLAY",
		OrgID:        "org-1",
	})

	issuer, _ := NewDeviceJWTIssuer([]byte("test-key-32-bytes-long-enough!!"), "", "")
	rawRT, record, _ := issuer.IssueRefreshToken(device, "fam-replay-test")
	_ = store.StoreRefreshToken(record)

	// Also store a second token in the same family
	rawRT2, record2, _ := issuer.IssueRefreshToken(device, "fam-replay-test")
	record2.Generation = 1
	_ = store.StoreRefreshToken(record2)

	// First use succeeds
	_, err := store.ConsumeRefreshToken(rawRT)
	if err != nil {
		t.Fatal(err)
	}

	// Replay: same token used again triggers family revocation
	_, err = store.ConsumeRefreshToken(rawRT)
	if err == nil {
		t.Fatal("expected replay detection error")
	}

	// The sibling token in the same family should also be revoked
	_, err = store.ConsumeRefreshToken(rawRT2)
	if err == nil {
		t.Fatal("expected error: sibling token should be revoked after replay")
	}
}

func TestRefreshTokenDeviceRevoked(t *testing.T) {
	store := NewStore(tempStorePath(t))

	device, _ := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-DEVREV",
		OrgID:        "org-1",
	})

	issuer, _ := NewDeviceJWTIssuer([]byte("test-key-32-bytes-long-enough!!"), "", "")
	rawRT, record, _ := issuer.IssueRefreshToken(device, "")
	_ = store.StoreRefreshToken(record)

	_ = store.RevokeDevice(device.DeviceID, "test")

	_, err := store.ConsumeRefreshToken(rawRT)
	if err == nil {
		t.Fatal("expected error: device is revoked")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := tempStorePath(t)
	store := NewStore(path)

	_, err := store.RegisterDevice(DeviceSpec{
		HardwareUUID: "HW-PERSIST",
		Hostname:     "persist.local",
		OrgID:        "org-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	store2 := NewStore(path)
	if err := store2.Load(); err != nil {
		t.Fatal(err)
	}

	got, ok := store2.GetDeviceByHardwareUUID("HW-PERSIST")
	if !ok {
		t.Fatal("device not found after reload")
	}
	if got.Hostname != "persist.local" {
		t.Fatalf("unexpected hostname after reload: %s", got.Hostname)
	}
}

func TestStoreFilePermissions(t *testing.T) {
	path := tempStorePath(t)
	store := NewStore(path)
	_, _ = store.RegisterDevice(DeviceSpec{HardwareUUID: "HW-PERM", OrgID: "org-1"})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("expected 0600, got %o", perm)
	}
}
