package deviceauth

import (
	"testing"
	"time"
)

const testSigningKey = "test-signing-key-at-least-32-bytes-long!!"

func testIssuer(t *testing.T) *DeviceJWTIssuer {
	t.Helper()
	issuer, err := NewDeviceJWTIssuer([]byte(testSigningKey), "cerebro", "cerebro-device")
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testDevice() DeviceRecord {
	return DeviceRecord{
		DeviceID:     "dev-test-123",
		HardwareUUID: "HW-UUID-TEST",
		OrgID:        "org-1",
		Status:       "active",
		EnrolledAt:   time.Now().UTC(),
	}
}

func TestIssueAndValidateAccessToken(t *testing.T) {
	issuer := testIssuer(t)
	device := testDevice()
	scopes := []string{"security.findings.read", "security.runtime.write"}

	tokenStr, err := issuer.IssueAccessToken(device, scopes)
	if err != nil {
		t.Fatal(err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := issuer.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "dev-test-123" {
		t.Fatalf("unexpected device_id: %s", claims.DeviceID)
	}
	if claims.HardwareUUID != "HW-UUID-TEST" {
		t.Fatalf("unexpected hardware_uuid: %s", claims.HardwareUUID)
	}
	if claims.OrgID != "org-1" {
		t.Fatalf("unexpected org_id: %s", claims.OrgID)
	}
	if claims.Kind != "device_access" {
		t.Fatalf("unexpected kind: %s", claims.Kind)
	}
	if len(claims.Scopes) != 2 {
		t.Fatalf("unexpected scopes count: %d", len(claims.Scopes))
	}
}

func TestAccessTokenWrongKey(t *testing.T) {
	issuer := testIssuer(t)
	device := testDevice()

	tokenStr, _ := issuer.IssueAccessToken(device, nil)

	wrongIssuer, _ := NewDeviceJWTIssuer([]byte("completely-different-key-32-bytes!!"), "cerebro", "cerebro-device")
	_, err := wrongIssuer.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error with wrong signing key")
	}
}

func TestAccessTokenWrongAudience(t *testing.T) {
	issuer := testIssuer(t)
	device := testDevice()

	tokenStr, _ := issuer.IssueAccessToken(device, nil)

	wrongAud, _ := NewDeviceJWTIssuer([]byte(testSigningKey), "cerebro", "wrong-audience")
	_, err := wrongAud.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error with wrong audience")
	}
}

func TestIssueRefreshToken(t *testing.T) {
	issuer := testIssuer(t)
	device := testDevice()

	raw, record, err := issuer.IssueRefreshToken(device, "")
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Fatal("expected non-empty raw token")
	}
	if record.TokenHash == "" {
		t.Fatal("expected non-empty token hash")
	}
	if record.TokenHash == raw {
		t.Fatal("token hash must not equal raw token")
	}
	if record.DeviceID != "dev-test-123" {
		t.Fatalf("unexpected device_id: %s", record.DeviceID)
	}
	if record.FamilyID == "" {
		t.Fatal("expected non-empty family id")
	}
}

func TestNewDeviceJWTIssuerRequiresKey(t *testing.T) {
	_, err := NewDeviceJWTIssuer(nil, "", "")
	if err == nil {
		t.Fatal("expected error with nil signing key")
	}
	_, err = NewDeviceJWTIssuer([]byte{}, "", "")
	if err == nil {
		t.Fatal("expected error with empty signing key")
	}
}
