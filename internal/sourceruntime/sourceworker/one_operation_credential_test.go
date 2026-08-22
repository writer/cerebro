package sourceworker

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestOneOperationCredentialRedeemerConsumesAndClearsCredential(t *testing.T) {
	credential := []byte("test-credential")
	redeemer := NewOneOperationCredentialRedeemer("credential:azure", credential, "operation-1", time.Now().UTC().Add(time.Minute))
	clear(credential)

	if _, err := redeemer.Redeem(context.Background(), "credential:other", CredentialScope{}); err == nil {
		t.Fatal("Redeem() accepted a mismatched opaque reference")
	}
	lease, err := redeemer.Redeem(context.Background(), "credential:azure", CredentialScope{})
	if err != nil {
		t.Fatal(err)
	}
	if got := lease.BearerToken(); !bytes.Equal(got, []byte("test-credential")) {
		t.Fatal("BearerToken() did not return the copied credential")
	}
	if _, err := redeemer.Redeem(context.Background(), "credential:azure", CredentialScope{}); err == nil {
		t.Fatal("Redeem() allowed a second operation")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if token := lease.BearerToken(); token != nil {
		t.Fatal("BearerToken() remained available after Close()")
	}
	if err := lease.Close(); err == nil {
		t.Fatal("Close() allowed a second close")
	}
}
