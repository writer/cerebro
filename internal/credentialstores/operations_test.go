package credentialstores

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/ports"
)

func TestBuildOperationsUsesNewestCredentialUpdateWithFractionalTimestamp(t *testing.T) {
	olderFractional := time.Date(2026, 6, 28, 10, 0, 0, 500_000_000, time.UTC)
	newerWholeSecond := time.Date(2026, 6, 28, 10, 0, 1, 0, time.UTC)

	response := BuildOperations(BuildInput{
		GeneratedAt: time.Date(2026, 6, 28, 11, 0, 0, 0, time.UTC),
		Stores: []StoreMetadata{
			{
				ID:        DefaultStoreID,
				Label:     "Cerebro Vault",
				Available: true,
			},
		},
		Credentials: []*ports.ConnectorCredentialRecord{
			{
				ID:                "cred-older",
				TenantID:          "tenant-a",
				SourceID:          "bootstrap_token",
				RuntimeID:         "runtime-older",
				CredentialStoreID: DefaultStoreID,
				UpdatedAt:         olderFractional,
				Fields:            []string{"token"},
			},
			{
				ID:                "cred-newer",
				TenantID:          "tenant-a",
				SourceID:          "bootstrap_token",
				RuntimeID:         "runtime-newer",
				CredentialStoreID: DefaultStoreID,
				UpdatedAt:         newerWholeSecond,
				Fields:            []string{"token"},
			},
		},
	})

	if len(response.Stores) != 1 {
		t.Fatalf("stores = %d, want 1", len(response.Stores))
	}
	if got, want := response.Stores[0].Usage.LastUpdatedAt, connectorcredentials.TimestampOrZero(newerWholeSecond); got != want {
		t.Fatalf("last_updated_at = %q, want %q", got, want)
	}
}
