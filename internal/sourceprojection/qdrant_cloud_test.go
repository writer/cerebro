package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestQdrantCloudGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"qdrant_cloud.account_members",
		"qdrant_cloud.accounts",
		"qdrant_cloud.backup_restores",
		"qdrant_cloud.backup_schedules",
		"qdrant_cloud.backups",
		"qdrant_cloud.clusters",
		"qdrant_cloud.database_api_keys",
		"qdrant_cloud.roles",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "qdrant_cloud",
				Kind:     kind,
			})
			if !errors.Is(err, errQdrantCloudRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}
