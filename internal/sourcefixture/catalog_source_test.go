package sourcefixture

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewCatalogSourceLoadsGeneratedFixturePairs(t *testing.T) {
	source, err := NewCatalogSource("../../sources/docker_hub", "repositories")
	if err != nil {
		t.Fatalf("NewCatalogSource() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": "repositories"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "docker_hub.repositories" {
		t.Fatalf("events = %#v, want one docker_hub.repositories event", pull.Events)
	}
}
