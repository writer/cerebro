package fivetran

import (
	"testing"

	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/sources/internal/fivetranapi"
)

func TestSourceReplaysCapturedPublicConnectorTypes(t *testing.T) {
	if _, err := sourcefixture.FindBundle("../..", "fivetran", fivetranapi.FamilyPublicConnectorTypes, "connector_types"); err != nil {
		t.Fatalf("FindBundle() error = %v", err)
	}
}
