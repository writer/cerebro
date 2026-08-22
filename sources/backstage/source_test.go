package backstage

import (
	"testing"

	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestGenuineProviderResponsesReplayEveryRuntimeFamily(t *testing.T) {
	for _, fixture := range []struct {
		family string
		name   string
	}{
		{family: "component", name: "public_first_page"},
		{family: "system", name: "public_first_page"},
	} {
		t.Run(fixture.family, func(t *testing.T) {
			if _, err := sourcefixture.FindBundle("../..", "backstage", fixture.family, fixture.name); err != nil {
				t.Fatalf("FindBundle(%s) error = %v", fixture.family, err)
			}
		})
	}
}
