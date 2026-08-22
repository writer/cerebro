package sourcefixture_test

import (
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/sourcefixture"
)

// These functions are compile-valid negative fixtures for the replay-binding
// verifier. They are intentionally not tests and must never be executed.
func replayBindingIfFalse(t *testing.T) {
	bundle, _ := sourcefixture.FindBundle("", "writer", "model", "authorized_first_page")
	if false {
		sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{
			SourceID: "writer",
			Family:   "model",
			Case:     "authorized_first_page",
			Method:   http.MethodGet,
			Host:     "api.writer.com",
			Path:     "/v1/models",
			RawQuery: "",
		})
	}
}

func replayBindingBlankContract(t *testing.T) {
	bundle, _ := sourcefixture.FindBundle("", "writer", "model", "authorized_first_page")
	sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{})
}

func replayBindingWrongFamily(t *testing.T) {
	bundle, _ := sourcefixture.FindBundle("", "writer", "model", "authorized_first_page")
	sourcefixture.RequireReplayContract(t, bundle, sourcefixture.ReplayContract{
		SourceID: "writer",
		Family:   "graph",
		Case:     "authorized_first_page",
		Method:   http.MethodGet,
		Host:     "api.writer.com",
		Path:     "/v1/models",
		RawQuery: "",
	})
}

func replayBindingIgnoredError(_ *testing.T) {
	bundle, _ := sourcefixture.FindBundle("", "writer", "model", "authorized_first_page")
	_ = sourcefixture.ValidateReplayContract(bundle, sourcefixture.ReplayContract{
		SourceID: "writer",
		Family:   "model",
		Case:     "authorized_first_page",
		Method:   http.MethodGet,
		Host:     "api.writer.com",
		Path:     "/v1/models",
		RawQuery: "",
	})
}

var replayBindingNegativeFixtures = [...]func(*testing.T){
	replayBindingIfFalse,
	replayBindingBlankContract,
	replayBindingWrongFamily,
	replayBindingIgnoredError,
}

func TestReplayBindingNegativeFixturesCompile(t *testing.T) {
	if len(replayBindingNegativeFixtures) != 4 {
		t.Fatalf("negative replay fixture count = %d, want 4", len(replayBindingNegativeFixtures))
	}
}
