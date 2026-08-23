package sourceruntime

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestPublicSourceExecutionConfigCarriesTailscaleScopeWithoutSecrets(t *testing.T) {
	t.Parallel()

	got := publicSourceExecutionConfig(sourcecdk.NewConfig(map[string]string{
		"base_url":    " https://api.tailscale.com/api/v2 ",
		"family":      " user ",
		"per_page":    " 100 ",
		"tailnet":     " example.test ",
		"token":       "must-not-cross",
		"graph_token": "must-not-cross-either",
	}))
	want := map[string]string{
		"base_url": "https://api.tailscale.com/api/v2",
		"family":   "user",
		"per_page": "100",
		"tailnet":  "example.test",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("publicSourceExecutionConfig() = %#v, want %#v", got, want)
	}
}
