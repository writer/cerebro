package sourceruntime

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSyncConfigDigestIsStableAcrossMapOrdering(t *testing.T) {
	t.Parallel()
	keys := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"}
	reference := ""
	for attempt := range 50 {
		config := map[string]string{}
		// Insert in a rotating order so map construction differs between attempts.
		for i := range keys {
			key := keys[(i+attempt)%len(keys)]
			config[key] = "value-" + key
		}
		digest := SyncConfigDigest(&cerebrov1.SourceRuntime{SourceId: "github", Config: config})
		if reference == "" {
			reference = digest
		}
		if digest != reference {
			t.Fatalf("attempt %d digest = %s, want %s", attempt, digest, reference)
		}
	}
	if len(reference) != 64 {
		t.Fatalf("digest = %q, want sha256 hex", reference)
	}
}

func TestSyncConfigDigestIgnoresRuntimeOwnedKeysOnly(t *testing.T) {
	t.Parallel()
	base := &cerebrov1.SourceRuntime{SourceId: "github", Config: map[string]string{"token": "env:A", "org": "writer"}}
	digest := SyncConfigDigest(base)

	runtimeOwned := &cerebrov1.SourceRuntime{SourceId: "github", Config: map[string]string{
		"token":                             "env:A",
		"org":                               "writer",
		runtimeStatusConfigKey:              "failed",
		runtimeLastFailureCategoryConfigKey: "auth_error",
		"__cerebro_resolved_progress_config_hash": "abc",
	}}
	if got := SyncConfigDigest(runtimeOwned); got != digest {
		t.Fatalf("runtime-owned keys changed digest: %s != %s", got, digest)
	}

	for name, changed := range map[string]*cerebrov1.SourceRuntime{
		"credential reference": {SourceId: "github", Config: map[string]string{"token": "env:B", "org": "writer"}},
		"added key":            {SourceId: "github", Config: map[string]string{"token": "env:A", "org": "writer", "repo": "cerebro"}},
		"source id":            {SourceId: "gitlab", Config: map[string]string{"token": "env:A", "org": "writer"}},
		"shifted boundary":     {SourceId: "github", Config: map[string]string{"token": "env:Aorg", "": "writer"}},
	} {
		if got := SyncConfigDigest(changed); got == digest {
			t.Fatalf("%s did not change digest", name)
		}
	}
	if SyncConfigDigest(nil) != "" {
		t.Fatal("nil runtime digest must be empty")
	}
}
