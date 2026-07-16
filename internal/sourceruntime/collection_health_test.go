package sourceruntime

import (
	"slices"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCollectionIncompletenessReasons(t *testing.T) {
	completeConfig := func() map[string]string {
		return map[string]string{
			runtimeStatusConfigKey:          "completed",
			runtimeRecordsRejectedConfigKey: "0",
		}
	}
	runtimeWithConfig := func(config map[string]string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{Config: config}
	}

	tests := []struct {
		name    string
		runtime *cerebrov1.SourceRuntime
		want    []string
	}{
		{name: "missing runtime", want: []string{CollectionIncompleteSourceRuntimeMissing}},
		{name: "disabled runtime", runtime: runtimeWithConfig(map[string]string{
			"enabled":                       "false",
			runtimeStatusConfigKey:          "completed",
			runtimeRecordsRejectedConfigKey: "0",
		}), want: []string{CollectionIncompleteSourceRuntimeDisabled}},
		{name: "missing sync status and rejected count", runtime: runtimeWithConfig(map[string]string{}), want: []string{
			CollectionIncompleteSyncStatusMissing,
			CollectionIncompleteRecordsRejectedInvalid,
		}},
		{name: "failed sync", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:          "failed",
			runtimeRecordsRejectedConfigKey: "0",
		}), want: []string{CollectionIncompleteSyncStatusNotCompleted}},
		{name: "invalid rejected count", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:          "completed",
			runtimeRecordsRejectedConfigKey: "-1",
		}), want: []string{CollectionIncompleteRecordsRejectedInvalid}},
		{name: "rejected records", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:          "completed",
			runtimeRecordsRejectedConfigKey: "2",
		}), want: []string{CollectionIncompleteRecordsRejectedNonzero}},
		{name: "next cursor", runtime: &cerebrov1.SourceRuntime{
			Config:     completeConfig(),
			NextCursor: &cerebrov1.SourceCursor{Opaque: "next"},
		}, want: []string{CollectionIncompleteNextCursorPresent}},
		{name: "scope excluded", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:             "completed",
			runtimeRecordsRejectedConfigKey:    "0",
			runtimeShortCircuitReasonConfigKey: string(sourcecdk.PullShortCircuitReasonScopeExcluded),
		}), want: []string{CollectionIncompleteShortCircuitScopeExcluded}},
		{name: "resource scope filtered", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:             "completed",
			runtimeRecordsRejectedConfigKey:    "0",
			runtimeShortCircuitReasonConfigKey: string(sourcecdk.PullShortCircuitReasonResourceScopeFiltered),
		}), want: []string{CollectionIncompleteShortCircuitResourceScopeFiltered}},
		{name: "unknown short circuit", runtime: runtimeWithConfig(map[string]string{
			runtimeStatusConfigKey:             "completed",
			runtimeRecordsRejectedConfigKey:    "0",
			runtimeShortCircuitReasonConfigKey: "unexpected_reason",
		}), want: []string{CollectionIncompleteShortCircuitUnknown}},
		{name: "all unsafe states are ordered", runtime: &cerebrov1.SourceRuntime{
			Config: map[string]string{
				runtimeStatusConfigKey:             "running",
				runtimeRecordsRejectedConfigKey:    "1",
				runtimeShortCircuitReasonConfigKey: "unexpected_reason",
			},
			NextCursor: &cerebrov1.SourceCursor{Opaque: "next"},
		}, want: []string{
			CollectionIncompleteSyncStatusNotCompleted,
			CollectionIncompleteRecordsRejectedNonzero,
			CollectionIncompleteNextCursorPresent,
			CollectionIncompleteShortCircuitUnknown,
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CollectionIncompletenessReasons(test.runtime); !slices.Equal(got, test.want) {
				t.Fatalf("CollectionIncompletenessReasons() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCollectionIncompletenessReasonsAcceptsCompleteShortCircuits(t *testing.T) {
	reasons := []string{
		"",
		string(sourcecdk.PullShortCircuitReasonNotModified),
		string(sourcecdk.PullShortCircuitReasonCheckpointAdvanced),
		string(sourcecdk.PullShortCircuitReasonWatermarkReached),
	}
	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Config: map[string]string{
				runtimeStatusConfigKey:             "completed",
				runtimeRecordsRejectedConfigKey:    "0",
				runtimeShortCircuitReasonConfigKey: reason,
			}}
			if got := CollectionIncompletenessReasons(runtime); len(got) != 0 {
				t.Fatalf("CollectionIncompletenessReasons() = %v, want no reasons", got)
			}
		})
	}
}
