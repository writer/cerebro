package sourceruntime

import (
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehealth"
)

const (
	CollectionIncompleteSourceRuntimeMissing              = "source_runtime_missing"
	CollectionIncompleteSourceRuntimeDisabled             = "source_runtime_disabled"
	CollectionIncompleteSyncStatusMissing                 = "sync_status_missing"
	CollectionIncompleteSyncStatusNotCompleted            = "sync_status_not_completed"
	CollectionIncompleteRecordsRejectedInvalid            = "records_rejected_invalid"
	CollectionIncompleteRecordsRejectedNonzero            = "records_rejected_nonzero"
	CollectionIncompleteNextCursorPresent                 = "next_cursor_present"
	CollectionIncompleteShortCircuitScopeExcluded         = "short_circuit_scope_excluded"
	CollectionIncompleteShortCircuitResourceScopeFiltered = "short_circuit_resource_scope_filtered"
	CollectionIncompleteShortCircuitUnknown               = "short_circuit_unknown"
)

// CollectionIncompletenessReasons returns deterministic reason codes when a
// persisted, unredacted source runtime cannot prove a complete collection.
func CollectionIncompletenessReasons(runtime *cerebrov1.SourceRuntime) []string {
	if runtime == nil {
		return []string{CollectionIncompleteSourceRuntimeMissing}
	}

	config := runtime.GetConfig()
	reasons := make([]string, 0, 4)
	if sourcehealth.RuntimeEnabledState(runtime) == "disabled" {
		reasons = append(reasons, CollectionIncompleteSourceRuntimeDisabled)
	}

	switch status := strings.TrimSpace(config[runtimeStatusConfigKey]); status {
	case "":
		reasons = append(reasons, CollectionIncompleteSyncStatusMissing)
	case "completed":
	default:
		reasons = append(reasons, CollectionIncompleteSyncStatusNotCompleted)
	}

	rejected, err := strconv.ParseUint(strings.TrimSpace(config[runtimeRecordsRejectedConfigKey]), 10, 32)
	switch {
	case err != nil:
		reasons = append(reasons, CollectionIncompleteRecordsRejectedInvalid)
	case rejected != 0:
		reasons = append(reasons, CollectionIncompleteRecordsRejectedNonzero)
	}

	if runtime.GetNextCursor() != nil {
		reasons = append(reasons, CollectionIncompleteNextCursorPresent)
	}

	switch reason := strings.TrimSpace(config[runtimeShortCircuitReasonConfigKey]); reason {
	case "",
		string(sourcecdk.PullShortCircuitReasonNotModified),
		string(sourcecdk.PullShortCircuitReasonCheckpointAdvanced),
		string(sourcecdk.PullShortCircuitReasonWatermarkReached):
	case string(sourcecdk.PullShortCircuitReasonScopeExcluded):
		reasons = append(reasons, CollectionIncompleteShortCircuitScopeExcluded)
	case string(sourcecdk.PullShortCircuitReasonResourceScopeFiltered):
		reasons = append(reasons, CollectionIncompleteShortCircuitResourceScopeFiltered)
	default:
		reasons = append(reasons, CollectionIncompleteShortCircuitUnknown)
	}

	return reasons
}
