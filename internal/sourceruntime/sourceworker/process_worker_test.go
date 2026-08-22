package sourceworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessWorkerPreservesClosedRustFailureClasses(t *testing.T) {
	t.Parallel()

	tests := map[string]error{
		"protobuf":                        ErrWorkerContract,
		"unknown_adapter":                 ErrWorkerUnsupported,
		"missing_configuration":           ErrSourceConfiguration,
		"missing_credential_reference":    ErrCredentialReferenceMissing,
		"credential_unavailable":          ErrCredentialUnavailable,
		"authentication_rejected":         ErrProviderAuthentication,
		"required_provider_scope_missing": ErrProviderPermission,
		"egress_denied":                   ErrProviderEgress,
		"connection_failure":              ErrProviderEgress,
		"provider_timeout":                ErrProviderTimeout,
		"provider_rate_limit":             ErrProviderRateLimited,
		"unexpected_provider_status":      ErrProviderUnexpectedStatus,
		"invalid_plan":                    ErrWorkerContract,
		"invalid_execution_context":       ErrWorkerContract,
		"invalid_cursor":                  ErrWorkerContract,
		"response_too_large":              ErrProviderResponseTooLarge,
		"result_too_large":                ErrWorkerResultTooLarge,
		"missing_execution_identity":      ErrWorkerContract,
		"tenant_mismatch":                 ErrWorkerContract,
		"stale_generation":                ErrWorkerContract,
		"invalid_digest":                  ErrWorkerContract,
		"malformed_response":              ErrProviderMalformedResponse,
		"invalid_provider_record":         ErrProviderMalformedResponse,
		"missing_stable_identity":         ErrProviderMalformedResponse,
		"duplicate_conflict":              ErrWorkerContract,
		"event_contract_rejected":         ErrWorkerContract,
		"append_failed":                   ErrWorkerAppend,
		"projection_failed":               ErrWorkerProjection,
		"lease_lost":                      ErrWorkerLeaseLost,
		"stale_authority":                 ErrWorkerStaleAuthority,
		"internal_runtime":                ErrWorkerInternal,
	}

	for class, want := range tests {
		class, want := class, want
		t.Run(class, func(t *testing.T) {
			t.Parallel()
			worker, command := newFailingProcessWorker(t, "source_worker."+class+": bounded detail")
			_, err := worker.run(context.Background(), command, nil, workerOverhead)
			if !errors.Is(err, want) {
				t.Fatalf("ProcessWorker.Context() error = %v, want %v", err, want)
			}
		})
	}
}

func TestProcessWorkerRejectsUnrecognizedFailureClass(t *testing.T) {
	t.Parallel()
	worker, command := newFailingProcessWorker(t, "source_worker.provider_timeout_extra: bounded detail")
	_, err := worker.run(context.Background(), command, nil, workerOverhead)
	if !errors.Is(err, ErrWorkerInternal) {
		t.Fatalf("ProcessWorker.Context() error = %v, want %v", err, ErrWorkerInternal)
	}
}

func newFailingProcessWorker(t *testing.T, failure string) (*ProcessWorker, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "source_worker")
	if err := os.Symlink("/bin/sh", path); err != nil {
		t.Fatalf("link source_worker fixture: %v", err)
	}
	command := filepath.Join(directory, "failure.sh")
	script := "#!/bin/sh\nprintf '%s\\n' '" + failure + "' >&2\nexit 1\n"
	if err := os.WriteFile(command, []byte(script), 0o600); err != nil {
		t.Fatalf("write source_worker fixture: %v", err)
	}
	return NewProcessWorker(path), command
}
