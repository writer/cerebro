package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	nativesync "github.com/writer/cerebro/internal/sync"
)

func TestSummarizeSyncRunErrors(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		if err := summarizeSyncRunErrors("aws sync", nil); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("single error", func(t *testing.T) {
		baseErr := errors.New("profile failure")
		err := summarizeSyncRunErrors("aws sync", []error{baseErr})
		if err == nil {
			t.Fatal("expected error")
			return
		}
		if !strings.Contains(err.Error(), "aws sync") {
			t.Fatalf("expected scope in error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "1 error(s)") {
			t.Fatalf("expected count in error, got %q", err.Error())
		}
		if !errors.Is(err, baseErr) {
			t.Fatalf("expected wrapped base error, got %v", err)
		}
	})

	t.Run("multiple errors", func(t *testing.T) {
		errA := errors.New("a")
		errB := errors.New("b")
		err := summarizeSyncRunErrors("aws sync", []error{errA, errB})
		if err == nil {
			t.Fatal("expected error")
			return
		}
		if !strings.Contains(err.Error(), "2 error(s)") {
			t.Fatalf("expected count in error, got %q", err.Error())
		}
		if !errors.Is(err, errA) || !errors.Is(err, errB) {
			t.Fatalf("expected joined errors to be discoverable via errors.Is, got %v", err)
		}
	})
}

func TestHandleSyncRunResultsNoResultsError(t *testing.T) {
	currentOutput := syncOutput
	syncOutput = FormatTable
	t.Cleanup(func() { syncOutput = currentOutput })

	err := errors.New("boom")
	output := captureStdout(t, func() {
		handleErr := handleSyncRunResults(nil, time.Now(), "AWS", err)
		if handleErr == nil {
			t.Fatal("expected error")
			return
		}
		if !errors.Is(handleErr, err) {
			t.Fatalf("expected wrapped sync error, got %v", handleErr)
		}
	})

	if strings.Contains(output, "Sync completed successfully") {
		t.Fatalf("did not expect success output for failed run without results: %q", output)
	}
}

func TestHandleSyncRunResultsWithPartialResults(t *testing.T) {
	currentOutput := syncOutput
	syncOutput = FormatTable
	t.Cleanup(func() { syncOutput = currentOutput })

	err := errors.New("partial failure")
	results := []nativesync.SyncResult{{Table: "aws_rds_instances", Region: "us-east-1", Synced: 3, Errors: 1, Error: "access denied", Duration: 500 * time.Millisecond}}
	output := captureStdout(t, func() {
		handleErr := handleSyncRunResults(results, time.Now(), "AWS", err)
		if handleErr == nil {
			t.Fatal("expected error")
			return
		}
		if !errors.Is(handleErr, err) {
			t.Fatalf("expected wrapped sync error, got %v", handleErr)
		}
	})

	if !strings.Contains(output, "AWS Sync Results") {
		t.Fatalf("expected sync summary output, got %q", output)
	}
}
