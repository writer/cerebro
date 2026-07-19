package eventadmission

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	nativeHelperModeEnv  = "CEREBRO_EVENT_ADMISSION_TEST_HELPER"
	nativeHelperStateEnv = "CEREBRO_EVENT_ADMISSION_TEST_STATE"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(nativeHelperModeEnv); mode != "" {
		os.Exit(runNativeHelper(mode))
	}
	os.Exit(m.Run())
}

func TestNativeClientReusesWorkerAndRejectsOversizedInput(t *testing.T) {
	client, err := NewNativeClient(context.Background(), os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	client.env = []string{nativeHelperModeEnv + "=echo"}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	for _, payload := range [][]byte{[]byte("first"), []byte("second")} {
		result, evaluateErr := client.Evaluate(context.Background(), payload)
		if evaluateErr != nil {
			t.Fatalf("Evaluate(%q) error = %v", payload, evaluateErr)
		}
		if string(result) != string(payload) {
			t.Fatalf("Evaluate(%q) = %q", payload, result)
		}
	}
	if _, err := client.Evaluate(context.Background(), make([]byte, MaxInputBytes+1)); err == nil {
		t.Fatal("Evaluate(oversized) error = nil")
	}
}

func TestNativeClientKillsCanceledWorkerAndRestarts(t *testing.T) {
	state := filepath.Join(t.TempDir(), "first-worker-started")
	client, err := NewNativeClient(context.Background(), os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	client.env = []string{
		nativeHelperModeEnv + "=block-once",
		nativeHelperStateEnv + "=" + state,
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := client.Evaluate(ctx, []byte("cancel")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Evaluate(canceled) error = %v, want %v", err, context.DeadlineExceeded)
	}
	result, err := client.Evaluate(context.Background(), []byte("restarted"))
	if err != nil {
		t.Fatalf("Evaluate(restarted) error = %v", err)
	}
	if string(result) != "restarted" {
		t.Fatalf("Evaluate(restarted) = %q", result)
	}
}

func TestNewNativeAdmitterRejectsInvalidPoolConfiguration(t *testing.T) {
	for _, workers := range []int{0, maxNativeWorkers + 1} {
		if _, err := NewNativeAdmitter(context.Background(), os.Args[0], workers); err == nil {
			t.Fatalf("NewNativeAdmitter(workers=%d) error = nil", workers)
		}
	}
	if _, err := NewNativeAdmitter(context.Background(), "", 1); err == nil {
		t.Fatal("NewNativeAdmitter(empty path) error = nil")
	}
}

func runNativeHelper(mode string) int {
	for {
		var header [nativeFrameHeaderBytes]byte
		if _, err := io.ReadFull(os.Stdin, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			return 1
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > MaxInputBytes+1 {
			return 1
		}
		request := make([]byte, int(length))
		if _, err := io.ReadFull(os.Stdin, request); err != nil {
			return 1
		}
		if mode == "block-once" && markNativeHelperFirstRun() {
			for {
				time.Sleep(time.Hour)
			}
		}
		binary.BigEndian.PutUint32(header[:], length)
		if _, err := os.Stdout.Write(header[:]); err != nil {
			return 1
		}
		if _, err := os.Stdout.Write(request); err != nil {
			return 1
		}
	}
}

func markNativeHelperFirstRun() bool {
	state := os.Getenv(nativeHelperStateEnv)
	if state == "" {
		return false
	}
	file, err := os.OpenFile(state, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 G703 -- the parent test supplies a path under t.TempDir.
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}
