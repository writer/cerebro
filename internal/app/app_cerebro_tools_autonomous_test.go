package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/autonomous"
)

type autonomousRunStoreStub struct {
	saveRunErr     error
	appendEventErr error
}

func (s *autonomousRunStoreStub) SaveRun(context.Context, *autonomous.RunRecord) error {
	return s.saveRunErr
}

func (s *autonomousRunStoreStub) LoadRun(context.Context, string) (*autonomous.RunRecord, error) {
	return nil, nil
}

func (s *autonomousRunStoreStub) ListRuns(context.Context, autonomous.RunListOptions) ([]autonomous.RunRecord, error) {
	return nil, nil
}

func (s *autonomousRunStoreStub) AppendEvent(context.Context, string, autonomous.RunEvent) (autonomous.RunEvent, error) {
	return autonomous.RunEvent{}, s.appendEventErr
}

func (s *autonomousRunStoreStub) LoadEvents(context.Context, string) ([]autonomous.RunEvent, error) {
	return nil, nil
}

func (s *autonomousRunStoreStub) Close() error {
	return nil
}

func TestSaveAutonomousRunBestEffortLogsWarning(t *testing.T) {
	var logs bytes.Buffer
	application := &App{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	store := &autonomousRunStoreStub{saveRunErr: errors.New("save failed")}

	application.saveAutonomousRunBestEffort(context.Background(), store, &autonomous.RunRecord{ID: "run-123"})

	output := logs.String()
	if !strings.Contains(output, "persist autonomous workflow run failed") {
		t.Fatalf("expected save warning log, got %q", output)
	}
	if !strings.Contains(output, "run-123") {
		t.Fatalf("expected run id in warning log, got %q", output)
	}
}

func TestAppendAutonomousRunEventBestEffortLogsWarning(t *testing.T) {
	var logs bytes.Buffer
	application := &App{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	store := &autonomousRunStoreStub{appendEventErr: errors.New("append failed")}

	application.appendAutonomousRunEventBestEffort(context.Background(), store, "run-456", autonomous.RunEvent{
		Status:     autonomous.RunStatusFailed,
		Stage:      autonomous.RunStageClosed,
		Message:    "failed",
		RecordedAt: time.Now().UTC(),
	})

	output := logs.String()
	if !strings.Contains(output, "persist autonomous workflow event failed") {
		t.Fatalf("expected append warning log, got %q", output)
	}
	if !strings.Contains(output, "run-456") {
		t.Fatalf("expected run id in warning log, got %q", output)
	}
}

func TestWarnAutonomousRunPersistenceSkipsNilLogger(t *testing.T) {
	application := &App{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	application.warnAutonomousRunPersistence("ignored", "run-789", nil)
}
