package worker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackgroundRunner_Run(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	done := make(chan struct{})
	runner.Run("test-task", func(ctx context.Context) error {
		close(done)
		return nil
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task did not complete")
	}

	// Wait for results to be recorded
	time.Sleep(10 * time.Millisecond)

	results := runner.Results()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "test-task" {
		t.Errorf("got name %s, want test-task", results[0].Name)
	}
	if results[0].Error != nil {
		t.Errorf("expected no error, got %v", results[0].Error)
	}
}

func TestBackgroundRunner_RunWithError(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	expectedErr := errors.New("task failed")
	done := make(chan struct{})

	runner.Run("failing-task", func(ctx context.Context) error {
		defer close(done)
		return expectedErr
	})

	<-done
	time.Sleep(10 * time.Millisecond)

	taskErrors := runner.Errors()
	if len(taskErrors) != 1 {
		t.Errorf("expected 1 error, got %d", len(taskErrors))
	}
	if !errors.Is(taskErrors[0].Error, expectedErr) {
		t.Errorf("got error %v, want %v", taskErrors[0].Error, expectedErr)
	}
}

func TestBackgroundRunner_Running(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	started := make(chan struct{})
	block := make(chan struct{})

	runner.Run("blocking-task", func(ctx context.Context) error {
		close(started)
		<-block
		return nil
	})

	<-started

	if runner.Running() != 1 {
		t.Errorf("expected 1 running, got %d", runner.Running())
	}

	close(block)
	time.Sleep(10 * time.Millisecond)

	if runner.Running() != 0 {
		t.Errorf("expected 0 running, got %d", runner.Running())
	}
}

func TestBackgroundRunner_RunWithContext(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	runner.RunWithContext(ctx, "context-task", func(ctx context.Context) error {
		defer close(done)
		<-ctx.Done()
		return ctx.Err()
	})

	cancel()
	<-done
	time.Sleep(10 * time.Millisecond)

	results := runner.Results()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if !errors.Is(results[0].Error, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", results[0].Error)
	}
}

func TestBackgroundRunner_Clear(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	done := make(chan struct{})
	runner.Run("task1", func(ctx context.Context) error {
		close(done)
		return nil
	})

	<-done
	time.Sleep(10 * time.Millisecond)

	if len(runner.Results()) != 1 {
		t.Error("expected 1 result before clear")
	}

	runner.Clear()

	if len(runner.Results()) != 0 {
		t.Error("expected 0 results after clear")
	}
}

func TestBackgroundRunner_MultipleTasks(t *testing.T) {
	runner := NewBackgroundRunner(nil)

	count := 10
	done := make(chan struct{}, count)

	for i := 0; i < count; i++ {
		runner.Run("task", func(ctx context.Context) error {
			done <- struct{}{}
			return nil
		})
	}

	for i := 0; i < count; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("task %d did not complete", i)
		}
	}

	time.Sleep(10 * time.Millisecond)

	results := runner.Results()
	if len(results) != count {
		t.Errorf("expected %d results, got %d", count, len(results))
	}
}

func TestTaskResult_Fields(t *testing.T) {
	now := time.Now()
	err := errors.New("test error")

	result := TaskResult{
		Name:      "test",
		StartedAt: now,
		EndedAt:   now.Add(time.Second),
		Error:     err,
	}

	if result.Name != "test" {
		t.Error("Name field incorrect")
	}
	if result.StartedAt != now {
		t.Error("StartedAt field incorrect")
	}
	if result.EndedAt != now.Add(time.Second) {
		t.Error("EndedAt field incorrect")
	}
	if !errors.Is(result.Error, err) {
		t.Error("Error field incorrect")
	}
}
