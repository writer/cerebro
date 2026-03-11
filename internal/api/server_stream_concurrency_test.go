package api

import (
	"testing"
	"time"
)

func TestPlatformReportStreamCleanupWaitsForEmit(t *testing.T) {
	s := newTestServer(t)
	runID := "report_run:test"
	_, cleanup := s.registerPlatformReportStream(runID)

	hookReached := make(chan struct{})
	releaseEmit := make(chan struct{})
	cleanupDone := make(chan struct{})
	errCh := make(chan string, 1)

	platformReportStreamEmitHook = func() {
		select {
		case <-hookReached:
		default:
			close(hookReached)
		}
		go func() {
			cleanup()
			close(cleanupDone)
		}()
		select {
		case <-cleanupDone:
			errCh <- "cleanup completed before emit released read lock"
		case <-time.After(20 * time.Millisecond):
		}
		<-releaseEmit
	}
	t.Cleanup(func() {
		platformReportStreamEmitHook = nil
	})

	emitDone := make(chan struct{})
	go func() {
		s.emitPlatformReportStreamMessage(runID, platformReportStreamMessage{Type: "lifecycle", RunID: runID})
		close(emitDone)
	}()

	select {
	case <-hookReached:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for platform stream emit hook")
	}
	close(releaseEmit)

	select {
	case <-emitDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for platform stream emit")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for platform stream cleanup")
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func TestAgentSDKMCPCleanupWaitsForEmit(t *testing.T) {
	s := newTestServer(t)
	sessionID := "session-test"
	_, cleanup := s.registerAgentSDKMCPSession(sessionID)

	hookReached := make(chan struct{})
	releaseEmit := make(chan struct{})
	cleanupDone := make(chan struct{})
	errCh := make(chan string, 1)

	agentSDKMCPSessionEmitHook = func() {
		select {
		case <-hookReached:
		default:
			close(hookReached)
		}
		go func() {
			cleanup()
			close(cleanupDone)
		}()
		select {
		case <-cleanupDone:
			errCh <- "cleanup completed before MCP emit released read lock"
		case <-time.After(20 * time.Millisecond):
		}
		<-releaseEmit
	}
	t.Cleanup(func() {
		agentSDKMCPSessionEmitHook = nil
	})

	emitDone := make(chan struct{})
	go func() {
		s.emitAgentSDKMCPNotification(sessionID, agentSDKMCPResponse{JSONRPC: "2.0", Method: "notifications/test"})
		close(emitDone)
	}()

	select {
	case <-hookReached:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MCP emit hook")
	}
	close(releaseEmit)

	select {
	case <-emitDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MCP emit")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for MCP cleanup")
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}
