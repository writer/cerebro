package integration

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestExtractNATSURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		line    string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "listener announcement",
			line:    "[12345] [INF] Listening for client connections on 127.0.0.1:4222",
			wantURL: "nats://127.0.0.1:4222",
			wantOK:  true,
		},
		{
			name:   "unrelated line",
			line:   "[12345] [INF] Server is ready",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOK := extractNATSURL(tt.line)
			if gotOK != tt.wantOK {
				t.Fatalf("extractNATSURL() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotURL != tt.wantURL {
				t.Fatalf("extractNATSURL() url = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestWaitForNATSURLReceivesAnnouncement(t *testing.T) {
	t.Parallel()

	announcedURL := make(chan string, 1)
	announcedURL <- "nats://127.0.0.1:4222"

	got, err := waitForNATSURL(announcedURL, time.Second)
	if err != nil {
		t.Fatalf("waitForNATSURL() error = %v", err)
	}
	if got != "nats://127.0.0.1:4222" {
		t.Fatalf("waitForNATSURL() = %q, want %q", got, "nats://127.0.0.1:4222")
	}
}

func TestWaitForNATSURLTimesOut(t *testing.T) {
	t.Parallel()

	got, err := waitForNATSURL(make(chan string), 10*time.Millisecond)
	if err == nil {
		t.Fatal("waitForNATSURL() error = nil, want timeout")
	}
	if got != "" {
		t.Fatalf("waitForNATSURL() = %q, want empty string", got)
	}
	if !strings.Contains(err.Error(), "timeout waiting for nats-server listener announcement") {
		t.Fatalf("waitForNATSURL() error = %v, want timeout message", err)
	}
}

func TestStreamLogsCapturesAnnouncementsAndScannerErrors(t *testing.T) {
	t.Parallel()

	var logs lockedBuffer
	announcedURL := make(chan string, 1)

	streamLogs(&failingLogReader{
		data: []byte("[12345] [INF] Listening for client connections on 127.0.0.1:4222\n"),
		err:  errors.New("boom"),
	}, &logs, announcedURL)

	select {
	case got := <-announcedURL:
		if got != "nats://127.0.0.1:4222" {
			t.Fatalf("streamLogs() announced %q, want %q", got, "nats://127.0.0.1:4222")
		}
	default:
		t.Fatal("streamLogs() did not announce a NATS URL")
	}

	logText := logs.String()
	if !strings.Contains(logText, "Listening for client connections on 127.0.0.1:4222") {
		t.Fatalf("streamLogs() logs = %q, want listener line", logText)
	}
	if !strings.Contains(logText, "log scanner error: boom") {
		t.Fatalf("streamLogs() logs = %q, want scanner error", logText)
	}
}

func TestLockedBufferWriteLine(t *testing.T) {
	t.Parallel()

	var logs lockedBuffer
	logs.WriteLine("first")
	logs.WriteLine("second")

	if got := logs.String(); got != "first\nsecond\n" {
		t.Fatalf("lockedBuffer.String() = %q, want %q", got, "first\nsecond\n")
	}
}

type failingLogReader struct {
	data []byte
	err  error
	read bool
}

func (r *failingLogReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	n := copy(p, r.data)
	return n, r.err
}
