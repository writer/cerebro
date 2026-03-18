package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

var natsListenPattern = regexp.MustCompile(`Listening for client connections on (\S+)`)

// StartJetStreamServer boots a local nats-server with JetStream enabled.
func StartJetStreamServer(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("nats-server"); err != nil {
		t.Skip("nats-server binary not found; skipping JetStream-backed integration test")
	}

	storeDir := t.TempDir()
	// #nosec G204 -- test helper executes the fixed local nats-server binary with deterministic arguments.
	cmd := exec.CommandContext(context.Background(), "nats-server", "-js", "-a", "127.0.0.1", "-p", "0", "-sd", storeDir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	var logs lockedBuffer
	announcedURL := make(chan string, 1)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nats-server: %v", err)
	}

	go streamLogs(stdout, &logs, announcedURL)
	go streamLogs(stderr, &logs, announcedURL)

	natsURL, err := waitForNATSURL(announcedURL, 10*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("nats-server did not announce a listener: %v\nlogs:\n%s", err, logs.String())
	}
	if err := waitForNATSReady(natsURL, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("nats-server did not become ready: %v\nlogs:\n%s", err, logs.String())
	}

	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)

		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	return natsURL
}

func streamLogs(r io.Reader, logs *lockedBuffer, announcedURL chan<- string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		logs.WriteLine(line)
		if natsURL, ok := extractNATSURL(line); ok {
			select {
			case announcedURL <- natsURL:
			default:
			}
		}
	}
	if err := scanner.Err(); err != nil {
		logs.WriteLine(fmt.Sprintf("log scanner error: %v", err))
	}
}

func waitForNATSURL(announcedURL <-chan string, timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case natsURL := <-announcedURL:
			return natsURL, nil
		case <-timer.C:
			return "", fmt.Errorf("timeout waiting for nats-server listener announcement")
		}
	}
}

func extractNATSURL(line string) (string, bool) {
	matches := natsListenPattern.FindStringSubmatch(line)
	if len(matches) != 2 {
		return "", false
	}
	return "nats://" + matches[1], true
}

func waitForNATSReady(natsURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		nc, err := nats.Connect(natsURL, nats.Timeout(250*time.Millisecond))
		if err == nil {
			nc.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", natsURL)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) WriteLine(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(line)
	b.buf.WriteByte('\n')
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
