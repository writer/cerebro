package eventadmission

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/telemetry"
	"github.com/writer/cerebro/internal/wasmhost"
)

const (
	nativeFrameHeaderBytes = 4
	nativeEncodingJSON     = 0
	nativeEncodingCBOR     = 1
	maxNativeWorkers       = 64
	nativeCallTimeout      = 5 * time.Second
	// NativeWorkerPathEnv configures the native Rust admission worker for tests and benchmarks.
	NativeWorkerPathEnv = "CEREBRO_EVENT_ADMISSION_WORKER"
)

var nativeCBORDecoder, nativeCBORDecoderError = (cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	IndefLength:       cbor.IndefLengthForbidden,
	TagsMd:            cbor.TagsForbidden,
	MaxNestedLevels:   16,
	MaxArrayElements:  16_384,
	MaxMapPairs:       16_384,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
}).DecMode()

// NativeAdmitter distributes source pages across persistent Rust workers.
type NativeAdmitter struct {
	clients chan *NativeClient
	all     []*NativeClient

	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
}

// NewNativeAdmitter configures a bounded pool of persistent Rust workers.
func NewNativeAdmitter(ctx context.Context, path string, workers int) (*NativeAdmitter, error) {
	if ctx == nil {
		return nil, errors.New("native source event admission context is required")
	}
	if workers < 1 || workers > maxNativeWorkers {
		return nil, fmt.Errorf("native source event admission workers must be between 1 and %d", maxNativeWorkers)
	}
	admitter := &NativeAdmitter{
		clients: make(chan *NativeClient, workers),
		all:     make([]*NativeClient, 0, workers),
	}
	for range workers {
		client, err := NewNativeClient(ctx, path)
		if err != nil {
			_ = admitter.closeClients()
			return nil, err
		}
		admitter.all = append(admitter.all, client)
	}
	probeCtx, cancel := context.WithTimeout(ctx, nativeCallTimeout)
	defer cancel()
	for _, client := range admitter.all {
		if _, err := admitNative(probeCtx, client, nil, nil); err != nil {
			_ = admitter.closeClients()
			return nil, fmt.Errorf("probe native source event admission worker: %w", err)
		}
		admitter.clients <- client
	}
	return admitter, nil
}

// Admit evaluates one page with an available native worker.
func (a *NativeAdmitter) Admit(ctx context.Context, events []*cerebrov1.EventEnvelope, contracts []sourcecdk.EventContract) (Response, error) {
	if a == nil {
		return Response{}, errors.New("native source event admitter is required")
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return Response{}, errors.New("native source event admitter is closed")
	}
	a.active.Add(1)
	a.mu.Unlock()
	defer a.active.Done()

	waitStarted := time.Now()
	availableAtEnqueue := len(a.clients)
	select {
	case client := <-a.clients:
		waitDuration := time.Since(waitStarted)
		telemetry.Event(ctx, "source_runtime.event_admission_worker_acquired", telemetry.Attrs(
			telemetry.Field{Key: "worker_pool_capacity", Value: cap(a.clients)},
			telemetry.Field{Key: "workers_available_at_enqueue", Value: availableAtEnqueue},
			telemetry.Field{Key: "queue_wait_duration_ms", Value: float64(waitDuration) / float64(time.Millisecond)},
			telemetry.Field{Key: "queued", Value: availableAtEnqueue == 0},
		))
		defer func() { a.clients <- client }()
		return admitNative(ctx, client, events, contracts)
	case <-ctx.Done():
		telemetry.Event(ctx, "source_runtime.event_admission_worker_wait_failed", telemetry.Attrs(
			telemetry.Field{Key: "worker_pool_capacity", Value: cap(a.clients)},
			telemetry.Field{Key: "workers_available_at_enqueue", Value: availableAtEnqueue},
			telemetry.Field{Key: "queue_wait_duration_ms", Value: float64(time.Since(waitStarted)) / float64(time.Millisecond)},
			telemetry.Field{Key: "error_kind", Value: "context_done"},
		))
		return Response{}, ctx.Err()
	}
}

// Close waits for active admissions and terminates every owned worker.
func (a *NativeAdmitter) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	a.active.Wait()

	return a.closeClients()
}

func (a *NativeAdmitter) closeClients() error {
	var closeErrors []error
	for _, client := range a.all {
		if err := client.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}

// NativeClient owns one persistent, capability-free Rust admission worker.
// Calls are serialized because the worker protocol preserves request order.
type NativeClient struct {
	path      string
	env       []string
	workerCtx context.Context

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Reader
	closed bool
}

// NewNativeClient configures a persistent native admission worker.
func NewNativeClient(ctx context.Context, path string) (*NativeClient, error) {
	if ctx == nil {
		return nil, errors.New("native source event admission worker context is required")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("native source event admission worker path is required")
	}
	resolvedPath, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("find native source event admission worker %q: %w", path, err)
	}
	return &NativeClient{path: resolvedPath, env: []string{}, workerCtx: ctx}, nil
}

// Evaluate sends one bounded admission request to the native Rust worker.
func (c *NativeClient) Evaluate(ctx context.Context, payload []byte) ([]byte, error) {
	return c.evaluate(ctx, nativeEncodingJSON, payload)
}

func (c *NativeClient) evaluateCBOR(ctx context.Context, payload []byte) ([]byte, error) {
	return c.evaluate(ctx, nativeEncodingCBOR, payload)
}

func (c *NativeClient) evaluate(ctx context.Context, encoding byte, payload []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("native source event admission client is required")
	}
	if ctx == nil {
		return nil, errors.New("native source event admission context is required")
	}
	if len(payload) > MaxInputBytes {
		return nil, fmt.Errorf("native source event admission input is %d bytes; maximum is %d", len(payload), MaxInputBytes)
	}
	callCtx, cancel := context.WithTimeout(ctx, nativeCallTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("native source event admission client is closed")
	}
	if err := c.startLocked(); err != nil {
		return nil, err
	}
	stdin := c.stdin
	stdout := c.stdout

	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		response, err := roundTripNative(stdin, stdout, encoding, payload)
		done <- result{payload: response, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			return nil, errors.Join(result.err, c.stopLocked())
		}
		return result.payload, nil
	case <-callCtx.Done():
		stopErr := c.stopLocked()
		<-done
		return nil, errors.Join(callCtx.Err(), stopErr)
	}
}

// Close terminates the owned native worker.
func (c *NativeClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.stopLocked()
}

func (c *NativeClient) startLocked() error {
	if c.cmd != nil {
		return nil
	}
	command := exec.CommandContext(c.workerCtx, c.path) // #nosec G204 G702 -- the validated operator path is executed without shell expansion, arguments, or inherited environment.
	command.Env = append([]string{}, c.env...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open native source event admission stdin: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("open native source event admission stdout: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return fmt.Errorf("start native source event admission worker: %w", err)
	}
	c.cmd = command
	c.stdin = bufio.NewWriter(stdin)
	c.stdout = bufio.NewReader(stdout)
	return nil
}

func roundTripNative(stdin *bufio.Writer, stdout *bufio.Reader, encoding byte, payload []byte) ([]byte, error) {
	var header [nativeFrameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)+1)) // #nosec G115 -- payload length is bounded above by MaxInputBytes.
	if _, err := stdin.Write(header[:]); err != nil {
		return nil, fmt.Errorf("write native source event admission header: %w", err)
	}
	if err := stdin.WriteByte(encoding); err != nil {
		return nil, fmt.Errorf("write native source event admission encoding: %w", err)
	}
	if _, err := stdin.Write(payload); err != nil {
		return nil, fmt.Errorf("write native source event admission request: %w", err)
	}
	if err := stdin.Flush(); err != nil {
		return nil, fmt.Errorf("flush native source event admission request: %w", err)
	}
	if _, err := io.ReadFull(stdout, header[:]); err != nil {
		return nil, fmt.Errorf("read native source event admission header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxOutputBytes+1 {
		return nil, fmt.Errorf("native source event admission output is %d bytes; maximum is %d", length, MaxOutputBytes)
	}
	responseEncoding, err := stdout.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read native source event admission encoding: %w", err)
	}
	if responseEncoding != encoding {
		return nil, fmt.Errorf("native source event admission response encoding is %d; want %d", responseEncoding, encoding)
	}
	response := make([]byte, int(length)-1)
	if _, err := io.ReadFull(stdout, response); err != nil {
		return nil, fmt.Errorf("read native source event admission response: %w", err)
	}
	return response, nil
}

func (c *NativeClient) stopLocked() error {
	if c.cmd == nil {
		return nil
	}
	command := c.cmd
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	err := command.Wait()
	c.cmd = nil
	c.stdin = nil
	c.stdout = nil
	if err != nil && !isExpectedWorkerStop(err) {
		return fmt.Errorf("stop native source event admission worker: %w", err)
	}
	return nil
}

func isExpectedWorkerStop(err error) bool {
	var exitError *exec.ExitError
	return errors.As(err, &exitError)
}

func admitNative(ctx context.Context, client *NativeClient, events []*cerebrov1.EventEnvelope, contracts []sourcecdk.EventContract) (Response, error) {
	request, err := newAdmissionRequest(events, contracts)
	if err != nil {
		return Response{}, err
	}
	payload, err := cbor.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf("%w: encode native request: %w", ErrKernelUnavailable, err)
	}
	result, err := client.evaluateCBOR(ctx, payload)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %w", ErrKernelUnavailable, err)
	}
	var outcome admissionOutcome
	if nativeCBORDecoderError != nil {
		return Response{}, fmt.Errorf("%w: configure native response decoder: %w", ErrKernelUnavailable, nativeCBORDecoderError)
	}
	if err := nativeCBORDecoder.Unmarshal(result, &outcome); err != nil {
		return Response{}, wasmhost.Diagnose(wasmhost.DiagnosticOutputInvalid, fmt.Errorf("%w: decode native response: %w", ErrKernelUnavailable, err))
	}
	return decodeAdmissionOutcome(outcome, events)
}
