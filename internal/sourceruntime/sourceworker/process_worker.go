package sourceworker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ProcessWorker invokes the standalone Rust worker with bounded protobuf I/O.
type ProcessWorker struct{ path string }

// NewProcessWorker binds the host to one configured worker executable path.
func NewProcessWorker(path string) *ProcessWorker {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || filepath.Base(path) != "source_worker" {
		path = ""
	}
	return &ProcessWorker{path: path}
}

// Plan invokes the credential-free worker planning command.
func (w *ProcessWorker) Plan(ctx context.Context, plan *cerebrov1.SourceExecutionPlanV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	output, err := w.run(ctx, "plan", plan, workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceWorkerHTTPRequestV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker plan output is invalid", ErrInvalidExecution)
	}
	return result, nil
}

// Decode invokes the credential-free worker decode command.
func (w *ProcessWorker) Decode(ctx context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	output, err := w.run(ctx, "decode", request, int64(maxResponseBytes)+workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceWorkerDecodeResultV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker decode output is invalid", ErrInvalidExecution)
	}
	return result, nil
}

func (w *ProcessWorker) run(ctx context.Context, command string, message proto.Message, maxOutput int64) ([]byte, error) {
	if w == nil || w.path == "" {
		return nil, fmt.Errorf("%w: worker executable is not configured", ErrInvalidExecution)
	}
	input, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%w: worker input is invalid", ErrInvalidExecution)
	}
	// #nosec G204,G702 -- NewProcessWorker accepts only an absolute executable named source_worker; command is private and closed to plan/decode.
	process := exec.CommandContext(ctx, w.path, command)
	process.Env = []string{"LANG=C", "LC_ALL=C"}
	process.Stdin = bytes.NewReader(input)
	stdout := &boundedBuffer{remaining: maxOutput}
	stderr := &boundedBuffer{remaining: workerOverhead}
	process.Stdout = stdout
	process.Stderr = stderr
	if err := process.Run(); err != nil {
		return nil, classifyWorkerFailure(stderr.String())
	}
	return stdout.Bytes(), nil
}

func classifyWorkerFailure(stderr string) error {
	class := strings.TrimSpace(stderr)
	switch {
	case strings.HasPrefix(class, "source_worker.response_too_large:"):
		return ErrProviderResponseTooLarge
	case strings.HasPrefix(class, "source_worker.invalid_provider_response:"):
		return ErrProviderMalformedResponse
	case strings.HasPrefix(class, "source_worker.unsupported_status:"):
		return ErrProviderMalformedResponse
	case strings.HasPrefix(class, "source_worker.protobuf:"),
		strings.HasPrefix(class, "source_worker.invalid_plan:"),
		strings.HasPrefix(class, "source_worker.missing_execution_identity:"):
		return ErrWorkerContract
	default:
		return ErrWorkerInternal
	}
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int64
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if int64(len(value)) > b.remaining {
		return 0, fmt.Errorf("%w: worker output exceeds %s bytes", ErrInvalidExecution, strconv.FormatInt(b.remaining, 10))
	}
	written, err := b.Buffer.Write(value)
	b.remaining -= int64(written)
	return written, err
}
