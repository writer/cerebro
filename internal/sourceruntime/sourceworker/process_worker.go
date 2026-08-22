package sourceworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const controlOutputBound = int64((12 << 20) + (64 << 10))

// ProcessWorker invokes the standalone Rust worker with bounded protocol I/O.
type ProcessWorker struct{ path string }

// NewProcessWorker binds the host to one configured worker executable path.
func NewProcessWorker(path string) *ProcessWorker {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || filepath.Base(path) != "source_worker" {
		path = ""
	}
	return &ProcessWorker{path: path}
}

func (w *ProcessWorker) Compile(ctx context.Context, request SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	output, err := w.runJSON(ctx, "compile", request, workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceExecutionPlanV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker compiled plan is invalid", ErrInvalidExecution)
	}
	return result, nil
}

func (w *ProcessWorker) Context(ctx context.Context, request ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	output, err := w.runJSON(ctx, "context", request, workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceWorkerExecutionContextV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker context output is invalid", ErrInvalidExecution)
	}
	return result, nil
}

func (w *ProcessWorker) Plan(ctx context.Context, request *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	result := new(cerebrov1.SourceWorkerHTTPRequestV1)
	return result, w.runProto(ctx, "plan", request, result, workerOverhead)
}

func (w *ProcessWorker) Decode(ctx context.Context, request *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error) {
	result := new(cerebrov1.SourceWorkerDecodeResultV1)
	return result, w.runProto(ctx, "decode", request, result, int64(maxResponseBytes)+workerOverhead)
}

func (w *ProcessWorker) Transition(ctx context.Context, request LifecycleRequest) (*LifecycleDecision, error) {
	control := struct {
		Plan, Context, Receipt, Result []byte
		CompletedPhase                 Phase  `json:"completed_phase"`
		PriorTransitionDigest          string `json:"prior_transition_digest"`
		CurrentLeaseGeneration         uint64 `json:"current_lease_generation"`
	}{CompletedPhase: request.CompletedPhase, PriorTransitionDigest: request.PriorTransitionDigest, CurrentLeaseGeneration: request.CurrentLeaseGeneration}
	var err error
	for target, message := range map[*[]byte]proto.Message{&control.Plan: request.Plan, &control.Context: request.Context, &control.Receipt: request.Receipt, &control.Result: request.Result} {
		if message == nil {
			return nil, fmt.Errorf("%w: lifecycle input is incomplete", ErrInvalidExecution)
		}
		*target, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("%w: lifecycle input is invalid", ErrInvalidExecution)
		}
	}
	output, err := w.runJSON(ctx, "transition", control, controlOutputBound)
	if err != nil {
		return nil, err
	}
	encoded := struct {
		RequiredPhase                 Phase    `json:"required_phase"`
		TransitionDigest              string   `json:"transition_digest"`
		AdmittedRecords               [][]byte `json:"admitted_records"`
		CheckpointCursor              string   `json:"checkpoint_cursor"`
		CheckpointWatermarkUnixMillis int64    `json:"checkpoint_watermark_unix_millis"`
	}{}
	if err := json.Unmarshal(output, &encoded); err != nil {
		return nil, fmt.Errorf("%w: worker transition output is invalid", ErrInvalidExecution)
	}
	decision := &LifecycleDecision{RequiredPhase: encoded.RequiredPhase, TransitionDigest: encoded.TransitionDigest, CheckpointCursor: encoded.CheckpointCursor, CheckpointWatermarkUnixMillis: encoded.CheckpointWatermarkUnixMillis}
	for _, value := range encoded.AdmittedRecords {
		record := new(cerebrov1.SourceWorkerRecordV1)
		if err := proto.Unmarshal(value, record); err != nil {
			return nil, fmt.Errorf("%w: worker admitted record is invalid", ErrInvalidExecution)
		}
		decision.AdmittedRecords = append(decision.AdmittedRecords, record)
	}
	return decision, nil
}

func (w *ProcessWorker) runProto(ctx context.Context, command string, input proto.Message, output proto.Message, bound int64) error {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(input)
	if err != nil {
		return fmt.Errorf("%w: worker input is invalid", ErrInvalidExecution)
	}
	encoded, err = w.run(ctx, command, encoded, bound)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(encoded, output); err != nil {
		return fmt.Errorf("%w: worker output is invalid", ErrInvalidExecution)
	}
	return nil
}

func (w *ProcessWorker) runJSON(ctx context.Context, command string, input any, bound int64) ([]byte, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: worker control input is invalid", ErrInvalidExecution)
	}
	return w.run(ctx, command, encoded, bound)
}

func (w *ProcessWorker) run(ctx context.Context, command string, input []byte, bound int64) ([]byte, error) {
	if w == nil || w.path == "" {
		return nil, fmt.Errorf("%w: worker executable is not configured", ErrInvalidExecution)
	}
	// #nosec G204,G702 -- path and command are closed by the constructor and Worker methods.
	process := exec.CommandContext(ctx, w.path, command)
	process.Env = []string{"LANG=C", "LC_ALL=C"}
	process.Stdin = bytes.NewReader(input)
	stdout, stderr := &boundedBuffer{remaining: bound}, &boundedBuffer{remaining: workerOverhead}
	process.Stdout, process.Stderr = stdout, stderr
	if err := process.Run(); err != nil {
		return nil, classifyWorkerFailure(stderr.String())
	}
	return stdout.Bytes(), nil
}

func classifyWorkerFailure(stderr string) error {
	class := strings.TrimSpace(stderr)
	switch {
	case strings.HasPrefix(class, "source_worker.unknown_adapter:"):
		return ErrWorkerUnsupported
	case strings.HasPrefix(class, "source_worker.response_too_large:"):
		return ErrProviderResponseTooLarge
	case strings.HasPrefix(class, "source_worker.malformed_response:"), strings.HasPrefix(class, "source_worker.invalid_provider_record:"), strings.HasPrefix(class, "source_worker.unexpected_provider_status:"):
		return ErrProviderMalformedResponse
	case strings.HasPrefix(class, "source_worker.protobuf:"), strings.HasPrefix(class, "source_worker.invalid_plan:"), strings.HasPrefix(class, "source_worker.invalid_execution_context:"), strings.HasPrefix(class, "source_worker.missing_execution_identity:"), strings.HasPrefix(class, "source_worker.tenant_mismatch:"), strings.HasPrefix(class, "source_worker.stale_generation:"), strings.HasPrefix(class, "source_worker.invalid_digest:"), strings.HasPrefix(class, "source_worker.invalid_cursor:"), strings.HasPrefix(class, "source_worker.duplicate_conflict:"), strings.HasPrefix(class, "source_worker.event_contract_rejected:"), strings.HasPrefix(class, "source_worker.lease_lost:"):
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
