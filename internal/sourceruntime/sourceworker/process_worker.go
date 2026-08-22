package sourceworker

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
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

// Compile selects one exact source-family plan through the closed Rust registry.
func (w *ProcessWorker) Compile(ctx context.Context, request SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	input := appendStringField(nil, 1, request.SourceID)
	input = appendStringField(input, 2, request.FamilyID)
	output, err := w.runBytes(ctx, "compile", input, workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceExecutionPlanV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker compiled plan is invalid", ErrInvalidExecution)
	}
	return result, nil
}

// Context asks Rust to mint the trusted logical-page execution identity.
func (w *ProcessWorker) Context(ctx context.Context, request ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	if request.ObservedAtUnixMillis <= 0 {
		return nil, fmt.Errorf("%w: worker observation time is invalid", ErrInvalidExecution)
	}
	input := appendStringField(nil, 1, request.TenantID)
	input = appendStringField(input, 2, request.RuntimeID)
	input = appendStringField(input, 3, request.PriorCursor)
	input = protowire.AppendTag(input, 4, protowire.VarintType)
	input = protowire.AppendVarint(input, uint64(request.PageNumber))
	input = protowire.AppendTag(input, 5, protowire.VarintType)
	input = protowire.AppendVarint(input, request.RuntimeGeneration)
	input = protowire.AppendTag(input, 6, protowire.VarintType)
	input = protowire.AppendVarint(input, request.LeaseGeneration)
	input = protowire.AppendTag(input, 7, protowire.VarintType)
	input = protowire.AppendVarint(input, uint64(request.ObservedAtUnixMillis))
	output, err := w.runBytes(ctx, "context", input, workerOverhead)
	if err != nil {
		return nil, err
	}
	result := new(cerebrov1.SourceWorkerExecutionContextV1)
	if err := proto.Unmarshal(output, result); err != nil {
		return nil, fmt.Errorf("%w: worker context output is invalid", ErrInvalidExecution)
	}
	return result, nil
}

// Plan invokes the credential-free worker planning command.
func (w *ProcessWorker) Plan(ctx context.Context, request *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error) {
	output, err := w.run(ctx, "plan", request, workerOverhead)
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

// Transition asks Rust for the only durable lifecycle action allowed next.
func (w *ProcessWorker) Transition(ctx context.Context, request LifecycleRequest) (*LifecycleDecision, error) {
	input, err := marshalLifecycleRequest(request)
	if err != nil {
		return nil, err
	}
	output, err := w.runBytes(ctx, "transition", input, int64(maxResponseBytes)+workerOverhead)
	if err != nil {
		return nil, err
	}
	return unmarshalLifecycleDecision(output)
}

func (w *ProcessWorker) run(ctx context.Context, command string, message proto.Message, maxOutput int64) ([]byte, error) {
	if w == nil || w.path == "" {
		return nil, fmt.Errorf("%w: worker executable is not configured", ErrInvalidExecution)
	}
	input, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%w: worker input is invalid", ErrInvalidExecution)
	}
	return w.runBytes(ctx, command, input, maxOutput)
}

func (w *ProcessWorker) runBytes(ctx context.Context, command string, input []byte, maxOutput int64) ([]byte, error) {
	if w == nil || w.path == "" {
		return nil, fmt.Errorf("%w: worker executable is not configured", ErrInvalidExecution)
	}
	// #nosec G204,G702 -- NewProcessWorker accepts only an absolute executable named source_worker; command is private and closed by Worker methods.
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

func marshalLifecycleRequest(request LifecycleRequest) ([]byte, error) {
	input := make([]byte, 0, workerOverhead)
	fields := []struct {
		number  protowire.Number
		message proto.Message
	}{{1, request.Plan}, {2, request.Context}, {3, request.Receipt}, {4, request.Result}}
	for _, field := range fields {
		number, message := field.number, field.message
		if message == nil {
			return nil, fmt.Errorf("%w: lifecycle input is incomplete", ErrInvalidExecution)
		}
		value, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("%w: lifecycle input is invalid", ErrInvalidExecution)
		}
		input = protowire.AppendTag(input, number, protowire.BytesType)
		input = protowire.AppendBytes(input, value)
	}
	input = protowire.AppendTag(input, 5, protowire.VarintType)
	input = protowire.AppendVarint(input, uint64(request.CompletedPhase))
	input = appendStringField(input, 6, request.PriorTransitionDigest)
	input = protowire.AppendTag(input, 7, protowire.VarintType)
	input = protowire.AppendVarint(input, request.CurrentLeaseGeneration)
	return input, nil
}

func unmarshalLifecycleDecision(value []byte) (*LifecycleDecision, error) {
	decision := new(LifecycleDecision)
	for len(value) > 0 {
		number, wireType, tagBytes := protowire.ConsumeTag(value)
		if tagBytes < 0 {
			return nil, fmt.Errorf("%w: worker transition output is invalid", ErrInvalidExecution)
		}
		value = value[tagBytes:]
		switch number {
		case 1, 5:
			field, consumed := protowire.ConsumeVarint(value)
			if consumed < 0 {
				return nil, fmt.Errorf("%w: worker transition varint is invalid", ErrInvalidExecution)
			}
			if number == 1 {
				if field > math.MaxUint32 {
					return nil, fmt.Errorf("%w: worker transition phase is invalid", ErrInvalidExecution)
				}
				decision.RequiredPhase = Phase(uint32(field))
			} else if field > math.MaxInt64 {
				return nil, fmt.Errorf("%w: worker transition watermark is invalid", ErrInvalidExecution)
			} else {
				decision.CheckpointWatermarkUnixMillis = int64(field)
			}
			value = value[consumed:]
		case 2, 3, 4:
			field, consumed := protowire.ConsumeBytes(value)
			if consumed < 0 {
				return nil, fmt.Errorf("%w: worker transition bytes are invalid", ErrInvalidExecution)
			}
			switch number {
			case 2:
				decision.TransitionDigest = string(field)
			case 3:
				record := new(cerebrov1.SourceWorkerRecordV1)
				if err := proto.Unmarshal(field, record); err != nil {
					return nil, fmt.Errorf("%w: worker admitted record is invalid", ErrInvalidExecution)
				}
				decision.AdmittedRecords = append(decision.AdmittedRecords, record)
			case 4:
				decision.CheckpointCursor = string(field)
			}
			value = value[consumed:]
		default:
			consumed := protowire.ConsumeFieldValue(number, wireType, value)
			if consumed < 0 {
				return nil, fmt.Errorf("%w: worker transition field is invalid", ErrInvalidExecution)
			}
			value = value[consumed:]
		}
	}
	return decision, nil
}

func appendStringField(output []byte, number protowire.Number, value string) []byte {
	output = protowire.AppendTag(output, number, protowire.BytesType)
	return protowire.AppendString(output, value)
}

func classifyWorkerFailure(stderr string) error {
	class := strings.TrimSpace(stderr)
	switch {
	case strings.HasPrefix(class, "source_worker.unknown_adapter:"):
		return ErrWorkerUnsupported
	case strings.HasPrefix(class, "source_worker.response_too_large:"):
		return ErrProviderResponseTooLarge
	case strings.HasPrefix(class, "source_worker.malformed_response:"),
		strings.HasPrefix(class, "source_worker.invalid_provider_record:"):
		return ErrProviderMalformedResponse
	case strings.HasPrefix(class, "source_worker.unexpected_provider_status:"):
		return ErrProviderMalformedResponse
	case strings.HasPrefix(class, "source_worker.protobuf:"),
		strings.HasPrefix(class, "source_worker.invalid_plan:"),
		strings.HasPrefix(class, "source_worker.invalid_execution_context:"),
		strings.HasPrefix(class, "source_worker.missing_execution_identity:"),
		strings.HasPrefix(class, "source_worker.tenant_mismatch:"),
		strings.HasPrefix(class, "source_worker.stale_generation:"),
		strings.HasPrefix(class, "source_worker.invalid_digest:"),
		strings.HasPrefix(class, "source_worker.invalid_cursor:"),
		strings.HasPrefix(class, "source_worker.duplicate_conflict:"),
		strings.HasPrefix(class, "source_worker.event_contract_rejected:"):
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
