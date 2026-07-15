package wasmjson

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tetratelabs/wazero/api"
	"github.com/writer/cerebro/internal/wasmhost"
)

const descriptorSize = 16

var (
	// ErrInvalidConfig indicates that an evaluator cannot initialize with its supplied configuration.
	ErrInvalidConfig = errors.New("embedded JSON Wasm evaluator configuration is invalid")
	// ErrInputTooLarge indicates that an input exceeds either the configured limit or Wasm32 address space.
	ErrInputTooLarge = errors.New("embedded JSON Wasm evaluator input exceeds maximum")
)

// Config defines one embedded, no-import Wasm module that accepts and returns JSON bytes.
type Config struct {
	Name              string
	Module            []byte
	ABIVersion        uint64
	ABIVersionExport  string
	AllocateExport    string
	EvaluateExport    string
	MemoryLimitPages  uint32
	MaxInputBytes     uint32
	MaxOutputBytes    uint32
	InitializeTimeout time.Duration
	CallTimeout       time.Duration
}

// Evaluator lazily compiles one embedded module and creates an isolated guest instance per call.
type Evaluator struct {
	config    Config
	configErr error
	runtime   *wasmhost.Runtime
}

// New returns a lazy evaluator. Configuration and module ABI errors are reported on the first call
// and cached for subsequent calls.
func New(config Config) *Evaluator {
	config.Name = strings.TrimSpace(config.Name)
	config.ABIVersionExport = strings.TrimSpace(config.ABIVersionExport)
	config.AllocateExport = strings.TrimSpace(config.AllocateExport)
	config.EvaluateExport = strings.TrimSpace(config.EvaluateExport)
	evaluator := &Evaluator{
		config: config,
		runtime: wasmhost.New(wasmhost.Config{
			Name:             config.Name,
			Module:           config.Module,
			ABIVersion:       config.ABIVersion,
			ABIVersionExport: config.ABIVersionExport,
			Functions: []wasmhost.Function{
				{Name: config.AllocateExport, Params: []api.ValueType{api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
				{Name: config.EvaluateExport, Params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
			},
			MemoryLimitPages:  config.MemoryLimitPages,
			InitializeTimeout: config.InitializeTimeout,
			CallTimeout:       config.CallTimeout,
		}),
	}
	evaluator.configErr = evaluator.validateConfig()
	return evaluator
}

// Evaluate passes one bounded JSON payload through the embedded module.
func (e *Evaluator) Evaluate(ctx context.Context, payload []byte) ([]byte, error) {
	if e.configErr != nil {
		return nil, e.configErr
	}
	if err := e.validatePayload(payload); err != nil {
		return nil, err
	}
	var output []byte
	err := e.runtime.Run(ctx, func(callCtx context.Context, module api.Module) error {
		allocate := module.ExportedFunction(e.config.AllocateExport)
		evaluate := module.ExportedFunction(e.config.EvaluateExport)
		if allocate == nil || evaluate == nil || module.Memory() == nil {
			return e.errorf("exports are incomplete")
		}
		inputAllocation, err := allocate.Call(callCtx, uint64(len(payload)))
		if err != nil {
			return e.wrap("allocate input", err)
		}
		inputPointer, err := e.pointer(inputAllocation, "input allocation")
		if err != nil {
			return err
		}
		descriptorAllocation, err := allocate.Call(callCtx, descriptorSize)
		if err != nil {
			return e.wrap("allocate result descriptor", err)
		}
		descriptorPointer, err := e.pointer(descriptorAllocation, "result descriptor allocation")
		if err != nil {
			return err
		}
		if !module.Memory().Write(inputPointer, payload) {
			return e.errorf("write input memory")
		}
		status, err := evaluate.Call(callCtx, uint64(inputPointer), uint64(len(payload)), uint64(descriptorPointer))
		if err != nil {
			return e.wrap("execute module", err)
		}
		if len(status) != 1 || status[0] != 0 {
			return e.errorf("execution status = %v", status)
		}
		descriptor, ok := module.Memory().Read(descriptorPointer, descriptorSize)
		if !ok {
			return e.errorf("read result descriptor")
		}
		if resultStatus := binary.LittleEndian.Uint32(descriptor[0:4]); resultStatus != 0 {
			return e.errorf("result status = %d", resultStatus)
		}
		if reserved := binary.LittleEndian.Uint32(descriptor[12:16]); reserved != 0 {
			return e.errorf("result reserved field = %d", reserved)
		}
		outputPointer := binary.LittleEndian.Uint32(descriptor[4:8])
		outputLength := binary.LittleEndian.Uint32(descriptor[8:12])
		if outputLength > e.config.MaxOutputBytes {
			return e.errorf("output is %d bytes; maximum is %d", outputLength, e.config.MaxOutputBytes)
		}
		outputBytes, ok := module.Memory().Read(outputPointer, outputLength)
		if !ok {
			return e.errorf("read output memory")
		}
		output = append([]byte(nil), outputBytes...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (e *Evaluator) validateConfig() error {
	switch {
	case e.config.Name == "":
		return e.errorfWith(ErrInvalidConfig, "name is required")
	case len(e.config.Module) == 0:
		return e.errorfWith(ErrInvalidConfig, "module is empty")
	case e.config.ABIVersionExport == "":
		return e.errorfWith(ErrInvalidConfig, "ABI version export is required")
	case e.config.AllocateExport == "":
		return e.errorfWith(ErrInvalidConfig, "allocation export is required")
	case e.config.EvaluateExport == "":
		return e.errorfWith(ErrInvalidConfig, "evaluation export is required")
	case e.config.MemoryLimitPages == 0:
		return e.errorfWith(ErrInvalidConfig, "memory limit must be positive")
	case e.config.MaxInputBytes == 0:
		return e.errorfWith(ErrInvalidConfig, "input limit must be positive")
	case e.config.MaxOutputBytes == 0:
		return e.errorfWith(ErrInvalidConfig, "output limit must be positive")
	case e.config.InitializeTimeout <= 0:
		return e.errorfWith(ErrInvalidConfig, "initialization timeout must be positive")
	case e.config.CallTimeout <= 0:
		return e.errorfWith(ErrInvalidConfig, "call timeout must be positive")
	default:
		return nil
	}
}

func (e *Evaluator) validatePayload(payload []byte) error {
	if uint64(len(payload)) > uint64(e.config.MaxInputBytes) {
		return e.inputTooLargeError(uint64(len(payload)), uint64(e.config.MaxInputBytes))
	}
	if uint64(len(payload)) > math.MaxUint32 {
		return e.inputTooLargeError(uint64(len(payload)), math.MaxUint32)
	}
	return nil
}

func (e *Evaluator) pointer(results []uint64, operation string) (uint32, error) {
	pointer, err := wasmhost.Pointer(results, operation)
	if err != nil {
		return 0, e.errorf("%s", err)
	}
	return pointer, nil
}

func (e *Evaluator) wrap(operation string, err error) error {
	return fmt.Errorf("%s: %s: %w", e.config.Name, operation, err)
}

func (e *Evaluator) errorf(format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if e.config.Name == "" {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %s", e.config.Name, message)
}

func (e *Evaluator) errorfWith(cause error, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if e.config.Name == "" {
		return fmt.Errorf("%w: %s", cause, message)
	}
	return fmt.Errorf("%s: %w: %s", e.config.Name, cause, message)
}

func (e *Evaluator) inputTooLargeError(inputBytes, maxBytes uint64) error {
	return e.errorfWith(ErrInputTooLarge, "input is %d bytes; maximum is %d", inputBytes, maxBytes)
}
