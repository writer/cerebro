package wasmjson

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const descriptorSize = 16

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
	config   Config
	once     sync.Once
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	err      error
}

// New returns a lazy evaluator. Configuration and module ABI errors are reported on the first call
// and cached for subsequent calls.
func New(config Config) *Evaluator {
	config.Name = strings.TrimSpace(config.Name)
	config.ABIVersionExport = strings.TrimSpace(config.ABIVersionExport)
	config.AllocateExport = strings.TrimSpace(config.AllocateExport)
	config.EvaluateExport = strings.TrimSpace(config.EvaluateExport)
	return &Evaluator{config: config}
}

// Evaluate passes one bounded JSON payload through the embedded module.
func (e *Evaluator) Evaluate(ctx context.Context, payload []byte) ([]byte, error) {
	if err := e.validatePayload(payload); err != nil {
		return nil, err
	}
	e.once.Do(func() {
		e.initialize(ctx)
	})
	if e.err != nil {
		return nil, e.err
	}

	callCtx, cancel := context.WithTimeout(ctx, e.config.CallTimeout)
	defer cancel()
	module, err := e.runtime.InstantiateModule(callCtx, e.compiled, moduleConfig())
	if err != nil {
		return nil, e.wrap("instantiate module", err)
	}
	defer func() {
		_ = module.Close(callCtx)
	}()

	allocate := module.ExportedFunction(e.config.AllocateExport)
	evaluate := module.ExportedFunction(e.config.EvaluateExport)
	if allocate == nil || evaluate == nil || module.Memory() == nil {
		return nil, e.errorf("exports are incomplete")
	}
	inputAllocation, err := allocate.Call(callCtx, uint64(len(payload)))
	if err != nil {
		return nil, e.wrap("allocate input", err)
	}
	inputPointer, err := e.pointer(inputAllocation, "input allocation")
	if err != nil {
		return nil, err
	}
	descriptorAllocation, err := allocate.Call(callCtx, descriptorSize)
	if err != nil {
		return nil, e.wrap("allocate result descriptor", err)
	}
	descriptorPointer, err := e.pointer(descriptorAllocation, "result descriptor allocation")
	if err != nil {
		return nil, err
	}
	if !module.Memory().Write(inputPointer, payload) {
		return nil, e.errorf("write input memory")
	}
	status, err := evaluate.Call(callCtx, uint64(inputPointer), uint64(len(payload)), uint64(descriptorPointer))
	if err != nil {
		return nil, e.wrap("execute module", err)
	}
	if len(status) != 1 || status[0] != 0 {
		return nil, e.errorf("execution status = %v", status)
	}
	descriptor, ok := module.Memory().Read(descriptorPointer, descriptorSize)
	if !ok {
		return nil, e.errorf("read result descriptor")
	}
	if resultStatus := binary.LittleEndian.Uint32(descriptor[0:4]); resultStatus != 0 {
		return nil, e.errorf("result status = %d", resultStatus)
	}
	if reserved := binary.LittleEndian.Uint32(descriptor[12:16]); reserved != 0 {
		return nil, e.errorf("result reserved field = %d", reserved)
	}
	outputPointer := binary.LittleEndian.Uint32(descriptor[4:8])
	outputLength := binary.LittleEndian.Uint32(descriptor[8:12])
	if outputLength > e.config.MaxOutputBytes {
		return nil, e.errorf("output is %d bytes; maximum is %d", outputLength, e.config.MaxOutputBytes)
	}
	output, ok := module.Memory().Read(outputPointer, outputLength)
	if !ok {
		return nil, e.errorf("read output memory")
	}
	return append([]byte(nil), output...), nil
}

func (e *Evaluator) initialize(ctx context.Context) {
	if err := e.validateConfig(); err != nil {
		e.err = err
		return
	}
	initCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.config.InitializeTimeout)
	defer cancel()
	config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(e.config.MemoryLimitPages)
	e.runtime = wazero.NewRuntimeWithConfig(initCtx, config)
	e.compiled, e.err = e.runtime.CompileModule(initCtx, e.config.Module)
	if e.err != nil {
		e.err = e.wrap("compile module", e.err)
		e.closeRuntime(initCtx)
		return
	}
	if err := e.validateABI(); err != nil {
		e.err = err
		e.closeRuntime(initCtx)
		return
	}
	module, err := e.runtime.InstantiateModule(initCtx, e.compiled, moduleConfig())
	if err != nil {
		e.err = e.wrap("instantiate module for ABI check", err)
		e.closeRuntime(initCtx)
		return
	}
	defer func() {
		_ = module.Close(initCtx)
	}()
	versionFunction := module.ExportedFunction(e.config.ABIVersionExport)
	version, err := versionFunction.Call(initCtx)
	if err != nil {
		e.err = e.wrap("read ABI version", err)
		e.closeRuntime(initCtx)
		return
	}
	if len(version) != 1 || version[0] != e.config.ABIVersion {
		e.err = e.errorf("ABI version = %v; want %d", version, e.config.ABIVersion)
		e.closeRuntime(initCtx)
	}
}

func (e *Evaluator) validateConfig() error {
	switch {
	case e.config.Name == "":
		return errors.New("embedded JSON Wasm evaluator name is required")
	case len(e.config.Module) == 0:
		return e.errorf("module is empty")
	case e.config.ABIVersionExport == "":
		return e.errorf("ABI version export is required")
	case e.config.AllocateExport == "":
		return e.errorf("allocation export is required")
	case e.config.EvaluateExport == "":
		return e.errorf("evaluation export is required")
	case e.config.MemoryLimitPages == 0:
		return e.errorf("memory limit must be positive")
	case e.config.MaxInputBytes == 0:
		return e.errorf("input limit must be positive")
	case e.config.MaxOutputBytes == 0:
		return e.errorf("output limit must be positive")
	case e.config.InitializeTimeout <= 0:
		return e.errorf("initialization timeout must be positive")
	case e.config.CallTimeout <= 0:
		return e.errorf("call timeout must be positive")
	default:
		return nil
	}
}

func (e *Evaluator) validatePayload(payload []byte) error {
	if uint64(len(payload)) > uint64(e.config.MaxInputBytes) {
		return e.errorf("input is %d bytes; maximum is %d", len(payload), e.config.MaxInputBytes)
	}
	if uint64(len(payload)) > math.MaxUint32 {
		return e.errorf("input exceeds the Wasm32 address space")
	}
	return nil
}

func (e *Evaluator) validateABI() error {
	if len(e.compiled.ImportedFunctions()) != 0 || len(e.compiled.ImportedMemories()) != 0 {
		return e.errorf("module must not import functions or memory")
	}
	if _, ok := e.compiled.ExportedMemories()["memory"]; !ok {
		return e.errorf("memory export is missing")
	}
	exports := e.compiled.ExportedFunctions()
	required := []struct {
		name    string
		params  []api.ValueType
		results []api.ValueType
	}{
		{name: e.config.ABIVersionExport, results: []api.ValueType{api.ValueTypeI32}},
		{name: e.config.AllocateExport, params: []api.ValueType{api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
		{name: e.config.EvaluateExport, params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
	}
	for _, expected := range required {
		definition, ok := exports[expected.name]
		if !ok {
			return e.errorf("export %q is missing", expected.name)
		}
		if !slices.Equal(definition.ParamTypes(), expected.params) || !slices.Equal(definition.ResultTypes(), expected.results) {
			return e.errorf("export %q has an incompatible signature", expected.name)
		}
	}
	return nil
}

func (e *Evaluator) pointer(results []uint64, operation string) (uint32, error) {
	if len(results) != 1 {
		return 0, e.errorf("%s returned %d values; want 1", operation, len(results))
	}
	if results[0] > math.MaxUint32 {
		return 0, e.errorf("%s pointer exceeds the Wasm32 address space", operation)
	}
	return uint32(results[0]), nil // #nosec G115 -- the value is bounded to MaxUint32 above.
}

func (e *Evaluator) closeRuntime(ctx context.Context) {
	if e.runtime != nil {
		_ = e.runtime.Close(ctx)
	}
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

func moduleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("").WithStartFunctions()
}
