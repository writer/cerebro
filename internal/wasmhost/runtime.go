// Package wasmhost owns the shared lifecycle for embedded, no-import Wasm modules.
package wasmhost

import (
	"context"
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

// ErrInvalidConfig reports an incomplete or inconsistent runtime contract.
var ErrInvalidConfig = errors.New("embedded Wasm runtime configuration is invalid")

const wasm32MaxMemoryPages uint32 = 65_536

// Function describes one required guest export.
type Function struct {
	Name    string
	Params  []api.ValueType
	Results []api.ValueType
}

// Config defines one embedded Wasm module and its bounded runtime contract.
type Config struct {
	Name              string
	Module            []byte
	ABIVersion        uint64
	ABIVersionExport  string
	Functions         []Function
	MemoryLimitPages  uint32
	InitializeTimeout time.Duration
	CallTimeout       time.Duration
}

// Runtime lazily compiles one embedded module and creates an isolated instance per call.
type Runtime struct {
	config   Config
	once     sync.Once
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	err      error
}

// New returns a lazy embedded Wasm runtime.
func New(config Config) *Runtime {
	config.Name = strings.TrimSpace(config.Name)
	config.ABIVersionExport = strings.TrimSpace(config.ABIVersionExport)
	config.Functions = append([]Function(nil), config.Functions...)
	for i := range config.Functions {
		config.Functions[i].Name = strings.TrimSpace(config.Functions[i].Name)
		config.Functions[i].Params = append([]api.ValueType(nil), config.Functions[i].Params...)
		config.Functions[i].Results = append([]api.ValueType(nil), config.Functions[i].Results...)
	}
	return &Runtime{config: config}
}

// Run invokes call with a fresh module instance governed by the configured timeout.
func (r *Runtime) Run(ctx context.Context, call func(context.Context, api.Module) error) error {
	if r == nil {
		return fmt.Errorf("%w: runtime is required", ErrInvalidConfig)
	}
	if ctx == nil {
		return r.errorfWith(ErrInvalidConfig, "context is required")
	}
	if call == nil {
		return r.errorfWith(ErrInvalidConfig, "call function is required")
	}
	r.once.Do(func() {
		r.initialize(ctx)
	})
	if r.err != nil {
		return r.err
	}

	callCtx, cancel := context.WithTimeout(ctx, r.config.CallTimeout)
	defer cancel()
	module, err := r.runtime.InstantiateModule(callCtx, r.compiled, moduleConfig())
	if err != nil {
		return r.wrap("instantiate module", err)
	}
	defer func() {
		_ = module.Close(callCtx)
	}()
	return call(callCtx, module)
}

// Pointer returns the single Wasm32 pointer produced by an allocation call.
func Pointer(results []uint64, operation string) (uint32, error) {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = "allocation"
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("%s returned %d values; want 1", operation, len(results))
	}
	if results[0] > math.MaxUint32 {
		return 0, fmt.Errorf("%s pointer exceeds the Wasm32 address space", operation)
	}
	return uint32(results[0]), nil // #nosec G115 -- the value is bounded to MaxUint32 above.
}

func (r *Runtime) initialize(ctx context.Context) {
	if err := r.validateConfig(); err != nil {
		r.err = err
		return
	}
	initCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.config.InitializeTimeout)
	defer cancel()
	config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(r.config.MemoryLimitPages)
	r.runtime = wazero.NewRuntimeWithConfig(initCtx, config)
	r.compiled, r.err = r.runtime.CompileModule(initCtx, r.config.Module)
	if r.err != nil {
		r.err = r.wrap("compile module", r.err)
		r.closeRuntime(initCtx)
		return
	}
	if err := r.validateABI(); err != nil {
		r.err = err
		r.closeRuntime(initCtx)
		return
	}
	module, err := r.runtime.InstantiateModule(initCtx, r.compiled, moduleConfig())
	if err != nil {
		r.err = r.wrap("instantiate module for ABI check", err)
		r.closeRuntime(initCtx)
		return
	}
	defer func() {
		_ = module.Close(initCtx)
	}()
	versionFunction := module.ExportedFunction(r.config.ABIVersionExport)
	version, err := versionFunction.Call(initCtx)
	if err != nil {
		r.err = r.wrap("read ABI version", err)
		r.closeRuntime(initCtx)
		return
	}
	if len(version) != 1 || version[0] != r.config.ABIVersion {
		r.err = r.errorf("ABI version = %v; want %d", version, r.config.ABIVersion)
		r.closeRuntime(initCtx)
	}
}

func (r *Runtime) validateConfig() error {
	switch {
	case r.config.Name == "":
		return r.errorfWith(ErrInvalidConfig, "name is required")
	case len(r.config.Module) == 0:
		return r.errorfWith(ErrInvalidConfig, "module is empty")
	case r.config.ABIVersionExport == "":
		return r.errorfWith(ErrInvalidConfig, "ABI version export is required")
	case len(r.config.Functions) == 0:
		return r.errorfWith(ErrInvalidConfig, "required functions are empty")
	case r.config.MemoryLimitPages == 0:
		return r.errorfWith(ErrInvalidConfig, "memory limit must be positive")
	case r.config.MemoryLimitPages > wasm32MaxMemoryPages:
		return r.errorfWith(ErrInvalidConfig, "memory limit must not exceed %d pages", wasm32MaxMemoryPages)
	case r.config.InitializeTimeout <= 0:
		return r.errorfWith(ErrInvalidConfig, "initialization timeout must be positive")
	case r.config.CallTimeout <= 0:
		return r.errorfWith(ErrInvalidConfig, "call timeout must be positive")
	}
	seen := make(map[string]struct{}, len(r.config.Functions))
	for _, function := range r.config.Functions {
		if function.Name == "" {
			return r.errorfWith(ErrInvalidConfig, "required function name is empty")
		}
		if _, ok := seen[function.Name]; ok {
			return r.errorfWith(ErrInvalidConfig, "required function %q is duplicated", function.Name)
		}
		seen[function.Name] = struct{}{}
	}
	return nil
}

func (r *Runtime) validateABI() error {
	if len(r.compiled.ImportedFunctions()) != 0 || len(r.compiled.ImportedMemories()) != 0 {
		return r.errorf("module must not import functions or memory")
	}
	if _, ok := r.compiled.ExportedMemories()["memory"]; !ok {
		return r.errorf("memory export is missing")
	}
	exports := r.compiled.ExportedFunctions()
	required := append([]Function{{
		Name:    r.config.ABIVersionExport,
		Results: []api.ValueType{api.ValueTypeI32},
	}}, r.config.Functions...)
	for _, expected := range required {
		definition, ok := exports[expected.Name]
		if !ok {
			return r.errorf("export %q is missing", expected.Name)
		}
		if !slices.Equal(definition.ParamTypes(), expected.Params) || !slices.Equal(definition.ResultTypes(), expected.Results) {
			return r.errorf("export %q has an incompatible signature", expected.Name)
		}
	}
	return nil
}

func (r *Runtime) closeRuntime(ctx context.Context) {
	if r.runtime != nil {
		_ = r.runtime.Close(ctx)
	}
}

func (r *Runtime) wrap(operation string, err error) error {
	return fmt.Errorf("%s: %s: %w", r.config.Name, operation, err)
}

func (r *Runtime) errorf(format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if r.config.Name == "" {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %s", r.config.Name, message)
}

func (r *Runtime) errorfWith(cause error, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if r.config.Name == "" {
		return fmt.Errorf("%w: %s", cause, message)
	}
	return fmt.Errorf("%s: %w: %s", r.config.Name, cause, message)
}

func moduleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("").WithStartFunctions()
}
