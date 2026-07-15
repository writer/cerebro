package graphagent

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	staticValidatorABIVersion = 1
	staticValidatorResultSize = 24
)

//go:embed staticvalidator.wasm
var staticValidatorWasm []byte

type staticValidatorDecision uint32

const (
	staticValidatorAllow staticValidatorDecision = iota
	staticValidatorCypherRequired
	staticValidatorUnsafeClause
	staticValidatorUnsafeAPOC
	staticValidatorAPOCNotAllowed
	staticValidatorProcedureCallNotAllowed
	staticValidatorVariableLengthRelationshipNotAllowed
	staticValidatorExpansionNotAllowed
	staticValidatorLimitRequired
	staticValidatorLimitExceeded
	staticValidatorTenantScopeRequired
)

type staticValidation struct {
	decision staticValidatorDecision
	limit    uint64
	detail   uint64
}

type staticValidatorEngine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	err      error
}

var (
	staticValidatorOnce   sync.Once
	staticValidatorShared staticValidatorEngine
)

func runStaticValidator(ctx context.Context, query string, maxRows int) (staticValidation, error) {
	staticValidatorOnce.Do(func() {
		initCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(128)
		staticValidatorShared.runtime = wazero.NewRuntimeWithConfig(initCtx, config)
		staticValidatorShared.compiled, staticValidatorShared.err = staticValidatorShared.runtime.CompileModule(initCtx, staticValidatorWasm)
		if staticValidatorShared.err != nil {
			staticValidatorShared.err = fmt.Errorf("compile embedded validator: %w", staticValidatorShared.err)
			return
		}
		if err := validateStaticValidatorABI(staticValidatorShared.compiled); err != nil {
			staticValidatorShared.err = err
			return
		}
		module, err := staticValidatorShared.runtime.InstantiateModule(initCtx, staticValidatorShared.compiled, staticValidatorModuleConfig())
		if err != nil {
			staticValidatorShared.err = fmt.Errorf("instantiate embedded validator for ABI check: %w", err)
			return
		}
		defer module.Close(initCtx) //nolint:errcheck // ABI check cleanup cannot change initialization result.
		abiVersion := module.ExportedFunction("cerebro_validator_abi_version")
		if abiVersion == nil {
			staticValidatorShared.err = errors.New("embedded validator ABI version export is missing")
			return
		}
		version, err := abiVersion.Call(initCtx)
		if err != nil {
			staticValidatorShared.err = fmt.Errorf("read embedded validator ABI version: %w", err)
			return
		}
		if len(version) != 1 || version[0] != staticValidatorABIVersion {
			staticValidatorShared.err = fmt.Errorf("embedded validator ABI version = %v, want %d", version, staticValidatorABIVersion)
		}
	})
	if staticValidatorShared.err != nil {
		return staticValidation{}, fmt.Errorf("%w: %w", ErrRuntimeUnavailable, staticValidatorShared.err)
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	module, err := staticValidatorShared.runtime.InstantiateModule(callCtx, staticValidatorShared.compiled, staticValidatorModuleConfig())
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: instantiate static validator: %w", ErrRuntimeUnavailable, err)
	}
	defer module.Close(callCtx) //nolint:errcheck // The validation result is already complete.

	alloc := module.ExportedFunction("cerebro_validator_alloc")
	validate := module.ExportedFunction("cerebro_validator_validate")
	if alloc == nil || validate == nil || module.Memory() == nil {
		return staticValidation{}, fmt.Errorf("%w: embedded validator exports are incomplete", ErrRuntimeUnavailable)
	}
	queryLength := uint64(len(query)) // #nosec G115 -- string lengths are non-negative and widened for the Wasm ABI.
	queryAllocation, err := alloc.Call(callCtx, queryLength)
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: allocate validator query: %w", ErrRuntimeUnavailable, err)
	}
	if len(queryAllocation) != 1 {
		return staticValidation{}, fmt.Errorf("%w: allocate validator query returned %d results", ErrRuntimeUnavailable, len(queryAllocation))
	}
	resultAllocation, err := alloc.Call(callCtx, staticValidatorResultSize)
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: allocate validator result: %w", ErrRuntimeUnavailable, err)
	}
	if len(resultAllocation) != 1 {
		return staticValidation{}, fmt.Errorf("%w: allocate validator result returned %d results", ErrRuntimeUnavailable, len(resultAllocation))
	}
	queryPointer, err := staticValidatorPointer(queryAllocation[0])
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: validator query allocation: %w", ErrRuntimeUnavailable, err)
	}
	resultPointer, err := staticValidatorPointer(resultAllocation[0])
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: validator result allocation: %w", ErrRuntimeUnavailable, err)
	}
	if !module.Memory().Write(queryPointer, []byte(query)) {
		return staticValidation{}, fmt.Errorf("%w: write validator query memory", ErrRuntimeUnavailable)
	}
	maxRowCount := uint64(maxRows) // #nosec G115 -- NewValidator normalizes MaxRows to a positive value.
	status, err := validate.Call(callCtx, uint64(queryPointer), queryLength, maxRowCount, uint64(resultPointer))
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: execute static validator: %w", ErrRuntimeUnavailable, err)
	}
	if len(status) != 1 || status[0] != 0 {
		return staticValidation{}, fmt.Errorf("%w: static validator status = %v", ErrRuntimeUnavailable, status)
	}
	result, ok := module.Memory().Read(resultPointer, staticValidatorResultSize)
	if !ok {
		return staticValidation{}, fmt.Errorf("%w: read validator result memory", ErrRuntimeUnavailable)
	}
	if reserved := binary.LittleEndian.Uint32(result[4:8]); reserved != 0 {
		return staticValidation{}, fmt.Errorf("%w: static validator reserved field = %d", ErrRuntimeUnavailable, reserved)
	}
	validation := staticValidation{
		decision: staticValidatorDecision(binary.LittleEndian.Uint32(result[0:4])),
		limit:    binary.LittleEndian.Uint64(result[8:16]),
		detail:   binary.LittleEndian.Uint64(result[16:24]),
	}
	if validation.decision > staticValidatorTenantScopeRequired {
		return staticValidation{}, fmt.Errorf("%w: unknown static validator decision %d", ErrRuntimeUnavailable, validation.decision)
	}
	return validation, nil
}

func staticValidatorPointer(value uint64) (uint32, error) {
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("pointer %d exceeds the Wasm32 address space", value)
	}
	return uint32(value), nil // #nosec G115 -- value is bounded to MaxUint32 above.
}

func staticValidatorModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("").WithStartFunctions()
}

func validateStaticValidatorABI(compiled wazero.CompiledModule) error {
	if len(compiled.ImportedFunctions()) != 0 || len(compiled.ImportedMemories()) != 0 {
		return errors.New("embedded validator must not import functions or memory")
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		return errors.New("embedded validator memory export is missing")
	}
	exports := compiled.ExportedFunctions()
	required := []struct {
		name    string
		params  []api.ValueType
		results []api.ValueType
	}{
		{name: "cerebro_validator_abi_version", results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_validator_alloc", params: []api.ValueType{api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_validator_validate", params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
	}
	for _, expected := range required {
		definition, ok := exports[expected.name]
		if !ok {
			return fmt.Errorf("embedded validator export %q is missing", expected.name)
		}
		if !slices.Equal(definition.ParamTypes(), expected.params) || !slices.Equal(definition.ResultTypes(), expected.results) {
			return fmt.Errorf("embedded validator export %q has an incompatible signature", expected.name)
		}
	}
	return nil
}

func staticValidationResult(validation staticValidation, maxRows int) (ValidatorResult, int, error) {
	switch validation.decision {
	case staticValidatorAllow:
		if validation.limit > uint64(^uint(0)>>1) {
			return ValidatorResult{}, 0, fmt.Errorf("%w: static validator limit overflows int", ErrRuntimeUnavailable)
		}
		return ValidatorResult{OK: true}, int(validation.limit), nil
	case staticValidatorCypherRequired:
		return validatorRefusal("cypher_required", "cypher is required"), 0, nil
	case staticValidatorUnsafeClause:
		return validatorRefusal("unsafe_clause", "write or bulk-load Cypher clauses are forbidden"), 0, nil
	case staticValidatorUnsafeAPOC:
		return validatorRefusal("unsafe_apoc", "apoc trigger and periodic procedures are forbidden"), 0, nil
	case staticValidatorAPOCNotAllowed:
		return validatorRefusal("apoc_not_allowed", "APOC functions and procedures are not available in Ask Cerebro"), 0, nil
	case staticValidatorProcedureCallNotAllowed:
		return validatorRefusal("procedure_call_not_allowed", "procedure CALL clauses are forbidden"), 0, nil
	case staticValidatorVariableLengthRelationshipNotAllowed:
		return validatorRefusal("variable_length_relationship_not_allowed", "variable-length relationship traversals are forbidden"), 0, nil
	case staticValidatorExpansionNotAllowed:
		return validatorRefusal("expansion_not_allowed", "row-expanding Cypher expressions such as UNWIND, range(), and collect() are forbidden"), 0, nil
	case staticValidatorLimitRequired:
		return validatorRefusal("limit_required", "read Cypher must include a numeric LIMIT clause"), 0, nil
	case staticValidatorLimitExceeded:
		return validatorRefusal("limit_exceeded", fmt.Sprintf("LIMIT %d exceeds maximum %d", validation.detail, maxRows)), 0, nil
	case staticValidatorTenantScopeRequired:
		return validatorRefusal("tenant_scope_required", "every node pattern must use Entity label and inline tenant_id"), 0, nil
	default:
		return ValidatorResult{}, 0, errors.New("unreachable static validator decision")
	}
}
