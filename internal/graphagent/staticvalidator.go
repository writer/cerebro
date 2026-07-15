package graphagent

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero/api"
	"github.com/writer/cerebro/internal/wasmhost"
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

var staticValidatorRuntime = wasmhost.New(wasmhost.Config{
	Name:             "embedded validator",
	Module:           staticValidatorWasm,
	ABIVersion:       staticValidatorABIVersion,
	ABIVersionExport: "cerebro_validator_abi_version",
	Functions: []wasmhost.Function{
		{Name: "cerebro_validator_alloc", Params: []api.ValueType{api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
		{Name: "cerebro_validator_validate", Params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
	},
	MemoryLimitPages:  128,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       time.Second,
})

func runStaticValidator(ctx context.Context, query string, maxRows int) (staticValidation, error) {
	var validation staticValidation
	err := staticValidatorRuntime.Run(ctx, func(callCtx context.Context, module api.Module) error {
		alloc := module.ExportedFunction("cerebro_validator_alloc")
		validate := module.ExportedFunction("cerebro_validator_validate")
		if alloc == nil || validate == nil || module.Memory() == nil {
			return errors.New("embedded validator exports are incomplete")
		}
		queryLength := uint64(len(query)) // #nosec G115 -- string lengths are non-negative and widened for the Wasm ABI.
		queryAllocation, err := alloc.Call(callCtx, queryLength)
		if err != nil {
			return fmt.Errorf("allocate validator query: %w", err)
		}
		resultAllocation, err := alloc.Call(callCtx, staticValidatorResultSize)
		if err != nil {
			return fmt.Errorf("allocate validator result: %w", err)
		}
		queryPointer, err := wasmhost.Pointer(queryAllocation, "validator query allocation")
		if err != nil {
			return err
		}
		resultPointer, err := wasmhost.Pointer(resultAllocation, "validator result allocation")
		if err != nil {
			return err
		}
		if !module.Memory().Write(queryPointer, []byte(query)) {
			return errors.New("write validator query memory")
		}
		maxRowCount := uint64(maxRows) // #nosec G115 -- NewValidator normalizes MaxRows to a positive value.
		status, err := validate.Call(callCtx, uint64(queryPointer), queryLength, maxRowCount, uint64(resultPointer))
		if err != nil {
			return fmt.Errorf("execute static validator: %w", err)
		}
		if len(status) != 1 || status[0] != 0 {
			return fmt.Errorf("static validator status = %v", status)
		}
		result, ok := module.Memory().Read(resultPointer, staticValidatorResultSize)
		if !ok {
			return errors.New("read validator result memory")
		}
		if reserved := binary.LittleEndian.Uint32(result[4:8]); reserved != 0 {
			return fmt.Errorf("static validator reserved field = %d", reserved)
		}
		validation = staticValidation{
			decision: staticValidatorDecision(binary.LittleEndian.Uint32(result[0:4])),
			limit:    binary.LittleEndian.Uint64(result[8:16]),
			detail:   binary.LittleEndian.Uint64(result[16:24]),
		}
		if validation.decision > staticValidatorTenantScopeRequired {
			return fmt.Errorf("unknown static validator decision %d", validation.decision)
		}
		return nil
	})
	if err != nil {
		return staticValidation{}, fmt.Errorf("%w: %w", ErrRuntimeUnavailable, err)
	}
	return validation, nil
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
