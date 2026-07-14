package sourcecoverage

import (
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	coverageEvaluatorABIVersion = 1
	coverageEvaluatorResultSize = 16
	coverageEvaluatorMaxInput   = 8 << 20
	coverageEvaluatorMaxOutput  = 16 << 20
)

var ErrEvaluatorUnavailable = errors.New("source coverage evaluator is unavailable")

//go:embed evaluator.wasm
var coverageEvaluatorWasm []byte

type coverageEvaluationRequest struct {
	Contracts    []sourcecdk.CoverageContract `json:"contracts"`
	Observations []coverageObservation        `json:"observations"`
	Options      coverageOptions              `json:"options"`
}

type coverageObservation struct {
	RuntimeID           string `json:"runtime_id"`
	SourceID            string `json:"source_id"`
	TenantID            string `json:"tenant_id"`
	Family              string `json:"family"`
	Status              string `json:"status"`
	LastFailureCategory string `json:"last_failure_category"`
	LastSyncedAt        string `json:"last_synced_at"`
}

type coverageOptions struct {
	TenantID string `json:"tenant_id"`
	SourceID string `json:"source_id"`
}

type coverageEvaluationResponse struct {
	Records []Record `json:"records"`
}

type coverageEvaluatorEngine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	err      error
}

var (
	coverageEvaluatorOnce   sync.Once
	coverageEvaluatorShared coverageEvaluatorEngine
)

func evaluateCoverage(ctx context.Context, contracts []sourcecdk.CoverageContract, observations []RuntimeObservation, options Options) ([]Record, error) {
	request := coverageEvaluationRequest{
		Contracts:    contracts,
		Options:      coverageOptions(options),
		Observations: make([]coverageObservation, 0, len(observations)),
	}
	for _, observation := range observations {
		request.Observations = append(request.Observations, coverageObservation(observation))
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: encode request: %w", ErrEvaluatorUnavailable, err)
	}
	result, err := runCoverageEvaluator(ctx, payload)
	if err != nil {
		return nil, err
	}
	var response coverageEvaluationResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", ErrEvaluatorUnavailable, err)
	}
	if response.Records == nil {
		response.Records = []Record{}
	}
	return response.Records, nil
}

func runCoverageEvaluator(ctx context.Context, payload []byte) ([]byte, error) {
	if len(payload) > coverageEvaluatorMaxInput {
		return nil, fmt.Errorf("%w: evaluator input is %d bytes, maximum is %d", ErrEvaluatorUnavailable, len(payload), coverageEvaluatorMaxInput)
	}
	coverageEvaluatorOnce.Do(func() {
		initCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(1024)
		coverageEvaluatorShared.runtime = wazero.NewRuntimeWithConfig(initCtx, config)
		coverageEvaluatorShared.compiled, coverageEvaluatorShared.err = coverageEvaluatorShared.runtime.CompileModule(initCtx, coverageEvaluatorWasm)
		if coverageEvaluatorShared.err != nil {
			coverageEvaluatorShared.err = fmt.Errorf("compile embedded evaluator: %w", coverageEvaluatorShared.err)
			return
		}
		if err := validateCoverageEvaluatorABI(coverageEvaluatorShared.compiled); err != nil {
			coverageEvaluatorShared.err = err
			return
		}
		module, err := coverageEvaluatorShared.runtime.InstantiateModule(initCtx, coverageEvaluatorShared.compiled, coverageEvaluatorModuleConfig())
		if err != nil {
			coverageEvaluatorShared.err = fmt.Errorf("instantiate embedded evaluator for ABI check: %w", err)
			return
		}
		defer func() {
			_ = module.Close(initCtx)
		}()
		versionFunction := module.ExportedFunction("cerebro_sourcecoverage_abi_version")
		version, err := versionFunction.Call(initCtx)
		if err != nil {
			coverageEvaluatorShared.err = fmt.Errorf("read embedded evaluator ABI version: %w", err)
			return
		}
		if len(version) != 1 || version[0] != coverageEvaluatorABIVersion {
			coverageEvaluatorShared.err = fmt.Errorf("embedded evaluator ABI version = %v, want %d", version, coverageEvaluatorABIVersion)
		}
	})
	if coverageEvaluatorShared.err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvaluatorUnavailable, coverageEvaluatorShared.err)
	}
	if uint64(len(payload)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: request exceeds the Wasm32 address space", ErrEvaluatorUnavailable)
	}

	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	module, err := coverageEvaluatorShared.runtime.InstantiateModule(callCtx, coverageEvaluatorShared.compiled, coverageEvaluatorModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("%w: instantiate evaluator: %w", ErrEvaluatorUnavailable, err)
	}
	defer func() {
		_ = module.Close(callCtx)
	}()

	alloc := module.ExportedFunction("cerebro_sourcecoverage_alloc")
	evaluate := module.ExportedFunction("cerebro_sourcecoverage_evaluate")
	if alloc == nil || evaluate == nil || module.Memory() == nil {
		return nil, fmt.Errorf("%w: embedded evaluator exports are incomplete", ErrEvaluatorUnavailable)
	}
	requestAllocation, err := alloc.Call(callCtx, uint64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("%w: allocate evaluator request: %w", ErrEvaluatorUnavailable, err)
	}
	resultAllocation, err := alloc.Call(callCtx, coverageEvaluatorResultSize)
	if err != nil {
		return nil, fmt.Errorf("%w: allocate evaluator result: %w", ErrEvaluatorUnavailable, err)
	}
	requestPointer, err := coverageEvaluatorPointer(requestAllocation, "request")
	if err != nil {
		return nil, err
	}
	resultPointer, err := coverageEvaluatorPointer(resultAllocation, "result")
	if err != nil {
		return nil, err
	}
	if !module.Memory().Write(requestPointer, payload) {
		return nil, fmt.Errorf("%w: write evaluator request memory", ErrEvaluatorUnavailable)
	}
	status, err := evaluate.Call(callCtx, uint64(requestPointer), uint64(len(payload)), uint64(resultPointer))
	if err != nil {
		return nil, fmt.Errorf("%w: execute evaluator: %w", ErrEvaluatorUnavailable, err)
	}
	if len(status) != 1 || status[0] != 0 {
		return nil, fmt.Errorf("%w: evaluator status = %v", ErrEvaluatorUnavailable, status)
	}
	result, ok := module.Memory().Read(resultPointer, coverageEvaluatorResultSize)
	if !ok {
		return nil, fmt.Errorf("%w: read evaluator result memory", ErrEvaluatorUnavailable)
	}
	if resultStatus := binary.LittleEndian.Uint32(result[0:4]); resultStatus != 0 {
		return nil, fmt.Errorf("%w: evaluator result status = %d", ErrEvaluatorUnavailable, resultStatus)
	}
	if reserved := binary.LittleEndian.Uint32(result[12:16]); reserved != 0 {
		return nil, fmt.Errorf("%w: evaluator reserved field = %d", ErrEvaluatorUnavailable, reserved)
	}
	outputPointer := binary.LittleEndian.Uint32(result[4:8])
	outputLength := binary.LittleEndian.Uint32(result[8:12])
	if outputLength > coverageEvaluatorMaxOutput {
		return nil, fmt.Errorf("%w: evaluator output is %d bytes, maximum is %d", ErrEvaluatorUnavailable, outputLength, coverageEvaluatorMaxOutput)
	}
	output, ok := module.Memory().Read(outputPointer, outputLength)
	if !ok {
		return nil, fmt.Errorf("%w: read evaluator output memory", ErrEvaluatorUnavailable)
	}
	return append([]byte(nil), output...), nil
}

func coverageEvaluatorPointer(results []uint64, allocation string) (uint32, error) {
	if len(results) != 1 {
		return 0, fmt.Errorf("%w: allocate evaluator %s returned %d results", ErrEvaluatorUnavailable, allocation, len(results))
	}
	if results[0] > math.MaxUint32 {
		return 0, fmt.Errorf("%w: evaluator %s pointer exceeds the Wasm32 address space", ErrEvaluatorUnavailable, allocation)
	}
	return uint32(results[0]), nil // #nosec G115 -- the value is bounded to MaxUint32 above.
}

func coverageEvaluatorModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("").WithStartFunctions()
}

func validateCoverageEvaluatorABI(compiled wazero.CompiledModule) error {
	if len(compiled.ImportedFunctions()) != 0 || len(compiled.ImportedMemories()) != 0 {
		return errors.New("embedded source coverage evaluator must not import functions or memory")
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		return errors.New("embedded source coverage evaluator memory export is missing")
	}
	exports := compiled.ExportedFunctions()
	required := []struct {
		name    string
		params  []api.ValueType
		results []api.ValueType
	}{
		{name: "cerebro_sourcecoverage_abi_version", results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_sourcecoverage_alloc", params: []api.ValueType{api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_sourcecoverage_evaluate", params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
	}
	for _, expected := range required {
		definition, ok := exports[expected.name]
		if !ok {
			return fmt.Errorf("embedded source coverage evaluator export %q is missing", expected.name)
		}
		if !slices.Equal(definition.ParamTypes(), expected.params) || !slices.Equal(definition.ResultTypes(), expected.results) {
			return fmt.Errorf("embedded source coverage evaluator export %q has an incompatible signature", expected.name)
		}
	}
	return nil
}
