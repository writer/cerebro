package sourceprojection

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
)

const (
	panopticonResourcesABIVersion     = 1
	panopticonResourcesDescriptorSize = 16
	panopticonResourcesMaxInputBytes  = 8 << 20
	panopticonResourcesMaxOutputBytes = 8 << 20
	// The guest needs room for the bounded input, serde's parsed tree, selected-object clones, and
	// the bounded output at the same time. The host caps each byte buffer at 8 MiB; the 64 MiB guest
	// ceiling leaves working memory without allowing unbounded growth.
	panopticonResourcesMemoryLimitPage = 1024
)

//go:embed panopticonresources.wasm
var panopticonResourcesWasm []byte

type panopticonResourcesEngine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	err      error
}

var (
	panopticonResourcesOnce   sync.Once
	panopticonResourcesShared panopticonResourcesEngine
)

func panopticonResourceObjectsWasm(payload []byte) ([]map[string]any, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload) > panopticonResourcesMaxInputBytes {
		return nil, fmt.Errorf("panopticon resource payload is %d bytes; maximum is %d", len(payload), panopticonResourcesMaxInputBytes)
	}
	panopticonResourcesOnce.Do(initializePanopticonResourcesEngine)
	if panopticonResourcesShared.err != nil {
		return nil, panopticonResourcesShared.err
	}

	callCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	module, err := panopticonResourcesShared.runtime.InstantiateModule(callCtx, panopticonResourcesShared.compiled, panopticonResourcesModuleConfig())
	if err != nil {
		return nil, fmt.Errorf("instantiate embedded panopticon resource extractor: %w", err)
	}
	defer module.Close(callCtx) //nolint:errcheck // The extraction result is already complete.

	alloc := module.ExportedFunction("cerebro_panopticon_resources_alloc")
	extract := module.ExportedFunction("cerebro_panopticon_resources_extract")
	if alloc == nil || extract == nil || module.Memory() == nil {
		return nil, errors.New("embedded panopticon resource extractor exports are incomplete")
	}
	inputAllocation, err := alloc.Call(callCtx, uint64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("allocate panopticon resource payload: %w", err)
	}
	inputPointer, err := panopticonResourcesPointer(inputAllocation, "payload allocation")
	if err != nil {
		return nil, err
	}
	descriptorAllocation, err := alloc.Call(callCtx, panopticonResourcesDescriptorSize)
	if err != nil {
		return nil, fmt.Errorf("allocate panopticon resource descriptor: %w", err)
	}
	descriptorPointer, err := panopticonResourcesPointer(descriptorAllocation, "descriptor allocation")
	if err != nil {
		return nil, err
	}
	if !module.Memory().Write(inputPointer, payload) {
		return nil, errors.New("write panopticon resource payload to embedded module memory")
	}
	status, err := extract.Call(callCtx, uint64(inputPointer), uint64(len(payload)), uint64(descriptorPointer))
	if err != nil {
		return nil, fmt.Errorf("execute embedded panopticon resource extractor: %w", err)
	}
	if len(status) != 1 || status[0] != 0 {
		return nil, fmt.Errorf("embedded panopticon resource extractor status = %v", status)
	}
	descriptor, ok := module.Memory().Read(descriptorPointer, panopticonResourcesDescriptorSize)
	if !ok {
		return nil, errors.New("read panopticon resource descriptor from embedded module memory")
	}
	if resultStatus := binary.LittleEndian.Uint32(descriptor[0:4]); resultStatus != 0 {
		return nil, fmt.Errorf("embedded panopticon resource result status = %d", resultStatus)
	}
	if reserved := binary.LittleEndian.Uint32(descriptor[4:8]); reserved != 0 {
		return nil, fmt.Errorf("embedded panopticon resource reserved field = %d", reserved)
	}
	outputPointer := binary.LittleEndian.Uint32(descriptor[8:12])
	outputLength := binary.LittleEndian.Uint32(descriptor[12:16])
	if outputLength > panopticonResourcesMaxOutputBytes {
		return nil, fmt.Errorf("embedded panopticon resource output is %d bytes; maximum is %d", outputLength, panopticonResourcesMaxOutputBytes)
	}
	output, ok := module.Memory().Read(outputPointer, outputLength)
	if !ok {
		return nil, errors.New("read panopticon resource output from embedded module memory")
	}
	var resources []map[string]any
	if err := json.Unmarshal(output, &resources); err != nil {
		return nil, fmt.Errorf("decode embedded panopticon resource output: %w", err)
	}
	if len(resources) > maxPanopticonResourceObjects {
		return nil, fmt.Errorf("embedded panopticon resource extractor returned %d objects; maximum is %d", len(resources), maxPanopticonResourceObjects)
	}
	return resources, nil
}

func initializePanopticonResourcesEngine() {
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config := wazero.NewRuntimeConfig().WithCloseOnContextDone(true).WithMemoryLimitPages(panopticonResourcesMemoryLimitPage)
	panopticonResourcesShared.runtime = wazero.NewRuntimeWithConfig(initCtx, config)
	panopticonResourcesShared.compiled, panopticonResourcesShared.err = panopticonResourcesShared.runtime.CompileModule(initCtx, panopticonResourcesWasm)
	if panopticonResourcesShared.err != nil {
		panopticonResourcesShared.err = fmt.Errorf("compile embedded panopticon resource extractor: %w", panopticonResourcesShared.err)
		return
	}
	if err := validatePanopticonResourcesABI(panopticonResourcesShared.compiled); err != nil {
		panopticonResourcesShared.err = err
		return
	}
	module, err := panopticonResourcesShared.runtime.InstantiateModule(initCtx, panopticonResourcesShared.compiled, panopticonResourcesModuleConfig())
	if err != nil {
		panopticonResourcesShared.err = fmt.Errorf("instantiate embedded panopticon resource extractor for ABI check: %w", err)
		return
	}
	defer module.Close(initCtx) //nolint:errcheck // ABI check cleanup cannot change initialization result.
	version := module.ExportedFunction("cerebro_panopticon_resources_abi_version")
	if version == nil {
		panopticonResourcesShared.err = errors.New("embedded panopticon resource ABI version export is missing")
		return
	}
	results, err := version.Call(initCtx)
	if err != nil {
		panopticonResourcesShared.err = fmt.Errorf("read embedded panopticon resource ABI version: %w", err)
		return
	}
	if len(results) != 1 || results[0] != panopticonResourcesABIVersion {
		panopticonResourcesShared.err = fmt.Errorf("embedded panopticon resource ABI version = %v, want %d", results, panopticonResourcesABIVersion)
	}
}

func panopticonResourcesModuleConfig() wazero.ModuleConfig {
	return wazero.NewModuleConfig().WithName("").WithStartFunctions()
}

func validatePanopticonResourcesABI(compiled wazero.CompiledModule) error {
	if len(compiled.ImportedFunctions()) != 0 || len(compiled.ImportedMemories()) != 0 {
		return errors.New("embedded panopticon resource extractor must not import functions or memory")
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		return errors.New("embedded panopticon resource extractor memory export is missing")
	}
	exports := compiled.ExportedFunctions()
	required := []struct {
		name    string
		params  []api.ValueType
		results []api.ValueType
	}{
		{name: "cerebro_panopticon_resources_abi_version", results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_panopticon_resources_alloc", params: []api.ValueType{api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
		{name: "cerebro_panopticon_resources_extract", params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, results: []api.ValueType{api.ValueTypeI32}},
	}
	for _, expected := range required {
		definition, ok := exports[expected.name]
		if !ok {
			return fmt.Errorf("embedded panopticon resource export %q is missing", expected.name)
		}
		if !slices.Equal(definition.ParamTypes(), expected.params) || !slices.Equal(definition.ResultTypes(), expected.results) {
			return fmt.Errorf("embedded panopticon resource export %q has an incompatible signature", expected.name)
		}
	}
	return nil
}

func panopticonResourcesPointer(results []uint64, operation string) (uint32, error) {
	if len(results) != 1 {
		return 0, fmt.Errorf("embedded panopticon resource %s returned %d values, want 1", operation, len(results))
	}
	if results[0] > math.MaxUint32 {
		return 0, fmt.Errorf("embedded panopticon resource %s pointer overflows uint32", operation)
	}
	return uint32(results[0]), nil
}
