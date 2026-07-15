package archtests

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type wasmGuestExports struct {
	abi       string
	allocate  string
	operation string
}

type wasmGuestProtocol struct {
	name               string
	artifact           string
	exports            wasmGuestExports
	abiVersion         uint64
	resultBytes        uint32
	maxInputBytes      uint32
	invalidRangeStatus uint64
	tooLargeStatus     uint64
	zeroInputStatus    uint64
	invalidUTF8Status  uint64
	malformedStatus    uint64
	unknownFieldStatus uint64
	staticValidator    bool
}

func TestEmbeddedWasmGuestMemoryProtocol(t *testing.T) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close Wasm runtime: %v", err)
		}
	})

	protocols := []wasmGuestProtocol{
		{
			name: "static validator", artifact: "internal/graphagent/staticvalidator.wasm",
			exports:    wasmGuestExports{abi: "cerebro_validator_abi_version", allocate: "cerebro_validator_alloc", operation: "cerebro_validator_validate"},
			abiVersion: 2, resultBytes: 24, maxInputBytes: 64 << 10, invalidRangeStatus: 1, tooLargeStatus: 2, zeroInputStatus: 1, invalidUTF8Status: 1, malformedStatus: 0, unknownFieldStatus: 0, staticValidator: true,
		},
		{
			name: "MITRE evaluator", artifact: "internal/mitre/evaluator.wasm",
			exports:    wasmGuestExports{abi: "cerebro_mitre_abi_version", allocate: "cerebro_mitre_alloc", operation: "cerebro_mitre_evaluate"},
			abiVersion: 1, resultBytes: 16, maxInputBytes: 1 << 20, invalidRangeStatus: 3, tooLargeStatus: 3, zeroInputStatus: 3, invalidUTF8Status: 1, malformedStatus: 1, unknownFieldStatus: 1,
		},
		{
			name: "source coverage evaluator", artifact: "internal/sourcecoverage/evaluator.wasm",
			exports:    wasmGuestExports{abi: "cerebro_sourcecoverage_abi_version", allocate: "cerebro_sourcecoverage_alloc", operation: "cerebro_sourcecoverage_evaluate"},
			abiVersion: 1, resultBytes: 16, maxInputBytes: 8 << 20, invalidRangeStatus: 3, tooLargeStatus: 3, zeroInputStatus: 3, invalidUTF8Status: 1, malformedStatus: 1, unknownFieldStatus: 1,
		},
		{
			name: "Panopticon resource extractor", artifact: "internal/sourceprojection/panopticonresources.wasm",
			exports:    wasmGuestExports{abi: "cerebro_panopticon_resources_abi_version", allocate: "cerebro_panopticon_resources_alloc", operation: "cerebro_panopticon_resources_extract"},
			abiVersion: 2, resultBytes: 16, maxInputBytes: 8 << 20, invalidRangeStatus: 1, tooLargeStatus: 1, zeroInputStatus: 1, invalidUTF8Status: 0, malformedStatus: 0, unknownFieldStatus: 0,
		},
	}

	for _, protocol := range protocols {
		t.Run(protocol.name, func(t *testing.T) {
			module := instantiateWasmGuest(t, ctx, runtime, protocol)
			assertWasmGuestABI(t, ctx, module, protocol)
			assertWasmGuestAllocationLimit(t, ctx, module, protocol)

			inputPointer := allocateWasmGuestMemory(t, ctx, module, protocol, 32)
			if !module.Memory().Write(inputPointer, []byte("{}")) {
				t.Fatal("write valid input memory")
			}

			resultPointer := allocateWasmGuestMemory(t, ctx, module, protocol, protocol.resultBytes)
			zeroStatus := callWasmGuest(t, ctx, module, protocol, 0, 0, resultPointer)
			if zeroStatus != protocol.zeroInputStatus {
				t.Fatalf("zero-length input status = %d, want %d", zeroStatus, protocol.zeroInputStatus)
			}
			assertWasmGuestZeroResult(t, module, protocol, resultPointer)

			for _, test := range []struct {
				name          string
				inputPointer  uint32
				inputLength   uint32
				resultPointer uint32
			}{
				{name: "non-empty null input", inputPointer: 0, inputLength: 1, resultPointer: resultPointer},
				{name: "null result", inputPointer: inputPointer, inputLength: 2, resultPointer: 0},
				{name: "overlapping input and result", inputPointer: inputPointer, inputLength: 2, resultPointer: inputPointer},
				{name: "partially overlapping input and result", inputPointer: inputPointer, inputLength: 2, resultPointer: inputPointer + 1},
				{name: "out-of-bounds input", inputPointer: module.Memory().Size() - 1, inputLength: 2, resultPointer: resultPointer},
				{name: "overflowing input end", inputPointer: math.MaxUint32 - 1, inputLength: 4, resultPointer: resultPointer},
				{
					name:          "out-of-bounds result",
					inputPointer:  inputPointer,
					inputLength:   2,
					resultPointer: module.Memory().Size() - protocol.resultBytes + 1,
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					status := callWasmGuest(t, ctx, module, protocol, test.inputPointer, test.inputLength, test.resultPointer)
					if status != protocol.invalidRangeStatus {
						t.Fatalf("status = %d, want invalid-range status %d", status, protocol.invalidRangeStatus)
					}
				})
			}
			assertWasmGuestPayloadStatus(t, ctx, module, protocol, []byte{0xff, 0xfe}, protocol.invalidUTF8Status)
			assertWasmGuestPayloadStatus(t, ctx, module, protocol, []byte("{"), protocol.malformedStatus)
			assertWasmGuestPayloadStatus(t, ctx, module, protocol, []byte(`{"unknown":true}`), protocol.unknownFieldStatus)

			adjacentStatus := callWasmGuest(t, ctx, module, protocol, inputPointer, 2, inputPointer+2)
			if adjacentStatus != 0 {
				t.Fatalf("adjacent input and result status = %d, want 0", adjacentStatus)
			}
		})
	}
}

func assertWasmGuestPayloadStatus(t *testing.T, ctx context.Context, module api.Module, protocol wasmGuestProtocol, payload []byte, want uint64) {
	t.Helper()
	inputPointer := allocateWasmGuestMemory(t, ctx, module, protocol, uint32(len(payload))) // #nosec G115 -- fixed test payloads fit Wasm32.
	if !module.Memory().Write(inputPointer, payload) {
		t.Fatal("write adversarial payload")
	}
	resultPointer := allocateWasmGuestMemory(t, ctx, module, protocol, protocol.resultBytes)
	status := callWasmGuest(t, ctx, module, protocol, inputPointer, uint32(len(payload)), resultPointer) // #nosec G115 -- fixed test payloads fit Wasm32.
	if status != want {
		t.Fatalf("payload %x status = %d, want %d", payload, status, want)
	}
}

func assertWasmGuestAllocationLimit(t *testing.T, ctx context.Context, module api.Module, protocol wasmGuestProtocol) {
	t.Helper()
	allocate := requireWasmGuestFunction(t, module, protocol.exports.allocate)
	result, err := allocate.Call(ctx, uint64(protocol.maxInputBytes)+1)
	if err != nil {
		t.Fatalf("allocate oversized input: %v", err)
	}
	if len(result) != 1 || result[0] != 0 {
		t.Fatalf("oversized allocation = %v, want [0]", result)
	}
	resultPointer := allocateWasmGuestMemory(t, ctx, module, protocol, protocol.resultBytes)
	status := callWasmGuest(t, ctx, module, protocol, 1, protocol.maxInputBytes+1, resultPointer)
	if status != protocol.tooLargeStatus {
		t.Fatalf("oversized input status = %d, want %d", status, protocol.tooLargeStatus)
	}
}

func instantiateWasmGuest(t *testing.T, ctx context.Context, runtime wazero.Runtime, protocol wasmGuestProtocol) api.Module {
	t.Helper()
	artifactPath := filepath.Join(repoRoot(t), filepath.FromSlash(protocol.artifact))
	artifact, err := os.ReadFile(artifactPath) // #nosec G304 -- the path is a fixed checked-in artifact from the test table.
	if err != nil {
		t.Fatalf("read %s: %v", protocol.artifact, err)
	}
	compiled, err := runtime.CompileModule(ctx, artifact)
	if err != nil {
		t.Fatalf("compile %s: %v", protocol.artifact, err)
	}
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		t.Fatalf("instantiate %s: %v", protocol.artifact, err)
	}
	t.Cleanup(func() {
		if err := module.Close(ctx); err != nil {
			t.Errorf("close %s: %v", protocol.artifact, err)
		}
	})
	return module
}

func assertWasmGuestABI(t *testing.T, ctx context.Context, module api.Module, protocol wasmGuestProtocol) {
	t.Helper()
	abi := requireWasmGuestFunction(t, module, protocol.exports.abi)
	version, err := abi.Call(ctx)
	if err != nil {
		t.Fatalf("call %s: %v", protocol.exports.abi, err)
	}
	if len(version) != 1 || version[0] != protocol.abiVersion {
		t.Fatalf("ABI version = %v, want %d", version, protocol.abiVersion)
	}
	requireWasmGuestFunction(t, module, protocol.exports.allocate)
	requireWasmGuestFunction(t, module, protocol.exports.operation)
	if module.Memory() == nil {
		t.Fatal("memory export is missing")
	}
}

func allocateWasmGuestMemory(t *testing.T, ctx context.Context, module api.Module, protocol wasmGuestProtocol, size uint32) uint32 {
	t.Helper()
	allocate := requireWasmGuestFunction(t, module, protocol.exports.allocate)
	result, err := allocate.Call(ctx, uint64(size))
	if err != nil {
		t.Fatalf("allocate %d bytes: %v", size, err)
	}
	if len(result) != 1 || result[0] == 0 || result[0] > math.MaxUint32 {
		t.Fatalf("allocation result = %v, want one nonzero Wasm32 pointer", result)
	}
	return uint32(result[0]) // #nosec G115 -- the result is bounded to MaxUint32 above.
}

func callWasmGuest(t *testing.T, ctx context.Context, module api.Module, protocol wasmGuestProtocol, inputPointer uint32, inputLength uint32, resultPointer uint32) uint64 {
	t.Helper()
	operation := requireWasmGuestFunction(t, module, protocol.exports.operation)
	arguments := []uint64{uint64(inputPointer), uint64(inputLength), uint64(resultPointer)}
	if protocol.staticValidator {
		arguments = []uint64{uint64(inputPointer), uint64(inputLength), 10, uint64(resultPointer)}
	}
	result, err := operation.Call(ctx, arguments...)
	if err != nil {
		t.Fatalf("call %s: %v", protocol.exports.operation, err)
	}
	if len(result) != 1 {
		t.Fatalf("%s result = %v, want one status", protocol.exports.operation, result)
	}
	return result[0]
}

func assertWasmGuestZeroResult(t *testing.T, module api.Module, protocol wasmGuestProtocol, resultPointer uint32) {
	t.Helper()
	result, ok := module.Memory().Read(resultPointer, protocol.resultBytes)
	if !ok {
		t.Fatalf("read %d-byte result", protocol.resultBytes)
	}
	if protocol.zeroInputStatus != 0 {
		if !bytes.Equal(result, make([]byte, protocol.resultBytes)) {
			t.Fatalf("failed zero-length input modified result: %x", result)
		}
		return
	}
	if protocol.staticValidator {
		if decision := binary.LittleEndian.Uint32(result[0:4]); decision != 1 {
			t.Fatalf("empty-query decision = %d, want cypher-required decision 1", decision)
		}
		if reserved := binary.LittleEndian.Uint32(result[4:8]); reserved != 0 {
			t.Fatalf("static result reserved field = %d, want 0", reserved)
		}
		return
	}
	if status := binary.LittleEndian.Uint32(result[0:4]); status != 0 {
		t.Fatalf("JSON result status = %d, want 0", status)
	}
	if reserved := binary.LittleEndian.Uint32(result[12:16]); reserved != 0 {
		t.Fatalf("JSON result reserved field = %d, want 0", reserved)
	}
	outputPointer := binary.LittleEndian.Uint32(result[4:8])
	outputLength := binary.LittleEndian.Uint32(result[8:12])
	output, ok := module.Memory().Read(outputPointer, outputLength)
	if !ok {
		t.Fatalf("read JSON output pointer=%d length=%d", outputPointer, outputLength)
	}
	if string(output) != "[]" {
		t.Fatalf("zero-length JSON output = %q, want []", output)
	}
}

func requireWasmGuestFunction(t *testing.T, module api.Module, name string) api.Function {
	t.Helper()
	function := module.ExportedFunction(name)
	if function == nil {
		t.Fatalf("export %q is missing", name)
	}
	return function
}
