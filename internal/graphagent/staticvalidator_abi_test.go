package graphagent

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func TestStaticValidatorWasmMatchesABIGoldenCases(t *testing.T) {
	file, err := os.Open("staticvalidator/testdata/abi_golden.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck // Read-only test fixture.

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			t.Fatalf("line %d has %d fields", lineNumber, len(fields))
		}
		maxRows, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("line %d max rows: %v", lineNumber, err)
		}
		decision, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			t.Fatalf("line %d decision: %v", lineNumber, err)
		}
		limit, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			t.Fatalf("line %d limit: %v", lineNumber, err)
		}
		detail, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			t.Fatalf("line %d detail: %v", lineNumber, err)
		}

		query := fields[4]
		if query == "<empty>" {
			query = ""
		}
		actual, err := runStaticValidator(context.Background(), query, maxRows)
		if err != nil {
			t.Fatalf("line %d validate: %v", lineNumber, err)
		}
		if actual.decision != staticValidatorDecision(decision) || actual.limit != limit || actual.detail != detail {
			t.Fatalf("line %d validation = %#v, want decision=%d limit=%d detail=%d", lineNumber, actual, decision, limit, detail)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestStaticValidatorQuerySizeLimit(t *testing.T) {
	query := strings.Repeat("x", staticValidatorMaxQueryBytes+1)
	validation, err := runStaticValidator(context.Background(), query, 100)
	if err != nil {
		t.Fatal(err)
	}
	if validation.decision != staticValidatorQueryTooLarge || validation.detail != uint64(len(query)) {
		t.Fatalf("validation = %#v, want query-too-large with detail %d", validation, len(query))
	}

	result, limit, err := staticValidationResult(validation, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK || result.Code != "query_too_large" || limit != 0 {
		t.Fatalf("result = (%#v, %d), want query_too_large refusal", result, limit)
	}
}

func TestStaticValidatorABIGoldenValues(t *testing.T) {
	if staticValidatorABIVersion != 2 || staticValidatorResultSize != 24 || staticValidatorMaxQueryBytes != 65536 {
		t.Fatalf("ABI constants changed: version=%d result=%d query=%d", staticValidatorABIVersion, staticValidatorResultSize, staticValidatorMaxQueryBytes)
	}
	if staticValidatorAllow != 0 || staticValidatorTenantScopeRequired != 10 || staticValidatorQueryTooLarge != 11 {
		t.Fatalf("ABI decisions changed: allow=%d tenant=%d size=%d", staticValidatorAllow, staticValidatorTenantScopeRequired, staticValidatorQueryTooLarge)
	}
	if staticValidatorStatusSuccess != 0 || staticValidatorStatusInvalidMemory != 1 || staticValidatorStatusQueryTooLarge != 2 {
		t.Fatalf("ABI statuses changed: success=%d memory=%d size=%d", staticValidatorStatusSuccess, staticValidatorStatusInvalidMemory, staticValidatorStatusQueryTooLarge)
	}
}

func TestStaticValidatorWasmRejectsOversizedGuestInput(t *testing.T) {
	const query = `MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25`
	if _, err := runStaticValidator(context.Background(), query, 100); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	module := instantiateStaticValidatorForABITest(t, ctx)

	allocation, err := module.ExportedFunction("cerebro_validator_alloc").Call(ctx, staticValidatorMaxQueryBytes+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(allocation) != 1 || allocation[0] != 0 {
		t.Fatalf("oversized allocation = %v, want [0]", allocation)
	}
	status, err := module.ExportedFunction("cerebro_validator_validate").Call(ctx, 0, staticValidatorMaxQueryBytes+1, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0] != uint64(staticValidatorStatusQueryTooLarge) {
		t.Fatalf("oversized validation status = %v, want %d", status, staticValidatorStatusQueryTooLarge)
	}
}

func TestStaticValidatorWasmRejectsOverlappingRanges(t *testing.T) {
	const query = `MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25`
	if _, err := runStaticValidator(context.Background(), query, 100); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	module := instantiateStaticValidatorForABITest(t, ctx)

	allocation, err := module.ExportedFunction("cerebro_validator_alloc").Call(ctx, uint64(len(query)))
	if err != nil {
		t.Fatal(err)
	}
	if len(allocation) != 1 || allocation[0] == 0 {
		t.Fatalf("query allocation = %v", allocation)
	}
	queryPointer := uint32(allocation[0]) // #nosec G115 -- Wasm32 allocator results are i32 values.
	if !module.Memory().Write(queryPointer, []byte(query)) {
		t.Fatal("write query memory")
	}
	resultPointer := uint64(queryPointer + 1)
	status, err := module.ExportedFunction("cerebro_validator_validate").Call(ctx, uint64(queryPointer), uint64(len(query)), 100, resultPointer)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0] != uint64(staticValidatorStatusInvalidMemory) {
		t.Fatalf("overlapping validation status = %v, want %d", status, staticValidatorStatusInvalidMemory)
	}
}

func instantiateStaticValidatorForABITest(t *testing.T, ctx context.Context) api.Module {
	t.Helper()
	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() {
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close validator ABI runtime: %v", err)
		}
	})
	compiled, err := runtime.CompileModule(ctx, staticValidatorWasm)
	if err != nil {
		t.Fatal(err)
	}
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func BenchmarkStaticValidator(b *testing.B) {
	const query = `MATCH (e:Entity {tenant_id:$tenant_id}) RETURN e LIMIT 25`
	ctx := context.Background()
	if _, err := runStaticValidator(ctx, query, 100); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := runStaticValidator(ctx, query, 100); err != nil {
			b.Fatal(err)
		}
	}
}
