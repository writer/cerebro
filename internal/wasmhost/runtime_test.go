package wasmhost

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero/api"
)

func TestRuntimeRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	runtime := New(Config{})
	err := runtime.Run(context.Background(), func(context.Context, api.Module) error { return nil })
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Run() error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestRuntimeValidatesABIVersionAndSignatures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "version",
			mutate: func(config *Config) {
				config.ABIVersion = 2
			},
		},
		{
			name: "signature",
			mutate: func(config *Config) {
				config.Functions[1].Params = []api.ValueType{api.ValueTypeI64}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testRuntimeConfig()
			test.mutate(&config)
			runtime := New(config)
			if err := runtime.Run(context.Background(), func(context.Context, api.Module) error { return nil }); err == nil {
				t.Fatal("Run() error = nil")
			}
		})
	}
}

func TestRuntimeCanceledFirstCallDoesNotPoisonInitialization(t *testing.T) {
	t.Parallel()
	runtime := New(testRuntimeConfig())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(canceled, func(callCtx context.Context, module api.Module) error {
		_, err := module.ExportedFunction("alloc").Call(callCtx, 1)
		return err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run(canceled) error = %v, want %v", err, context.Canceled)
	}
	if err := runtime.Run(context.Background(), func(callCtx context.Context, module api.Module) error {
		if module.Memory() == nil {
			t.Fatal("module memory = nil")
		}
		_, err := module.ExportedFunction("alloc").Call(callCtx, 1)
		return err
	}); err != nil {
		t.Fatalf("Run(live) error = %v", err)
	}
}

func TestRuntimeSupportsConcurrentCalls(t *testing.T) {
	t.Parallel()
	runtime := New(testRuntimeConfig())
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := runtime.Run(context.Background(), func(context.Context, api.Module) error { return nil }); err != nil {
				errorsByWorker <- err
			}
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Errorf("Run() error = %v", err)
	}
}

func TestPointer(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		results []uint64
		want    uint32
		wantErr bool
	}{
		{name: "valid", results: []uint64{42}, want: 42},
		{name: "missing", wantErr: true},
		{name: "multiple", results: []uint64{1, 2}, wantErr: true},
		{name: "overflow", results: []uint64{uint64(math.MaxUint32) + 1}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Pointer(test.results, "test allocation")
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("Pointer() = (%d, %v), want (%d, error=%t)", got, err, test.want, test.wantErr)
			}
		})
	}
}

func testRuntimeConfig() Config {
	return Config{
		Name:             "test module",
		Module:           testModule(),
		ABIVersion:       1,
		ABIVersionExport: "abi_version",
		Functions: []Function{
			{Name: "alloc", Params: []api.ValueType{api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
			{Name: "run", Params: []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, Results: []api.ValueType{api.ValueTypeI32}},
		},
		MemoryLimitPages:  1,
		InitializeTimeout: time.Second,
		CallTimeout:       time.Second,
	}
}

func testModule() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x11, 0x03,
		0x60, 0x00, 0x01, 0x7f,
		0x60, 0x01, 0x7f, 0x01, 0x7f,
		0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
		0x03, 0x04, 0x03, 0x00, 0x01, 0x02,
		0x05, 0x03, 0x01, 0x00, 0x01,
		0x07, 0x26, 0x04,
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
		0x0b, 'a', 'b', 'i', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00, 0x00,
		0x05, 'a', 'l', 'l', 'o', 'c', 0x00, 0x01,
		0x03, 'r', 'u', 'n', 0x00, 0x02,
		0x0a, 0x10, 0x03,
		0x04, 0x00, 0x41, 0x01, 0x0b,
		0x04, 0x00, 0x41, 0x20, 0x0b,
		0x04, 0x00, 0x41, 0x00, 0x0b,
	}
}
