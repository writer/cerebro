// Package wasmjsontest provides test-only JSON corpus and differential helpers
// for packages that own an embedded JSON Wasm evaluator.
package wasmjsontest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

const maxDiagnosticBytes = 4096

// ErrDifferentialMismatch marks a candidate output that differs from its Go oracle.
var ErrDifferentialMismatch = errors.New("JSON differential mismatch")

// Input is one strictly decoded, input-only JSON corpus entry.
type Input[T any] struct {
	Name  string
	Raw   []byte
	Value T
}

// Differential compares an embedded evaluator with the Go oracle owned by its
// domain package. Candidate receives Raw so tests can preserve the guest's
// exact JSON input when that is part of the contract.
type Differential[T, O any] struct {
	MaxInputBytes int
	Oracle        func(T) O
	Candidate     func(context.Context, Input[T]) (O, error)
	Equal         func(O, O) bool
}

// LoadInputs loads a sorted JSON corpus and rejects unknown fields, trailing
// values, empty corpora, and entries above maxInputBytes.
func LoadInputs[T any](t testing.TB, filesystem fs.FS, pattern string, maxInputBytes int) []Input[T] {
	t.Helper()
	matches, err := fs.Glob(filesystem, pattern)
	if err != nil {
		t.Fatalf("load JSON corpus %q: %v", pattern, err)
	}
	if len(matches) == 0 {
		t.Fatalf("load JSON corpus %q: no entries", pattern)
	}
	inputs := make([]Input[T], 0, len(matches))
	for _, name := range matches {
		raw, err := fs.ReadFile(filesystem, name)
		if err != nil {
			t.Fatalf("read JSON corpus entry %q: %v", name, err)
		}
		if maxInputBytes > 0 && len(raw) > maxInputBytes {
			t.Fatalf("read JSON corpus entry %q: %d bytes exceeds %d", name, len(raw), maxInputBytes)
		}
		value, err := DecodeStrict[T](raw)
		if err != nil {
			t.Fatalf("decode JSON corpus entry %q: %v", name, err)
		}
		base := path.Base(name)
		inputs = append(inputs, Input[T]{
			Name:  strings.TrimSuffix(base, path.Ext(base)),
			Raw:   raw,
			Value: value,
		})
	}
	return inputs
}

// DecodeStrict decodes exactly one JSON value and rejects unknown struct
// fields. Untyped numbers retain encoding/json's float64 behavior so map-based
// Go oracles observe the same inputs as their former production paths.
func DecodeStrict[T any](raw []byte) (T, error) {
	var value T
	if !utf8.Valid(raw) {
		return value, fmt.Errorf("JSON input is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return value, fmt.Errorf("multiple JSON values")
		}
		return value, fmt.Errorf("trailing JSON value: %w", err)
	}
	return value, nil
}

// RunCorpus runs every entry as a named subtest.
func RunCorpus[T, O any](t *testing.T, ctx context.Context, inputs []Input[T], differential Differential[T, O]) {
	t.Helper()
	for _, input := range inputs {
		input := input
		t.Run(input.Name, func(t *testing.T) {
			t.Parallel()
			if err := compare(ctx, input, differential); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// AddSeeds adds the raw corpus entries to a Go fuzz target.
func AddSeeds[T any](f *testing.F, inputs []Input[T]) {
	f.Helper()
	for _, input := range inputs {
		f.Add(input.Raw)
	}
}

// CheckFuzzInput ignores invalid or oversized mutations and differentially
// checks every strict JSON input accepted by the owning domain type.
func CheckFuzzInput[T, O any](t *testing.T, ctx context.Context, raw []byte, differential Differential[T, O]) {
	t.Helper()
	if differential.MaxInputBytes > 0 && len(raw) > differential.MaxInputBytes {
		return
	}
	value, err := DecodeStrict[T](raw)
	if err != nil {
		return
	}
	if err := compare(ctx, Input[T]{Name: "fuzz", Raw: raw, Value: value}, differential); err != nil {
		t.Fatal(err)
	}
}

func compare[T, O any](ctx context.Context, input Input[T], differential Differential[T, O]) error {
	if differential.Oracle == nil {
		return fmt.Errorf("JSON differential oracle is required")
	}
	if differential.Candidate == nil {
		return fmt.Errorf("JSON differential candidate is required")
	}
	if differential.MaxInputBytes > 0 && len(input.Raw) > differential.MaxInputBytes {
		return fmt.Errorf("JSON differential input is %d bytes; maximum is %d", len(input.Raw), differential.MaxInputBytes)
	}
	want := differential.Oracle(input.Value)
	got, err := differential.Candidate(ctx, input)
	if err != nil {
		return fmt.Errorf("JSON differential candidate: %w", err)
	}
	equal := differential.Equal
	if equal == nil {
		equal = func(left O, right O) bool {
			return reflect.DeepEqual(left, right)
		}
	}
	if equal(got, want) {
		return nil
	}
	return fmt.Errorf("%w\ncandidate: %s\noracle:    %s", ErrDifferentialMismatch, diagnosticJSON(got), diagnosticJSON(want))
}

func diagnosticJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("<encode error: %v>", err)
	}
	if len(raw) <= maxDiagnosticBytes {
		return string(raw)
	}
	return string(raw[:maxDiagnosticBytes]) + "..."
}
