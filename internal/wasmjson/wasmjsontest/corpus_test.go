package wasmjsontest

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"
)

type strictInput struct {
	Value string `json:"value"`
}

func TestLoadInputsStrictlyDecodesSortedCorpus(t *testing.T) {
	t.Parallel()
	filesystem := fstest.MapFS{
		"cases/z.json": {Data: []byte(`{"value":"z"}`)},
		"cases/a.json": {Data: []byte(`{"value":"a"}`)},
	}
	inputs := LoadInputs[strictInput](t, filesystem, "cases/*.json", 1024)
	if len(inputs) != 2 || inputs[0].Name != "a" || inputs[1].Name != "z" {
		t.Fatalf("inputs = %#v, want sorted a and z entries", inputs)
	}
}

func TestDecodeStrictRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"value":"ok","unknown":true}`,
		`{"value":"ok"} {"value":"trailing"}`,
	} {
		if _, err := DecodeStrict[strictInput]([]byte(raw)); err == nil {
			t.Fatalf("DecodeStrict(%q) error = nil", raw)
		}
	}
	if _, err := DecodeStrict[strictInput]([]byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("DecodeStrict(invalid UTF-8) error = nil")
	}
}

func TestRunCorpusReportsDifferentialMismatch(t *testing.T) {
	t.Parallel()
	input := Input[strictInput]{Name: "case", Raw: []byte(`{"value":"a"}`), Value: strictInput{Value: "a"}}
	differential := Differential[strictInput, string]{
		MaxInputBytes: 1024,
		Oracle:        func(input strictInput) string { return input.Value },
		Candidate: func(context.Context, Input[strictInput]) (string, error) {
			return "b", nil
		},
	}
	err := compare(context.Background(), input, differential)
	if !errors.Is(err, ErrDifferentialMismatch) {
		t.Fatalf("compare() error = %v, want differential mismatch", err)
	}
}
