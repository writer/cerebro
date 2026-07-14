package mitre

import (
	"context"
	"embed"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/wasmjson"
	"github.com/writer/cerebro/internal/wasmjson/wasmjsontest"
)

const contextEvaluatorFuzzMaxInput = 64 << 10

//go:embed testdata/wasmjson/*.json
var contextEvaluatorCorpus embed.FS

func TestContextInputHasValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input ContextInput
		want  bool
	}{
		{name: "empty", input: ContextInput{}, want: false},
		{name: "blank", input: ContextInput{AttackTacticValues: []string{"", " \t"}}, want: false},
		{name: "attack tactic", input: ContextInput{AttackTacticValues: []string{"TA0001"}}, want: true},
		{name: "attack technique", input: ContextInput{AttackTechniqueValues: []string{"T1190"}}, want: true},
		{name: "attack technique ID", input: ContextInput{AttackTechniqueIDValues: []string{"T1562.001"}}, want: true},
		{name: "defend tactic", input: ContextInput{DefendTacticValues: []string{"d3f:Model"}}, want: true},
		{name: "defend technique", input: ContextInput{DefendTechniqueValues: []string{"d3f:ProcessTermination"}}, want: true},
		{name: "defend artifact", input: ContextInput{DefendArtifactValues: []string{"d3f:Credential"}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.input.HasValues(); got != test.want {
				t.Fatalf("HasValues() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestContextEvaluatorCorpus(t *testing.T) {
	t.Parallel()
	inputs := wasmjsontest.LoadInputs[ContextInput](t, contextEvaluatorCorpus, "testdata/wasmjson/*.json", contextEvaluatorFuzzMaxInput)
	wasmjsontest.RunCorpus(t, context.Background(), inputs, contextEvaluatorDifferential())
}

func FuzzContextEvaluatorParity(f *testing.F) {
	inputs := wasmjsontest.LoadInputs[ContextInput](f, contextEvaluatorCorpus, "testdata/wasmjson/*.json", contextEvaluatorFuzzMaxInput)
	wasmjsontest.AddSeeds(f, inputs)
	differential := contextEvaluatorDifferential()
	f.Fuzz(func(t *testing.T, raw []byte) {
		wasmjsontest.CheckFuzzInput(t, context.Background(), raw, differential)
	})
}

func TestContextEvaluatorRejectsMalformedAndOversizedInput(t *testing.T) {
	t.Parallel()
	if _, err := runContextEvaluator(context.Background(), []byte("{")); !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runContextEvaluator(malformed) error = %v; want ErrEvaluatorUnavailable", err)
	}
	oversized := make([]byte, contextEvaluatorMaxInput+1)
	_, err := runContextEvaluator(context.Background(), oversized)
	if !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runContextEvaluator(oversized) error = %v; want ErrEvaluatorUnavailable", err)
	}
	if !errors.Is(err, wasmjson.ErrInputTooLarge) {
		t.Fatalf("runContextEvaluator(oversized) error = %v; want ErrInputTooLarge", err)
	}
}

func evaluateContextGoOracle(input ContextInput) Context {
	attackTechniques := ExtractAttackTechniques(input.AttackTechniqueValues...)
	attackTechniques = append(attackTechniques, ExtractAttackTechniqueIDs(input.AttackTechniqueIDValues...)...)
	return Context{
		AttackTactics:    ExtractAttackTactics(input.AttackTacticValues...),
		AttackTechniques: attackTechniques,
		DefendTactics:    ExtractDefendTactics(input.DefendTacticValues...),
		DefendTechniques: ExtractDefendTechniques(input.DefendTechniqueValues...),
		DefendArtifacts:  ExtractDefendArtifacts(input.DefendArtifactValues...),
	}
}

func contextEvaluatorDifferential() wasmjsontest.Differential[ContextInput, Context] {
	return wasmjsontest.Differential[ContextInput, Context]{
		MaxInputBytes: contextEvaluatorFuzzMaxInput,
		Oracle:        evaluateContextGoOracle,
		Candidate: func(ctx context.Context, input wasmjsontest.Input[ContextInput]) (Context, error) {
			return EvaluateContext(ctx, input.Value)
		},
	}
}
