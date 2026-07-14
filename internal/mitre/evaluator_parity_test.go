package mitre

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestContextEvaluatorMatchesGoOracle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input ContextInput
	}{
		{
			name: "current metadata",
			input: ContextInput{
				AttackTacticValues:      []string{"Defense Evasion", "mitre-ta0011", "attack.initial-access", "Collection:T1530"},
				AttackTechniqueValues:   []string{"T1190", "Native API"},
				AttackTechniqueIDValues: []string{"github,attack.t1562.001", "https://attack.mitre.org/techniques/T1098/003/"},
				DefendTacticValues:      []string{"d3f:Model"},
				DefendTechniqueValues:   []string{"https://d3fend.mitre.org/technique/ProcessScreenshot/", "d3f:ProcessTermination"},
				DefendArtifactValues:    []string{"d3f:Credential"},
			},
		},
		{
			name: "separators duplicates and source precedence",
			input: ContextInput{
				AttackTacticValues:      []string{"Initial Access|TA0001", "TA9999"},
				AttackTechniqueValues:   []string{"t1190,T1190;Native API\nnative-api\tT1562.001"},
				AttackTechniqueIDValues: []string{"attack.t1190|T1486"},
				DefendTechniqueValues:   []string{"TokenBinding,TokenBinding,tokenbinding"},
			},
		},
		{
			name: "URL precedence and non identifiers",
			input: ContextInput{
				AttackTechniqueValues: []string{
					"https://attack.mitre.org/techniques/T1098/003/ and T1190",
					"Initial Access",
					"T123",
					"T١١٩٠",
				},
				AttackTechniqueIDValues: []string{"Native API", "T123"},
			},
		},
		{
			name: "D3FEND exact prefix and name behavior",
			input: ContextInput{
				DefendTacticValues:    []string{"d3f:", "D3FEND:Network", "D3f:Mixed"},
				DefendTechniqueValues: []string{"Process Termination", "https://d3fend.mitre.org/technique/ProcessScreenshot/"},
				DefendArtifactValues:  []string{"https://d3fend.mitre.org/artifact/Credential/#", "Credential"},
			},
		},
		{
			name: "empty values and internal unicode whitespace",
			input: ContextInput{
				AttackTacticValues:    []string{"", "\u00a0Initial\u00a0Access\u00a0"},
				DefendTechniqueValues: []string{"\u00a0TokenBinding\u00a0"},
			},
		},
		{
			name: "simple unicode lowercase duplicate precedence",
			input: ContextInput{
				AttackTechniqueValues: []string{"İ", "i"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := EvaluateContext(context.Background(), test.input)
			if err != nil {
				t.Fatalf("EvaluateContext() error = %v", err)
			}
			want := evaluateContextGoOracle(test.input)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("context mismatch\ngot:  %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestContextEvaluatorRejectsMalformedAndOversizedInput(t *testing.T) {
	t.Parallel()
	if _, err := runContextEvaluator(context.Background(), []byte("{")); !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runContextEvaluator(malformed) error = %v; want ErrEvaluatorUnavailable", err)
	}
	marker := "metadata-marker-that-must-not-be-logged"
	oversized := []byte(marker + strings.Repeat("x", contextEvaluatorMaxInput))
	_, err := runContextEvaluator(context.Background(), oversized)
	if !errors.Is(err, ErrEvaluatorUnavailable) {
		t.Fatalf("runContextEvaluator(oversized) error = %v; want ErrEvaluatorUnavailable", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("oversized input error exposed metadata: %v", err)
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
