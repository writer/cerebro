package mitre

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	contextEvaluatorABIVersion = 1
	contextEvaluatorMaxInput   = 1 << 20
	contextEvaluatorMaxOutput  = 2 << 20
)

var ErrEvaluatorUnavailable = errors.New("MITRE context evaluator is unavailable")

//go:embed evaluator.wasm
var contextEvaluatorWasm []byte

// ContextInput contains ordered metadata values selected by the projection layer.
type ContextInput struct {
	AttackTacticValues      []string `json:"attack_tactic_values,omitempty"`
	AttackTechniqueValues   []string `json:"attack_technique_values,omitempty"`
	AttackTechniqueIDValues []string `json:"attack_technique_id_values,omitempty"`
	DefendTacticValues      []string `json:"defend_tactic_values,omitempty"`
	DefendTechniqueValues   []string `json:"defend_technique_values,omitempty"`
	DefendArtifactValues    []string `json:"defend_artifact_values,omitempty"`
}

// HasValues reports whether the input contains MITRE metadata to normalize.
func (input ContextInput) HasValues() bool {
	for _, values := range [][]string{
		input.AttackTacticValues,
		input.AttackTechniqueValues,
		input.AttackTechniqueIDValues,
		input.DefendTacticValues,
		input.DefendTechniqueValues,
		input.DefendArtifactValues,
	} {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

// Context is one normalized MITRE ATT&CK and D3FEND metadata batch.
type Context struct {
	AttackTactics    []AttackTactic    `json:"attack_tactics"`
	AttackTechniques []AttackTechnique `json:"attack_techniques"`
	DefendTactics    []DefendTactic    `json:"defend_tactics"`
	DefendTechniques []DefendTechnique `json:"defend_techniques"`
	DefendArtifacts  []DefendArtifact  `json:"defend_artifacts"`
}

var contextEvaluator = wasmjson.New(wasmjson.Config{
	Name:              "embedded MITRE context evaluator",
	Module:            contextEvaluatorWasm,
	ABIVersion:        contextEvaluatorABIVersion,
	ABIVersionExport:  "cerebro_mitre_abi_version",
	AllocateExport:    "cerebro_mitre_alloc",
	EvaluateExport:    "cerebro_mitre_evaluate",
	MemoryLimitPages:  512,
	MaxInputBytes:     contextEvaluatorMaxInput,
	MaxOutputBytes:    contextEvaluatorMaxOutput,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       time.Second,
})

// EvaluateContext normalizes one ordered metadata batch without projecting graph state.
func EvaluateContext(ctx context.Context, input ContextInput) (Context, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return Context{}, fmt.Errorf("%w: encode request: %w", ErrEvaluatorUnavailable, err)
	}
	output, err := runContextEvaluator(ctx, payload)
	if err != nil {
		return Context{}, err
	}
	var result Context
	if err := json.Unmarshal(output, &result); err != nil {
		return Context{}, fmt.Errorf("%w: decode response: %w", ErrEvaluatorUnavailable, err)
	}
	if result.AttackTactics == nil {
		result.AttackTactics = []AttackTactic{}
	}
	if result.AttackTechniques == nil {
		result.AttackTechniques = []AttackTechnique{}
	}
	if result.DefendTactics == nil {
		result.DefendTactics = []DefendTactic{}
	}
	if result.DefendTechniques == nil {
		result.DefendTechniques = []DefendTechnique{}
	}
	if result.DefendArtifacts == nil {
		result.DefendArtifacts = []DefendArtifact{}
	}
	return result, nil
}

func runContextEvaluator(ctx context.Context, payload []byte) ([]byte, error) {
	output, err := contextEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvaluatorUnavailable, err)
	}
	return output, nil
}
