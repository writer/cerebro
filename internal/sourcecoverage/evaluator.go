package sourcecoverage

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	coverageEvaluatorABIVersion = 1
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

var coverageEvaluator = wasmjson.New(wasmjson.Config{
	Name:              "embedded source coverage evaluator",
	Module:            coverageEvaluatorWasm,
	ABIVersion:        coverageEvaluatorABIVersion,
	ABIVersionExport:  "cerebro_sourcecoverage_abi_version",
	AllocateExport:    "cerebro_sourcecoverage_alloc",
	EvaluateExport:    "cerebro_sourcecoverage_evaluate",
	MemoryLimitPages:  1024,
	MaxInputBytes:     coverageEvaluatorMaxInput,
	MaxOutputBytes:    coverageEvaluatorMaxOutput,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       2 * time.Second,
})

func evaluateCoverage(ctx context.Context, contracts []sourcecdk.CoverageContract, observations []RuntimeObservation, options Options) ([]Record, error) {
	if contracts == nil {
		contracts = []sourcecdk.CoverageContract{}
	}
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
	result, err := coverageEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvaluatorUnavailable, err)
	}
	return result, nil
}
