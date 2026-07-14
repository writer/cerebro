package sourceprojection

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	panopticonResourcesABIVersion     = 2
	panopticonResourcesMaxInputBytes  = 8 << 20
	panopticonResourcesMaxOutputBytes = 8 << 20
)

var errPanopticonResourceExtractorUnavailable = errors.New("panopticon resource extractor is unavailable")

//go:embed panopticonresources.wasm
var panopticonResourcesWasm []byte

var panopticonResourcesEvaluator = wasmjson.New(wasmjson.Config{
	Name:              "embedded Panopticon resource extractor",
	Module:            panopticonResourcesWasm,
	ABIVersion:        panopticonResourcesABIVersion,
	ABIVersionExport:  "cerebro_panopticon_resources_abi_version",
	AllocateExport:    "cerebro_panopticon_resources_alloc",
	EvaluateExport:    "cerebro_panopticon_resources_extract",
	MemoryLimitPages:  1024,
	MaxInputBytes:     panopticonResourcesMaxInputBytes,
	MaxOutputBytes:    panopticonResourcesMaxOutputBytes,
	InitializeTimeout: 30 * time.Second,
	CallTimeout:       time.Second,
})

func panopticonResourceObjectsWasm(ctx context.Context, payload []byte) ([]map[string]any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", errPanopticonResourceExtractorUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", errPanopticonResourceExtractorUnavailable, err)
	}
	if len(payload) == 0 {
		return nil, nil
	}
	output, err := panopticonResourcesEvaluator.Evaluate(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPanopticonResourceExtractorUnavailable, err)
	}
	var resources []map[string]any
	if err := json.Unmarshal(output, &resources); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", errPanopticonResourceExtractorUnavailable, err)
	}
	if len(resources) > maxPanopticonResourceObjects {
		return nil, fmt.Errorf("%w: returned %d objects; maximum is %d", errPanopticonResourceExtractorUnavailable, len(resources), maxPanopticonResourceObjects)
	}
	return resources, nil
}
