// Funnel aggregation: folds per-target outcomes into a measured Summary
// (yield + blocking-reason histogram) used by CI artifacts and the roadmap.
package connectorimport

import (
	"strings"
)

// Summary aggregates a batch funnel for CI artifacts and roadmap input.
type Summary struct {
	Targets            int            `json:"targets"`
	Supported          int            `json:"supported"`
	ExtensionNeeded    int            `json:"extension_required"`
	BespokeNeeded      int            `json:"bespoke_required"`
	RuntimeUnsupported int            `json:"runtime_unsupported"`
	ProofGateFailed    int            `json:"proof_gate_failed"`
	CatalogRejected    int            `json:"catalog_rejected"`
	GenerationError    int            `json:"generation_error"`
	YieldPercent       float64        `json:"yield_percent"`
	ByAuthModel        map[string]int `json:"by_auth_model,omitempty"`
	ByDomain           map[string]int `json:"by_domain,omitempty"`
	BlockingReasons    map[string]int `json:"blocking_reasons,omitempty"`
}

// Summarize folds outcomes into a funnel. BlockingReasons combines classifier
// missing-feature identifiers with a coarse bucket for generation failures, so
// the histogram answers one question: what unblocks the most connectors next.
func Summarize(outcomes []Outcome) Summary {
	summary := Summary{
		ByAuthModel:     map[string]int{},
		ByDomain:        map[string]int{},
		BlockingReasons: map[string]int{},
	}
	for _, outcome := range outcomes {
		summary.Targets++
		if model := strings.TrimSpace(outcome.AuthModel); model != "" {
			summary.ByAuthModel[model]++
		}
		switch outcome.Verdict {
		case VerdictSupported:
			summary.Supported++
			if domain := strings.TrimSpace(outcome.Domain); domain != "" {
				summary.ByDomain[domain]++
			}
		case VerdictExtensionRequired:
			summary.ExtensionNeeded++
		case VerdictBespokeRequired:
			summary.BespokeNeeded++
		case VerdictRuntimeUnsupported:
			summary.RuntimeUnsupported++
			summary.BlockingReasons["runtime."+runtimeReasonBucket(outcome.Error)]++
		case VerdictProofGate:
			summary.ProofGateFailed++
			summary.BlockingReasons["proofgate."+strings.TrimSpace(outcome.Error)]++
		case VerdictCatalogRejected:
			summary.CatalogRejected++
			summary.BlockingReasons["catalog."+strings.TrimSpace(outcome.Error)]++
		case VerdictGenerationError:
			summary.GenerationError++
			summary.BlockingReasons["generation."+generationReasonBucket(outcome.Error)]++
		}
		for _, feature := range outcome.MissingFeatures {
			summary.BlockingReasons[feature]++
		}
	}
	if summary.Targets > 0 {
		summary.YieldPercent = round1(float64(summary.Supported) * 100 / float64(summary.Targets))
	}
	if len(summary.ByAuthModel) == 0 {
		summary.ByAuthModel = nil
	}
	if len(summary.ByDomain) == 0 {
		summary.ByDomain = nil
	}
	if len(summary.BlockingReasons) == 0 {
		summary.BlockingReasons = nil
	}
	return summary
}

func runtimeReasonBucket(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "method") && strings.Contains(message, "not supported"):
		return "non_get_list_method"
	case strings.Contains(message, "runtime") && strings.Contains(message, "not supported"):
		return "non_jsonapi_runtime"
	case strings.Contains(message, "auth"):
		return "auth_not_executable"
	case strings.Contains(message, "transport"):
		return "transport_missing"
	default:
		return "other"
	}
}

func generationReasonBucket(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "no sourcegen-ready") || strings.Contains(message, "get list"):
		return "no_list_endpoint"
	case strings.Contains(message, "openapi document is required") || strings.Contains(message, "load") || strings.Contains(message, "parse") || strings.Contains(message, "unmarshal"):
		return "spec_parse"
	case strings.Contains(message, "not valid") || strings.Contains(message, "blocked"):
		return "definition_invalid"
	default:
		return "other"
	}
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}
