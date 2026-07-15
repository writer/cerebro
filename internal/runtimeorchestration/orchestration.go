package runtimeorchestration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/sourceruntime"
)

type findingRuleEvaluator interface {
	EvaluateSourceRuntimeRules(context.Context, findings.EvaluateRulesRequest) (*findings.EvaluateRulesResult, error)
}

type OrchestrationRequest struct {
	RuntimeID                string
	SourcePageLimit          uint32
	GraphPageLimit           uint32
	RuleIDs                  []string
	EventLimit               uint32
	CaptureSecurityPathDelta bool
	SecurityPathRustShadow   bool
	SecurityPathAccountID    string
	ObservationID            string
	LeaseOwner               string
}

type OrchestrationResult struct {
	Sync         *cerebrov1.SyncSourceRuntimeResponse
	Graph        *graphingest.RunResult
	FindingRules *findings.EvaluateRulesResult
	SecurityPath *SecurityPathResult
}

// OrchestrationJobPayload is the persisted job document produced by an orchestration run.
type OrchestrationJobPayload map[string]any

func (s *SecurityPathService) Orchestrate(ctx context.Context, evaluator findingRuleEvaluator, request OrchestrationRequest) (result OrchestrationResult, runErr error) {
	if request.CaptureSecurityPathDelta {
		capture, captureErr := s.Capture(ctx, SecurityPathRequest{
			RuntimeID: request.RuntimeID, AccountID: request.SecurityPathAccountID, ObservationID: request.ObservationID,
			SourcePageLimit: request.SourcePageLimit, GraphPageLimit: request.GraphPageLimit, LeaseOwner: request.LeaseOwner, RustShadow: request.SecurityPathRustShadow,
		})
		result.Sync, result.Graph, result.SecurityPath = capture.Sync, capture.Graph, &capture
		if result.Graph != nil && evaluator != nil {
			result.FindingRules, runErr = evaluator.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
				RuntimeID: request.RuntimeID, RuleIDs: request.RuleIDs, EventLimit: request.EventLimit,
			})
		}
		if captureErr != nil {
			return result, errors.Join(captureErr, runErr)
		}
		return result, runErr
	}
	result.Sync, runErr = s.deps.RuntimeSync.SyncWithLease(ctx, &cerebrov1.SyncSourceRuntimeRequest{
		Id: request.RuntimeID, PageLimit: request.SourcePageLimit,
	}, sourceruntime.SyncWithLeaseOptions{LeaseStore: s.deps.LeaseStore})
	if runErr != nil {
		return result, runErr
	}
	result.Graph, runErr = s.deps.GraphIngest.RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID: strings.TrimSpace(request.RuntimeID), PageLimit: request.GraphPageLimit, Trigger: "platform_orchestration_job",
	})
	if runErr != nil {
		return result, runErr
	}
	if evaluator != nil {
		result.FindingRules, runErr = evaluator.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
			RuntimeID: request.RuntimeID, RuleIDs: request.RuleIDs, EventLimit: request.EventLimit,
		})
	}
	return result, runErr
}

func (result OrchestrationResult) JobPayload() (OrchestrationJobPayload, map[string]string, error) {
	payload := OrchestrationJobPayload{}
	refs := map[string]string{}
	if result.Sync != nil {
		encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(result.Sync)
		if err != nil {
			return nil, nil, err
		}
		var syncValue map[string]any
		if err := json.Unmarshal(encoded, &syncValue); err != nil {
			return nil, nil, err
		}
		payload["sync"] = syncValue
	}
	if result.Graph != nil {
		payload["graph_ingest"] = result.Graph
		if result.Graph.Run.ID != "" {
			refs["graph_ingest_run_id"] = result.Graph.Run.ID
		}
	}
	if result.FindingRules != nil {
		payload["finding_rules"] = result.FindingRules
	}
	if result.SecurityPath == nil || result.SecurityPath.Delta.ID == "" {
		return payload, refs, nil
	}
	capture := result.SecurityPath
	securityPath := map[string]any{"before": capture.Before, "after": capture.After, "delta": capture.Delta}
	if len(capture.RustShadow) != 0 {
		securityPath["rust_shadow"] = capture.RustShadow
	}
	payload["security_path_delta"] = securityPath
	refs["security_path_delta_id"] = capture.Delta.ID
	refs["security_path_delta_digest"] = capture.Delta.Digest
	if capture.VerificationGraphIngest != nil {
		securityPath["verification_graph_ingest"] = capture.VerificationGraphIngest
		refs["security_path_verification_graph_run_id"] = capture.VerificationGraphIngest.Run.ID
	}
	if len(capture.VerificationGraphRuns) != 0 {
		securityPath["verification_graph_ingests"] = capture.VerificationGraphRuns
	}
	if capture.VerificationSnapshot != nil {
		securityPath["verification_snapshot"] = capture.VerificationSnapshot
	}
	if capture.Verification != nil {
		securityPath["verification"] = capture.Verification
		refs["security_path_verification_id"] = capture.Verification.ID
	}
	return payload, refs, nil
}
