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
	"github.com/writer/cerebro/internal/securitypathdelta"
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

// JobPayload is the typed result contract for a source runtime orchestration job.
type JobPayload struct {
	Sync              map[string]any                `json:"sync,omitempty"`
	GraphIngest       *graphingest.RunResult        `json:"graph_ingest,omitempty"`
	FindingRules      *findings.EvaluateRulesResult `json:"finding_rules,omitempty"`
	SecurityPathDelta *SecurityPathJobPayload       `json:"security_path_delta,omitempty"`
}

// SecurityPathJobPayload records comparison and verification outputs from one
// orchestrated security-path capture.
type SecurityPathJobPayload struct {
	Before                  securitypathdelta.Snapshot               `json:"before"`
	After                   securitypathdelta.Snapshot               `json:"after"`
	Delta                   securitypathdelta.Delta                  `json:"delta"`
	RustAuthority           []securitypathdelta.RustAuthorityReceipt `json:"rust_authority"`
	VerificationGraphIngest *graphingest.RunResult                   `json:"verification_graph_ingest,omitempty"`
	VerificationGraphRuns   []RuntimeGraphRun                        `json:"verification_graph_ingests,omitempty"`
	VerificationSnapshot    *securitypathdelta.Snapshot              `json:"verification_snapshot,omitempty"`
	Verification            *securitypathdelta.Verification          `json:"verification,omitempty"`
}

// JobResult is the storage shape accepted by the platform job service.
type JobResult map[string]any

// Result returns the typed payload in the platform job storage envelope.
func (payload JobPayload) Result() JobResult {
	result := JobResult{}
	if payload.Sync != nil {
		result["sync"] = payload.Sync
	}
	if payload.GraphIngest != nil {
		result["graph_ingest"] = payload.GraphIngest
	}
	if payload.FindingRules != nil {
		result["finding_rules"] = payload.FindingRules
	}
	if payload.SecurityPathDelta != nil {
		result["security_path_delta"] = payload.SecurityPathDelta
	}
	return result
}

func (s *SecurityPathService) Orchestrate(ctx context.Context, evaluator findingRuleEvaluator, request OrchestrationRequest) (result OrchestrationResult, runErr error) {
	if request.CaptureSecurityPathDelta {
		capture, captureErr := s.Capture(ctx, SecurityPathRequest{
			RuntimeID: request.RuntimeID, AccountID: request.SecurityPathAccountID, ObservationID: request.ObservationID,
			SourcePageLimit: request.SourcePageLimit, GraphPageLimit: request.GraphPageLimit, LeaseOwner: request.LeaseOwner,
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

func (result OrchestrationResult) JobPayload() (JobPayload, map[string]string, error) {
	payload := JobPayload{}
	refs := map[string]string{}
	if result.Sync != nil {
		encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(result.Sync)
		if err != nil {
			return JobPayload{}, nil, err
		}
		var syncValue map[string]any
		if err := json.Unmarshal(encoded, &syncValue); err != nil {
			return JobPayload{}, nil, err
		}
		payload.Sync = syncValue
	}
	if result.Graph != nil {
		payload.GraphIngest = result.Graph
		if result.Graph.Run.ID != "" {
			refs["graph_ingest_run_id"] = result.Graph.Run.ID
		}
	}
	if result.FindingRules != nil {
		payload.FindingRules = result.FindingRules
	}
	if result.SecurityPath == nil || result.SecurityPath.Delta.ID == "" {
		return payload, refs, nil
	}
	capture := result.SecurityPath
	securityPath := &SecurityPathJobPayload{
		Before: capture.Before, After: capture.After, Delta: capture.Delta,
		RustAuthority: capture.RustAuthority,
	}
	payload.SecurityPathDelta = securityPath
	refs["security_path_delta_id"] = capture.Delta.ID
	refs["security_path_delta_digest"] = capture.Delta.Digest
	if capture.VerificationGraphIngest != nil {
		securityPath.VerificationGraphIngest = capture.VerificationGraphIngest
		refs["security_path_verification_graph_run_id"] = capture.VerificationGraphIngest.Run.ID
	}
	if len(capture.VerificationGraphRuns) != 0 {
		securityPath.VerificationGraphRuns = capture.VerificationGraphRuns
	}
	if capture.VerificationSnapshot != nil {
		securityPath.VerificationSnapshot = capture.VerificationSnapshot
	}
	if capture.Verification != nil {
		securityPath.Verification = capture.Verification
		refs["security_path_verification_id"] = capture.Verification.ID
	}
	return payload, refs, nil
}
