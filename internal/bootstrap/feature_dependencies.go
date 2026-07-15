package bootstrap

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/claims"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/graphquery"
	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
	"github.com/writer/cerebro/internal/runtimeresponse"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceruntime"
	"github.com/writer/cerebro/internal/workflowprojection"
)

type sourceFeatureDeps struct {
	Sources *sourcecdk.Registry
}

func newSourceFeatureDeps(sources *sourcecdk.Registry) sourceFeatureDeps {
	return sourceFeatureDeps{Sources: sources}
}

func newSourceFeatureService(deps sourceFeatureDeps) *sourceops.Service {
	return sourceops.New(deps.Sources)
}

type reportFeatureDeps struct {
	Findings     ports.FindingStore
	GraphQueries ports.GraphQueryStore
	Reports      ports.ReportStore
}

func newReportFeatureDeps(deps Dependencies) reportFeatureDeps {
	return reportFeatureDeps{
		Findings:     findingStore(deps.StateStore),
		GraphQueries: graphQueryStore(deps.GraphStore),
		Reports:      reportStore(deps.StateStore),
	}
}

func newReportFeatureService(deps reportFeatureDeps) *reports.Service {
	return reports.New(deps.Findings, deps.GraphQueries, deps.Reports)
}

type runtimeFeatureDeps struct {
	Sources            *sourcecdk.Registry
	Runtimes           ports.SourceRuntimeStore
	AppendLog          ports.AppendLog
	Projector          ports.SourceProjector
	RuntimeConfigStore ports.StateStore
	Definitions        ports.ConnectorDefinitionStore
}

func newRuntimeFeatureDeps(deps Dependencies, sources *sourcecdk.Registry) runtimeFeatureDeps {
	return runtimeFeatureDeps{
		Sources:            sources,
		Runtimes:           sourceRuntimeStore(deps.StateStore),
		AppendLog:          deps.AppendLog,
		Projector:          sourceProjector(deps.StateStore, deps.GraphStore),
		RuntimeConfigStore: deps.StateStore,
		Definitions:        connectorDefinitionStore(deps.StateStore),
	}
}

func newRuntimeFeatureService(cfg config.Config, deps runtimeFeatureDeps) *sourceruntime.Service {
	return sourceruntime.New(
		deps.Sources,
		deps.Runtimes,
		deps.AppendLog,
		deps.Projector,
	).WithConnectorDefinitionStore(deps.Definitions).WithConfigResolver(func(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
		return resolveRuntimeSourceConfigWithStore(ctx, cfg.ConnectorCredentials, cfg.ConnectorSecretStores, deps.RuntimeConfigStore, sourceID, values)
	})
}

type claimFeatureDeps struct {
	Runtimes        ports.SourceRuntimeStore
	Claims          ports.ClaimStore
	ProjectionState ports.ProjectionStateStore
	ProjectionGraph ports.ProjectionGraphStore
}

func newClaimFeatureDeps(deps Dependencies) claimFeatureDeps {
	return claimFeatureDeps{
		Runtimes:        sourceRuntimeStore(deps.StateStore),
		Claims:          claimStore(deps.StateStore),
		ProjectionState: sourceProjectionStateStore(deps.StateStore),
		ProjectionGraph: sourceProjectionGraphStore(deps.GraphStore),
	}
}

func newClaimFeatureService(deps claimFeatureDeps) *claims.Service {
	return claims.New(deps.Runtimes, deps.Claims, deps.ProjectionState, deps.ProjectionGraph)
}

type findingFeatureDeps struct {
	Runtimes        ports.SourceRuntimeStore
	EventReplayer   ports.EventReplayer
	Findings        ports.FindingStore
	EvaluationRuns  ports.FindingEvaluationRunStore
	Evidence        ports.FindingEvidenceStore
	Claims          ports.ClaimStore
	Candidates      ports.FindingCandidateStore
	ProjectionGraph ports.ProjectionGraphStore
	GraphQueries    ports.GraphQueryStore
	AppendLog       ports.AppendLog
	Rules           *findings.Registry
}

func newFindingFeatureDeps(deps Dependencies) findingFeatureDeps {
	return findingFeatureDeps{
		Runtimes:        sourceRuntimeStore(deps.StateStore),
		EventReplayer:   eventReplayer(deps.AppendLog),
		Findings:        findingStore(deps.StateStore),
		EvaluationRuns:  findingEvaluationRunStore(deps.StateStore),
		Evidence:        findingEvidenceStore(deps.StateStore),
		Claims:          claimStore(deps.StateStore),
		Candidates:      findingCandidateStore(deps.StateStore),
		ProjectionGraph: sourceProjectionGraphStore(deps.GraphStore),
		GraphQueries:    graphQueryStore(deps.GraphStore),
		AppendLog:       deps.AppendLog,
		Rules:           deps.FindingRules,
	}
}

func newFindingCoreFeatureService(deps findingFeatureDeps) *findings.Service {
	return findings.NewWithOptionalRegistry(deps.Runtimes, deps.EventReplayer, deps.Findings, deps.EvaluationRuns, deps.Evidence, deps.Claims, deps.Rules)
}

func newFindingCandidateFeatureService(deps findingFeatureDeps) *findings.Service {
	return newFindingCoreFeatureService(deps).WithFindingCandidateStore(deps.Candidates)
}

func newFindingWorkflowFeatureService(deps findingFeatureDeps) *findings.Service {
	return newFindingCandidateFeatureService(deps).
		WithGraphStore(deps.ProjectionGraph).
		WithGraphQueryStore(deps.GraphQueries).
		WithAppendLog(deps.AppendLog)
}

type knowledgeFeatureDeps struct {
	GraphQueries    ports.GraphQueryStore
	ProjectionGraph ports.ProjectionGraphStore
	AppendLog       ports.AppendLog
}

func newKnowledgeFeatureDeps(deps Dependencies) knowledgeFeatureDeps {
	return knowledgeFeatureDeps{
		GraphQueries:    graphQueryStore(deps.GraphStore),
		ProjectionGraph: sourceProjectionGraphStore(deps.GraphStore),
		AppendLog:       deps.AppendLog,
	}
}

func newKnowledgeFeatureService(deps knowledgeFeatureDeps) *knowledge.Service {
	return knowledge.New(deps.GraphQueries, deps.ProjectionGraph).WithAppendLog(deps.AppendLog)
}

type graphQueryFeatureDeps struct {
	GraphQueries ports.GraphQueryStore
}

func newGraphQueryFeatureDeps(deps Dependencies) graphQueryFeatureDeps {
	return graphQueryFeatureDeps{GraphQueries: graphQueryStore(deps.GraphStore)}
}

func newGraphQueryFeatureService(deps graphQueryFeatureDeps) *graphquery.Service {
	return graphquery.New(deps.GraphQueries)
}

type graphIngestFeatureDeps struct {
	Sources            *sourcecdk.Registry
	Runtimes           ports.SourceRuntimeStore
	Projector          ports.SourceProjector
	GraphStore         ports.GraphStore
	RuntimeConfigStore ports.StateStore
}

func newGraphIngestFeatureDeps(deps Dependencies, sources *sourcecdk.Registry) graphIngestFeatureDeps {
	return graphIngestFeatureDeps{
		Sources:            sources,
		Runtimes:           sourceRuntimeStore(deps.StateStore),
		Projector:          sourceProjector(nil, deps.GraphStore),
		GraphStore:         deps.GraphStore,
		RuntimeConfigStore: deps.StateStore,
	}
}

func newGraphIngestFeatureService(cfg config.Config, deps graphIngestFeatureDeps) *graphingest.Service {
	return graphingest.New(
		deps.Sources,
		deps.Runtimes,
		deps.Projector,
		deps.GraphStore,
	).WithConfigPreparer(func(ctx context.Context, sourceID string, values map[string]string) (map[string]string, error) {
		return resolveRuntimeSourceConfigWithStore(ctx, cfg.ConnectorCredentials, cfg.ConnectorSecretStores, deps.RuntimeConfigStore, sourceID, values)
	})
}

type workflowReplayFeatureDeps struct {
	EventReplayer   ports.EventReplayer
	ProjectionGraph ports.ProjectionGraphStore
}

func newWorkflowReplayFeatureDeps(deps Dependencies) workflowReplayFeatureDeps {
	return workflowReplayFeatureDeps{
		EventReplayer:   eventReplayer(deps.AppendLog),
		ProjectionGraph: sourceProjectionGraphStore(deps.GraphStore),
	}
}

func newWorkflowReplayFeatureService(deps workflowReplayFeatureDeps) *workflowprojection.Replayer {
	return workflowprojection.NewReplayer(deps.EventReplayer, deps.ProjectionGraph)
}

type jobFeatureDeps struct {
	Jobs ports.JobStore
}

func newJobFeatureDeps(deps Dependencies) jobFeatureDeps {
	return jobFeatureDeps{Jobs: jobStore(deps.StateStore)}
}

func newJobFeatureService(deps jobFeatureDeps) *platformjobs.Service {
	return platformjobs.New(deps.Jobs)
}

type runtimeResponseFeatureDeps struct {
	Blocklist ports.RuntimeBlocklistStore
}

func newRuntimeResponseFeatureDeps(deps Dependencies) runtimeResponseFeatureDeps {
	return runtimeResponseFeatureDeps{Blocklist: runtimeBlocklistStore(deps.StateStore)}
}

func newRuntimeResponseFeatureService(deps runtimeResponseFeatureDeps) *runtimeresponse.Service {
	return runtimeresponse.New(deps.Blocklist)
}

type graphReasoningFeatureDeps struct {
	GraphQueries    ports.GraphQueryStore
	GraphAgentLLM   graphagent.LLMClient
	TrajectoryStore ports.AskTrajectoryStore
}

func newGraphReasoningFeatureDeps(deps Dependencies) graphReasoningFeatureDeps {
	return graphReasoningFeatureDeps{
		GraphQueries:    graphQueryStore(deps.GraphStore),
		GraphAgentLLM:   deps.GraphAgentLLM,
		TrajectoryStore: askTrajectoryStore(deps.StateStore),
	}
}

func newGraphReasoningFeatureService(deps graphReasoningFeatureDeps) (*graphagent.Service, error) {
	if deps.GraphQueries == nil {
		return nil, graphquery.ErrRuntimeUnavailable
	}
	if deps.GraphAgentLLM == nil {
		return nil, errors.Join(graphagent.ErrRuntimeUnavailable, errors.New("graph agent llm is not configured"))
	}
	return graphagent.NewServiceWithOptions(deps.GraphQueries, deps.GraphAgentLLM, graphagent.ValidatorOptions{Explain: true}, graphagent.ServiceOptions{
		TrajectoryStore:             deps.TrajectoryStore,
		EnableGraphProbes:           true,
		EnableDeterministicFastPath: true,
		EnableRecovery:              true,
		EnableMapReduce:             true,
		MaxDepth:                    2,
		MaxChildren:                 2,
	}), nil
}
