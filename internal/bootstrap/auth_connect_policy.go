package bootstrap

import "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"

const (
	scopeCosmoSecurityRead         = "cerebro.cosmo.security.read"
	scopeFindingCandidatePromote   = "cerebro.finding_candidates.promote"
	scopeFindingLifecycleWrite     = "cerebro.findings.write"
	scopeGRCInventoryWrite         = "cerebro.grc.inventory.write"
	scopeConnectorCredentialsRead  = "cerebro.connector_credentials.read"
	scopeConnectorCredentialsWrite = "cerebro.connector_credentials.write"
	scopeRuntimeResponseWrite      = "cerebro.runtime_response.write"
	scopeGraphActionsWrite         = "cerebro.graph_actions.write"
	scopeReportsRun                = "cerebro.reports.run"
	scopeKnowledgeWrite            = "cerebro.knowledge.write"
	scopeWorkflowReplay            = "cerebro.workflow.replay"
	scopeSourcesPreview            = "cerebro.sources.preview"
	scopeConnectorDefinitionsWrite = "cerebro.connector_definitions.write"
	scopeConnectorsWrite           = "cerebro.connectors.write"
	scopeJobsWrite                 = "cerebro.jobs.write"
	scopeSourceRuntimesWrite       = "cerebro.source_runtimes.write"
)

type connectProcedureAuthPolicy struct {
	Scope     string
	AdminOnly bool
}

func connectProcedurePolicyKnown(procedure string) bool {
	policy := connectProcedurePolicyFor(procedure)
	return policy.Scope != "" || policy.AdminOnly
}

func connectProcedurePolicyFor(procedure string) connectProcedureAuthPolicy {
	switch procedure {
	case cerebrov1connect.BootstrapServiceGetVersionProcedure,
		cerebrov1connect.BootstrapServiceCheckHealthProcedure,
		cerebrov1connect.BootstrapServiceListSourcesProcedure,
		cerebrov1connect.BootstrapServiceListReportDefinitionsProcedure,
		cerebrov1connect.BootstrapServiceListFindingRulesProcedure,
		cerebrov1connect.BootstrapServiceGetReportRunProcedure,
		cerebrov1connect.BootstrapServiceGetSourceRuntimeProcedure,
		cerebrov1connect.BootstrapServiceListClaimsProcedure,
		cerebrov1connect.BootstrapServiceListFindingsProcedure,
		cerebrov1connect.BootstrapServiceGetFindingProcedure,
		cerebrov1connect.BootstrapServiceListFindingCandidatesProcedure,
		cerebrov1connect.BootstrapServiceGetFindingCandidateProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvaluationRunsProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetEntityNeighborhoodProcedure,
		cerebrov1connect.BootstrapServiceGetGraphIngestRunProcedure,
		cerebrov1connect.BootstrapServiceListGraphIngestRunsProcedure,
		cerebrov1connect.BootstrapServiceCheckGraphIngestHealthProcedure:
		return connectProcedureAuthPolicy{Scope: scopeCosmoSecurityRead}
	case cerebrov1connect.BootstrapServicePromoteFindingCandidateProcedure,
		cerebrov1connect.BootstrapServiceRejectFindingCandidateProcedure:
		return connectProcedureAuthPolicy{Scope: scopeFindingCandidatePromote}
	case cerebrov1connect.BootstrapServiceResolveFindingProcedure,
		cerebrov1connect.BootstrapServiceSuppressFindingProcedure,
		cerebrov1connect.BootstrapServiceAssignFindingProcedure,
		cerebrov1connect.BootstrapServiceSetFindingDueDateProcedure,
		cerebrov1connect.BootstrapServiceAddFindingNoteProcedure,
		cerebrov1connect.BootstrapServiceLinkFindingTicketProcedure,
		cerebrov1connect.BootstrapServiceLinkFindingExternalRefProcedure:
		return connectProcedureAuthPolicy{Scope: scopeFindingLifecycleWrite}
	case cerebrov1connect.BootstrapServiceExecuteGraphActionProcedure,
		cerebrov1connect.BootstrapServiceReconcileGraphActionProcedure:
		return connectProcedureAuthPolicy{Scope: scopeGraphActionsWrite}
	case cerebrov1connect.BootstrapServiceRunReportProcedure:
		return connectProcedureAuthPolicy{Scope: scopeReportsRun}
	case cerebrov1connect.BootstrapServiceCheckSourceProcedure,
		cerebrov1connect.BootstrapServiceDiscoverSourceProcedure,
		cerebrov1connect.BootstrapServiceReadSourceProcedure:
		return connectProcedureAuthPolicy{Scope: scopeSourcesPreview}
	case cerebrov1connect.BootstrapServicePutSourceRuntimeProcedure,
		cerebrov1connect.BootstrapServiceSyncSourceRuntimeProcedure,
		cerebrov1connect.BootstrapServiceWriteClaimsProcedure,
		cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingCandidatesProcedure,
		cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingRulesProcedure,
		cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingsProcedure,
		cerebrov1connect.BootstrapServiceRunGraphIngestRuntimeProcedure:
		return connectProcedureAuthPolicy{Scope: scopeSourceRuntimesWrite}
	case cerebrov1connect.BootstrapServiceWriteDecisionProcedure,
		cerebrov1connect.BootstrapServiceWriteActionProcedure,
		cerebrov1connect.BootstrapServiceWriteOutcomeProcedure:
		return connectProcedureAuthPolicy{Scope: scopeKnowledgeWrite}
	case cerebrov1connect.BootstrapServiceReplayWorkflowEventsProcedure:
		return connectProcedureAuthPolicy{Scope: scopeWorkflowReplay}
	default:
		return connectProcedureAuthPolicy{}
	}
}
