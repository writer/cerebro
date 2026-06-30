package bootstrap

import (
	"context"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
	grcvendorquestionnairehttp "github.com/writer/cerebro/internal/sourcehttp/grcvendorquestionnaire"
)

func (app *App) grcVendorQuestionnaireHandler() *grcvendorquestionnairehttp.Handler {
	return grcvendorquestionnairehttp.NewHandler(app.deps.StateStore, grcvendorquestionnairehttp.Options{
		Scope: func(r *http.Request) (grcvendorquestionnairehttp.Scope, error) {
			scope, err := grcScopeFromRequest(r)
			return grcVendorQuestionnaireHTTPScope(scope), err
		},
		Vendor: func(r *http.Request, scope grcvendorquestionnairehttp.Scope, vendorID string, vendorURN string) (*grcvendor.VendorDetail, error) {
			return grcvendor.New(graphQueryStore(app.deps.GraphStore)).GetVendor(r.Context(), grcvendor.VendorDetailRequest{
				URN:        vendorURN,
				VendorID:   strings.TrimSpace(vendorID),
				TenantID:   scope.TenantID,
				RuntimeID:  scope.RuntimeID,
				RuntimeIDs: scope.RuntimeIDs,
				SourceID:   scope.SourceID,
				Limit:      scope.Limit,
			})
		},
		Signals:   app.grcVendorQuestionnaireSignals,
		Summary:   app.grcVendorQuestionnaireLLMSummary,
		Authorize: authorizeCerebroURNTenant,
		Actor:     customDashboardActorID,
		BumpCache: func(ctx context.Context, tenantID string) {
			app.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeGraph)
		},
		WriteErr: writeGRCError,
	})
}

func grcVendorQuestionnaireHTTPScope(scope grcScope) grcvendorquestionnairehttp.Scope {
	return grcvendorquestionnairehttp.Scope{
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}
}

func grcVendorQuestionnaireScope(scope grcvendorquestionnairehttp.Scope) grcScope {
	return grcScope{
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}
}

func (app *App) grcVendorQuestionnaireSignals(r *http.Request, scope grcvendorquestionnairehttp.Scope, vendorURN string) ([]grcvendor.QuestionnaireFindingSignal, []grcvendor.QuestionnaireEvidenceSignal) {
	if findingStore(app.deps.StateStore) == nil || sourceRuntimeStore(app.deps.StateStore) == nil {
		return nil, nil
	}
	grcScope := grcVendorQuestionnaireScope(scope)
	runtimes, err := app.grcListRuntimes(r, grcScope)
	if err != nil {
		return nil, nil
	}
	findings, err := app.grcListFindingRecords(r, runtimes, grcFindingFilter{ResourceURN: vendorURN, Status: "open", Limit: scope.Limit})
	if err != nil {
		return nil, nil
	}
	evidence, err := app.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), GraphRootURN: vendorURN, Limit: scope.Limit})
	if err != nil {
		return grcQuestionnaireFindingSignals(grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), nil)), nil
	}
	return grcQuestionnaireFindingSignals(grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence))), grcQuestionnaireEvidenceSignals(grcEvidenceItems(evidence, grcFindingTitleMap(findings)))
}

func (app *App) grcVendorQuestionnaireLLMSummary(r *http.Request, scope grcvendorquestionnairehttp.Scope, record *ports.GRCVendorQuestionnaireReviewRecord, detail *grcvendor.VendorDetail, findings []grcvendor.QuestionnaireFindingSignal, evidence []grcvendor.QuestionnaireEvidenceSignal) string {
	if app.deps.GraphAgentLLM == nil || record == nil || detail == nil {
		return ""
	}
	rows := []map[string]any{
		{
			"review_id":        record.ReviewID,
			"vendor_urn":       record.VendorURN,
			"vendor_name":      detail.Vendor.Name,
			"risk_level":       detail.Vendor.RiskLevel,
			"risk_score":       detail.Vendor.RiskScore,
			"packet_state":     detail.Vendor.PacketState,
			"open_findings":    len(findings),
			"evidence_items":   len(evidence),
			"missing_packet":   detail.Vendor.PacketMissingItems,
			"monitoring_state": detail.Vendor.MonitoringState,
			"freshness_state":  detail.Vendor.EvidenceFreshnessState,
		},
	}
	summary, err := app.deps.GraphAgentLLM.Summarize(r.Context(), graphagent.SummarizeRequest{
		TenantID: scope.TenantID,
		Question: "Summarize the vendor security questionnaire review using only these rows. State the decision support, gaps, and reviewer follow-up. Do not invent evidence.",
		ScopeURN: record.VendorURN,
		Model:    graphagent.HaikuModel,
		Rows:     rows,
	})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(summary)
}

func grcQuestionnaireFindingSignals(findings []grcFindingItem) []grcvendor.QuestionnaireFindingSignal {
	signals := make([]grcvendor.QuestionnaireFindingSignal, 0, len(findings))
	for _, finding := range findings {
		controlID := ""
		if len(finding.Controls) > 0 {
			controlID = finding.Controls[0].ControlID
		}
		resourceURN := ""
		if len(finding.ResourceURNs) > 0 {
			resourceURN = finding.ResourceURNs[0]
		}
		signals = append(signals, grcvendor.QuestionnaireFindingSignal{
			ID:            finding.ID,
			Title:         finding.Title,
			Severity:      strings.ToLower(finding.Severity),
			Status:        finding.Status,
			ControlID:     controlID,
			ResourceURN:   resourceURN,
			EvidenceCount: finding.EvidenceCount,
		})
	}
	return signals
}

func grcQuestionnaireEvidenceSignals(evidence []grcEvidenceItem) []grcvendor.QuestionnaireEvidenceSignal {
	signals := make([]grcvendor.QuestionnaireEvidenceSignal, 0, len(evidence))
	for _, item := range evidence {
		signals = append(signals, grcvendor.QuestionnaireEvidenceSignal{
			ID:       item.ID,
			Title:    firstNonEmpty(item.FindingTitle, item.FindingID, item.ID),
			Type:     "finding_evidence",
			SourceID: item.RuntimeID,
			State:    "current",
		})
	}
	return signals
}
