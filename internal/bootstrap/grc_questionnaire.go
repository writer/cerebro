package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/evidencepackets"
	questionnairehttp "github.com/writer/cerebro/internal/sourcehttp/questionnaire"
)

func (app *App) grcQuestionnaireRunHandler() *questionnairehttp.Handler {
	return questionnairehttp.NewHandler(app.deps.StateStore, questionnairehttp.Options{
		Scope: func(r *http.Request) (questionnairehttp.Scope, error) {
			return grcQuestionnaireScopeFromRequest(r)
		},
		Evidence:  app.grcQuestionnaireEvidenceAnswers,
		Authorize: authorizeTenantID,
		Actor:     customDashboardActorID,
		BumpCache: func(ctx context.Context, tenantID string) {
			app.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeEvidence, grcCacheScopeFindings, grcCacheScopeGraph)
		},
		WriteErr:        writeGRCQuestionnaireError,
		ProjectionState: sourceProjectionStateStore(app.deps.StateStore),
		ProjectionGraph: sourceProjectionGraphStore(app.deps.GraphStore),
	})
}

func grcQuestionnaireScopeFromRequest(r *http.Request) (questionnairehttp.Scope, error) {
	scope, err := grcScopeFromRequest(r)
	httpScope := grcQuestionnaireHTTPScope(scope)
	httpScope.VendorURN = strings.TrimSpace(r.URL.Query().Get("vendor_urn"))
	return httpScope, err
}

func grcQuestionnaireHTTPScope(scope grcScope) questionnairehttp.Scope {
	return questionnairehttp.Scope{
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		VendorURN:  scope.VendorURN,
		Limit:      scope.Limit,
	}
}

func (app *App) grcQuestionnaireEvidenceAnswers(r *http.Request, httpScope questionnairehttp.Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
	scope := grcScope{
		TenantID:   httpScope.TenantID,
		RuntimeID:  httpScope.RuntimeID,
		RuntimeIDs: httpScope.RuntimeIDs,
		SourceID:   httpScope.SourceID,
		VendorURN:  httpScope.VendorURN,
		Limit:      httpScope.Limit,
	}
	runtimes, err := app.grcListRuntimes(r, scope)
	if err != nil {
		return nil, err
	}
	result, err := app.buildGRCControlEvidencePacketWithScope(r, scope, runtimes)
	if err != nil {
		return nil, err
	}
	return evidencepackets.Build(result).Answers, nil
}

func writeGRCQuestionnaireError(w http.ResponseWriter, err error) {
	if errors.Is(err, questionnairehttp.ErrInvalidRequest) {
		err = errors.Join(errInvalidHTTPRequest, err)
	}
	writeGRCError(w, err)
}
