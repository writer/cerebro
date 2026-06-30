package bootstrap

import (
	"context"
	"errors"
	"net/http"

	"github.com/writer/cerebro/internal/evidencepackets"
	questionnairehttp "github.com/writer/cerebro/internal/sourcehttp/questionnaire"
)

func (app *App) grcQuestionnaireRunHandler() *questionnairehttp.Handler {
	return questionnairehttp.NewHandler(app.deps.StateStore, questionnairehttp.Options{
		Scope: func(r *http.Request) (questionnairehttp.Scope, error) {
			scope, err := grcScopeFromRequest(r)
			return grcQuestionnaireHTTPScope(scope), err
		},
		Evidence:  app.grcQuestionnaireEvidenceAnswers,
		Authorize: authorizeTenantID,
		Actor:     customDashboardActorID,
		BumpCache: func(ctx context.Context, tenantID string) {
			app.bumpGRCCacheVersions(ctx, tenantID, grcCacheScopeEvidence, grcCacheScopeFindings, grcCacheScopeGraph)
		},
		WriteErr: writeGRCQuestionnaireError,
	})
}

func grcQuestionnaireHTTPScope(scope grcScope) questionnairehttp.Scope {
	return questionnairehttp.Scope{
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}
}

func (app *App) grcQuestionnaireEvidenceAnswers(r *http.Request, _ questionnairehttp.Scope) ([]evidencepackets.QuestionnaireAnswer, error) {
	result, err := app.buildGRCControlEvidencePacket(r)
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
