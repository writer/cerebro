package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
)

func (a *App) handleGRCControlArchetypes(w http.ResponseWriter, _ *http.Request) {
	response, err := compliance.BuiltinControlArchetypes(time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGRCControlProfiles(w http.ResponseWriter, r *http.Request) {
	response, err := compliance.BuiltinControlProfiles(r.URL.Query()["profile"], time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGRCControlCoverage(w http.ResponseWriter, r *http.Request) {
	response, err := compliance.BuiltinControlCoverage(r.URL.Query()["profile"], time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGRCControlEvidencePacket(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	result, err := grccontrol.BuildBuiltinEvidencePacket(grccontrol.BuildInput{
		ProfileID: firstNonEmpty(r.URL.Query().Get("profile"), r.URL.Query().Get("profile_id")),
		Framework: r.URL.Query().Get("framework"),
		ControlID: r.URL.Query().Get("control"),
		Findings:  findings,
		Evidence:  evidence,
		SourceIDs: grcRuntimeSourceIDs(runtimes),
		Now:       time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, grccontrol.ErrInvalidRequest) {
			err = errors.Join(errInvalidHTTPRequest, err)
		}
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":      result.Profile,
		"packet":       result.Packet,
		"controls":     result.Controls,
		"generated_at": result.Packet.GeneratedAt,
	})
}

func (a *App) handleGRCControlPackPreview(w http.ResponseWriter, r *http.Request) {
	a.writeGRCControlPackPreview(w, r, http.StatusOK)
}

func (a *App) handleGRCControlPackCreate(w http.ResponseWriter, r *http.Request) {
	a.writeGRCControlPackPreview(w, r, http.StatusOK)
}

func (a *App) writeGRCControlPackPreview(w http.ResponseWriter, r *http.Request, status int) {
	var request compliance.ControlPackBuildRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	response, issues, err := compliance.BuildBuiltinControlPackResponse(request, compliance.BuiltinRuleControlMappings(), time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if len(issues) != 0 {
		writeJSON(w, http.StatusBadRequest, compliance.ControlPackIssueResponse{Issues: issues, GeneratedAt: time.Now().UTC()})
		return
	}
	writeJSON(w, status, response)
}
