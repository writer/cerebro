package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/compliance"
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

func (a *App) handleGRCControlPackPreview(w http.ResponseWriter, r *http.Request) {
	a.writeGRCControlPackPreview(w, r, http.StatusOK)
}

func (a *App) handleGRCControlPackCreate(w http.ResponseWriter, r *http.Request) {
	a.writeGRCControlPackPreview(w, r, http.StatusCreated)
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
