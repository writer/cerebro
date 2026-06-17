package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
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
	result, err := a.buildGRCControlEvidencePacket(r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	writeGRCControlPacketJSON(w, result)
}

func (a *App) handleGRCControlEvidencePacketDetail(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.URL.Query().Get("control")) == "" {
		writeGRCError(w, fmt.Errorf("%w: control query parameter is required", errInvalidHTTPRequest))
		return
	}
	result, err := a.buildGRCControlEvidencePacket(r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	if len(result.Packet.Controls) != 1 {
		writeGRCError(w, fmt.Errorf("%w: expected exactly one matching control, got %d", errInvalidHTTPRequest, len(result.Packet.Controls)))
		return
	}
	writeGRCControlPacketJSON(w, result)
}

func (a *App) handleGRCControlEvidencePacketExport(w http.ResponseWriter, r *http.Request) {
	result, err := a.buildGRCControlEvidencePacket(r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		writeGRCControlPacketJSON(w, result)
		return
	}
	writeGRCMarkdownExport(w, "control-evidence-packet.md", grccontrol.RenderMarkdown(result))
}

func (a *App) handleGRCCustomControlEvidencePacket(w http.ResponseWriter, r *http.Request) {
	result, issues, err := a.buildGRCCustomControlEvidencePacket(w, r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	if len(issues) != 0 {
		writeJSON(w, http.StatusBadRequest, compliance.ControlPackIssueResponse{Issues: issues, GeneratedAt: time.Now().UTC()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":      result.Profile,
		"packet":       result.Packet,
		"controls":     result.Controls,
		"preview":      result.Preview,
		"generated_at": result.Packet.GeneratedAt,
	})
}

func (a *App) handleGRCCustomControlEvidencePacketExport(w http.ResponseWriter, r *http.Request) {
	result, issues, err := a.buildGRCCustomControlEvidencePacket(w, r)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	if len(issues) != 0 {
		writeJSON(w, http.StatusBadRequest, compliance.ControlPackIssueResponse{Issues: issues, GeneratedAt: time.Now().UTC()})
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"profile":      result.Profile,
			"packet":       result.Packet,
			"controls":     result.Controls,
			"preview":      result.Preview,
			"generated_at": result.Packet.GeneratedAt,
		})
		return
	}
	writeGRCMarkdownExport(w, "custom-control-evidence-packet.md", grccontrol.RenderCustomMarkdown(result))
}

func (a *App) buildGRCControlEvidencePacket(r *http.Request) (grccontrol.PacketResult, error) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		return grccontrol.PacketResult{}, err
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return grccontrol.PacketResult{}, err
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: scope.Limit})
	if err != nil {
		return grccontrol.PacketResult{}, err
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		return grccontrol.PacketResult{}, err
	}
	return grccontrol.BuildBuiltinEvidencePacket(grccontrol.BuildInput{
		ProfileID: firstNonEmpty(r.URL.Query().Get("profile"), r.URL.Query().Get("profile_id")),
		Framework: r.URL.Query().Get("framework"),
		ControlID: r.URL.Query().Get("control"),
		Findings:  findings,
		Evidence:  evidence,
		SourceIDs: grcRuntimeSourceIDs(runtimes),
		Now:       time.Now().UTC(),
	})
}

func (a *App) buildGRCCustomControlEvidencePacket(w http.ResponseWriter, r *http.Request) (grccontrol.CustomPacketResult, []compliance.ValidationIssue, error) {
	var request compliance.ControlPackBuildRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return grccontrol.CustomPacketResult{}, nil, errors.Join(errInvalidHTTPRequest, err)
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		return grccontrol.CustomPacketResult{}, nil, err
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return grccontrol.CustomPacketResult{}, nil, err
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: scope.Limit})
	if err != nil {
		return grccontrol.CustomPacketResult{}, nil, err
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		return grccontrol.CustomPacketResult{}, nil, err
	}
	return grccontrol.BuildCustomEvidencePacket(grccontrol.CustomBuildInput{
		Request:   request,
		Framework: r.URL.Query().Get("framework"),
		ControlID: r.URL.Query().Get("control"),
		Findings:  findings,
		Evidence:  evidence,
		SourceIDs: grcRuntimeSourceIDs(runtimes),
		Now:       time.Now().UTC(),
	})
}

func writeGRCControlPacketJSON(w http.ResponseWriter, result grccontrol.PacketResult) {
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":      result.Profile,
		"packet":       result.Packet,
		"controls":     result.Controls,
		"generated_at": result.Packet.GeneratedAt,
	})
}

func writeGRCControlPacketError(w http.ResponseWriter, err error) {
	if errors.Is(err, grccontrol.ErrInvalidRequest) {
		err = errors.Join(errInvalidHTTPRequest, err)
	}
	writeGRCError(w, err)
}

func writeGRCMarkdownExport(w http.ResponseWriter, filename, body string) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(html.EscapeString(body)))
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
