package grcauditpackethttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/grcauditpacket"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/ports"
)

const maxCreateBodyBytes = 1 << 20

type PreviewBuilder func(*http.Request, string) (grcauditpacket.Packet, error)

type HTTPHandler struct {
	stateStore    ports.StateStore
	appendLog     ports.AppendLog
	preview       PreviewBuilder
	tenantAllowed func(context.Context, string) bool
	invalid       func(error) error
	writeError    func(http.ResponseWriter, error)
}

type auditPacketProjectionStore interface {
	ports.GRCAuditPacketStore
	ApplyAuditProjectionEvent(context.Context, *cerebrov1.EventEnvelope) (bool, error)
}

func NewHTTPHandler(stateStore ports.StateStore, appendLog ports.AppendLog, preview PreviewBuilder, tenantAllowed func(context.Context, string) bool, invalid func(error) error, writeError func(http.ResponseWriter, error)) *HTTPHandler {
	return &HTTPHandler{stateStore: stateStore, appendLog: appendLog, preview: preview, tenantAllowed: tenantAllowed, invalid: invalid, writeError: writeError}
}

func (h *HTTPHandler) Preview(w http.ResponseWriter, r *http.Request) {
	packet, err := h.preview(r, strings.TrimSpace(r.PathValue("findingID")))
	h.write(w, http.StatusOK, packet, err)
}

func (h *HTTPHandler) Create(w http.ResponseWriter, r *http.Request) {
	request := struct {
		FindingID  string   `json:"finding_id"`
		Supersedes []string `json:"supersedes,omitempty"`
	}{}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCreateBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		h.writeError(w, h.invalid(fmt.Errorf("decode audit packet request: %w", err)))
		return
	}
	store, ok := h.stateStore.(auditPacketProjectionStore)
	if !ok || h.appendLog == nil {
		h.writeError(w, findings.ErrRuntimeUnavailable)
		return
	}
	preview, err := h.preview(r, request.FindingID)
	if err == nil {
		preview, err = grcauditpacket.Freeze(r.Context(), store, preview, request.Supersedes, func(tenantID string) bool { return h.tenantAllowed(r.Context(), tenantID) })
	}
	var event *cerebrov1.EventEnvelope
	if err == nil {
		event, err = grcauditpacket.RecordedEvent(preview)
	}
	if err == nil {
		if appendErr := h.appendLog.Append(r.Context(), event); appendErr != nil {
			err = fmt.Errorf("%w: append audit packet receipt", findings.ErrRuntimeUnavailable)
		}
	}
	if err == nil {
		if _, projectionErr := store.ApplyAuditProjectionEvent(r.Context(), event); projectionErr != nil {
			err = fmt.Errorf("%w: project audit packet receipt", findings.ErrRuntimeUnavailable)
		}
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Location", "/grc/audit-packets/"+preview.ID)
	h.write(w, http.StatusCreated, preview, nil)
}

func (h *HTTPHandler) Get(w http.ResponseWriter, r *http.Request) {
	packet, err := h.load(r)
	h.write(w, http.StatusOK, packet, err)
}

func (h *HTTPHandler) Export(w http.ResponseWriter, r *http.Request) {
	packet, err := h.load(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") {
		h.write(w, http.StatusOK, packet, nil)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="finding-audit-packet.md"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	markdown := grccontrol.RenderFindingAuditPacketMarkdown(markdownInput(packet))
	markdown += fmt.Sprintf("\n## Receipt\n\n- Packet ID: `%s`\n- Canonical digest: `%s`\n- Review state: %s\n- Export state: %s\n", packet.ID, packet.Digest, packet.ReviewState, packet.ExportState)
	for _, gap := range packet.Gaps {
		markdown += fmt.Sprintf("- Gap `%s`: %s\n", gap.Code, gap.Message)
	}
	_, _ = w.Write([]byte(markdown))
}

func (h *HTTPHandler) load(r *http.Request) (grcauditpacket.Packet, error) {
	packetID := strings.TrimSpace(r.PathValue("packetID"))
	if packetID == "" {
		return grcauditpacket.Packet{}, h.invalid(fmt.Errorf("packet id is required"))
	}
	store, ok := h.stateStore.(ports.GRCAuditPacketStore)
	if !ok {
		return grcauditpacket.Packet{}, findings.ErrRuntimeUnavailable
	}
	return grcauditpacket.Load(r.Context(), store, packetID, func(tenantID string) bool { return h.tenantAllowed(r.Context(), tenantID) })
}

func (h *HTTPHandler) write(w http.ResponseWriter, status int, packet grcauditpacket.Packet, err error) {
	if err != nil {
		h.writeError(w, err)
		return
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func markdownInput(packet grcauditpacket.Packet) grccontrol.FindingAuditMarkdownInput {
	controls := make([]grccontrol.ControlRef, 0, len(packet.Controls))
	for _, control := range packet.Controls {
		controls = append(controls, grccontrol.ControlRef{FrameworkName: control.FrameworkName, ControlID: control.ControlID})
	}
	evidence := make([]grccontrol.FindingAuditMarkdownEvidence, 0, len(packet.Evidence))
	for _, item := range packet.Evidence {
		evidence = append(evidence, grccontrol.FindingAuditMarkdownEvidence{ID: item.ID, RuleID: item.RuleID, CreatedAt: item.CreatedAt})
	}
	return grccontrol.FindingAuditMarkdownInput{
		Finding: grccontrol.FindingAuditMarkdownFinding{
			ID: packet.Finding.ID, Title: packet.Finding.Title, Severity: packet.Finding.Severity, Status: packet.Finding.Status,
			Summary: packet.Finding.Summary, RiskScore: packet.Finding.RiskScore, Owner: packet.Finding.Owner, SLAStatus: packet.Finding.SLAStatus,
		},
		Controls: controls, Evidence: evidence, RecommendedAction: packet.RecommendedAction, Metadata: packet.Metadata, GeneratedAt: packet.GeneratedAt,
	}
}
