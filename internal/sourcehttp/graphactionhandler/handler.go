package graphactionhandler

import (
	"context"
	"encoding/json"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactionapi"
	"github.com/writer/cerebro/internal/ports"
)

type Handler struct {
	Executor       graphactionapi.Executor
	ErrorSentinels graphactionapi.ErrorSentinels
	ReadProtoJSON  func(*http.Request, proto.Message) error
	WriteProtoJSON func(http.ResponseWriter, int, proto.Message)
	ErrorMessage   func(int, error) string
	FindingMessage func(*ports.FindingRecord) *cerebrov1.Finding
}

func (h Handler) HandleExecute(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ExecuteGraphActionRequest{}
	if err := h.ReadProtoJSON(r, request); err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.Executor.Execute(r.Context(), graphactionapi.InputFromRequest(request))
	if err != nil {
		h.writeError(w, err)
		return
	}
	status := http.StatusAccepted
	if result.DryRun {
		status = http.StatusOK
	}
	h.WriteProtoJSON(w, status, graphactionapi.ResponseMessage(result, h.findingMessage(result.Finding)))
}

func (h Handler) ExecuteConnect(ctx context.Context, request *cerebrov1.ExecuteGraphActionRequest) (*connect.Response[cerebrov1.ExecuteGraphActionResponse], error) {
	result, err := h.Executor.Execute(ctx, graphactionapi.InputFromRequest(request))
	if err != nil {
		return nil, graphactionapi.ConnectError(err, h.ErrorSentinels)
	}
	return connect.NewResponse(graphactionapi.ResponseMessage(result, h.findingMessage(result.Finding))), nil
}

func (h Handler) HandleReconcile(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ReconcileGraphActionRequest{}
	if err := h.ReadProtoJSON(r, request); err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.Executor.Reconcile(r.Context(), graphactionapi.ReconcileInputFromRequest(request))
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.WriteProtoJSON(w, http.StatusAccepted, graphactionapi.ReconcileResponseMessage(result, h.findingMessage(result.Finding)))
}

func (h Handler) ReconcileConnect(ctx context.Context, request *cerebrov1.ReconcileGraphActionRequest) (*connect.Response[cerebrov1.ReconcileGraphActionResponse], error) {
	result, err := h.Executor.Reconcile(ctx, graphactionapi.ReconcileInputFromRequest(request))
	if err != nil {
		return nil, graphactionapi.ConnectError(err, h.ErrorSentinels)
	}
	return connect.NewResponse(graphactionapi.ReconcileResponseMessage(result, h.findingMessage(result.Finding))), nil
}

func (h Handler) writeError(w http.ResponseWriter, err error) {
	status := graphactionapi.HTTPStatus(err, h.ErrorSentinels)
	message := err.Error()
	if h.ErrorMessage != nil {
		message = h.ErrorMessage(status, err)
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func (h Handler) findingMessage(finding *ports.FindingRecord) *cerebrov1.Finding {
	if h.FindingMessage == nil {
		return nil
	}
	return h.FindingMessage(finding)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
