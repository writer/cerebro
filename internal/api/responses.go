package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/graph"
)

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	payload, err := encodeJSONPayload(data)
	if err != nil {
		s.writeJSONEncodingError(w, err)
		return
	}
	writeJSONPayload(w, status, payload, nil)
}

func (s *Server) error(w http.ResponseWriter, status int, message string) {
	code := httpStatusToCode(status)
	if status == http.StatusInternalServerError {
		if s.app != nil && s.app.Logger != nil {
			s.app.Logger.Error("api internal error", "code", code, "error", message)
		}
		message = "internal server error"
	}
	s.json(w, status, APIError{Error: message, Code: code})
}

func (s *Server) errorFromErr(w http.ResponseWriter, err error) {
	if err == nil {
		s.error(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.error(w, statusFromError(err), err.Error())
}

func statusFromError(err error) int {
	switch {
	case cerrors.IsValidation(err):
		return http.StatusBadRequest
	case errors.Is(err, errGraphRiskUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, graph.ErrStoreUnavailable):
		return http.StatusServiceUnavailable
	case cerrors.IsNotFound(err):
		return http.StatusNotFound
	case cerrors.IsAuth(err):
		if errors.Is(err, cerrors.ErrForbidden) {
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	case cerrors.IsTimeout(err):
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

func httpStatusToCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "validation_error"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	case http.StatusGatewayTimeout:
		return "gateway_timeout"
	default:
		return "error"
	}
}

func (s *Server) writeJSONEncodingError(w http.ResponseWriter, err error) {
	if s.app != nil && s.app.Logger != nil {
		s.app.Logger.Error("api json encoding failed", "error", err)
	}

	payload, marshalErr := encodeJSONPayload(APIError{
		Error: "internal server error",
		Code:  httpStatusToCode(http.StatusInternalServerError),
	})
	if marshalErr != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSONPayload(w, http.StatusInternalServerError, payload, nil)
}

func encodeJSONPayload(data any) ([]byte, error) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(data); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func writeJSONPayload(w http.ResponseWriter, status int, payload []byte, headers map[string]string) {
	for key, value := range headers {
		w.Header().Set(key, value)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(payload) // #nosec G705 -- payload is JSON encoded with html escaping enabled in encodeJSONPayload.
}
