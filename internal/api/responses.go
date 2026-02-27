package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
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
	default:
		return "error"
	}
}
