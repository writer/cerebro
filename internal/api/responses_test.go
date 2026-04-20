package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/cerrors"
)

func decodeAPIErrorResponse(t *testing.T, w *httptest.ResponseRecorder) APIError {
	t.Helper()

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return body
}

func TestStatusFromError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "validation",
			err:  cerrors.E(cerrors.Op("validate"), cerrors.ErrInvalidInput, errors.New("missing field")),
			want: http.StatusBadRequest,
		},
		{
			name: "not found",
			err:  cerrors.E(cerrors.Op("provider"), cerrors.ErrProviderNotFound, errors.New("provider absent")),
			want: http.StatusNotFound,
		},
		{
			name: "forbidden auth",
			err:  cerrors.E(cerrors.Op("authz"), cerrors.ErrForbidden, errors.New("denied")),
			want: http.StatusForbidden,
		},
		{
			name: "unauthorized auth",
			err:  cerrors.E(cerrors.Op("authn"), cerrors.ErrUnauthorized, errors.New("missing token")),
			want: http.StatusUnauthorized,
		},
		{
			name: "timeout",
			err:  cerrors.E(cerrors.Op("sync"), cerrors.ErrContextTimeout, errors.New("timed out")),
			want: http.StatusGatewayTimeout,
		},
		{
			name: "fallback internal",
			err:  errors.New("unexpected failure"),
			want: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusFromError(tc.err); got != tc.want {
				t.Fatalf("statusFromError() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestErrorFromErr_ResponseMapping(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantStatus   int
		wantCode     string
		wantSanitize bool
	}{
		{
			name:         "validation response",
			err:          cerrors.E(cerrors.Op("validate"), cerrors.ErrInvalidInput, errors.New("bad input")),
			wantStatus:   http.StatusBadRequest,
			wantCode:     "bad_request",
			wantSanitize: false,
		},
		{
			name:         "not found response",
			err:          cerrors.E(cerrors.Op("lookup"), cerrors.ErrNotFound, errors.New("missing")),
			wantStatus:   http.StatusNotFound,
			wantCode:     "not_found",
			wantSanitize: false,
		},
		{
			name:         "timeout response",
			err:          cerrors.E(cerrors.Op("sync"), cerrors.ErrDBTimeout, errors.New("slow db")),
			wantStatus:   http.StatusGatewayTimeout,
			wantCode:     "gateway_timeout",
			wantSanitize: false,
		},
		{
			name:         "fallback internal response",
			err:          errors.New("sensitive backend details"),
			wantStatus:   http.StatusInternalServerError,
			wantCode:     "internal_error",
			wantSanitize: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			w := httptest.NewRecorder()

			s.errorFromErr(w, tc.err)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}

			body := decodeAPIErrorResponse(t, w)
			if body.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", body.Code, tc.wantCode)
			}
			if tc.wantSanitize && body.Error != "internal server error" {
				t.Fatalf("expected sanitized internal message, got %q", body.Error)
			}
			if !tc.wantSanitize && body.Error == "internal server error" {
				t.Fatalf("expected original error message for status %d", tc.wantStatus)
			}
		})
	}
}

func TestJSONEncodingFailureReturnsInternalServerError(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()

	s.json(w, http.StatusOK, map[string]float64{"value": math.NaN()})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}

	body := decodeAPIErrorResponse(t, w)
	if body.Code != "internal_error" {
		t.Fatalf("code = %q, want internal_error", body.Code)
	}
	if body.Error != "internal server error" {
		t.Fatalf("error = %q, want internal server error", body.Error)
	}
}

func TestEncodeJSONPayloadEscapesHTML(t *testing.T) {
	payload, err := encodeJSONPayload(map[string]string{
		"value": "<script>alert(1)</script>",
	})
	if err != nil {
		t.Fatalf("encodeJSONPayload() error = %v", err)
	}
	if got := string(payload); got != "{\"value\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}\n" {
		t.Fatalf("encodeJSONPayload() = %q", got)
	}
}
