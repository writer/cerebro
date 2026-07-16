package mcptransport

import (
	"net/http/httptest"
	"testing"
)

func TestWriteJSONReportsResponseBytes(t *testing.T) {
	recorder := httptest.NewRecorder()
	written := WriteJSON(recorder, Response{
		JSONRPC: "2.0",
		Result:  map[string]any{"status": "ok"},
	})
	if written != recorder.Body.Len() || written <= 0 {
		t.Fatalf("WriteJSON() bytes = %d, body bytes = %d", written, recorder.Body.Len())
	}
}
