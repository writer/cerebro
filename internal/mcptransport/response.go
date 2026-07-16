package mcptransport

import (
	"encoding/json"
	"io"
)

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type responseByteCounter struct {
	io.Writer
	written int
}

func (w *responseByteCounter) Write(payload []byte) (int, error) {
	written, err := w.Writer.Write(payload)
	w.written += written
	return written, err
}

// WriteJSON writes one JSON-RPC response and returns the exact number of bytes
// accepted by the writer.
func WriteJSON(w io.Writer, response Response) int {
	counter := &responseByteCounter{Writer: w}
	_ = json.NewEncoder(counter).Encode(response)
	return counter.written
}
