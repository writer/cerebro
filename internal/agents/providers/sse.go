package providers

import (
	"bufio"
	"io"
	"strings"
)

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	Event string
	Data  string
	ID    string
}

// SSEReader reads Server-Sent Events from an io.Reader
type SSEReader struct {
	scanner *bufio.Scanner
}

// newSSEReader creates a new SSE reader
func newSSEReader(r io.Reader) *SSEReader {
	return &SSEReader{
		scanner: bufio.NewScanner(r),
	}
}

// Next reads the next SSE event
func (r *SSEReader) Next() (*SSEEvent, error) {
	event := &SSEEvent{}
	var dataLines []string

	for r.scanner.Scan() {
		line := r.scanner.Text()

		// Empty line means end of event
		if line == "" {
			if len(dataLines) > 0 {
				event.Data = strings.Join(dataLines, "\n")
				return event, nil
			}
			continue
		}

		// Parse field
		if strings.HasPrefix(line, "event:") {
			event.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		} else if strings.HasPrefix(line, "id:") {
			event.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		}
		// Ignore comments (lines starting with :) and unknown fields
	}

	if err := r.scanner.Err(); err != nil {
		return nil, err
	}

	// Return any remaining data
	if len(dataLines) > 0 {
		event.Data = strings.Join(dataLines, "\n")
		return event, nil
	}

	return nil, io.EOF
}
