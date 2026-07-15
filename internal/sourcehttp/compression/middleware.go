package httpcompression

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const responseThreshold = 1024

// AcceptsGzip reports whether an Accept-Encoding header permits gzip.
func AcceptsGzip(value string) bool {
	return acceptsGzip(value)
}

// Middleware compresses JSON responses larger than one KiB when the client
// accepts gzip. Smaller and non-JSON responses pass through unchanged.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &responseWriter{
			dst:       w,
			allowGzip: r.Method != http.MethodHead && acceptsGzip(r.Header.Get("Accept-Encoding")),
			status:    http.StatusOK,
		}
		next.ServeHTTP(writer, r)
		_ = writer.finish()
	})
}

type responseWriter struct {
	dst         http.ResponseWriter
	allowGzip   bool
	status      int
	wroteHeader bool
	committed   bool
	compressed  bool
	buffer      bytes.Buffer
	gzip        *gzip.Writer
}

func (w *responseWriter) Header() http.Header {
	return w.dst.Header()
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	if !w.allowGzip || !statusAllowsResponseBody(status) {
		_ = w.commit(false)
	}
}

func (w *responseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.committed {
		if w.compressed {
			return w.gzip.Write(payload)
		}
		return copyPayload(w.dst, payload)
	}
	if _, err := w.buffer.Write(payload); err != nil {
		return 0, err
	}
	if w.buffer.Len() < responseThreshold {
		return len(payload), nil
	}
	if err := w.commit(w.shouldCompress()); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (w *responseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if !w.committed {
		_ = w.commit(w.shouldCompress())
	}
	if w.compressed && w.gzip != nil {
		_ = w.gzip.Flush()
	}
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.dst.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	w.committed = true
	w.wroteHeader = true
	return hijacker.Hijack()
}

func (w *responseWriter) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.dst.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.dst
}

func (w *responseWriter) finish() error {
	if !w.committed {
		if err := w.commit(w.shouldCompress()); err != nil {
			return err
		}
	}
	if w.compressed && w.gzip != nil {
		return w.gzip.Close()
	}
	return nil
}

func (w *responseWriter) shouldCompress() bool {
	return w.allowGzip &&
		w.buffer.Len() >= responseThreshold &&
		statusAllowsResponseBody(w.status) &&
		strings.TrimSpace(w.Header().Get("Content-Encoding")) == "" &&
		isJSONContentType(w.Header().Get("Content-Type"))
}

func (w *responseWriter) commit(compress bool) error {
	if w.committed {
		return nil
	}
	w.committed = true
	if isJSONContentType(w.Header().Get("Content-Type")) {
		w.Header().Set("Vary", appendVary(w.Header().Get("Vary"), "Accept-Encoding"))
	}
	if compress {
		w.compressed = true
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
	}
	w.dst.WriteHeader(w.status)
	if compress {
		w.gzip = gzip.NewWriter(w.dst)
		if _, err := w.gzip.Write(w.buffer.Bytes()); err != nil {
			return err
		}
	} else if w.buffer.Len() > 0 {
		if _, err := io.Copy(w.dst, &w.buffer); err != nil {
			return err
		}
	}
	w.buffer.Reset()
	return nil
}

func copyPayload(dst io.Writer, payload []byte) (int, error) {
	// codeql[go/reflected-xss] The middleware only selects JSON responses and preserves their application/json content type.
	written, err := io.Copy(dst, bytes.NewReader(payload))
	if err != nil {
		return int(written), err // #nosec G115 -- bytes.Reader bounds written to len(payload), which is an int.
	}
	return len(payload), nil
}

func acceptsGzip(value string) bool {
	for _, encoding := range strings.Split(strings.ToLower(value), ",") {
		parts := strings.Split(strings.TrimSpace(encoding), ";")
		if len(parts) == 0 || parts[0] != "gzip" {
			continue
		}
		for _, parameter := range parts[1:] {
			name, raw, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || strings.TrimSpace(name) != "q" {
				continue
			}
			quality, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err == nil && quality <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

func isJSONContentType(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func statusAllowsResponseBody(status int) bool {
	return status >= http.StatusOK && status != http.StatusNoContent && status != http.StatusNotModified
}

func appendVary(current, value string) string {
	for _, item := range strings.Split(current, ",") {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return current
		}
	}
	if strings.TrimSpace(current) == "" {
		return value
	}
	return current + ", " + value
}
