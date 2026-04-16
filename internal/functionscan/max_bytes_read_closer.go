package functionscan

import (
	"fmt"
	"io"
)

var maxArtifactResponseBodyBytes int64 = 5 << 30

type maxBytesReadCloser struct {
	body        io.ReadCloser
	description string
	maxBytes    int64
	remaining   int64
}

func newMaxBytesReadCloser(body io.ReadCloser, maxBytes int64, description string) io.ReadCloser {
	if body == nil || maxBytes <= 0 {
		return body
	}
	return &maxBytesReadCloser{
		body:        body,
		description: description,
		maxBytes:    maxBytes,
		remaining:   maxBytes,
	}
}

func (r *maxBytesReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining < 0 {
		return 0, fmt.Errorf("%s exceeds max size of %d bytes", r.description, r.maxBytes)
	}

	limit := r.remaining + 1
	if int64(len(p)) > limit {
		p = p[:limit]
	}

	n, err := r.body.Read(p)
	if int64(n) <= r.remaining {
		r.remaining -= int64(n)
		return n, err
	}

	allowed := int(r.remaining)
	r.remaining = -1
	if allowed > 0 {
		return allowed, fmt.Errorf("%s exceeds max size of %d bytes", r.description, r.maxBytes)
	}
	return 0, fmt.Errorf("%s exceeds max size of %d bytes", r.description, r.maxBytes)
}

func (r *maxBytesReadCloser) Close() error {
	return r.body.Close()
}
