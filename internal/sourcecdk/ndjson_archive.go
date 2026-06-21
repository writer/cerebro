package sourcecdk

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// ErrNDJSONDecompressedTooLarge is returned by ReadNDJSONArchive when the
// decompressed stream exceeds the configured byte ceiling.
var ErrNDJSONDecompressedTooLarge = errors.New("decompressed ndjson archive exceeds limit")

type countingReader struct {
	reader    io.Reader
	bytesRead int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)
	return n, err
}

// ReadNDJSONArchive reads newline-delimited JSON from r, transparently
// decompressing gzip when gzipped is true. It enforces a decompressed byte
// ceiling and a maximum line length, returning each non-empty line's raw bytes.
// Returned slices are copies safe to retain after the call.
func ReadNDJSONArchive(r io.Reader, gzipped bool, decompressedLimitBytes int64, maxLineBytes int) ([][]byte, error) {
	if gzipped {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gunzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	counter := &countingReader{reader: io.LimitReader(r, decompressedLimitBytes+1)}
	scanner := bufio.NewScanner(counter)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	lines := make([][]byte, 0, 64)
	for scanner.Scan() {
		if counter.bytesRead > decompressedLimitBytes {
			return nil, fmt.Errorf("%w: %d bytes", ErrNDJSONDecompressedTooLarge, decompressedLimitBytes)
		}
		text := bytes.TrimSpace(scanner.Bytes())
		if len(text) == 0 {
			continue
		}
		line := make([]byte, len(text))
		copy(line, text)
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan archive: %w", err)
	}
	if counter.bytesRead > decompressedLimitBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrNDJSONDecompressedTooLarge, decompressedLimitBytes)
	}
	return lines, nil
}
