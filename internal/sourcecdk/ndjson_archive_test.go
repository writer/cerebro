package sourcecdk

import (
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
)

func TestReadNDJSONArchivePlainSkipsBlankLines(t *testing.T) {
	input := strings.NewReader("{\"a\":1}\n\n  \n{\"b\":2}\n")
	lines, err := ReadNDJSONArchive(input, false, 1<<20, 1<<20)
	if err != nil {
		t.Fatalf("ReadNDJSONArchive() error = %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2", len(lines))
	}
	if string(lines[0]) != "{\"a\":1}" || string(lines[1]) != "{\"b\":2}" {
		t.Fatalf("lines = %q, want trimmed json records", lines)
	}
}

func TestReadNDJSONArchiveGzip(t *testing.T) {
	compressed := &bytes.Buffer{}
	gz := gzip.NewWriter(compressed)
	if _, err := gz.Write([]byte("{\"a\":1}\n{\"b\":2}\n")); err != nil {
		t.Fatalf("gzip.Write() error = %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close() error = %v", err)
	}
	lines, err := ReadNDJSONArchive(bytes.NewReader(compressed.Bytes()), true, 1<<20, 1<<20)
	if err != nil {
		t.Fatalf("ReadNDJSONArchive() error = %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2", len(lines))
	}
}

func TestReadNDJSONArchiveEnforcesDecompressedLimit(t *testing.T) {
	record := []byte("{\"value\":\"aaaaaaaaaaaaaaaaaaaa\"}\n")
	compressed := &bytes.Buffer{}
	gz := gzip.NewWriter(compressed)
	for i := 0; i < 3; i++ {
		if _, err := gz.Write(record); err != nil {
			t.Fatalf("gzip.Write() error = %v", err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close() error = %v", err)
	}
	_, err := ReadNDJSONArchive(bytes.NewReader(compressed.Bytes()), true, int64(len(record))*2, 1<<20)
	if !errors.Is(err, ErrNDJSONDecompressedTooLarge) {
		t.Fatalf("ReadNDJSONArchive() error = %v, want ErrNDJSONDecompressedTooLarge", err)
	}
}
