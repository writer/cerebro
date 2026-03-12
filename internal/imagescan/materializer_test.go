package imagescan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"archive/tar"

	"github.com/writer/cerebro/internal/scanner"
)

func TestLocalMaterializerRejectsOversizedRegularFiles(t *testing.T) {
	layer := gzipTarEntries(t, []tarEntry{{
		name:     "etc/oversized.txt",
		typeflag: tar.TypeReg,
		body:     []byte("hello"),
		mode:     0o644,
	}})
	manifest := &scanner.ImageManifest{Layers: []scanner.Layer{{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"}}}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	materializer.maxFileBytes = 4

	_, _, err := materializer.Materialize(context.Background(), "image_scan:oversized-file", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		if digest != "sha256:one" {
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
		return io.NopCloser(bytes.NewReader(layer)), nil
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected oversized file error, got %v", err)
	}
}

func TestLocalMaterializerRejectsTotalExtractedSizeLimit(t *testing.T) {
	layer1 := gzipTarEntries(t, []tarEntry{{
		name:     "etc/one.txt",
		typeflag: tar.TypeReg,
		body:     []byte("abcd"),
		mode:     0o644,
	}})
	layer2 := gzipTarEntries(t, []tarEntry{{
		name:     "etc/two.txt",
		typeflag: tar.TypeReg,
		body:     []byte("efgh"),
		mode:     0o644,
	}})
	manifest := &scanner.ImageManifest{Layers: []scanner.Layer{
		{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		{Digest: "sha256:two", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
	}}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	materializer.maxTotalBytes = 6

	_, _, err := materializer.Materialize(context.Background(), "image_scan:oversized-total", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		switch digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layer1)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layer2)), nil
		default:
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "materialized filesystem exceeds max size") {
		t.Fatalf("expected total extracted size error, got %v", err)
	}
}
