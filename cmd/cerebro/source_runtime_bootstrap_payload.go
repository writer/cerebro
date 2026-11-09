package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// sourceRuntimeBootstrapGzipBase64Prefix marks a bootstrap document carried
// as standard padded base64 of gzip-compressed JSON. Platforms use it when
// the plain JSON would exceed the kernel's per-string environment limit
// (MAX_ARG_STRLEN, 128 KiB on 4 KiB-page hosts), which fails the container's
// exec before this CLI ever runs.
const sourceRuntimeBootstrapGzipBase64Prefix = "gzip+base64:"

// maxSourceRuntimeBootstrapPayloadBytes bounds the decompressed document so a
// small compressed value cannot expand without limit.
const maxSourceRuntimeBootstrapPayloadBytes = 16 << 20

// decodeSourceRuntimeBootstrapPayload returns the JSON bootstrap document
// carried by an environment value: plain JSON unchanged, or the decompressed
// form of a sourceRuntimeBootstrapGzipBase64Prefix value.
func decodeSourceRuntimeBootstrapPayload(value string) (string, error) {
	encoded, compressed := strings.CutPrefix(strings.TrimSpace(value), sourceRuntimeBootstrapGzipBase64Prefix)
	if !compressed {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode compressed source runtime bootstrap payload: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("open compressed source runtime bootstrap payload: %w", err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, maxSourceRuntimeBootstrapPayloadBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return "", fmt.Errorf("read compressed source runtime bootstrap payload: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close compressed source runtime bootstrap payload: %w", closeErr)
	}
	if len(decoded) > maxSourceRuntimeBootstrapPayloadBytes {
		return "", fmt.Errorf("compressed source runtime bootstrap payload exceeds %d decoded bytes", maxSourceRuntimeBootstrapPayloadBytes)
	}
	return string(decoded), nil
}
