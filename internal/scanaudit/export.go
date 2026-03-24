package scanaudit

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

func BuildExportPackage(record Record, generatedAt time.Time) ExportPackage {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	return ExportPackage{
		Manifest: ExportManifest{
			Namespace:   record.Namespace,
			RunID:       record.RunID,
			Kind:        record.Kind,
			GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
			GeneratedBy: "cerebro",
		},
		Record:     record,
		Events:     append([]Event(nil), record.Events...),
		Exceptions: append([]Exception(nil), record.Exceptions...),
	}
}

func ExportPackageFilename(record Record, generatedAt time.Time) string {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	return fmt.Sprintf(
		"cerebro-scan-audit-%s-%s-%s.zip",
		sanitizeFilenameComponent(record.Namespace, "scan"),
		sanitizeFilenameComponent(record.RunID, "run"),
		generatedAt.UTC().Format("20060102T150405Z"),
	)
}

func RenderExportPackageZIP(pkg ExportPackage) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if err := writeJSONZipEntry(zw, "manifest.json", pkg.Manifest); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeJSONZipEntry(zw, "record.json", pkg.Record); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeJSONZipEntry(zw, "events.json", pkg.Events); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeJSONZipEntry(zw, "exceptions.json", pkg.Exceptions); err != nil {
		_ = zw.Close()
		return nil, err
	}
	for _, artifact := range pkg.SBOMs {
		if err := writeRawZipEntry(zw, artifact.Filename, artifact.Document); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip writer: %w", err)
	}
	return buf.Bytes(), nil
}

func writeJSONZipEntry(zw *zip.Writer, name string, value any) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.Modified = time.Unix(0, 0).UTC()
	header.SetMode(0o644)

	w, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("write newline %s: %w", name, err)
	}
	return nil
}

func writeRawZipEntry(zw *zip.Writer, name string, payload []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.Modified = time.Unix(0, 0).UTC()
	header.SetMode(0o644)

	w, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		if _, err := w.Write([]byte("\n")); err != nil {
			return fmt.Errorf("write newline %s: %w", name, err)
		}
	}
	return nil
}

func sanitizeFilenameComponent(raw string, fallback string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return fallback
	}
	raw = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			return r
		case unicode.IsSpace(r), r == ':', r == '/':
			return '-'
		default:
			return -1
		}
	}, raw)
	raw = strings.Trim(raw, "-._")
	if raw == "" {
		return fallback
	}
	return raw
}
