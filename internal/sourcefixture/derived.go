package sourcefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// StabilizeEvents makes captured-response replay output independent of the
// loopback server used by a test. Event IDs remain content-addressed to the
// genuine provider record. Families without a provider timestamp may use the
// capture timestamp as their deterministic observation time.
func StabilizeEvents(bundle Bundle, events []*primitives.Event, useCaptureTime bool) error {
	capturedAt, err := time.Parse(time.RFC3339, bundle.Manifest.Response.CapturedAt)
	if err != nil {
		return fmt.Errorf("parse capture time: %w", err)
	}
	for _, event := range events {
		if event == nil {
			continue
		}
		payloadDigest := sha256.Sum256(event.Payload)
		event.Id = strings.Join([]string{
			cleanEventIDPart(bundle.Manifest.SourceID),
			cleanEventIDPart(event.TenantId),
			cleanEventIDPart(bundle.Manifest.Family),
			hex.EncodeToString(payloadDigest[:8]),
		}, "-")
		if useCaptureTime {
			event.OccurredAt = timestamppb.New(capturedAt.UTC())
		}
	}
	return nil
}

// CompareOrUpdateSourceOutputs verifies the normalized read and discovery
// fixtures derived from a genuine provider response capture.
func CompareOrUpdateSourceOutputs(sourceDirectory, family string, events []*primitives.Event, urns []sourcecdk.URN, update bool) error {
	readPayload, err := sourcecdk.MarshalFixtureEvents(events)
	if err != nil {
		return err
	}
	discoverPayload, err := sourcecdk.MarshalFixtureURNs(urns)
	if err != nil {
		return err
	}
	if err := CompareOrUpdateGenerated(filepath.Join(sourceDirectory, "testdata", "read_"+family+".json"), readPayload, update); err != nil {
		return err
	}
	return CompareOrUpdateGenerated(filepath.Join(sourceDirectory, "testdata", "discover_"+family+".json"), discoverPayload, update)
}

func cleanEventIDPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			builder.WriteRune(character)
			continue
		}
		builder.WriteByte('-')
	}
	cleaned := strings.Trim(builder.String(), "-")
	if cleaned == "" {
		return "record"
	}
	return cleaned
}
