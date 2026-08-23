package sourceworker

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const rustCheckpointCursorMode = "rust_provider_checkpoint"

var tailscaleFamilies = map[string]struct{}{
	"device": {}, "grant": {}, "group": {}, "service": {}, "tag": {}, "tailnet": {}, "user": {},
}

// RustAuthoritativeTailscale reports whether the closed Rust dispatcher owns
// the exact public Tailscale family.
func RustAuthoritativeTailscale(sourceID, familyID string) bool {
	_, ok := TailscaleFamily(sourceID, familyID)
	return ok
}

// TailscaleFamily returns the exact closed-dispatch family, including the
// public default used when family is omitted.
func TailscaleFamily(sourceID, familyID string) (string, bool) {
	if strings.TrimSpace(sourceID) != "tailscale" {
		return "", false
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		familyID = "device"
	}
	_, ok := tailscaleFamilies[familyID]
	return familyID, ok
}

// PublicExecutionConfig returns only configuration declared safe for the
// credential-free worker protocol.
func PublicExecutionConfig(values map[string]string) map[string]string {
	public := make(map[string]string)
	for _, key := range []string{
		"audit_end_time", "audit_services", "audit_sort", "audit_start_time", "base_url",
		"family", "group_id", "group_ids", "insights_base_url", "org_id", "per_page",
		"tailnet", "user_group_id", "user_group_ids",
	} {
		if value, ok := values[key]; ok {
			public[key] = strings.TrimSpace(value)
		}
	}
	return public
}

// ProviderResume unwraps a durable Rust checkpoint without allowing it to
// switch source or family. Provider-native cursors remain accepted for an
// active page continuation and are validated again by Rust planning.
func ProviderResume(cursor *cerebrov1.SourceCursor, sourceID, familyID string) (string, int64, error) {
	if cursor == nil {
		return "", 0, nil
	}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return "", 0, nil
	}
	envelope, encoded := sourcecdk.DecodeCursorEnvelope(opaque)
	if !encoded {
		if strings.HasPrefix(opaque, "{") {
			return "", 0, fmt.Errorf("%w: malformed durable cursor envelope", ErrWorkerContract)
		}
		return opaque, 0, nil
	}
	if envelope.Version != 1 || !envelope.ResumableCheckpoint || envelope.Mode != rustCheckpointCursorMode || envelope.Source != strings.TrimSpace(sourceID) || envelope.Family != strings.TrimSpace(familyID) {
		return "", 0, fmt.Errorf("%w: durable cursor source or family mismatch", ErrWorkerContract)
	}
	watermark := sourcecdk.CursorWatermark(envelope)
	if envelope.Watermark != "" && watermark.IsZero() {
		return "", 0, fmt.Errorf("%w: durable cursor watermark is malformed", ErrWorkerContract)
	}
	return envelope.Token, watermark.UnixMilli(), nil
}

// PullFromExecutionOutput maps Rust-authored page evidence into the Go host's
// append input. Result.NextCursor controls only same-run pagination; the
// lifecycle checkpoint is encoded independently for a later restart.
func PullFromExecutionOutput(output *ExecutionOutput, tenantID string) (sourcecdk.Pull, error) {
	if output == nil || output.Plan == nil || output.Result == nil || output.Program == nil || output.Program.TransitionDigest == "" {
		return sourcecdk.Pull{}, fmt.Errorf("%w: Rust did not seal the page program", ErrWorkerContract)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(output.Program.AdmittedRecords))
	for _, record := range output.Program.AdmittedRecords {
		if record == nil {
			return sourcecdk.Pull{}, fmt.Errorf("%w: Rust admitted an empty record", ErrWorkerContract)
		}
		events = append(events, &cerebrov1.EventEnvelope{
			Id: record.GetEventId(), TenantId: strings.TrimSpace(tenantID), SourceId: output.Plan.GetSourceId(),
			Kind: output.Plan.GetEventKind(), SchemaRef: output.Plan.GetSchemaRef(), Payload: record.GetPayloadJson(),
			Attributes: record.GetAttributes(), OccurredAt: timestamppb.New(time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()),
		})
	}
	watermark := timestamppb.New(time.UnixMilli(output.Program.CheckpointWatermarkUnixMillis).UTC())
	if err := watermark.CheckValid(); err != nil {
		return sourcecdk.Pull{}, fmt.Errorf("%w: Rust checkpoint watermark is invalid", ErrWorkerContract)
	}
	checkpointCursor := output.Result.GetResultDigestSha256()
	if RustAuthoritativeTailscale(output.Plan.GetSourceId(), output.Plan.GetFamilyId()) {
		envelope := sourcecdk.CursorEnvelope{
			Version: 1, Source: output.Plan.GetSourceId(), Family: output.Plan.GetFamilyId(),
			Mode: rustCheckpointCursorMode, ResumableCheckpoint: true, Token: output.Program.CheckpointCursor,
		}
		sourcecdk.SetCursorWatermark(&envelope, watermark.AsTime())
		var err error
		checkpointCursor, err = sourcecdk.EncodeCursorEnvelope(envelope)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("%w: encode Rust checkpoint: %w", ErrWorkerContract, err)
		}
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: checkpointCursor, Watermark: watermark}}
	if next := strings.TrimSpace(output.Result.GetNextCursor()); next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}
