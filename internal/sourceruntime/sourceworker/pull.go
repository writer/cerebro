package sourceworker

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const rustCheckpointCursorMode = "rust_provider_checkpoint"

// RustAuthoritativeFamily returns the normalized family only when the closed
// Rust dispatcher owns production execution for that exact source-family
// pair. Keep this allowlist narrower than the dispatcher's compiled adapters:
// an adapter contract alone is not an authority decision.
func RustAuthoritativeFamily(sourceID, familyID string) (string, bool) {
	sourceID = strings.TrimSpace(sourceID)
	familyID = strings.TrimSpace(familyID)
	switch sourceID {
	case "azure":
		return familyID, familyID == "authorization_policy"
	case "jumpcloud":
		if familyID == "" {
			familyID = "users"
		}
		// Every public JumpCloud family is closed in the Rust dispatcher. An
		// unknown future family must fail there instead of restoring Go authority.
		return familyID, true
	case "sentinelone":
		switch familyID {
		case "activity", "agent", "exclusion", "group", "site":
			return familyID, true
		default:
			return familyID, false
		}
	case "tailscale":
		return TailscaleFamily(sourceID, familyID)
	case "twilio":
		return familyID, familyID == "accounts"
	default:
		return "", false
	}
}

// CredentialBinding selects the provider's ordered credential aliases from
// stored references and trusted-host resolved values. It returns strings only
// to the Go host; callers must never include the resolved value in worker
// metadata, receipts, or errors.
func CredentialBinding(sourceID string, references, resolved map[string]string) (string, string) {
	if strings.TrimSpace(sourceID) == "twilio" {
		username := strings.TrimSpace(resolved["username"])
		passwordReference := strings.TrimSpace(references["password"])
		password := strings.TrimSpace(resolved["password"])
		if username == "" || passwordReference == "" || password == "" {
			return "", ""
		}
		basic := make([]byte, 0, len(username)+1+len(password))
		basic = append(basic, username...)
		basic = append(basic, ':')
		basic = append(basic, password...)
		encoded := base64.StdEncoding.EncodeToString(basic)
		clear(basic)
		return passwordReference, encoded
	}
	keys := []string{"graph_token", "token"}
	if strings.TrimSpace(sourceID) == "jumpcloud" {
		keys = []string{"api_key", "api_token", "token"}
	}
	for _, key := range keys {
		if reference := strings.TrimSpace(references[key]); reference != "" {
			return reference, strings.TrimSpace(resolved[key])
		}
	}
	return "", ""
}

// TailscaleFamily normalizes the requested Tailscale family, including the
// public default used when family is omitted. The closed Rust dispatcher owns
// family membership validation; Go must not restore legacy authority for an
// unknown family.
func TailscaleFamily(sourceID, familyID string) (string, bool) {
	if strings.TrimSpace(sourceID) != "tailscale" {
		return "", false
	}
	familyID = strings.TrimSpace(familyID)
	if familyID == "" {
		familyID = "device"
	}
	return familyID, true
}

// PublicExecutionConfig returns only configuration declared safe for the
// credential-free worker protocol.
func PublicExecutionConfig(values map[string]string) map[string]string {
	public := make(map[string]string)
	for _, key := range []string{
		"activity_type", "audit_end_time", "audit_services", "audit_sort", "audit_start_time", "base_url",
		"family", "group_id", "group_ids", "insights_base_url", "org_id", "per_page",
		"since", "site_id", "tailnet", "until", "user_group_id", "user_group_ids",
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
	if envelope.Token != "" && len(envelope.BoundaryIDs) != 0 {
		return "", 0, fmt.Errorf("%w: durable cursor mixes continuation and terminal boundary", ErrWorkerContract)
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
	nextCursor := strings.TrimSpace(output.Result.GetNextCursor())
	if _, authoritative := RustAuthoritativeFamily(output.Plan.GetSourceId(), output.Plan.GetFamilyId()); authoritative {
		envelope := sourcecdk.CursorEnvelope{
			Version: 1, Source: output.Plan.GetSourceId(), Family: output.Plan.GetFamilyId(),
			Mode: rustCheckpointCursorMode, ResumableCheckpoint: true, Token: nextCursor,
		}
		if boundary := strings.TrimSpace(output.Program.CheckpointCursor); nextCursor == "" && boundary != "" {
			envelope.BoundaryIDs = []string{boundary}
		}
		sourcecdk.SetCursorWatermark(&envelope, watermark.AsTime())
		var err error
		checkpointCursor, err = sourcecdk.EncodeCursorEnvelope(envelope)
		if err != nil {
			return sourcecdk.Pull{}, fmt.Errorf("%w: encode Rust checkpoint: %w", ErrWorkerContract, err)
		}
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: checkpointCursor, Watermark: watermark}}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	return pull, nil
}
