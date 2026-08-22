package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func (s *Service) readSourcePull(ctx context.Context, runtime *cerebrov1.SourceRuntime, source sourcecdk.Source, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pageNumber uint32) (sourcecdk.Pull, bool, error) {
	if s == nil || s.sourceWorker == nil {
		pull, err := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, false, err
	}
	familyID, _ := cfg.Lookup("family")
	fence, ok := sourceRuntimeLeaseFenceFromContext(ctx)
	if !ok || !fence.ExpiresAt.After(time.Now().UTC()) {
		return sourcecdk.Pull{}, false, fmt.Errorf("%w: source worker requires a current durable lease fence", ErrRuntimeUnavailable)
	}
	reference, resolved := strings.TrimSpace(runtime.GetConfig()["graph_token"]), strings.TrimSpace(cfg.Values()["graph_token"])
	if reference == "" {
		reference = strings.TrimSpace(runtime.GetConfig()["token"])
	}
	if resolved == "" {
		resolved = strings.TrimSpace(cfg.Values()["token"])
	}
	if reference == "" || resolved == "" || reference == resolved || (!sourceconfig.IsCredentialReference(reference) && !sourceconfig.IsSecretReference(reference)) {
		return sourcecdk.Pull{}, false, fmt.Errorf("%w: Rust source execution requires an opaque credential reference", ErrInvalidRequest)
	}
	credential := []byte(resolved)
	host := sourceworker.NewHost(s.sourceWorker, reference, credential, fence.ExpiresAt)
	clear(credential)
	publicConfig := publicSourceExecutionConfig(cfg)
	priorWatermark := int64(0)
	if watermark := checkpoint.GetWatermark(); watermark != nil && watermark.CheckValid() == nil {
		priorWatermark = watermark.AsTime().UTC().UnixMilli()
	}
	output, err := host.Execute(ctx, sourceworker.ExecutionInput{
		SourceID: runtime.GetSourceId(), FamilyID: strings.TrimSpace(familyID), CredentialReference: reference, PageNumber: pageNumber,
		Scope: sourceworker.CredentialScope{
			TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
			PriorCursor: strings.TrimSpace(cursor.GetOpaque()), LeaseOwner: fence.Owner,
			RuntimeGeneration: fence.Generation, LeaseGeneration: fence.Generation, LeaseExpiresAt: fence.ExpiresAt,
			PublicConfig: publicConfig, PriorTerminalWatermarkUnixMillis: priorWatermark,
			PriorCheckpoint: strings.TrimSpace(checkpoint.GetCursorOpaque()),
		},
	})
	if errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		pull, compatibilityErr := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, false, compatibilityErr
	}
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	if output.Program == nil || output.Program.TransitionDigest == "" {
		return sourcecdk.Pull{}, false, fmt.Errorf("%w: Rust did not seal the page program", sourceworker.ErrWorkerContract)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(output.Program.AdmittedRecords))
	for _, record := range output.Program.AdmittedRecords {
		events = append(events, &cerebrov1.EventEnvelope{
			Id: record.GetEventId(), TenantId: runtime.GetTenantId(), SourceId: output.Plan.GetSourceId(),
			Kind: output.Plan.GetEventKind(), SchemaRef: output.Plan.GetSchemaRef(), Payload: record.GetPayloadJson(),
			Attributes: record.GetAttributes(), OccurredAt: timestamppb.New(time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()),
		})
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{
		CursorOpaque: output.Result.GetResultDigestSha256(),
		Watermark:    timestamppb.New(time.UnixMilli(output.Program.CheckpointWatermarkUnixMillis).UTC()),
	}}
	if output.Program.CheckpointCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: output.Program.CheckpointCursor}
	}
	return pull, true, nil
}

func publicSourceExecutionConfig(cfg sourcecdk.Config) map[string]string {
	public := make(map[string]string)
	for _, key := range []string{
		"audit_end_time", "audit_services", "audit_sort", "audit_start_time", "base_url",
		"family", "group_id", "group_ids", "insights_base_url", "org_id", "per_page",
		"tailnet", "user_group_id", "user_group_ids",
	} {
		if value, ok := cfg.Lookup(key); ok {
			public[key] = strings.TrimSpace(value)
		}
	}
	return public
}
