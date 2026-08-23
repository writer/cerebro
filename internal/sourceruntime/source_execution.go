package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func (s *Service) validateRustSourceRuntimePlan(ctx context.Context, runtime *cerebrov1.SourceRuntime, config map[string]string) error {
	familyID, authoritative := sourceworker.TailscaleFamily(runtime.GetSourceId(), config["family"])
	if !authoritative {
		return nil
	}
	if s == nil || s.sourceWorker == nil {
		return fmt.Errorf("%w: the closed Rust worker is required for Tailscale", ErrRuntimeUnavailable)
	}
	plan, err := s.sourceWorker.Compile(ctx, sourceworker.SelectionRequest{SourceID: runtime.GetSourceId(), FamilyID: familyID})
	if err != nil {
		return fmt.Errorf("%w: compile Tailscale source plan: %w", ErrInvalidRequest, err)
	}
	now := time.Now().UTC()
	executionContext, err := s.sourceWorker.Context(ctx, sourceworker.ContextRequest{
		TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
		PageNumber: 1, RuntimeGeneration: 1, LeaseGeneration: 1,
		ObservedAtUnixMillis: now.UnixMilli(), PublicConfig: sourceworker.PublicExecutionConfig(config),
	})
	if err != nil {
		return fmt.Errorf("%w: validate Tailscale execution context: %w", ErrInvalidRequest, err)
	}
	_, err = s.sourceWorker.PlanV2(ctx, &cerebrov1.SourceWorkerPlanEnvelopeV2{
		Request:  &cerebrov1.SourceWorkerPlanRequestV1{Plan: plan, Context: executionContext},
		Metadata: &cerebrov1.SourceWorkerRuntimeMetadataV2{PublicConfig: sourceworker.PublicExecutionConfig(config)},
	})
	if err != nil {
		return fmt.Errorf("%w: validate Tailscale source plan: %w", ErrInvalidRequest, err)
	}
	return nil
}

func (s *Service) readSourcePull(ctx context.Context, runtime *cerebrov1.SourceRuntime, source sourcecdk.Source, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pageNumber uint32) (sourcecdk.Pull, bool, error) {
	familyID, _ := cfg.Lookup("family")
	if normalized, authoritative := sourceworker.TailscaleFamily(runtime.GetSourceId(), familyID); authoritative {
		familyID = normalized
		if s == nil || s.sourceWorker == nil {
			return sourcecdk.Pull{}, false, fmt.Errorf("%w: the closed Rust worker is required for Tailscale", ErrRuntimeUnavailable)
		}
	}
	if s == nil || s.sourceWorker == nil {
		pull, err := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, false, err
	}
	plan, err := s.sourceWorker.Compile(ctx, sourceworker.SelectionRequest{
		SourceID: strings.TrimSpace(runtime.GetSourceId()), FamilyID: strings.TrimSpace(familyID),
	})
	if errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		if _, tailscale := sourceworker.TailscaleFamily(runtime.GetSourceId(), familyID); !tailscale {
			pull, compatibilityErr := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
			return pull, false, compatibilityErr
		}
	}
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
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
	providerCursor, cursorWatermark, err := sourceworker.ProviderResume(cursor, runtime.GetSourceId(), familyID)
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	publicConfig := sourceworker.PublicExecutionConfig(cfg.Values())
	priorWatermark := int64(0)
	if watermark := checkpoint.GetWatermark(); watermark != nil && watermark.CheckValid() == nil {
		priorWatermark = watermark.AsTime().UTC().UnixMilli()
	}
	if cursorWatermark > priorWatermark {
		priorWatermark = cursorWatermark
	}
	output, err := host.Execute(ctx, sourceworker.ExecutionInput{
		SourceID: runtime.GetSourceId(), FamilyID: strings.TrimSpace(familyID), Plan: plan, CredentialReference: reference, PageNumber: pageNumber,
		Scope: sourceworker.CredentialScope{
			TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()), SourceID: plan.GetSourceId(),
			FamilyID: plan.GetFamilyId(), PlanDigestSHA256: plan.GetPlanDigestSha256(),
			PriorCursor: providerCursor, LeaseOwner: fence.Owner,
			RuntimeGeneration: fence.Generation, LeaseGeneration: fence.Generation, LeaseExpiresAt: fence.ExpiresAt,
			PublicConfig: publicConfig, PriorTerminalWatermarkUnixMillis: priorWatermark,
			PriorCheckpoint: strings.TrimSpace(checkpoint.GetCursorOpaque()),
		},
	})
	if errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		if _, tailscale := sourceworker.TailscaleFamily(runtime.GetSourceId(), familyID); !tailscale {
			pull, compatibilityErr := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
			return pull, false, compatibilityErr
		}
	}
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	pull, err := sourceworker.PullFromExecutionOutput(output, runtime.GetTenantId())
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	return pull, true, nil
}
