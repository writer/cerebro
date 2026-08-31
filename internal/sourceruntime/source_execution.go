package sourceruntime

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func (s *Service) validateRustSourceRuntimePlan(ctx context.Context, runtime *cerebrov1.SourceRuntime, config map[string]string) error {
	familyID, authoritative := sourceworker.RustAuthoritativeFamily(runtime.GetSourceId(), config["family"])
	if !authoritative {
		return nil
	}
	if s == nil || s.sourceWorker == nil {
		return fmt.Errorf("%w: the closed Rust worker is required for %s.%s", ErrRuntimeUnavailable, runtime.GetSourceId(), familyID)
	}
	plan, err := s.sourceWorker.Compile(ctx, sourceworker.SelectionRequest{SourceID: runtime.GetSourceId(), FamilyID: familyID})
	if err != nil {
		return fmt.Errorf("%w: compile Rust source plan: %w", ErrInvalidRequest, err)
	}
	now := time.Now().UTC()
	executionContext, err := s.sourceWorker.Context(ctx, sourceworker.ContextRequest{
		TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
		PageNumber: 1, RuntimeGeneration: 1, LeaseGeneration: 1,
		ObservedAtUnixMillis: now.UnixMilli(), PublicConfig: sourceworker.PublicExecutionConfigForSource(runtime.GetSourceId(), config),
	})
	if err != nil {
		return fmt.Errorf("%w: validate Rust execution context: %w", ErrInvalidRequest, err)
	}
	_, err = s.sourceWorker.PlanV2(ctx, &cerebrov1.SourceWorkerPlanEnvelopeV2{
		Request:  &cerebrov1.SourceWorkerPlanRequestV1{Plan: plan, Context: executionContext},
		Metadata: &cerebrov1.SourceWorkerRuntimeMetadataV2{PublicConfig: sourceworker.PublicExecutionConfigForSource(runtime.GetSourceId(), config)},
	})
	if err != nil {
		return fmt.Errorf("%w: validate Rust source plan: %w", ErrInvalidRequest, err)
	}
	return nil
}

func sourceExecutionHostCredential(ctx context.Context, sourceID string, source sourcecdk.Source, references map[string]string, cfg sourcecdk.Config) (string, []byte, error) {
	reference, resolved := sourceworker.CredentialBinding(sourceID, references, cfg.Values())
	credential := []byte(resolved)
	provider, ok := sourcecdk.SourceExecutionCredentialProviderFrom(source)
	if !ok {
		return reference, credential, nil
	}
	reference = sourceworker.TrustedHostCredentialReference(sourceID, references, cfg.Values())
	clear(credential)
	if reference == "" || (!sourceconfig.IsCredentialReference(reference) && !sourceconfig.IsSecretReference(reference)) {
		return "", nil, fmt.Errorf("%w: Rust source execution requires an opaque credential reference", ErrInvalidRequest)
	}
	credential, err := provider.SourceExecutionCredential(ctx, cfg)
	if err != nil {
		clear(credential)
		return "", nil, err
	}
	return reference, credential, nil
}

func (s *Service) readSourcePull(ctx context.Context, runtime *cerebrov1.SourceRuntime, source sourcecdk.Source, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pageNumber uint32) (sourcecdk.Pull, bool, error) {
	familyID, _ := cfg.Lookup("family")
	normalizedFamilyID, authoritative := sourceworker.RustAuthoritativeFamily(runtime.GetSourceId(), familyID)
	if !authoritative {
		pull, err := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, false, err
	}
	familyID = normalizedFamilyID
	if s == nil || s.sourceWorker == nil {
		return sourcecdk.Pull{}, false, fmt.Errorf("%w: the closed Rust worker is required for %s.%s", ErrRuntimeUnavailable, runtime.GetSourceId(), familyID)
	}
	fence, err := currentSourceRuntimeLeaseFence(ctx, runtime.GetId())
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	reference, credential, err := sourceExecutionHostCredential(ctx, runtime.GetSourceId(), source, runtime.GetConfig(), cfg)
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	if reference == "" || len(credential) == 0 || (!sourceconfig.IsCredentialReference(reference) && !sourceconfig.IsSecretReference(reference)) {
		clear(credential)
		return sourcecdk.Pull{}, false, fmt.Errorf("%w: Rust source execution requires an opaque credential reference", ErrInvalidRequest)
	}
	host := sourceworker.NewHost(s.sourceWorker, reference, credential, fence.ExpiresAt)
	clear(credential)
	providerCursor, cursorWatermark, err := sourceworker.ProviderResume(cursor, runtime.GetSourceId(), familyID)
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	publicConfig := sourceworker.PublicExecutionConfigForSource(runtime.GetSourceId(), cfg.Values())
	priorWatermark := int64(0)
	if watermark := checkpoint.GetWatermark(); watermark != nil && watermark.CheckValid() == nil {
		priorWatermark = watermark.AsTime().UTC().UnixMilli()
	}
	if cursorWatermark > priorWatermark {
		priorWatermark = cursorWatermark
	}
	output, err := host.Execute(ctx, sourceworker.ExecutionInput{
		SourceID: runtime.GetSourceId(), FamilyID: strings.TrimSpace(familyID), CredentialReference: reference, PageNumber: pageNumber,
		Scope: sourceworker.CredentialScope{
			TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
			PriorCursor: providerCursor, LeaseOwner: fence.Owner,
			RuntimeGeneration: fence.Generation, LeaseGeneration: fence.Generation, LeaseExpiresAt: fence.ExpiresAt,
			PublicConfig: publicConfig, PriorTerminalWatermarkUnixMillis: priorWatermark,
			PriorCheckpoint: strings.TrimSpace(checkpoint.GetCursorOpaque()),
		},
	})
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	pull, err := sourceworker.PullFromExecutionOutput(output, runtime.GetTenantId())
	if err != nil {
		return sourcecdk.Pull{}, false, err
	}
	return pull, true, nil
}
