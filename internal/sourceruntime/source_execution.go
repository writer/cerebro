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

// sourceExecutionPage is the temporary Go side-effect bridge. Rust owns the
// plan, execution identity, admitted records, phase sequence, and checkpoint
// candidate. Delete this type when Rust can call the private durable ports.
type sourceExecutionPage struct {
	host   *sourceworker.Host
	output *sourceworker.ExecutionOutput
}

func (p *sourceExecutionPage) advance(ctx context.Context, completed sourceworker.Phase, priorDigest string) (*sourceworker.LifecycleDecision, error) {
	if p == nil || p.host == nil || p.output == nil {
		return nil, fmt.Errorf("%w: source execution lifecycle is unavailable", ErrRuntimeUnavailable)
	}
	generation, err := currentSourceRuntimeLeaseGeneration(ctx)
	if err != nil {
		return nil, err
	}
	return p.host.Advance(ctx, p.output, completed, priorDigest, generation)
}

func (s *Service) readSourcePull(ctx context.Context, runtime *cerebrov1.SourceRuntime, source sourcecdk.Source, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pageNumber uint32) (sourcecdk.Pull, *sourceExecutionPage, error) {
	if s == nil || s.sourceWorker == nil {
		pull, err := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, nil, err
	}
	familyID := strings.TrimSpace(configValue(cfg, "family"))
	plan, err := s.sourceWorker.Compile(ctx, sourceworker.SelectionRequest{
		SourceID: runtime.GetSourceId(), FamilyID: familyID,
	})
	if errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		pull, compatibilityErr := readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
		return pull, nil, compatibilityErr
	}
	if err != nil {
		return sourcecdk.Pull{}, nil, err
	}
	fence, ok := sourceRuntimeLeaseFenceFromContext(ctx)
	if !ok || !fence.ExpiresAt.After(time.Now().UTC()) {
		return sourcecdk.Pull{}, nil, fmt.Errorf("%w: source worker requires a current durable lease fence", ErrRuntimeUnavailable)
	}
	reference := firstConfigValue(runtime.GetConfig(), "graph_token", "token")
	resolved := firstConfigValue(cfg.Values(), "graph_token", "token")
	if reference == "" || resolved == "" || reference == resolved || (!sourceconfig.IsCredentialReference(reference) && !sourceconfig.IsSecretReference(reference)) {
		return sourcecdk.Pull{}, nil, fmt.Errorf("%w: Rust source execution requires an opaque credential reference", ErrInvalidRequest)
	}
	credential := []byte(resolved)
	redeemer := sourceworker.NewOneOperationCredentialRedeemer(reference, credential, "source-page-redemption", fence.ExpiresAt)
	clear(credential)
	host := sourceworker.NewHost(s.sourceWorker, redeemer)
	output, err := host.Execute(ctx, sourceworker.ExecutionInput{
		Plan: plan, CredentialReference: reference, PageNumber: pageNumber,
		Scope: sourceworker.CredentialScope{
			TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
			SourceID: plan.GetSourceId(), FamilyID: plan.GetFamilyId(), PlanDigestSHA256: plan.GetPlanDigestSha256(),
			PriorCursor: strings.TrimSpace(cursor.GetOpaque()), LeaseOwner: fence.Owner,
			RuntimeGeneration: fence.Generation, LeaseGeneration: fence.Generation, LeaseExpiresAt: fence.ExpiresAt,
		},
	})
	if err != nil {
		return sourcecdk.Pull{}, nil, err
	}
	if output.Decision.RequiredPhase != sourceworker.PhaseAppended {
		return sourcecdk.Pull{}, nil, fmt.Errorf("%w: Rust did not authorize append", sourceworker.ErrWorkerContract)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, len(output.Decision.AdmittedRecords))
	for _, record := range output.Decision.AdmittedRecords {
		if record == nil {
			return sourcecdk.Pull{}, nil, fmt.Errorf("%w: Rust admitted a nil record", sourceworker.ErrWorkerContract)
		}
		events = append(events, &cerebrov1.EventEnvelope{
			Id: record.GetEventId(), TenantId: runtime.GetTenantId(), SourceId: plan.GetSourceId(),
			Kind: plan.GetEventKind(), SchemaRef: plan.GetSchemaRef(), Payload: record.GetPayloadJson(),
			Attributes: record.GetAttributes(), OccurredAt: timestamppb.New(time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()),
		})
	}
	return sourcecdk.Pull{Events: events}, &sourceExecutionPage{host: host, output: output}, nil
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func firstConfigValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}
