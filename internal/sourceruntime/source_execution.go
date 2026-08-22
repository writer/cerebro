package sourceruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

const azureAuthorizationPolicyFamily = "authorization_policy"

type sourceExecutionHost interface {
	Execute(context.Context, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error)
}

func (s *Service) readSourcePull(ctx context.Context, runtime *cerebrov1.SourceRuntime, source sourcecdk.Source, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, pageNumber uint32) (sourcecdk.Pull, error) {
	if s == nil || s.sourceHostFactory == nil || !isSourceExecutionFamily(runtime, cfg) {
		return readCompatibilitySourcePull(ctx, source, cfg, cursor, checkpoint)
	}
	return s.readAzureAuthorizationPolicyPull(ctx, runtime, cfg, cursor, pageNumber)
}

func (s *Service) readAzureAuthorizationPolicyPull(ctx context.Context, runtime *cerebrov1.SourceRuntime, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, pageNumber uint32) (sourcecdk.Pull, error) {
	fence, ok := sourceRuntimeLeaseFenceFromContext(ctx)
	if !ok || !fence.ExpiresAt.After(time.Now().UTC()) {
		return sourcecdk.Pull{}, fmt.Errorf("%w: source worker requires a current durable lease fence", ErrRuntimeUnavailable)
	}
	reference := firstConfigValue(runtime.GetConfig(), "graph_token", "token")
	resolved := firstConfigValue(cfg.Values(), "graph_token", "token")
	if reference == "" || resolved == "" || reference == resolved || (!sourceconfig.IsCredentialReference(reference) && !sourceconfig.IsSecretReference(reference)) {
		return sourcecdk.Pull{}, fmt.Errorf("%w: Azure authorization policy requires an opaque credential reference", ErrInvalidRequest)
	}
	priorCursor := strings.TrimSpace(cursor.GetOpaque())
	logicalPageID := sourceWorkerLogicalPageID(runtime.GetId(), pageNumber, priorCursor)
	credential := []byte(resolved)
	redeemer := sourceworker.NewOneOperationCredentialRedeemer(
		reference,
		credential,
		"source-page-"+logicalPageID[:32],
		fence.ExpiresAt,
	)
	clear(credential)
	plan := sourceworker.AzureAuthorizationPolicyPlan()
	scope := sourceworker.CredentialScope{
		TenantID: strings.TrimSpace(runtime.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()),
		SourceID: plan.GetSourceId(), FamilyID: plan.GetFamilyId(), PlanDigestSHA256: plan.GetPlanDigestSha256(),
		LogicalPageID: logicalPageID, PriorCursor: priorCursor, LeaseOwner: fence.Owner,
		RuntimeGeneration: fence.Generation, LeaseGeneration: fence.Generation, LeaseExpiresAt: fence.ExpiresAt,
	}
	output, err := s.sourceHostFactory(redeemer).Execute(ctx, sourceworker.ExecutionInput{
		Plan: plan, CredentialReference: reference, Scope: scope,
	})
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if err := validateSourceRuntimeLeaseFence(ctx); err != nil {
		return sourcecdk.Pull{}, err
	}
	event, err := sourceworker.AuthorizationPolicyEvent(plan, scope, output.Receipt, output.Result, time.UnixMilli(output.Receipt.ObservedAtUnixMillis))
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	pull := sourcecdk.Pull{
		Events: []*cerebrov1.EventEnvelope{event},
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark: event.GetOccurredAt(), CursorOpaque: output.Result.GetResultDigestSha256(),
		},
	}
	if nextCursor := strings.TrimSpace(output.Result.GetNextCursor()); nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	return pull, nil
}

func isSourceExecutionFamily(runtime *cerebrov1.SourceRuntime, cfg sourcecdk.Config) bool {
	return runtime.GetSourceId() == "azure" && strings.TrimSpace(configValue(cfg, "family")) == azureAuthorizationPolicyFamily
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

func sourceWorkerLogicalPageID(runtimeID string, pageNumber uint32, priorCursor string) string {
	hasher := sha256.New()
	for _, value := range []string{strings.TrimSpace(runtimeID), strconv.FormatUint(uint64(pageNumber), 10), strings.TrimSpace(priorCursor)} {
		hasher.Write([]byte(strconv.Itoa(len(value))))
		hasher.Write([]byte{0})
		hasher.Write([]byte(value))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
