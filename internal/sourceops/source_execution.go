package sourceops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

const (
	tailscaleSourceID                 = "tailscale"
	previewCredentialReference        = "credential:source-preview:token" // #nosec G101 -- opaque credential-reference label.
	previewLeaseOwner                 = "source-preview"
	previewRuntimeGeneration   uint64 = 1
	previewLeaseGeneration     uint64 = 1
)

type sourceExecutionRunner func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error)

func runSourceExecution(ctx context.Context, worker sourceworker.Worker, reference string, credential []byte, expiresAt time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
	return sourceworker.NewHost(worker, reference, credential, expiresAt).Execute(ctx, input)
}

// WithSourceExecutionWorkerPath enables the closed Rust execution path for
// source preview operations owned by the dispatcher.
func (s *Service) WithSourceExecutionWorkerPath(path string) *Service {
	if s == nil {
		return nil
	}
	if path = strings.TrimSpace(path); path != "" {
		s.sourceWorker = sourceworker.NewProcessWorker(path)
		s.runSourceExecution = runSourceExecution
	}
	return s
}

func tailscaleSource(sourceID string) bool {
	return strings.TrimSpace(sourceID) == tailscaleSourceID
}

func (s *Service) executeTailscale(ctx context.Context, config map[string]string, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if s == nil || s.sourceWorker == nil || s.runSourceExecution == nil {
		return sourcecdk.Pull{}, sourceExecutionError("", sourceworker.ErrWorkerUnsupported)
	}
	family := strings.TrimSpace(config["family"])
	if family == "" {
		family = "device"
	}
	if !sourceworker.RustAuthoritativeTailscale(tailscaleSourceID, family) {
		return sourcecdk.Pull{}, sourceExecutionError(family, sourceworker.ErrWorkerUnsupported)
	}
	tenantID := strings.TrimSpace(config["tenant_id"])
	credential := []byte(strings.TrimSpace(config["token"]))
	if tenantID == "" || len(credential) == 0 {
		clear(credential)
		return sourcecdk.Pull{}, sourceExecutionError(family, sourceworker.ErrSourceConfiguration)
	}
	providerCursor, priorWatermark, err := sourceworker.ProviderResume(cursor, tailscaleSourceID, family)
	if err != nil {
		clear(credential)
		return sourcecdk.Pull{}, sourceExecutionError(family, err)
	}
	publicConfig := sourceworker.PublicExecutionConfig(config)
	publicConfig["family"] = family
	now := time.Now().UTC()
	input := sourceworker.ExecutionInput{
		SourceID: tailscaleSourceID, FamilyID: family, CredentialReference: previewCredentialReference, PageNumber: 1,
		Scope: sourceworker.CredentialScope{
			TenantID: tenantID, RuntimeID: "source-preview-tailscale-" + family,
			PriorCursor: providerCursor, PublicConfig: publicConfig,
			PriorTerminalWatermarkUnixMillis: priorWatermark, PriorCheckpoint: strings.TrimSpace(cursor.GetOpaque()),
			LeaseOwner: previewLeaseOwner, RuntimeGeneration: previewRuntimeGeneration,
			LeaseGeneration: previewLeaseGeneration, LeaseExpiresAt: now.Add(time.Minute),
		},
	}
	output, err := s.runSourceExecution(ctx, s.sourceWorker, previewCredentialReference, credential, now.Add(time.Minute), input)
	clear(credential)
	if err != nil {
		return sourcecdk.Pull{}, sourceExecutionError(family, err)
	}
	pull, err := sourceworker.PullFromExecutionOutput(output, tenantID)
	if err != nil {
		return sourcecdk.Pull{}, sourceExecutionError(family, err)
	}
	return pull, nil
}

func discoverURNs(pull sourcecdk.Pull) ([]sourcecdk.URN, error) {
	seen := make(map[string]struct{}, len(pull.Events))
	urns := make([]sourcecdk.URN, 0, len(pull.Events))
	for _, event := range pull.Events {
		raw := strings.TrimSpace(event.GetAttributes()["resource_urn"])
		urn, err := sourcecdk.ParseURN(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: Rust record resource URN is invalid", sourceworker.ErrWorkerContract)
		}
		if _, ok := seen[urn.String()]; ok {
			continue
		}
		seen[urn.String()] = struct{}{}
		urns = append(urns, urn)
	}
	return urns, nil
}

func sourceExecutionError(family string, err error) error {
	kind := sourcecdk.ErrorKindProvider
	switch {
	case errors.Is(err, sourceworker.ErrSourceConfiguration), errors.Is(err, sourceworker.ErrCredentialReferenceMissing), errors.Is(err, sourceworker.ErrWorkerUnsupported):
		kind = sourcecdk.ErrorKindInvalidConfig
	case errors.Is(err, sourceworker.ErrProviderAuthentication), errors.Is(err, sourceworker.ErrCredentialUnavailable):
		kind = sourcecdk.ErrorKindAuth
	case errors.Is(err, sourceworker.ErrProviderPermission):
		kind = sourcecdk.ErrorKindPermission
	case errors.Is(err, sourceworker.ErrProviderRateLimited):
		kind = sourcecdk.ErrorKindRateLimited
	case errors.Is(err, sourceworker.ErrProviderTimeout), errors.Is(err, sourceworker.ErrProviderEgress):
		kind = sourcecdk.ErrorKindTransient
	case errors.Is(err, sourceworker.ErrProviderMalformedResponse), errors.Is(err, sourceworker.ErrWorkerContract), errors.Is(err, sourceworker.ErrInvalidExecution):
		kind = sourcecdk.ErrorKindDecode
	}
	return sourcecdk.WrapSourceError(kind, tailscaleSourceID, family, err)
}
