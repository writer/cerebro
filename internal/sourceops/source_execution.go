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
	previewCredentialReference        = "credential:source-preview:token" // #nosec G101 -- opaque credential-reference label.
	previewLeaseOwner                 = "source-preview"
	previewRuntimeGeneration   uint64 = 1
	previewLeaseGeneration     uint64 = 1
	maxRustDiscoveryPages             = 10_000
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

func rustSourceFamily(sourceID string, config map[string]string) (string, bool) {
	sourceID = strings.TrimSpace(sourceID)
	// Preview authority is promoted separately from the durable runtime. A new
	// runtime-authoritative provider must keep its existing sourceops path until
	// its preview credential adapter and product-surface parity are ready.
	switch sourceID {
	case "azure", "sentinelone", "tailscale":
		return sourceworker.RustAuthoritativeFamily(sourceID, config["family"])
	case "jumpcloud":
		family := strings.TrimSpace(config["family"])
		if family == "" {
			family = "users"
		}
		// The Rust dispatcher owns the closed family catalog. Keeping unknown
		// names authoritative makes them fail closed instead of reaching Go.
		return family, true
	default:
		return "", false
	}
}

func (s *Service) executeRustSource(ctx context.Context, sourceID, family string, config map[string]string, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if s == nil || s.sourceWorker == nil || s.runSourceExecution == nil {
		return sourcecdk.Pull{}, sourceExecutionError(sourceID, family, sourceworker.ErrWorkerUnsupported)
	}
	sourceID, family = strings.TrimSpace(sourceID), strings.TrimSpace(family)
	tenantID := strings.TrimSpace(config["tenant_id"])
	credential := []byte(previewCredential(sourceID, config))
	if tenantID == "" || len(credential) == 0 {
		clear(credential)
		return sourcecdk.Pull{}, sourceExecutionError(sourceID, family, sourceworker.ErrSourceConfiguration)
	}
	providerCursor, priorWatermark, err := sourceworker.ProviderResume(cursor, sourceID, family)
	if err != nil {
		clear(credential)
		return sourcecdk.Pull{}, sourceExecutionError(sourceID, family, err)
	}
	publicConfig := sourceworker.PublicExecutionConfig(config)
	publicConfig["family"] = family
	now := time.Now().UTC()
	input := sourceworker.ExecutionInput{
		SourceID: sourceID, FamilyID: family, CredentialReference: previewCredentialReference, PageNumber: 1,
		Scope: sourceworker.CredentialScope{
			TenantID: tenantID, RuntimeID: "source-preview-" + sourceID + "-" + family,
			PriorCursor: providerCursor, PublicConfig: publicConfig,
			PriorTerminalWatermarkUnixMillis: priorWatermark, PriorCheckpoint: strings.TrimSpace(cursor.GetOpaque()),
			LeaseOwner: previewLeaseOwner, RuntimeGeneration: previewRuntimeGeneration,
			LeaseGeneration: previewLeaseGeneration, LeaseExpiresAt: now.Add(time.Minute),
		},
	}
	output, err := s.runSourceExecution(ctx, s.sourceWorker, previewCredentialReference, credential, now.Add(time.Minute), input)
	clear(credential)
	if err != nil {
		return sourcecdk.Pull{}, sourceExecutionError(sourceID, family, err)
	}
	pull, err := sourceworker.PullFromExecutionOutput(output, tenantID)
	if err != nil {
		return sourcecdk.Pull{}, sourceExecutionError(sourceID, family, err)
	}
	return pull, nil
}

func (s *Service) discoverRustSource(ctx context.Context, sourceID, family string, config map[string]string) ([]sourcecdk.URN, error) {
	seenURNs := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	urns := make([]sourcecdk.URN, 0)
	var cursor *cerebrov1.SourceCursor
	for page := 0; page < maxRustDiscoveryPages; page++ {
		pull, err := s.executeRustSource(ctx, sourceID, family, config, cursor)
		if err != nil {
			return nil, err
		}
		pageURNs, err := discoverURNs(pull)
		if err != nil {
			return nil, err
		}
		for _, urn := range pageURNs {
			if _, ok := seenURNs[urn.String()]; ok {
				continue
			}
			seenURNs[urn.String()] = struct{}{}
			urns = append(urns, urn)
		}
		if pull.NextCursor == nil {
			return urns, nil
		}
		next := strings.TrimSpace(pull.NextCursor.GetOpaque())
		if next == "" {
			return nil, fmt.Errorf("%w: Rust discovery continuation is empty", sourceworker.ErrWorkerContract)
		}
		if _, ok := seenCursors[next]; ok {
			return nil, fmt.Errorf("%w: Rust discovery continuation repeated", sourceworker.ErrWorkerContract)
		}
		seenCursors[next] = struct{}{}
		cursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return nil, fmt.Errorf("%w: Rust discovery exceeded %d pages", sourceworker.ErrWorkerContract, maxRustDiscoveryPages)
}

func previewCredential(sourceID string, config map[string]string) string {
	switch strings.TrimSpace(sourceID) {
	case "azure":
		if credential := strings.TrimSpace(config["graph_token"]); credential != "" {
			return credential
		}
	case "jumpcloud":
		for _, key := range []string{"api_key", "api_token", "token"} {
			if credential := strings.TrimSpace(config[key]); credential != "" {
				return credential
			}
		}
		return ""
	}
	return strings.TrimSpace(config["token"])
}

func discoverURNs(pull sourcecdk.Pull) ([]sourcecdk.URN, error) {
	seen := make(map[string]struct{}, len(pull.Events))
	urns := make([]sourcecdk.URN, 0, len(pull.Events))
	for _, event := range pull.Events {
		attributes := event.GetAttributes()
		raw := strings.TrimSpace(attributes["resource_urn"])
		if raw == "" && strings.TrimSpace(event.GetSourceId()) == "jumpcloud" {
			family := strings.TrimSpace(attributes["family"])
			if family == "" {
				family = strings.TrimPrefix(strings.TrimSpace(event.GetKind()), "jumpcloud.")
			}
			stableID := firstNonEmpty(attributes, "source_event_id", "resource_id")
			var urn sourcecdk.URN
			var err error
			if family == "group_members" {
				memberID := firstNonEmpty(attributes, "member_user_id", "member_id", "resource_id", "source_event_id")
				urn, err = sourcecdk.URNForEscaped(event.GetTenantId(), "jumpcloud_group_members", strings.TrimSpace(attributes["group_id"]), memberID)
			} else {
				if family == "audit_events" {
					stableID = sourcecdk.StableExternalID(stableID, "event")
				}
				urn, err = sourcecdk.URNFor(event.GetTenantId(), "jumpcloud_"+family, stableID)
			}
			if err != nil {
				return nil, fmt.Errorf("%w: JumpCloud discovery identity is invalid", sourceworker.ErrWorkerContract)
			}
			raw = urn.String()
		}
		if raw == "" {
			provider := strings.TrimSpace(attributes["resource_provider"])
			resourceType := strings.TrimSpace(attributes["resource_type"])
			resourceID := strings.TrimSpace(attributes["resource_id"])
			if provider != "" && resourceType != "" && resourceID != "" {
				raw = fmt.Sprintf("urn:cerebro:%s:%s_%s:%s", event.GetTenantId(), provider, resourceType, resourceID)
			}
		}
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

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func sourceExecutionError(sourceID, family string, err error) error {
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
	return sourcecdk.WrapSourceError(kind, sourceID, family, err)
}
