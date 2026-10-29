package cloudidentitysource

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxEvidenceBytes = 768 * 1024

type Factory func(context.Context, Settings) (ci.CollectionPorts, error)

type Source struct {
	spec    *cerebrov1.SourceSpec
	factory Factory
	now     func() time.Time
}

func NewSource(spec *cerebrov1.SourceSpec, factory Factory, now func() time.Time) (*Source, error) {
	if spec == nil || spec.Id != ci.SourceID {
		return nil, fmt.Errorf("cloud_identity source spec is required")
	}
	if factory == nil {
		factory = DefaultFactory
	}
	if now == nil {
		now = time.Now
	}
	return &Source{spec: spec, factory: factory, now: now}, nil
}

func (source *Source) Spec() *cerebrov1.SourceSpec { return source.spec }

func (source *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	settings, err := ParseSettings(cfg)
	if err != nil {
		return err
	}
	ports, err := source.factory(ctx, settings)
	if err != nil {
		return err
	}
	for _, target := range settings.Plan.Targets {
		for _, input := range target.Manifests {
			if _, err := ports.Repositories.ReadRepository(ctx, input.Source); err != nil {
				return fmt.Errorf("cloud_identity pinned manifest repository access check failed")
			}
		}
	}
	return nil
}

func (source *Source) Discover(_ context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	settings, err := ParseSettings(cfg)
	if err != nil {
		return nil, err
	}
	identity, err := sourcecdk.URNForEscaped(settings.TenantID, "source", ci.SourceID, settings.Plan.Scope)
	if err != nil {
		return nil, err
	}
	return []sourcecdk.URN{identity}, nil
}

func (source *Source) Read(ctx context.Context, cfg sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	settings, err := ParseSettings(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, settings.Timeout)
	defer cancel()
	ports, err := source.factory(ctx, settings)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	collection, err := ci.Collect(ctx, settings.Plan, ports, source.now())
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events, err := CollectionEvents(settings.TenantID, collection)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return sourcecdk.Pull{Events: events}, nil
}

// CollectionEvents preserves bounded replay evidence. An oversized cohort emits
// an explicitly incomplete record instead of dropping policies and claiming clear.
func CollectionEvents(tenant string, collection ci.Collection) ([]*primitives.Event, error) {
	events := make([]*primitives.Event, 0, len(collection.Evidence)+1)
	coverage := CollectionCoverage{Schema: ci.SchemaVersion, Scope: collection.Scope, CollectedAt: collection.CollectedAt, InventoryComplete: collection.InventoryComplete, PrincipalCount: len(collection.Evidence), Gaps: collectionCoverageGaps(collection)}
	for _, evidence := range collection.Evidence {
		if evidence.Consumers == nil {
			evidence.Consumers = []ci.Workload{}
		}
		if evidence.Investigations == nil {
			evidence.Investigations = []ci.Investigation{}
		}
		raw, err := json.Marshal(evidence)
		if err != nil {
			return nil, fmt.Errorf("encode cloud identity evidence: %w", err)
		}
		if len(raw) > maxEvidenceBytes {
			gap := ci.Gap{Code: "principal_evidence_budget_exceeded", Scope: evidence.Principal.ID, Message: "Principal evidence exceeded the bounded event payload; assessment remains incomplete"}
			coverage.Gaps = append(coverage.Gaps, gap)
			evidence = ci.Evidence{Schema: ci.SchemaVersion, Principal: evidence.Principal, Scope: evidence.Scope, CollectedAt: evidence.CollectedAt, Consumers: []ci.Workload{}, Investigations: []ci.Investigation{}, Gaps: []ci.Gap{gap}}
			raw, err = json.Marshal(evidence)
			if err != nil {
				return nil, err
			}
		}
		attributes := map[string]string{"principal_id": evidence.Principal.ID, "cloud_provider": string(evidence.Principal.Provider), "scope": evidence.Scope, "resource_id": evidence.Principal.ID, "resource_type": "cloud_identity.principal", "collection_complete": fmt.Sprint(evidence.ConsumerInventoryComplete)}
		if evidence.Principal.Account != "" {
			attributes["account_id"] = evidence.Principal.Account
		}
		if evidence.Principal.Project != "" {
			attributes["project_id"] = evidence.Principal.Project
		}
		event, err := cloudIdentityEvent(tenant, ci.EventKind, "cloud_identity/principal_evidence/v1", evidence.Principal.ID, raw, attributes, collection.CollectedAt)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	coverage.GapCount = len(coverage.Gaps)
	if len(coverage.Gaps) > 1000 {
		coverage.Gaps = coverage.Gaps[:1000]
		coverage.GapsTruncated = true
	}
	raw, err := json.Marshal(coverage)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxEvidenceBytes {
		coverage.Gaps = nil
		coverage.GapsTruncated = true
		raw, err = json.Marshal(coverage)
	}
	if err != nil {
		return nil, err
	}
	event, err := cloudIdentityEvent(tenant, ci.CoverageEventKind, "cloud_identity/coverage/v1", collection.Scope, raw, map[string]string{"scope": collection.Scope}, collection.CollectedAt)
	if err != nil {
		return nil, err
	}
	return append(events, event), nil
}

func collectionCoverageGaps(collection ci.Collection) []ci.Gap {
	seen := make(map[string]struct{})
	var result []ci.Gap
	add := func(gaps []ci.Gap) {
		for _, gap := range gaps {
			key := gap.Code + "\x00" + gap.Scope + "\x00" + gap.Message
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, gap)
		}
	}
	add(collection.Gaps)
	for _, evidence := range collection.Evidence {
		add(evidence.Gaps)
		add(evidence.Declared.Gaps)
		add(evidence.Observed.Gaps)
		add(evidence.Definitions.Gaps)
		for _, investigation := range evidence.Investigations {
			add(investigation.Validation.Gaps)
		}
	}
	return result
}

func cloudIdentityEvent(tenant, kind, schema, identity string, payload []byte, attributes map[string]string, observedAt time.Time) (*primitives.Event, error) {
	event := &cerebrov1.EventEnvelope{Id: sourcecdk.EventID(ci.SourceID, tenant, kind, identity, observedAt.UTC().Format(time.RFC3339Nano), ci.Digest(json.RawMessage(payload))), TenantId: tenant, SourceId: ci.SourceID, Kind: kind, SchemaRef: schema, Payload: payload, Attributes: attributes, OccurredAt: timestamppb.New(observedAt.UTC())}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, err
	}
	return event, nil
}
