package complianceimpact

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/workflowevents"
)

type ComplianceProgramAdapter struct{ processor *Processor }

func NewComplianceProgramAdapter(processor *Processor) (*ComplianceProgramAdapter, error) {
	if processor == nil {
		return nil, ErrImpactProcessorUnavailable
	}
	return &ComplianceProgramAdapter{processor: processor}, nil
}

func (a *ComplianceProgramAdapter) ProcessComplianceProgramEvent(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if a == nil || a.processor == nil || event == nil {
		return ErrImpactProcessorUnavailable
	}
	record, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return err
	}
	changedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.RecordedAt))
	if err != nil {
		return fmt.Errorf("decode compliance program impact time: %w", err)
	}
	var fact complianceintegration.DomainFact
	var predecessor *complianceintegration.RevisionRef
	switch record.Kind {
	case workflowevents.EventKindComplianceProgramScopeRecorded:
		var scope grcprogram.ProgramScopeRevisionRecord
		if err := json.Unmarshal([]byte(record.PayloadJSON), &scope); err != nil {
			return fmt.Errorf("decode program scope impact event: %w", err)
		}
		fact, predecessor, err = programScopeFact(scope)
	case workflowevents.EventKindComplianceImplementationRecorded:
		var payload grcprogram.ControlImplementationRecordedPayload
		if err := json.Unmarshal([]byte(record.PayloadJSON), &payload); err != nil {
			return fmt.Errorf("decode control implementation impact event: %w", err)
		}
		fact, predecessor, err = implementationFact(payload.Revision)
	default:
		return fmt.Errorf("%w: event is not a revisioned compliance program fact", ErrImpactProcessorUnavailable)
	}
	if err != nil {
		return err
	}
	kind := complianceintegration.ChangeCreated
	if fact.Revision().Version() > 1 {
		if predecessor == nil {
			return fmt.Errorf("%w: compliance program update lacks exact predecessor", ErrImpactProcessorUnavailable)
		}
		kind = complianceintegration.ChangeUpdated
	}
	_, err = a.processor.Process(ctx, FactChange{EventID: event.GetId(), Kind: kind, Fact: fact, Predecessor: predecessor, ChangedAt: changedAt})
	return err
}

func programScopeFact(scope grcprogram.ProgramScopeRevisionRecord) (complianceintegration.DomainFact, *complianceintegration.RevisionRef, error) {
	root, err := adaptVersion(scope.TenantID, "compliance.program_scope", complianceintegration.FactProgram, scope.Version)
	if err != nil {
		return complianceintegration.DomainFact{}, nil, err
	}
	dependencies := make([]complianceintegration.DependencyRef, 0, len(scope.Specification.FrameworkRevisions)+len(scope.Specification.ProfileRevisions))
	for _, value := range scope.Specification.FrameworkRevisions {
		dependency, dependencyErr := exactDependency(scope.TenantID, "compliance.framework", complianceintegration.FactCatalog, value, "scope_framework")
		if dependencyErr != nil {
			return complianceintegration.DomainFact{}, nil, dependencyErr
		}
		dependencies = append(dependencies, dependency)
	}
	for _, value := range scope.Specification.ProfileRevisions {
		dependency, dependencyErr := exactDependency(scope.TenantID, "compliance.profile", complianceintegration.FactCatalog, value, "scope_profile")
		if dependencyErr != nil {
			return complianceintegration.DomainFact{}, nil, dependencyErr
		}
		dependencies = append(dependencies, dependency)
	}
	fact, err := complianceintegration.NewDomainFact(root, dependencies)
	if err != nil {
		return complianceintegration.DomainFact{}, nil, err
	}
	previous, err := adaptOptionalPredecessor(scope.TenantID, "compliance.program_scope", complianceintegration.FactProgram, scope.PredecessorRevision)
	return fact, previous, err
}

func implementationFact(revision grcprogram.ControlImplementationRevisionRecord) (complianceintegration.DomainFact, *complianceintegration.RevisionRef, error) {
	root, err := adaptVersion(revision.TenantID, "compliance.control_implementation", complianceintegration.FactProjection, revision.Version)
	if err != nil {
		return complianceintegration.DomainFact{}, nil, err
	}
	dependencies := make([]complianceintegration.DependencyRef, 0, 1+2*len(revision.Specification.MappingRefs))
	if revision.Specification.ExactScopeRevision != nil {
		dependency, dependencyErr := exactDependency(revision.TenantID, "compliance.program_scope", complianceintegration.FactProgram, *revision.Specification.ExactScopeRevision, "implementation_scope")
		if dependencyErr != nil {
			return complianceintegration.DomainFact{}, nil, dependencyErr
		}
		dependencies = append(dependencies, dependency)
	}
	for _, mapping := range revision.Specification.MappingRefs {
		for _, value := range []struct {
			domain   string
			relation string
			ref      compliance.RevisionRef
		}{{"compliance.mapping_source", "mapping_source", mapping.Source}, {"compliance.mapping_target", "mapping_target", mapping.Target}} {
			dependency, dependencyErr := exactDependency(revision.TenantID, value.domain, complianceintegration.FactMapping, value.ref, value.relation)
			if dependencyErr != nil {
				return complianceintegration.DomainFact{}, nil, dependencyErr
			}
			dependencies = append(dependencies, dependency)
		}
	}
	fact, err := complianceintegration.NewDomainFact(root, dependencies)
	if err != nil {
		return complianceintegration.DomainFact{}, nil, err
	}
	previous, err := adaptOptionalPredecessor(revision.TenantID, "compliance.control_implementation", complianceintegration.FactProjection, revision.PredecessorRevision)
	return fact, previous, err
}

func adaptVersion(tenantID, domain string, kind complianceintegration.FactKind, value compliance.VersionMetadata) (complianceintegration.RevisionRef, error) {
	return complianceintegration.AdaptRevisionRef(tenantID, domain, kind, compliance.RevisionRef{
		ID: value.ID, RevisionID: value.RevisionID, Version: value.Version,
		ContentDigest: value.ContentDigest, LastModified: value.LastModified,
	})
}

func exactDependency(tenantID, domain string, kind complianceintegration.FactKind, value compliance.RevisionRef, relation string) (complianceintegration.DependencyRef, error) {
	ref, err := complianceintegration.AdaptRevisionRef(tenantID, domain, kind, value)
	if err != nil {
		return complianceintegration.DependencyRef{}, err
	}
	return complianceintegration.NewDependencyRef(ref, relation)
}

func adaptOptionalPredecessor(tenantID, domain string, kind complianceintegration.FactKind, value *compliance.RevisionRef) (*complianceintegration.RevisionRef, error) {
	if value == nil {
		return nil, nil
	}
	ref, err := complianceintegration.AdaptRevisionRef(tenantID, domain, kind, *value)
	if err != nil {
		return nil, err
	}
	return &ref, nil
}
