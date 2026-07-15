package complianceimpact

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/workflowevents"
)

type AssessmentPlanAdapter struct {
	processor *Processor
}

func NewAssessmentPlanAdapter(processor *Processor) (*AssessmentPlanAdapter, error) {
	if processor == nil {
		return nil, ErrImpactProcessorUnavailable
	}
	return &AssessmentPlanAdapter{processor: processor}, nil
}

func (a *AssessmentPlanAdapter) ProcessAssessmentPlanEvent(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if a == nil || a.processor == nil || event == nil {
		return ErrImpactProcessorUnavailable
	}
	record, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return err
	}
	if record.Kind != workflowevents.EventKindCompliancePlanRevisionRecorded && record.Kind != workflowevents.EventKindCompliancePlanPublished {
		return fmt.Errorf("%w: event is not an assessment plan revision", ErrImpactProcessorUnavailable)
	}
	var plan complianceassessment.AssessmentPlanRevision
	if err := json.Unmarshal([]byte(record.PayloadJSON), &plan); err != nil {
		return fmt.Errorf("decode assessment plan impact event: %w", err)
	}
	changedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.RecordedAt))
	if err != nil {
		return fmt.Errorf("decode assessment plan impact time: %w", err)
	}
	current, err := complianceintegration.AdaptRevisionRef(plan.TenantID, "compliance.assessment", complianceintegration.FactAssessmentPlan, compliance.RevisionRef{
		ID: plan.ID, RevisionID: plan.RevisionID, Version: plan.Version,
		ContentDigest: compliance.ContentDigest(plan.ContentDigest), LastModified: plan.RevisionModifiedAt,
	})
	if err != nil {
		return err
	}
	fact, err := complianceintegration.NewDomainFact(current, nil)
	if err != nil {
		return err
	}
	kind := complianceintegration.ChangeCreated
	var predecessor *complianceintegration.RevisionRef
	if plan.Version > 1 {
		if plan.PredecessorRevision == nil {
			return fmt.Errorf("%w: assessment plan update lacks exact predecessor", ErrImpactProcessorUnavailable)
		}
		value, adaptErr := complianceintegration.AdaptRevisionRef(plan.TenantID, "compliance.assessment", complianceintegration.FactAssessmentPlan, *plan.PredecessorRevision)
		if adaptErr != nil {
			return adaptErr
		}
		predecessor = &value
		kind = complianceintegration.ChangeUpdated
	}
	_, err = a.processor.Process(ctx, FactChange{EventID: event.GetId(), Kind: kind, Fact: fact, Predecessor: predecessor, ChangedAt: changedAt})
	return err
}
