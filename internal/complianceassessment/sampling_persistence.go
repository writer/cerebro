package complianceassessment

import (
	"context"
	"errors"
)

var (
	ErrSamplingProjectionConflict = errors.New("assessment sampling projection conflict")
	ErrSamplingProjectionGap      = errors.New("assessment sampling projection version gap")
	ErrActivityNotFound           = errors.New("assessment activity not found")
	ErrPopulationNotFound         = errors.New("assessment population not found")
	ErrSampleNotFound             = errors.New("assessment sample not found")
)

const (
	AggregateTypeAssessmentActivity   = "assessment_activity"
	AggregateTypeAssessmentPopulation = "assessment_population"
	AggregateTypeAssessmentSample     = "assessment_sample"
)

type PopulationRecordedPayload struct {
	Snapshot PopulationSnapshot  `json:"snapshot"`
	Subjects []PopulationSubject `json:"subjects"`
}

type SamplingStateStore interface {
	GetAssessmentActivity(context.Context, string, string) (*AssessmentActivity, error)
	GetAssessmentPopulation(context.Context, string, string) (*PopulationRecordedPayload, error)
	GetAssessmentSample(context.Context, string, string) (*SampleSelection, error)
}
