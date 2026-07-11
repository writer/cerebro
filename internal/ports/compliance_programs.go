package ports

import "errors"

var (
	ErrComplianceProgramNotFound          = errors.New("compliance program not found")
	ErrComplianceProgramVersionConflict   = errors.New("compliance program version conflict")
	ErrProgramRevisionConflict            = errors.New("compliance program revision conflict")
	ErrControlImplementationNotFound      = errors.New("control implementation not found")
	ErrComplianceEventApplicationConflict = errors.New("compliance event application conflict")
	ErrComplianceEventVersionGap          = errors.New("compliance event aggregate version gap")
)
