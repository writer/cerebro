package complianceassessment

func knownScopeState(value ScopeState) bool {
	switch value {
	case ScopeInScope, ScopeNotApplicable, ScopeUnresolved:
		return true
	default:
		return false
	}
}

func knownOutcome(value AutomatedOutcome) bool {
	switch value {
	case OutcomeSatisfied, OutcomeNotSatisfied, OutcomeIndeterminate, OutcomeNotAssessed:
		return true
	default:
		return false
	}
}

func knownDesignState(value DesignState) bool {
	switch value {
	case DesignEffective, DesignIneffective, DesignUnknown, DesignNotAssessed:
		return true
	default:
		return false
	}
}

func knownOperatingState(value OperatingEffectivenessState) bool {
	switch value {
	case OperatingEffective, OperatingIneffective, OperatingUnknown, OperatingNotTested:
		return true
	default:
		return false
	}
}

func knownEvidenceState(value EvidenceState) bool {
	switch value {
	case EvidenceSufficient, EvidenceMissing, EvidenceStale, EvidenceConflicting,
		EvidenceUntrusted, EvidenceIncomplete, EvidenceManualReview:
		return true
	default:
		return false
	}
}

func knownDispositionState(value DispositionState) bool {
	switch value {
	case DispositionNone, DispositionAcceptedException, DispositionAcceptedRisk, DispositionReviewOverride:
		return true
	default:
		return false
	}
}

func knownAssurance(value Assurance) bool {
	switch value {
	case AssuranceHigh, AssuranceMedium, AssuranceLow, AssuranceNone:
		return true
	default:
		return false
	}
}

func knownAuditorState(value AuditorState) bool {
	switch value {
	case AuditorNotReviewed, AuditorAccepted, AuditorChangesRequested, AuditorRejected:
		return true
	default:
		return false
	}
}

func knownCoverageState(value CoverageState) bool {
	switch value {
	case CoverageComplete, CoveragePartial, CoverageEmpty, CoverageUnknown:
		return true
	default:
		return false
	}
}

func knownSourceState(value SourceState) bool {
	switch value {
	case SourceSupported, SourcePartial, SourceStale, SourceFailed, SourceUnconfigured,
		SourceUnsupported, SourceUnverified, SourceConflicting, SourceUnknown:
		return true
	default:
		return false
	}
}

func knownReasonCode(value ReasonCode) bool {
	switch value {
	case ReasonSatisfied, ReasonActiveFinding, ReasonEvidenceMissing, ReasonEvidenceInvalid,
		ReasonEvidenceStale, ReasonEvidenceConflicting, ReasonCoverageIncomplete,
		ReasonSourceUntrusted, ReasonSourceUnknown, ReasonManualEvidence,
		ReasonAcceptedException, ReasonAcceptedRisk, ReasonNotApplicable,
		ReasonInheritedResponsibility, ReasonSampledTesting, ReasonSourceUnconfigured,
		ReasonSourceUnsupported, ReasonSourcePartial, ReasonSourceFailed, ReasonSourceStale,
		ReasonScopeUnresolved, ReasonPopulationEmpty:
		return true
	default:
		return false
	}
}

func knownNextAction(value NextAction) bool {
	switch value {
	case ActionNone, ActionReview, ActionCollectEvidence, ActionRefreshEvidence,
		ActionRestoreSource, ActionResolveScope, ActionRemediate, ActionRetest:
		return true
	default:
		return false
	}
}

func knownCompleteness(value CollectionCompleteness) bool {
	switch value {
	case CollectionComplete, CollectionPartial, CollectionTruncated,
		CollectionChangedDuringScan, CollectionUnknown:
		return true
	default:
		return false
	}
}
