package riskplan

import "slices"

// DiffCandidates compares a previous plan candidate set with the current set.
func DiffCandidates(previous []Candidate, current []Candidate) PlanDiff {
	previousByID := map[string]Candidate{}
	currentByID := map[string]Candidate{}
	for _, candidate := range previous {
		if candidate.ID != "" {
			previousByID[candidate.ID] = candidate
		}
	}
	for _, candidate := range current {
		if candidate.ID != "" {
			currentByID[candidate.ID] = candidate
		}
	}
	diff := PlanDiff{}
	for id, candidate := range currentByID {
		previousCandidate, ok := previousByID[id]
		if !ok {
			diff.Added = append(diff.Added, candidateDiff("", Candidate{}, candidate))
			continue
		}
		if candidateChanged(previousCandidate, candidate) {
			diff.Changed = append(diff.Changed, candidateDiff("changed", previousCandidate, candidate))
			continue
		}
		diff.UnchangedCount++
	}
	for id, candidate := range previousByID {
		if _, ok := currentByID[id]; ok {
			continue
		}
		diff.Removed = append(diff.Removed, candidateDiff("removed", candidate, Candidate{}))
	}
	sortCandidateDiffs(diff.Added)
	sortCandidateDiffs(diff.Removed)
	sortCandidateDiffs(diff.Changed)
	return diff
}

func candidateChanged(previous Candidate, current Candidate) bool {
	return previous.PriorityScore != current.PriorityScore ||
		previous.ExpectedRiskScoreReduction != current.ExpectedRiskScoreReduction ||
		previous.ExpectedAttackPathScoreReduction != current.ExpectedAttackPathScoreReduction ||
		previous.ExpectedAttackPathCountReduction != current.ExpectedAttackPathCountReduction ||
		previous.SimulationStatus != current.SimulationStatus ||
		previous.Owner != current.Owner
}

func candidateDiff(changeType string, previous Candidate, current Candidate) CandidateDiff {
	if changeType == "" {
		changeType = "added"
	}
	id := current.ID
	title := current.Title
	if id == "" {
		id = previous.ID
	}
	if title == "" {
		title = previous.Title
	}
	return CandidateDiff{
		ID:                                       id,
		Title:                                    title,
		ChangeType:                               changeType,
		PreviousPriorityScore:                    previous.PriorityScore,
		CurrentPriorityScore:                     current.PriorityScore,
		PriorityScoreDelta:                       current.PriorityScore - previous.PriorityScore,
		PreviousExpectedRiskScoreReduction:       previous.ExpectedRiskScoreReduction,
		CurrentExpectedRiskScoreReduction:        current.ExpectedRiskScoreReduction,
		ExpectedRiskScoreReductionDelta:          current.ExpectedRiskScoreReduction - previous.ExpectedRiskScoreReduction,
		PreviousExpectedAttackPathCountReduction: previous.ExpectedAttackPathCountReduction,
		CurrentExpectedAttackPathCountReduction:  current.ExpectedAttackPathCountReduction,
	}
}

func sortCandidateDiffs(values []CandidateDiff) {
	slices.SortFunc(values, func(left CandidateDiff, right CandidateDiff) int {
		switch {
		case left.ID < right.ID:
			return -1
		case left.ID > right.ID:
			return 1
		default:
			return 0
		}
	})
}
