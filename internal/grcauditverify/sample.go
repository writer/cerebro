package grcauditverify

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

func verifySample(population PopulationManifest, sample SampleManifest, trustedKeys map[string]string) []Defect {
	defects := []Defect{}
	if population.SchemaVersion != PopulationSchemaVersion {
		defects = append(defects, defect("population_schema_unsupported", "population.schema_version", "The population manifest schema is not supported."))
	}
	populationDigest, err := DigestPopulation(population)
	if err != nil || population.Digest == "" || population.Digest != populationDigest {
		defects = append(defects, defect("population_digest_invalid", "population.digest", "The population manifest digest does not match its contents."))
	}
	if err := verifySignature(population.Signature, population.Digest, trustedKeys); err != nil {
		defects = append(defects, defect("population_signature_invalid", "population.signature", err.Error()))
	}
	if !population.Complete {
		defects = append(defects, defect("population_incomplete", "population.complete", "A sample cannot be verified from an incomplete population."))
	}
	if !validWindow(population.Window) {
		defects = append(defects, defect("population_window_invalid", "population.window", "The population window must have an ordered start and end."))
	}
	if sample.SchemaVersion != SampleSchemaVersion {
		defects = append(defects, defect("sample_schema_unsupported", "sample.schema_version", "The sample manifest schema is not supported."))
	}
	sampleDigest, err := DigestSample(sample)
	if err != nil || sample.Digest == "" || sample.Digest != sampleDigest {
		defects = append(defects, defect("sample_digest_invalid", "sample.digest", "The sample manifest digest does not match its contents."))
	}
	if err := verifySignature(sample.Signature, sample.Digest, trustedKeys); err != nil {
		defects = append(defects, defect("sample_signature_invalid", "sample.signature", err.Error()))
	}
	if sample.PopulationID != population.ID || sample.PopulationDigest != population.Digest {
		defects = append(defects, defect("sample_population_binding_invalid", "sample.population_digest", "The sample is not bound to this exact population manifest."))
	}
	if sample.Algorithm != SampleAlgorithmDeterministicSHA256V1 || sample.AlgorithmVersion != "1" {
		defects = append(defects, defect("sample_algorithm_unsupported", "sample.algorithm", "The sample algorithm or version is not supported."))
	}
	if strings.TrimSpace(sample.Seed) == "" || strings.TrimSpace(sample.Rationale) == "" || !sameWindow(sample.Window, population.Window) {
		defects = append(defects, defect("sample_basis_invalid", "sample", "The sample must record a seed, rationale, and the population window."))
	}

	members := make(map[string]PopulationMember, len(population.Members))
	for _, member := range population.Members {
		if member.ID == "" || !validSHA256Digest(member.Digest) || member.ObservedAt.IsZero() || member.ArrivedAt.IsZero() || members[member.ID].ID != "" {
			defects = append(defects, defect("population_member_invalid", "population.members", "Population member IDs and digests must be unique and complete."))
			continue
		}
		members[member.ID] = member
	}

	excluded := map[string]bool{}
	for _, exclusion := range sample.Exclusions {
		if members[exclusion.MemberID].ID == "" || strings.TrimSpace(exclusion.Reason) == "" || excluded[exclusion.MemberID] {
			defects = append(defects, defect("sample_exclusion_invalid", "sample.exclusions", "Each exclusion must name one population member once and include a reason."))
			continue
		}
		excluded[exclusion.MemberID] = true
	}

	eligible := make([]PopulationMember, 0, len(members))
	for _, member := range members {
		if !excluded[member.ID] {
			eligible = append(eligible, member)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		left := sampleRank(sample.Seed, eligible[i])
		right := sampleRank(sample.Seed, eligible[j])
		if left == right {
			return eligible[i].ID < eligible[j].ID
		}
		return left < right
	})
	if sample.SampleSize <= 0 || sample.SampleSize > len(eligible) {
		defects = append(defects, defect("sample_size_invalid", "sample.sample_size", "The sample size must fit the eligible population."))
		return defects
	}

	selected := make([]string, sample.SampleSize)
	for i := 0; i < sample.SampleSize; i++ {
		selected[i] = eligible[i].ID
	}
	next := sample.SampleSize
	for _, replacement := range sample.Replacements {
		position := indexOf(selected, replacement.RemovedID)
		if position < 0 || strings.TrimSpace(replacement.Reason) == "" || next >= len(eligible) || replacement.AddedID != eligible[next].ID {
			defects = append(defects, defect("sample_replacement_invalid", "sample.replacements", "A replacement must remove a selected member, include a reason, and use the next deterministic candidate."))
			continue
		}
		selected[position] = replacement.AddedID
		next++
	}
	sort.Strings(selected)
	actual := append([]string(nil), sample.SelectedIDs...)
	sort.Strings(actual)
	if !sameStrings(selected, actual) {
		defects = append(defects, defect("sample_selection_mismatch", "sample.selected_ids", "The selected members do not match deterministic selection and recorded replacements."))
	}

	lateSeen := map[string]bool{}
	for _, late := range sample.LateArrivals {
		member := members[late.MemberID]
		validDisposition := late.Disposition == "included" || late.Disposition == "excluded" || late.Disposition == "after_window"
		if member.ID == "" || lateSeen[late.MemberID] || !validDisposition || strings.TrimSpace(late.Reason) == "" {
			defects = append(defects, defect("late_arrival_invalid", "sample.late_arrivals", "Each late arrival must name one population member, disposition, and reason."))
			continue
		}
		lateSeen[late.MemberID] = true
		if late.Disposition == "after_window" && !member.ArrivedAt.After(population.Window.End) {
			defects = append(defects, defect("late_arrival_window_mismatch", "sample.late_arrivals", "An after-window late arrival must have an arrival time after the population window."))
		}
		if late.Disposition == "included" && indexOf(actual, late.MemberID) < 0 {
			defects = append(defects, defect("late_arrival_not_selected", "sample.late_arrivals", "A late arrival marked included must be selected."))
		}
		if late.Disposition == "excluded" && !excluded[late.MemberID] {
			defects = append(defects, defect("late_arrival_not_excluded", "sample.late_arrivals", "A late arrival marked excluded must have a recorded exclusion."))
		}
		if late.Disposition == "after_window" && !excluded[late.MemberID] {
			defects = append(defects, defect("late_arrival_not_excluded", "sample.late_arrivals", "An after-window late arrival must have a recorded exclusion."))
		}
	}
	for _, member := range members {
		if member.ArrivedAt.After(population.Window.End) && !lateSeen[member.ID] {
			defects = append(defects, defect("late_arrival_unrecorded", "sample.late_arrivals", "Every population member received after the window must have a recorded disposition."))
		}
	}
	return defects
}

func sampleRank(seed string, member PopulationMember) string {
	sum := sha256.Sum256([]byte(seed + "\x00" + member.ID + "\x00" + member.Digest))
	return hex.EncodeToString(sum[:])
}

func indexOf(values []string, wanted string) int {
	for i, value := range values {
		if value == wanted {
			return i
		}
	}
	return -1
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
