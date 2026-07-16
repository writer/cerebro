package complianceimprovement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

var (
	ErrInvalidRequest = errors.New("invalid compliance improvement request")
	ErrNotFound       = errors.New("compliance improvement run not found")
	ErrConflict       = errors.New("compliance improvement version conflict")
	ErrInvalidState   = errors.New("invalid compliance improvement state transition")
	ErrVerification   = errors.New("compliance improvement verification blocked")
	ErrUnavailable    = errors.New("compliance improvement runtime is unavailable")
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	commitSHAPattern  = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
)

func normalizeProposal(value ImprovementProposal) ImprovementProposal {
	value.ContentDigest = compliance.ContentDigest(strings.TrimSpace(string(value.ContentDigest)))
	value.Inputs = append([]InputRevision(nil), value.Inputs...)
	for index := range value.Inputs {
		value.Inputs[index].Kind = strings.TrimSpace(value.Inputs[index].Kind)
		value.Inputs[index].Ref = compliance.NormalizeRevisionRef(value.Inputs[index].Ref)
	}
	sort.Slice(value.Inputs, func(i, j int) bool {
		left := value.Inputs[i].Kind + "\x00" + value.Inputs[i].Ref.ID + "\x00" + value.Inputs[i].Ref.RevisionID
		right := value.Inputs[j].Kind + "\x00" + value.Inputs[j].Ref.ID + "\x00" + value.Inputs[j].Ref.RevisionID
		return left < right
	})
	value.Gap.Kind = strings.TrimSpace(value.Gap.Kind)
	value.Gap.Summary = strings.TrimSpace(value.Gap.Summary)
	value.Gap.DetectedBy = strings.TrimSpace(value.Gap.DetectedBy)
	value.Gap.DetectedAt = canonicalTime(value.Gap.DetectedAt)
	value.Gap.Current = normalizeMeasurement(value.Gap.Current)
	value.Gap.Target.Name = strings.TrimSpace(value.Gap.Target.Name)
	value.Gap.Target.Comparator = strings.TrimSpace(value.Gap.Target.Comparator)
	value.Gap.Target.Unit = strings.TrimSpace(value.Gap.Target.Unit)
	value.Gap.Guardrails = append([]Guardrail(nil), value.Gap.Guardrails...)
	for index := range value.Gap.Guardrails {
		value.Gap.Guardrails[index].Name = strings.TrimSpace(value.Gap.Guardrails[index].Name)
		value.Gap.Guardrails[index].Comparator = strings.TrimSpace(value.Gap.Guardrails[index].Comparator)
		value.Gap.Guardrails[index].Unit = strings.TrimSpace(value.Gap.Guardrails[index].Unit)
	}
	sort.Slice(value.Gap.Guardrails, func(i, j int) bool { return value.Gap.Guardrails[i].Name < value.Gap.Guardrails[j].Name })
	value.Research = normalizeResearch(value.Research)
	value.Impact.ExpectedBenefit = strings.TrimSpace(value.Impact.ExpectedBenefit)
	value.Patch = normalizePatch(value.Patch)
	value.Verification.VerifiedBy = strings.TrimSpace(value.Verification.VerifiedBy)
	value.Verification.VerifiedAt = canonicalTime(value.Verification.VerifiedAt)
	value.Verification.Results = normalizeVerificationResults(value.Verification.Results)
	return value
}

func normalizeMeasurement(value Measurement) Measurement {
	value.Name = strings.TrimSpace(value.Name)
	value.Unit = strings.TrimSpace(value.Unit)
	return value
}

func normalizeResearch(value ResearchPacket) ResearchPacket {
	value.ResearchedBy = strings.TrimSpace(value.ResearchedBy)
	value.ResearchedAt = canonicalTime(value.ResearchedAt)
	value.Citations = append([]Citation(nil), value.Citations...)
	for index := range value.Citations {
		value.Citations[index].ID = strings.TrimSpace(value.Citations[index].ID)
		value.Citations[index].SourceURN = strings.TrimSpace(value.Citations[index].SourceURN)
		value.Citations[index].SnapshotRevision = compliance.NormalizeRevisionRef(value.Citations[index].SnapshotRevision)
		value.Citations[index].CapturedAt = canonicalTime(value.Citations[index].CapturedAt)
		value.Citations[index].ExpiresAt = canonicalTime(value.Citations[index].ExpiresAt)
	}
	sort.Slice(value.Citations, func(i, j int) bool { return value.Citations[i].ID < value.Citations[j].ID })
	value.Claims = normalizeClaims(value.Claims)
	value.Counterevidence = normalizeClaims(value.Counterevidence)
	value.Unknowns = normalizeStrings(value.Unknowns, false)
	return value
}

func normalizeClaims(values []ResearchClaim) []ResearchClaim {
	result := append([]ResearchClaim(nil), values...)
	for index := range result {
		result[index].ID = strings.TrimSpace(result[index].ID)
		result[index].Statement = strings.TrimSpace(result[index].Statement)
		result[index].CitationIDs = normalizeStrings(result[index].CitationIDs, true)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func normalizePatch(value RepositoryPatch) RepositoryPatch {
	value.Repository = strings.TrimSpace(value.Repository)
	value.BaseBranch = strings.TrimSpace(value.BaseBranch)
	value.BaseCommitSHA = strings.TrimSpace(value.BaseCommitSHA)
	value.ProposalBranch = strings.TrimSpace(value.ProposalBranch)
	value.ChangeKind = strings.TrimSpace(value.ChangeKind)
	value.Changes = append([]FileChange(nil), value.Changes...)
	for index := range value.Changes {
		value.Changes[index].Path = strings.TrimSpace(value.Changes[index].Path)
		value.Changes[index].Operation = strings.TrimSpace(value.Changes[index].Operation)
	}
	sort.Slice(value.Changes, func(i, j int) bool { return value.Changes[i].Path < value.Changes[j].Path })
	value.ValidationSteps = normalizeStrings(value.ValidationSteps, false)
	value.RollbackSteps = normalizeStrings(value.RollbackSteps, false)
	return value
}

func normalizeVerificationResults(values []VerificationResult) []VerificationResult {
	result := append([]VerificationResult(nil), values...)
	for index := range result {
		result[index].VerifierID = strings.TrimSpace(result[index].VerifierID)
		result[index].Status = strings.TrimSpace(result[index].Status)
		result[index].Message = strings.TrimSpace(result[index].Message)
		result[index].Evidence = normalizeStrings(result[index].Evidence, true)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].VerifierID == result[j].VerifierID {
			return result[i].Message < result[j].Message
		}
		return result[i].VerifierID < result[j].VerifierID
	})
	return result
}

func normalizeStrings(values []string, sortValues bool) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if sortValues {
		sort.Strings(result)
	}
	return result
}

func canonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Millisecond)
}

func proposalDigest(value ImprovementProposal) (compliance.ContentDigest, error) {
	value = normalizeProposal(value)
	value.ContentDigest = ""
	value.DraftPullRequest = nil
	value.TeamUpdate = nil
	value.Decision = nil
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal improvement proposal: %w", err)
	}
	digest := sha256.Sum256(payload)
	return compliance.ContentDigest("sha256:" + hex.EncodeToString(digest[:])), nil
}

func revisionDigest(state string, value ImprovementProposal) (compliance.ContentDigest, error) {
	payload, err := json.Marshal(struct {
		State    string              `json:"state"`
		Proposal ImprovementProposal `json:"proposal"`
	}{State: strings.TrimSpace(state), Proposal: normalizeProposal(value)})
	if err != nil {
		return "", fmt.Errorf("marshal improvement revision: %w", err)
	}
	digest := sha256.Sum256(payload)
	return compliance.ContentDigest("sha256:" + hex.EncodeToString(digest[:])), nil
}

func validateDetectedProposal(value ImprovementProposal) error {
	if len(value.Inputs) == 0 || len(value.Inputs) > MaxInputRevisions {
		return fmt.Errorf("%w: inputs must contain between 1 and %d exact revisions", ErrInvalidRequest, MaxInputRevisions)
	}
	seen := map[string]struct{}{}
	for _, input := range value.Inputs {
		if input.Kind == "" {
			return fmt.Errorf("%w: input kind is required", ErrInvalidRequest)
		}
		if err := input.Ref.Validate(); err != nil {
			return fmt.Errorf("%w: input %q: %v", ErrInvalidRequest, input.Kind, err)
		}
		key := input.Kind + "\x00" + input.Ref.ID + "\x00" + input.Ref.RevisionID
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate input revision %q", ErrInvalidRequest, key)
		}
		seen[key] = struct{}{}
	}
	if value.Gap.Kind == "" || value.Gap.Summary == "" || value.Gap.DetectedBy == "" || value.Gap.DetectedAt.IsZero() {
		return fmt.Errorf("%w: gap kind, summary, detector, and detection time are required", ErrInvalidRequest)
	}
	if err := validateMeasurement(value.Gap.Current); err != nil {
		return err
	}
	if err := validateTarget(value.Gap.Target); err != nil {
		return err
	}
	if value.Gap.Target.Name != value.Gap.Current.Name || value.Gap.Target.Unit != value.Gap.Current.Unit {
		return fmt.Errorf("%w: current and target measurements must use the same name and unit", ErrInvalidRequest)
	}
	seenGuardrails := map[string]struct{}{}
	for _, guardrail := range value.Gap.Guardrails {
		if guardrail.Name == "" || guardrail.Unit == "" || !validComparator(guardrail.Comparator) || !finite(guardrail.Value) {
			return fmt.Errorf("%w: each guardrail requires a name, comparator, finite value, and unit", ErrInvalidRequest)
		}
		if _, ok := seenGuardrails[guardrail.Name]; ok {
			return fmt.Errorf("%w: duplicate guardrail %q", ErrInvalidRequest, guardrail.Name)
		}
		seenGuardrails[guardrail.Name] = struct{}{}
	}
	return nil
}

func validateMeasurement(value Measurement) error {
	if value.Name == "" || value.Unit == "" || !finite(value.Value) {
		return fmt.Errorf("%w: current measurement requires a name, finite value, and unit", ErrInvalidRequest)
	}
	return nil
}

func validateTarget(value TargetMeasurement) error {
	if value.Name == "" || value.Unit == "" || !validComparator(value.Comparator) || !finite(value.Value) {
		return fmt.Errorf("%w: target measurement requires a name, comparator, finite value, and unit", ErrInvalidRequest)
	}
	return nil
}

func validComparator(value string) bool {
	switch value {
	case "=", ">", ">=", "<", "<=":
		return true
	default:
		return false
	}
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func validateResearch(value ResearchPacket, now time.Time) error {
	if value.ResearchedBy == "" || value.ResearchedAt.IsZero() {
		return fmt.Errorf("%w: researcher and research time are required", ErrInvalidRequest)
	}
	if len(value.Claims) == 0 || len(value.Claims) > MaxClaims {
		return fmt.Errorf("%w: research must contain between 1 and %d claims", ErrInvalidRequest, MaxClaims)
	}
	if len(value.Counterevidence) > MaxClaims || len(value.Citations) == 0 || len(value.Citations) > MaxCitations || len(value.Unknowns) > MaxUnknowns {
		return fmt.Errorf("%w: research packet exceeds configured bounds", ErrInvalidRequest)
	}
	citations := map[string]struct{}{}
	for _, citation := range value.Citations {
		if citation.ID == "" || citation.SourceURN == "" || citation.CapturedAt.IsZero() {
			return fmt.Errorf("%w: citation id, source URN, and capture time are required", ErrInvalidRequest)
		}
		if err := citation.SnapshotRevision.Validate(); err != nil {
			return fmt.Errorf("%w: citation %q snapshot: %v", ErrInvalidRequest, citation.ID, err)
		}
		if _, ok := citations[citation.ID]; ok {
			return fmt.Errorf("%w: duplicate citation %q", ErrInvalidRequest, citation.ID)
		}
		if !citation.ExpiresAt.IsZero() && !now.Before(citation.ExpiresAt) {
			return fmt.Errorf("%w: citation %q is expired", ErrVerification, citation.ID)
		}
		citations[citation.ID] = struct{}{}
	}
	claims := append(append([]ResearchClaim(nil), value.Claims...), value.Counterevidence...)
	seenClaims := map[string]struct{}{}
	for _, claim := range claims {
		if claim.ID == "" || claim.Statement == "" || len(claim.CitationIDs) == 0 {
			return fmt.Errorf("%w: every research claim requires an id, statement, and citation", ErrVerification)
		}
		if _, ok := seenClaims[claim.ID]; ok {
			return fmt.Errorf("%w: duplicate research claim %q", ErrInvalidRequest, claim.ID)
		}
		seenClaims[claim.ID] = struct{}{}
		for _, citationID := range claim.CitationIDs {
			if _, ok := citations[citationID]; !ok {
				return fmt.Errorf("%w: claim %q cites unknown source %q", ErrVerification, claim.ID, citationID)
			}
		}
	}
	return nil
}

func validatePatch(value RepositoryPatch) error {
	if !repositoryPattern.MatchString(value.Repository) {
		return fmt.Errorf("%w: repository must use owner/name format", ErrInvalidRequest)
	}
	if value.BaseBranch == "" || value.ProposalBranch == "" || value.BaseBranch == value.ProposalBranch {
		return fmt.Errorf("%w: distinct base and proposal branches are required", ErrInvalidRequest)
	}
	if !commitSHAPattern.MatchString(value.BaseCommitSHA) {
		return fmt.Errorf("%w: exact lowercase base commit SHA is required", ErrInvalidRequest)
	}
	if !validChangeKind(value.ChangeKind) {
		return fmt.Errorf("%w: unsupported change kind %q", ErrInvalidRequest, value.ChangeKind)
	}
	if len(value.Changes) == 0 || len(value.Changes) > MaxFileChanges {
		return fmt.Errorf("%w: patch must contain between 1 and %d file changes", ErrInvalidRequest, MaxFileChanges)
	}
	if len(value.ValidationSteps) == 0 || len(value.ValidationSteps) > MaxValidationSteps || len(value.RollbackSteps) == 0 {
		return fmt.Errorf("%w: bounded validation and rollback steps are required", ErrInvalidRequest)
	}
	seen := map[string]struct{}{}
	totalBytes := 0
	for _, change := range value.Changes {
		cleaned := path.Clean(change.Path)
		if change.Path == "" || cleaned != change.Path || path.IsAbs(change.Path) || cleaned == "." || strings.HasPrefix(cleaned, "../") {
			return fmt.Errorf("%w: unsafe repository path %q", ErrInvalidRequest, change.Path)
		}
		if change.Operation != FileOperationCreate && change.Operation != FileOperationUpdate {
			return fmt.Errorf("%w: file %q must use create or update; automated deletion is not allowed", ErrInvalidRequest, change.Path)
		}
		if _, ok := seen[change.Path]; ok {
			return fmt.Errorf("%w: duplicate file change %q", ErrInvalidRequest, change.Path)
		}
		seen[change.Path] = struct{}{}
		totalBytes += len(change.Content)
		if totalBytes > MaxPatchBytes {
			return fmt.Errorf("%w: patch content exceeds %d bytes", ErrInvalidRequest, MaxPatchBytes)
		}
	}
	return nil
}

// NormalizeRepositoryPatch returns the stable representation shared by domain
// validation and provider adapters.
func NormalizeRepositoryPatch(value RepositoryPatch) RepositoryPatch {
	return normalizePatch(value)
}

// ValidateRepositoryPatch applies the bounded repository-change contract.
func ValidateRepositoryPatch(value RepositoryPatch) error {
	return validatePatch(normalizePatch(value))
}

func validChangeKind(value string) bool {
	switch value {
	case ChangeKindControlDefinition, ChangeKindEvidencePolicy, ChangeKindAssessmentTest, ChangeKindMonitoringRule, ChangeKindDocumentation:
		return true
	default:
		return false
	}
}

func intrinsicVerification(value ImprovementProposal) []VerificationResult {
	results := []VerificationResult{
		{VerifierID: "research-citations", Status: VerificationPass, Message: "Every research claim has a source citation."},
		{VerifierID: "bounded-repository-patch", Status: VerificationPass, Message: "The repository patch is within configured file and byte limits."},
		{VerifierID: "human-merge-boundary", Status: VerificationPass, Message: "The proposal can open only a draft pull request; a human GRC owner must decide whether to merge."},
	}
	impact := value.Impact
	if impact.ScopeSubjectsRemoved > 0 || impact.ControlsRemoved > 0 || impact.EvidenceRequirementsRemoved > 0 || impact.OwnersRemoved > 0 || impact.ReviewRequirementsRemoved > 0 {
		results = append(results, VerificationResult{
			VerifierID: "program-integrity",
			Status:     VerificationBlock,
			Message:    "The proposal removes scope, controls, evidence, ownership, or review requirements and cannot use the automated path.",
		})
	} else {
		results = append(results, VerificationResult{VerifierID: "program-integrity", Status: VerificationPass, Message: "The proposal does not weaken program scope or requirements."})
	}
	if strings.TrimSpace(impact.ExpectedBenefit) == "" {
		results = append(results, VerificationResult{VerifierID: "measurable-benefit", Status: VerificationBlock, Message: "Expected program benefit is required."})
	} else {
		results = append(results, VerificationResult{VerifierID: "measurable-benefit", Status: VerificationPass, Message: "The proposal records a measurable target and expected benefit."})
	}
	return normalizeVerificationResults(results)
}

func hasBlockingResult(values []VerificationResult) bool {
	for _, value := range values {
		if value.Status == VerificationBlock {
			return true
		}
	}
	return false
}

// HasBlockingVerification reports whether any verifier denied progression.
func HasBlockingVerification(values []VerificationResult) bool {
	return hasBlockingResult(values)
}

// NormalizeVerificationResults returns stable verifier ordering for receipts.
func NormalizeVerificationResults(values []VerificationResult) []VerificationResult {
	return normalizeVerificationResults(values)
}

func validateVerificationResults(values []VerificationResult) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value.VerifierID == "" || value.Message == "" {
			return fmt.Errorf("%w: verifier id and message are required", ErrInvalidRequest)
		}
		if value.Status != VerificationPass && value.Status != VerificationWarn && value.Status != VerificationBlock {
			return fmt.Errorf("%w: verifier %q returned invalid status %q", ErrInvalidRequest, value.VerifierID, value.Status)
		}
		key := value.VerifierID + "\x00" + value.Message
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate verifier result", ErrInvalidRequest)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func publicPullRequestMetadata(kind string) (string, string) {
	var subject string
	switch kind {
	case ChangeKindControlDefinition:
		subject = "compliance control definitions"
	case ChangeKindEvidencePolicy:
		subject = "compliance evidence policy"
	case ChangeKindAssessmentTest:
		subject = "compliance assessment tests"
	case ChangeKindMonitoringRule:
		subject = "compliance monitoring rules"
	default:
		subject = "compliance program documentation"
	}
	title := "Update " + subject
	body := "## Summary\n\n- update " + subject + " from a verified program-improvement proposal\n- keep the proposed change in draft for a human GRC decision\n\n## Safety\n\n- exact base revision required\n- automated merge is unavailable\n- program scope and requirements cannot be weakened through this path\n"
	return title, body
}
