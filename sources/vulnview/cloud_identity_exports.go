package vulnview

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	cloudIdentityExportSource          = "cloud_identity"
	cloudIdentityFindingMaxPageSize    = 200
	cloudIdentityAssessmentMaxPageSize = 500
)

// cloudIdentityFindingFamily builds the cloud_identity_finding family. Its
// Check/Discover reuse the generic lister-driven defaults (reached through
// sourcecdk.CursorFeedPageToList, which adapts cloudIdentityFindingsPage to
// the legacy (records, nextOpaqueCursor) shape); ReadWithCheckpoint is
// overridden so Contract H's resumable cursor-feed checkpointing (see
// sourcecdk.CursorFeedCheckpointPull) applies to this family too, not just
// the assessment feed.
func (s *Source) cloudIdentityFindingFamily() sourcecdk.Family[settings] {
	family := familyFromLister(familyCloudIdentityFinding, sourcecdk.CursorFeedPageToList(s.cloudIdentityFindingsPage))
	family.ReadWithCheckpoint = func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
		records, page, err := s.cloudIdentityFindingsPage(ctx, settings, sourcecdk.CursorToken(cursor), settings.perPage)
		if err != nil {
			return sourcecdk.Pull{}, wrapFamilyErr(familyCloudIdentityFinding, err)
		}
		return sourcecdk.CursorFeedCheckpointPull(sourceID, familyCloudIdentityFinding, records, page, checkpoint, func(rec record) (*primitives.Event, error) {
			return eventFromRecord(settings, familyCloudIdentityFinding, rec), nil
		})
	}
	return family
}

// cloudIdentityAssessmentFamily builds the cloud_identity_assessment family,
// overriding ReadWithCheckpoint the same way cloudIdentityFindingFamily does.
func (s *Source) cloudIdentityAssessmentFamily() sourcecdk.Family[settings] {
	family := familyFromListerWithEvent(familyCloudIdentityAssessment, sourcecdk.CursorFeedPageToList(s.cloudIdentityAssessmentsPage), cloudIdentityAssessmentEventFromRecord)
	family.ReadWithCheckpoint = func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
		records, page, err := s.cloudIdentityAssessmentsPage(ctx, settings, sourcecdk.CursorToken(cursor), settings.perPage)
		if err != nil {
			return sourcecdk.Pull{}, wrapFamilyErr(familyCloudIdentityAssessment, err)
		}
		return sourcecdk.CursorFeedCheckpointPull(sourceID, familyCloudIdentityAssessment, records, page, checkpoint, func(rec record) (*primitives.Event, error) {
			return cloudIdentityAssessmentEventFromRecord(settings, rec), nil
		})
	}
	return family
}

// cloudIdentityFindingsPage pages GET /exports/findings: within one read,
// only the highest version per findingId is kept (the feed can repeat a
// finding across a read-resume lookback). familyFromLister's Check/Discover
// reach it through sourcecdk.CursorFeedPageToList above; ReadWithCheckpoint
// (above) calls it directly for Contract H checkpointing.
func (s *Source) cloudIdentityFindingsPage(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, sourcecdk.CursorFeedPage, error) {
	page, err := s.getCloudIdentityExportPage(ctx, settings, "/exports/findings", cursor, sourcecdk.ClampPageSize(pageSize, cloudIdentityFindingMaxPageSize))
	if err != nil {
		return nil, sourcecdk.CursorFeedPage{}, err
	}
	records := make([]record, 0, len(page.Items))
	for _, item := range page.Items {
		rec, err := recordFromRaw(familyCloudIdentityFinding, item)
		if err != nil {
			return nil, sourcecdk.CursorFeedPage{}, err
		}
		if firstValueString(rec.Values, "findingId") == "" {
			continue
		}
		records = append(records, rec)
	}
	deduped := sourcecdk.KeepHighestVersion(records,
		func(rec record) string { return firstValueString(rec.Values, "findingId") },
		cloudIdentityVersionGreater,
	)
	return deduped, page, nil
}

// cloudIdentityVersionGreater compares "version" numerically when possible,
// falling back to string comparison for an unparsable value.
func cloudIdentityVersionGreater(candidate, existing record) bool {
	candidateVersion := firstValueString(candidate.Values, "version")
	existingVersion := firstValueString(existing.Values, "version")
	candidateNum, candidateErr := strconv.ParseInt(candidateVersion, 10, 64)
	existingNum, existingErr := strconv.ParseInt(existingVersion, 10, 64)
	if candidateErr == nil && existingErr == nil {
		return candidateNum > existingNum
	}
	return candidateVersion > existingVersion
}

// cloudIdentityAssessmentsPage pages GET /exports/assessments: a flattened
// feed of one "run" item followed by that run's "assessment" items. A single
// "assessment_error" item (see cloudIdentityAssessmentErrorForItem) replaces
// a run's assessment items when its object could not be read; that item
// fails the page read instead of being silently discarded (#13), so the
// page is retried rather than checkpointed past. familyFromListerWithEvent's
// Check/Discover reach it through sourcecdk.CursorFeedPageToList above;
// ReadWithCheckpoint (above) calls it directly for Contract H checkpointing.
func (s *Source) cloudIdentityAssessmentsPage(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, sourcecdk.CursorFeedPage, error) {
	page, err := s.getCloudIdentityExportPage(ctx, settings, "/exports/assessments", cursor, sourcecdk.ClampPageSize(pageSize, cloudIdentityAssessmentMaxPageSize))
	if err != nil {
		return nil, sourcecdk.CursorFeedPage{}, err
	}
	records := make([]record, 0, len(page.Items))
	for _, item := range page.Items {
		values := map[string]any{}
		if err := json.Unmarshal(item, &values); err != nil {
			return nil, sourcecdk.CursorFeedPage{}, fmt.Errorf("decode VulnView cloud_identity assessment record: %w", err)
		}
		if firstValueString(values, "type") == "assessment_error" {
			return nil, sourcecdk.CursorFeedPage{}, cloudIdentityAssessmentErrorForItem(values)
		}
		id := cloudIdentityAssessmentRecordID(values)
		if id == "" {
			continue
		}
		records = append(records, record{Raw: sourcecdk.CloneRawMessage(item), Values: values, ID: id})
	}
	return records, page, nil
}

// cloudIdentityAssessmentErrorForItem turns a VulnView "assessment_error"
// item into a retryable error carrying only VulnView's fixed error code --
// never upstream request detail -- so the family's cursor is never advanced
// past it: the next scheduled read retries this exact page.
func cloudIdentityAssessmentErrorForItem(values map[string]any) error {
	return fmt.Errorf("vulnview cloud_identity_assessment: run %s/%s assessment object unavailable: %s",
		firstValueString(values, "scanId"), firstValueString(values, "runId"),
		firstNonEmpty(firstValueString(values, "error"), "assessment_unavailable"))
}

// cloudIdentityAssessmentRecordID dedupes a run on (scanId, runId) and an assessment on (scanId,
// runId, checkId, provider, principalId): one principal can be assessed once per provider per run.
// Per Contract H, the ID is a SHA-256 digest of a length-prefixed canonical
// tuple rather than a lossy "/"/":" replacement join: two distinct
// principalId values that only differ in "/" vs ":" placement (for example
// two AWS role ARNs "role/a-b" and "role/a/b") must never alias to the same
// ID, which they would under naive separator-based normalization.
func cloudIdentityAssessmentRecordID(values map[string]any) string {
	switch firstValueString(values, "type") {
	case "run":
		return sourcecdk.CanonicalRecordID("run", firstValueString(values, "scanId"), firstValueString(values, "runId"))
	case "assessment":
		return sourcecdk.CanonicalRecordID("assessment", firstValueString(values, "scanId"), firstValueString(values, "runId"), firstValueString(values, "checkId"), firstValueString(values, "provider"), firstValueString(values, "principalId"))
	default:
		return ""
	}
}

// cloudIdentityAssessmentEventFromRecord emits vulnview.cloud_identity_run
// for a "run" item and vulnview.cloud_identity_assessment for an "assessment" item.
func cloudIdentityAssessmentEventFromRecord(settings settings, rec record) *primitives.Event {
	kind := sourceID + "." + familyCloudIdentityAssessment
	schema := sourceID + "/" + familyCloudIdentityAssessment + "/v1"
	if firstValueString(rec.Values, "type") == "run" {
		kind = sourceID + ".cloud_identity_run"
		schema = sourceID + "/cloud_identity_run/v1"
	}
	return &primitives.Event{
		Id:         eventID(settings, familyCloudIdentityAssessment, rec.ID),
		TenantId:   settings.tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		OccurredAt: timestamppb.New(cloudIdentityAssessmentOccurredAt(rec.Values)),
		SchemaRef:  schema,
		Payload:    sourcecdk.CloneRawMessage(rec.Raw),
		Attributes: cloudIdentityAssessmentAttributes(rec.Values),
	}
}

// cloudIdentityAssessmentOccurredAt resolves OccurredAt deterministically
// per Contract H: assessment -> collectedAt, else evaluatedAt, else
// completedAt; run -> finishedAt, else completedAt. Never time.Now(), so a
// replayed page always reproduces the identical OccurredAt.
func cloudIdentityAssessmentOccurredAt(values map[string]any) time.Time {
	keys := []string{"finishedAt", "completedAt"}
	if firstValueString(values, "type") == "assessment" {
		keys = []string{"collectedAt", "evaluatedAt", "completedAt"}
	}
	return sourcecdk.JSONObject(values).FieldTime(vulnviewTimeLayouts, keys...)
}

func cloudIdentityAssessmentAttributes(values map[string]any) map[string]string {
	attrs := map[string]string{
		"family":          familyCloudIdentityAssessment,
		"provider":        sourceID,
		"source_provider": sourceID,
		"scan_id":         firstValueString(values, "scanId"),
		"run_id":          firstValueString(values, "runId"),
	}
	switch firstValueString(values, "type") {
	case "run":
		copyFields(attrs, values, map[string]string{"cohort_scope": "cohortScope", "evidence_stream": "evidenceStream", "authoritative": "authoritative", "evaluated_at": "evaluatedAt", "completed_at": "completedAt", "finished_at": "finishedAt", "detector_version": "detectorVersion", "assessments_state": "assessmentsState", "bundle_key": "bundle.key", "bundle_sha256": "bundle.sha256", "bundle_collected_at": "bundle.collectedAt", "bundle_principal_count": "bundle.principalCount", "reasons": "reasons", "count_supported": "counts.supported", "count_candidate": "counts.candidate", "count_incomplete": "counts.incomplete", "count_clear": "counts.clear", "collection_coverage_complete": "collectionCoverage.inventoryComplete", "collection_coverage_gap_codes": "collectionCoverage.gapCodes", "collection_coverage_gap_count": "collectionCoverage.gapCount"})
	case "assessment":
		copyFields(attrs, values, map[string]string{"check_id": "checkId", "check_version": "checkVersion", "cloud_provider": "provider", "account_id": "account", "project_id": "project", "principal_id": "principalId", "principal_kind": "principalKind", "cohort_scope": "cohortScope", "status": "status", "severity": "severity", "title": "title", "side": "side", "drift": "drift", "finding_id": "findingId", "evidence_fresh": "evidenceFresh", "gap_codes": "gapCodes", "collected_at": "collectedAt", "evaluated_at": "evaluatedAt", "completed_at": "completedAt", "finished_at": "finishedAt", "consumers_truncated": "consumersTruncated"})
		attrs["source_severity"] = firstValueString(values, "severity")
		if consumers := cloudIdentityConsumersSummary(values); consumers != "" {
			attrs["consumers"] = consumers
		}
	}
	trimEmptyAttributes(attrs)
	return attrs
}

// getCloudIdentityExportPage issues one authenticated GET against a
// VulnView machine-reader export route, scoped to source=cloud_identity.
func (s *Source) getCloudIdentityExportPage(ctx context.Context, settings settings, path string, cursor string, pageSize int) (sourcecdk.CursorFeedPage, error) {
	query := sourcecdk.CursorFeedQuery(map[string]string{"source": cloudIdentityExportSource}, pageSize, cursor)
	var page sourcecdk.CursorFeedPage
	if err := s.getJSON(ctx, settings, path, query, &page); err != nil {
		return sourcecdk.CursorFeedPage{}, err
	}
	return page, nil
}
