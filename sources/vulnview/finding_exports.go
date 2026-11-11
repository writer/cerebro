package vulnview

import (
	"context"
	"strconv"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	findingExportSourceParam = "source"
	findingMaxPageSize       = 200
)

// findingFamily reads the standardized GET /exports/findings export (Contract
// C7/C8), one runtime per VulnView finding source, with resumable cursor-feed
// checkpoints (sourcecdk.CursorFeedCheckpointPull) for ReadWithCheckpoint.
func (s *Source) findingFamily() sourcecdk.Family[settings] {
	family := familyFromLister(familyFinding, sourcecdk.CursorFeedPageToList(s.findingsPage))
	family.ReadWithCheckpoint = func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
		records, page, err := s.findingsPage(ctx, settings, sourcecdk.CursorToken(cursor), settings.perPage)
		if err != nil {
			return sourcecdk.Pull{}, wrapFamilyErr(familyFinding, err)
		}
		return sourcecdk.CursorFeedCheckpointPull(sourceID, familyFinding, records, page, checkpoint, func(rec record) (*primitives.Event, error) {
			return eventFromRecord(settings, familyFinding, rec), nil
		})
	}
	return family
}

// findingsPage pages GET /exports/findings, keeping only the highest version
// per findingId within one read (lookback replays can repeat a finding).
func (s *Source) findingsPage(ctx context.Context, settings settings, cursor string, pageSize int) ([]record, sourcecdk.CursorFeedPage, error) {
	query := sourcecdk.CursorFeedQuery(map[string]string{findingExportSourceParam: settings.source}, sourcecdk.ClampPageSize(pageSize, findingMaxPageSize), cursor)
	var page sourcecdk.CursorFeedPage
	if err := s.getJSON(ctx, settings, "/exports/findings", query, &page); err != nil {
		return nil, sourcecdk.CursorFeedPage{}, err
	}
	records := make([]record, 0, len(page.Items))
	for _, item := range page.Items {
		rec, err := recordFromRaw(familyFinding, item)
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
		findingVersionGreater,
	)
	return deduped, page, nil
}

// findingVersionGreater compares "version" numerically when possible,
// falling back to string comparison for an unparsable value.
func findingVersionGreater(candidate, existing record) bool {
	candidateVersion := firstValueString(candidate.Values, "version")
	existingVersion := firstValueString(existing.Values, "version")
	candidateNum, candidateErr := strconv.ParseInt(candidateVersion, 10, 64)
	existingNum, existingErr := strconv.ParseInt(existingVersion, 10, 64)
	if candidateErr == nil && existingErr == nil {
		return candidateNum > existingNum
	}
	return candidateVersion > existingVersion
}
