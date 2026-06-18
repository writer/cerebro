package awssecurity

import (
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macie2types "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func GuardDutyListFindingsInput(detectorID string, maxResults int32, token string, checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) *guardduty.ListFindingsInput {
	input := &guardduty.ListFindingsInput{
		DetectorId:   awssdk.String(detectorID),
		MaxResults:   awssdk.Int32(maxResults),
		NextToken:    stringPtr(token),
		SortCriteria: &guarddutytypes.SortCriteria{AttributeName: awssdk.String("updatedAt"), OrderBy: guarddutytypes.OrderByDesc},
	}
	if start, ok := checkpointStart(checkpoint, lookback); ok {
		input.FindingCriteria = &guarddutytypes.FindingCriteria{Criterion: map[string]guarddutytypes.Condition{
			"updatedAt": {GreaterThanOrEqual: awssdk.Int64(start.UnixMilli())},
		}}
	}
	return input
}

func SecurityHubGetFindingsInput(maxResults int32, token string, checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) *securityhub.GetFindingsInput {
	input := &securityhub.GetFindingsInput{
		MaxResults: awssdk.Int32(maxResults),
		NextToken:  stringPtr(token),
		SortCriteria: []securityhubtypes.SortCriterion{{
			Field:     awssdk.String("UpdatedAt"),
			SortOrder: securityhubtypes.SortOrderDescending,
		}},
	}
	if start, ok := checkpointStart(checkpoint, lookback); ok {
		input.Filters = &securityhubtypes.AwsSecurityFindingFilters{
			UpdatedAt: []securityhubtypes.DateFilter{{Start: awssdk.String(start.Format(time.RFC3339Nano))}},
		}
	}
	return input
}

func Inspector2ListFindingsInput(maxResults int32, token string, checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) *inspector2.ListFindingsInput {
	input := &inspector2.ListFindingsInput{
		MaxResults: awssdk.Int32(maxResults),
		NextToken:  stringPtr(token),
		SortCriteria: &inspector2types.SortCriteria{
			Field:     inspector2types.SortFieldLastObservedAt,
			SortOrder: inspector2types.SortOrderDesc,
		},
	}
	if start, ok := checkpointStart(checkpoint, lookback); ok {
		input.FilterCriteria = &inspector2types.FilterCriteria{
			LastObservedAt: []inspector2types.DateFilter{{StartInclusive: awssdk.Time(start)}},
		}
	}
	return input
}

func MacieListFindingsInput(maxResults int32, token string, checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) *macie2.ListFindingsInput {
	input := &macie2.ListFindingsInput{
		MaxResults:   awssdk.Int32(maxResults),
		NextToken:    stringPtr(token),
		SortCriteria: &macie2types.SortCriteria{AttributeName: awssdk.String("updatedAt"), OrderBy: macie2types.OrderByDesc},
	}
	if start, ok := checkpointStart(checkpoint, lookback); ok {
		input.FindingCriteria = &macie2types.FindingCriteria{Criterion: map[string]macie2types.CriterionAdditionalProperties{
			"updatedAt": {Gte: awssdk.Int64(start.UnixMilli())},
		}}
	}
	return input
}

func checkpointStart(checkpoint *cerebrov1.SourceCheckpoint, lookback time.Duration) (time.Time, bool) {
	if checkpoint == nil || checkpoint.GetWatermark() == nil {
		return time.Time{}, false
	}
	watermark := checkpoint.GetWatermark().AsTime().UTC()
	if watermark.IsZero() {
		return time.Time{}, false
	}
	return watermark.Add(-lookback), true
}

func stringPtr(value string) *string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return &trimmed
	}
	return nil
}
