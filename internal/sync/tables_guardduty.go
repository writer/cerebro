package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

func (e *SyncEngine) guarddutyDetectorTable() TableSpec {
	return TableSpec{
		Name: "aws_guardduty_detectors",
		Columns: []string{
			"arn", "detector_id", "region", "account_id", "created_at",
			"finding_publishing_frequency", "service_role", "status",
			"features", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := guardduty.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all detector IDs
			listOutput, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
			if err != nil {
				return nil, fmt.Errorf("list detectors: %w", err)
			}

			for _, detectorID := range listOutput.DetectorIds {
				// Get detector details
				detector, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
					DetectorId: aws.String(detectorID),
				})
				if err != nil {
					continue
				}

				arn := fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s", region, e.accountID, detectorID)
				row := map[string]interface{}{
					"_cq_id":                       arn,
					"arn":                          arn,
					"detector_id":                  detectorID,
					"region":                       region,
					"account_id":                   e.accountID,
					"created_at":                   detector.CreatedAt,
					"finding_publishing_frequency": string(detector.FindingPublishingFrequency),
					"service_role":                 ptrToStr(detector.ServiceRole),
					"status":                       string(detector.Status),
					"features":                     detector.Features,
					"tags":                         detector.Tags,
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) guarddutyFindingsTable() TableSpec {
	return TableSpec{
		Name: "aws_guardduty_findings",
		Columns: []string{
			"arn", "finding_id", "detector_id", "region", "account_id",
			"title", "description", "severity", "type", "confidence",
			"created_at", "updated_at", "resource", "service", "partition",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := guardduty.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all detector IDs
			listDetOutput, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
			if err != nil {
				return nil, fmt.Errorf("list detectors: %w", err)
			}

			for _, detectorID := range listDetOutput.DetectorIds {
				// List findings for this detector
				findingsPager := guardduty.NewListFindingsPaginator(client, &guardduty.ListFindingsInput{
					DetectorId: aws.String(detectorID),
				})

				var findingIDs []string
				for findingsPager.HasMorePages() {
					page, err := findingsPager.NextPage(ctx)
					if err != nil {
						continue
					}
					findingIDs = append(findingIDs, page.FindingIds...)
				}

				if len(findingIDs) == 0 {
					continue
				}

				// Get finding details in batches
				for i := 0; i < len(findingIDs); i += 50 {
					end := i + 50
					if end > len(findingIDs) {
						end = len(findingIDs)
					}

					findings, err := client.GetFindings(ctx, &guardduty.GetFindingsInput{
						DetectorId: aws.String(detectorID),
						FindingIds: findingIDs[i:end],
					})
					if err != nil {
						continue
					}

					for _, f := range findings.Findings {
						arn := ptrToStr(f.Arn)
						if arn == "" {
							arn = fmt.Sprintf("arn:aws:guardduty:%s:%s:detector/%s/finding/%s",
								region, ptrToStr(f.AccountId), detectorID, ptrToStr(f.Id))
						}

						row := map[string]interface{}{
							"_cq_id":      arn,
							"arn":         arn,
							"finding_id":  ptrToStr(f.Id),
							"detector_id": detectorID,
							"region":      ptrToStr(f.Region),
							"account_id":  ptrToStr(f.AccountId),
							"title":       ptrToStr(f.Title),
							"description": ptrToStr(f.Description),
							"severity":    f.Severity,
							"type":        ptrToStr(f.Type),
							"confidence":  f.Confidence,
							"created_at":  ptrToStr(f.CreatedAt),
							"updated_at":  ptrToStr(f.UpdatedAt),
							"resource":    f.Resource,
							"service":     f.Service,
							"partition":   ptrToStr(f.Partition),
						}

						results = append(results, row)
					}
				}
			}

			return results, nil
		},
	}
}

func ptrToStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
