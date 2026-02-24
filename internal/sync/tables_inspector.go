package sync

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

const inspectorIncrementalLookback = 5 * time.Minute

// Inspector Findings table
func (e *SyncEngine) inspectorFindingTable() TableSpec {
	table := TableSpec{
		Name: "aws_inspector2_findings",
		Columns: []string{
			"_cq_hash", "arn", "finding_arn", "account_id", "region",
			"aws_account_id", "description", "exploit_available", "exploitability_details",
			"finding_account_id", "first_observed_at", "fix_available",
			"inspector_score", "inspector_score_details", "last_observed_at",
			"network_reachability_details", "package_vulnerability_details",
			"remediation", "resources", "severity", "status", "title", "type",
			"updated_at",
		},
		Mode:                TableSyncModeIncremental,
		IncrementalLookback: inspectorIncrementalLookback,
	}

	table.Fetch = func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
		client := inspector2.NewFromConfig(cfg, func(o *inspector2.Options) {
			o.Region = region
		})
		accountID := e.getAccountIDFromConfig(ctx, cfg)
		var results []map[string]interface{}

		filterCriteria := &types.FilterCriteria{
			FindingStatus: []types.StringFilter{
				{
					Comparison: types.StringComparisonEquals,
					Value:      aws.String("ACTIVE"),
				},
			},
		}
		if start, ok := e.incrementalStartTime(ctx, table.Name, region, true, table.IncrementalLookback); ok {
			startTime := start
			filterCriteria.UpdatedAt = []types.DateFilter{
				{StartInclusive: &startTime},
			}
			e.logger.Info("inspector findings incremental sync", "region", region, "start", start.Format(time.RFC3339))
		}

		paginator := inspector2.NewListFindingsPaginator(client, &inspector2.ListFindingsInput{
			FilterCriteria: filterCriteria,
			MaxResults:     aws.Int32(100),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				if len(results) > 0 {
					return results, newPartialFetchError(err)
				}
				return nil, err
			}

			for _, finding := range page.Findings {
				exploitJSON, _ := json.Marshal(finding.ExploitabilityDetails)
				scoreDetailsJSON, _ := json.Marshal(finding.InspectorScoreDetails)
				networkJSON, _ := json.Marshal(finding.NetworkReachabilityDetails)
				vulnJSON, _ := json.Marshal(finding.PackageVulnerabilityDetails)
				remediationJSON, _ := json.Marshal(finding.Remediation)
				resourcesJSON, _ := json.Marshal(finding.Resources)

				row := map[string]interface{}{
					"arn":                           aws.ToString(finding.FindingArn),
					"finding_arn":                   aws.ToString(finding.FindingArn),
					"account_id":                    accountID,
					"region":                        region,
					"aws_account_id":                aws.ToString(finding.AwsAccountId),
					"description":                   aws.ToString(finding.Description),
					"exploit_available":             string(finding.ExploitAvailable),
					"exploitability_details":        string(exploitJSON),
					"finding_account_id":            accountID,
					"first_observed_at":             timeToString(finding.FirstObservedAt),
					"fix_available":                 string(finding.FixAvailable),
					"inspector_score":               finding.InspectorScore,
					"inspector_score_details":       string(scoreDetailsJSON),
					"last_observed_at":              timeToString(finding.LastObservedAt),
					"network_reachability_details":  string(networkJSON),
					"package_vulnerability_details": string(vulnJSON),
					"remediation":                   string(remediationJSON),
					"resources":                     string(resourcesJSON),
					"severity":                      string(finding.Severity),
					"status":                        string(finding.Status),
					"title":                         aws.ToString(finding.Title),
					"type":                          string(finding.Type),
					"updated_at":                    timeToString(finding.UpdatedAt),
				}
				results = append(results, row)
			}
		}
		return results, nil
	}

	return table
}

// Inspector Coverage table
func (e *SyncEngine) inspectorCoverageTable() TableSpec {
	return TableSpec{
		Name: "aws_inspector2_coverage",
		Columns: []string{
			"_cq_hash", "account_id", "region", "resource_id", "resource_type",
			"scan_status", "scan_status_reason", "scan_type",
			"ec2_instance_id", "ec2_platform", "ec2_ami_id",
			"ecr_repository_name", "ecr_image_digest", "lambda_function_name",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := inspector2.NewFromConfig(cfg, func(o *inspector2.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := inspector2.NewListCoveragePaginator(client, &inspector2.ListCoverageInput{
				MaxResults: aws.Int32(200),
			})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, cov := range page.CoveredResources {
					row := map[string]interface{}{
						"account_id":           accountID,
						"region":               region,
						"resource_id":          aws.ToString(cov.ResourceId),
						"resource_type":        string(cov.ResourceType),
						"scan_status":          "",
						"scan_status_reason":   "",
						"scan_type":            string(cov.ScanType),
						"ec2_instance_id":      "",
						"ec2_platform":         "",
						"ec2_ami_id":           "",
						"ecr_repository_name":  "",
						"ecr_image_digest":     "",
						"lambda_function_name": "",
					}

					if cov.ScanStatus != nil {
						row["scan_status"] = string(cov.ScanStatus.StatusCode)
						row["scan_status_reason"] = string(cov.ScanStatus.Reason)
					}

					if cov.ResourceMetadata != nil {
						if cov.ResourceMetadata.Ec2 != nil {
							row["ec2_ami_id"] = aws.ToString(cov.ResourceMetadata.Ec2.AmiId)
							row["ec2_platform"] = string(cov.ResourceMetadata.Ec2.Platform)
						}
						if cov.ResourceMetadata.EcrRepository != nil {
							row["ecr_repository_name"] = aws.ToString(cov.ResourceMetadata.EcrRepository.Name)
						}
						if cov.ResourceMetadata.EcrImage != nil {
							// Use ImageHash if available
							tagsJSON, _ := json.Marshal(cov.ResourceMetadata.EcrImage.Tags)
							row["ecr_image_digest"] = string(tagsJSON)
						}
						if cov.ResourceMetadata.LambdaFunction != nil {
							row["lambda_function_name"] = aws.ToString(cov.ResourceMetadata.LambdaFunction.FunctionName)
						}
					}

					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
