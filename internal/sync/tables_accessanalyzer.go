package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
)

// Access Analyzer Analyzers table
func (e *SyncEngine) accessAnalyzerAnalyzerTable() TableSpec {
	return TableSpec{
		Name: "aws_accessanalyzer_analyzers",
		Columns: []string{
			"_cq_hash", "arn", "name", "account_id", "region",
			"created_at", "last_resource_analyzed", "last_resource_analyzed_at",
			"status", "status_reason", "type", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := accessanalyzer.NewFromConfig(cfg, func(o *accessanalyzer.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := accessanalyzer.NewListAnalyzersPaginator(client, &accessanalyzer.ListAnalyzersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, analyzer := range page.Analyzers {
					tagsJSON, _ := json.Marshal(analyzer.Tags)
					statusReasonJSON, _ := json.Marshal(analyzer.StatusReason)

					row := map[string]interface{}{
						"arn":                       aws.ToString(analyzer.Arn),
						"name":                      aws.ToString(analyzer.Name),
						"account_id":                accountID,
						"region":                    region,
						"created_at":                timeToString(analyzer.CreatedAt),
						"last_resource_analyzed":    aws.ToString(analyzer.LastResourceAnalyzed),
						"last_resource_analyzed_at": timeToString(analyzer.LastResourceAnalyzedAt),
						"status":                    string(analyzer.Status),
						"status_reason":             string(statusReasonJSON),
						"type":                      string(analyzer.Type),
						"tags":                      string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Access Analyzer Findings table
func (e *SyncEngine) accessAnalyzerFindingTable() TableSpec {
	return TableSpec{
		Name: "aws_accessanalyzer_findings",
		Columns: []string{
			"_cq_hash", "id", "analyzer_arn", "account_id", "region",
			"resource", "resource_owner_account", "resource_type",
			"condition", "action", "error", "is_public", "principal",
			"sources", "status", "analyzed_at", "created_at", "updated_at",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := accessanalyzer.NewFromConfig(cfg, func(o *accessanalyzer.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all analyzers
			analyzersPaginator := accessanalyzer.NewListAnalyzersPaginator(client, &accessanalyzer.ListAnalyzersInput{})
			for analyzersPaginator.HasMorePages() {
				analyzersPage, err := analyzersPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, analyzer := range analyzersPage.Analyzers {
					// Get findings for this analyzer
					findingsPaginator := accessanalyzer.NewListFindingsPaginator(client, &accessanalyzer.ListFindingsInput{
						AnalyzerArn: analyzer.Arn,
					})

					for findingsPaginator.HasMorePages() {
						findingsPage, err := findingsPaginator.NextPage(ctx)
						if err != nil {
							break
						}

						for _, finding := range findingsPage.Findings {
							conditionJSON, _ := json.Marshal(finding.Condition)
							actionJSON, _ := json.Marshal(finding.Action)
							principalJSON, _ := json.Marshal(finding.Principal)
							sourcesJSON, _ := json.Marshal(finding.Sources)

							row := map[string]interface{}{
								"id":                     aws.ToString(finding.Id),
								"analyzer_arn":           aws.ToString(analyzer.Arn),
								"account_id":             accountID,
								"region":                 region,
								"resource":               aws.ToString(finding.Resource),
								"resource_owner_account": aws.ToString(finding.ResourceOwnerAccount),
								"resource_type":          string(finding.ResourceType),
								"condition":              string(conditionJSON),
								"action":                 string(actionJSON),
								"error":                  aws.ToString(finding.Error),
								"is_public":              finding.IsPublic,
								"principal":              string(principalJSON),
								"sources":                string(sourcesJSON),
								"status":                 string(finding.Status),
								"analyzed_at":            timeToString(finding.AnalyzedAt),
								"created_at":             timeToString(finding.CreatedAt),
								"updated_at":             timeToString(finding.UpdatedAt),
							}
							results = append(results, row)
						}
					}
				}
			}
			return results, nil
		},
	}
}
