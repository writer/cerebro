package sync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

const securityHubIncrementalLookback = 5 * time.Minute

func (e *SyncEngine) securityHubTable() TableSpec {
	return TableSpec{
		Name: "aws_securityhub_hubs",
		Columns: []string{
			"arn", "region", "account_id", "hub_arn", "subscribed_at",
			"auto_enable_controls", "control_finding_generator",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := securityhub.NewFromConfig(cfg)
			var results []map[string]interface{}

			hub, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
			if err != nil {
				// SecurityHub might not be enabled
				return results, nil
			}

			arn := ptrToStr(hub.HubArn)
			if arn == "" {
				arn = fmt.Sprintf("arn:aws:securityhub:%s:%s:hub/default", region, e.accountID)
			}

			row := map[string]interface{}{
				"_cq_id":                    arn,
				"arn":                       arn,
				"hub_arn":                   ptrToStr(hub.HubArn),
				"region":                    region,
				"account_id":                e.accountID,
				"subscribed_at":             ptrToStr(hub.SubscribedAt),
				"auto_enable_controls":      hub.AutoEnableControls,
				"control_finding_generator": string(hub.ControlFindingGenerator),
			}

			results = append(results, row)
			return results, nil
		},
	}
}

func (e *SyncEngine) securityHubFindingsTable() TableSpec {
	table := TableSpec{
		Name: "aws_securityhub_findings",
		Columns: []string{
			"arn", "id", "region", "account_id", "title", "description",
			"severity_label", "severity_normalized", "workflow_status",
			"compliance_status", "product_arn", "generator_id", "types",
			"created_at", "updated_at", "resources", "remediation",
		},
		Mode:                TableSyncModeIncremental,
		IncrementalLookback: securityHubIncrementalLookback,
	}

	table.Fetch = func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
		client := securityhub.NewFromConfig(cfg)
		var results []map[string]interface{}

		filters := &securityhubtypes.AwsSecurityFindingFilters{
			RecordState: []securityhubtypes.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: securityhubtypes.StringFilterComparisonEquals},
			},
		}

		if start, ok := e.incrementalStartTime(ctx, table.Name, region, true, table.IncrementalLookback); ok {
			filters.UpdatedAt = []securityhubtypes.DateFilter{
				{Start: aws.String(start.Format(time.RFC3339))},
			}
			e.logger.Info("securityhub findings incremental sync", "region", region, "start", start.Format(time.RFC3339))
		}

		paginator := securityhub.NewGetFindingsPaginator(client, &securityhub.GetFindingsInput{
			Filters:    filters,
			MaxResults: aws.Int32(100),
		})

		pageNum := 0
		for paginator.HasMorePages() {
			pageNum++
			var page *securityhub.GetFindingsOutput
			var err error
			for attempt := 0; attempt <= awsPageRetryMax; attempt++ {
				pageStart := time.Now()
				page, err = paginator.NextPage(ctx)
				pageDuration := time.Since(pageStart)
				if err == nil {
					logAWSPageDuration(e.logger, "securityhub", "GetFindings", pageNum, pageDuration, len(page.Findings))
					break
				}

				if !isAWSRateLimitError(err) || attempt == awsPageRetryMax {
					e.logger.Warn("failed to fetch securityhub findings", "page", pageNum, "error", err)
					if len(results) > 0 {
						return results, newPartialFetchError(err)
					}
					return nil, err
				}

				delay := awsRetryDelay(attempt)
				e.logger.Warn("aws request throttled", "service", "securityhub", "operation", "GetFindings", "page", pageNum, "attempt", attempt+1, "delay", delay, "error", err)
				if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
					return nil, sleepErr
				}
			}

			if page == nil {
				continue
			}

			for _, f := range page.Findings {
				id := ptrToStr(f.Id)
				if id == "" {
					continue
				}

				productArn := ptrToStr(f.ProductArn)
				arn := id
				if productArn != "" && !strings.HasPrefix(id, "arn:") {
					arn = fmt.Sprintf("%s/%s", productArn, id)
				}

				regionVal := ptrToStr(f.Region)
				if regionVal == "" {
					regionVal = region
				}

				accountID := ptrToStr(f.AwsAccountId)
				if accountID == "" {
					accountID = e.accountID
				}

				var severityLabel, severityNorm string
				if f.Severity != nil {
					severityLabel = string(f.Severity.Label)
					if f.Severity.Normalized != nil {
						severityNorm = fmt.Sprintf("%d", *f.Severity.Normalized)
					}
				}

				var complianceStatus string
				if f.Compliance != nil {
					complianceStatus = string(f.Compliance.Status)
				}

				var workflowStatus string
				if f.Workflow != nil {
					workflowStatus = string(f.Workflow.Status)
				}

				row := map[string]interface{}{
					"_cq_id":              arn,
					"arn":                 arn,
					"id":                  id,
					"region":              regionVal,
					"account_id":          accountID,
					"title":               ptrToStr(f.Title),
					"description":         ptrToStr(f.Description),
					"severity_label":      severityLabel,
					"severity_normalized": severityNorm,
					"workflow_status":     workflowStatus,
					"compliance_status":   complianceStatus,
					"product_arn":         productArn,
					"generator_id":        ptrToStr(f.GeneratorId),
					"types":               f.Types,
					"created_at":          ptrToStr(f.CreatedAt),
					"updated_at":          ptrToStr(f.UpdatedAt),
					"resources":           f.Resources,
					"remediation":         f.Remediation,
				}

				results = append(results, row)
			}
		}

		return results, nil
	}

	return table
}

func (e *SyncEngine) securityHubStandardsTable() TableSpec {
	return TableSpec{
		Name: "aws_securityhub_standards",
		Columns: []string{
			"arn", "standards_arn", "standards_subscription_arn", "region",
			"account_id", "standards_status", "standards_status_reason",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := securityhub.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := securityhub.NewGetEnabledStandardsPaginator(client, &securityhub.GetEnabledStandardsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					break
				}

				for _, s := range page.StandardsSubscriptions {
					arn := ptrToStr(s.StandardsSubscriptionArn)
					if arn == "" {
						continue
					}

					var statusReason string
					if s.StandardsStatusReason != nil {
						statusReason = string(s.StandardsStatusReason.StatusReasonCode)
					}

					row := map[string]interface{}{
						"_cq_id":                     arn,
						"arn":                        arn,
						"standards_arn":              ptrToStr(s.StandardsArn),
						"standards_subscription_arn": arn,
						"region":                     region,
						"account_id":                 e.accountID,
						"standards_status":           string(s.StandardsStatus),
						"standards_status_reason":    statusReason,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}
