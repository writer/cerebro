package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

func (e *SyncEngine) configRecorderTable() TableSpec {
	return TableSpec{
		Name: "aws_config_configuration_recorders",
		Columns: []string{
			"arn", "name", "region", "account_id", "role_arn",
			"recording_group", "recording_mode", "status",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := configservice.NewFromConfig(cfg)
			var results []map[string]interface{}

			recorders, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
			if err != nil {
				return nil, fmt.Errorf("describe recorders: %w", err)
			}

			// Get recorder status
			statusMap := make(map[string]*configtypes.ConfigurationRecorderStatus)
			if len(recorders.ConfigurationRecorders) > 0 {
				statusResp, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
				if err == nil {
					for i := range statusResp.ConfigurationRecordersStatus {
						s := &statusResp.ConfigurationRecordersStatus[i]
						if s.Name != nil {
							statusMap[*s.Name] = s
						}
					}
				}
			}

			for _, recorder := range recorders.ConfigurationRecorders {
				name := ptrToStr(recorder.Name)
				arn := fmt.Sprintf("arn:aws:config:%s:%s:config-recorder/%s", region, e.accountID, name)

				var status interface{}
				if s, ok := statusMap[name]; ok {
					status = map[string]interface{}{
						"recording":          s.Recording,
						"last_status":        string(s.LastStatus),
						"last_start_time":    s.LastStartTime,
						"last_stop_time":     s.LastStopTime,
						"last_error_code":    ptrToStr(s.LastErrorCode),
						"last_error_message": ptrToStr(s.LastErrorMessage),
					}
				}

				row := map[string]interface{}{
					"_cq_id":          arn,
					"arn":             arn,
					"name":            name,
					"region":          region,
					"account_id":      e.accountID,
					"role_arn":        ptrToStr(recorder.RoleARN),
					"recording_group": recorder.RecordingGroup,
					"recording_mode":  recorder.RecordingMode,
					"status":          status,
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) configRuleTable() TableSpec {
	return TableSpec{
		Name: "aws_config_rules",
		Columns: []string{
			"arn", "config_rule_name", "config_rule_id", "region", "account_id",
			"description", "scope", "source", "input_parameters",
			"maximum_execution_frequency", "config_rule_state", "compliance",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := configservice.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := configservice.NewDescribeConfigRulesPaginator(client, &configservice.DescribeConfigRulesInput{})

			pageNum := 0
			for paginator.HasMorePages() {
				pageNum++
				var page *configservice.DescribeConfigRulesOutput
				var err error
				for attempt := 0; attempt <= awsPageRetryMax; attempt++ {
					pageStart := time.Now()
					page, err = paginator.NextPage(ctx)
					pageDuration := time.Since(pageStart)
					if err == nil {
						logAWSPageDuration(e.logger, "config", "DescribeConfigRules", pageNum, pageDuration, len(page.ConfigRules))
						break
					}

					if !isAWSRateLimitError(err) || attempt == awsPageRetryMax {
						return nil, fmt.Errorf("describe config rules: %w", err)
					}

					delay := awsRetryDelay(attempt)
					e.logger.Warn("aws request throttled", "service", "config", "operation", "DescribeConfigRules", "page", pageNum, "attempt", attempt+1, "delay", delay, "error", err)
					if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
						return nil, sleepErr
					}
				}

				if page == nil {
					continue
				}

				// Get compliance status for rules
				complianceMap := make(map[string]string)
				if len(page.ConfigRules) > 0 {
					ruleNames := make([]string, 0, len(page.ConfigRules))
					for _, rule := range page.ConfigRules {
						if rule.ConfigRuleName != nil {
							ruleNames = append(ruleNames, *rule.ConfigRuleName)
						}
					}

					var complianceResp *configservice.DescribeComplianceByConfigRuleOutput
					for attempt := 0; attempt <= awsPageRetryMax; attempt++ {
						complianceStart := time.Now()
						complianceResp, err = client.DescribeComplianceByConfigRule(ctx, &configservice.DescribeComplianceByConfigRuleInput{
							ConfigRuleNames: ruleNames,
						})
						complianceDuration := time.Since(complianceStart)
						if err == nil {
							logAWSPageDuration(e.logger, "config", "DescribeComplianceByConfigRule", pageNum, complianceDuration, len(complianceResp.ComplianceByConfigRules))
							break
						}

						if !isAWSRateLimitError(err) || attempt == awsPageRetryMax {
							e.logger.Warn("failed to fetch config rule compliance", "rules", len(ruleNames), "error", err)
							break
						}

						delay := awsRetryDelay(attempt)
						e.logger.Warn("aws request throttled", "service", "config", "operation", "DescribeComplianceByConfigRule", "page", pageNum, "attempt", attempt+1, "delay", delay, "error", err)
						if sleepErr := sleepWithContext(ctx, delay); sleepErr != nil {
							return nil, sleepErr
						}
					}
					if err == nil && complianceResp != nil {
						for _, c := range complianceResp.ComplianceByConfigRules {
							if c.ConfigRuleName != nil && c.Compliance != nil {
								complianceMap[*c.ConfigRuleName] = string(c.Compliance.ComplianceType)
							}
						}
					}
				}

				for _, rule := range page.ConfigRules {
					arn := ptrToStr(rule.ConfigRuleArn)
					name := ptrToStr(rule.ConfigRuleName)

					var maxFreq string
					if rule.MaximumExecutionFrequency != "" {
						maxFreq = string(rule.MaximumExecutionFrequency)
					}

					row := map[string]interface{}{
						"_cq_id":                      arn,
						"arn":                         arn,
						"config_rule_name":            name,
						"config_rule_id":              ptrToStr(rule.ConfigRuleId),
						"region":                      region,
						"account_id":                  e.accountID,
						"description":                 ptrToStr(rule.Description),
						"scope":                       rule.Scope,
						"source":                      rule.Source,
						"input_parameters":            ptrToStr(rule.InputParameters),
						"maximum_execution_frequency": maxFreq,
						"config_rule_state":           string(rule.ConfigRuleState),
						"compliance":                  complianceMap[name],
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) configDeliveryChannelTable() TableSpec {
	return TableSpec{
		Name: "aws_config_delivery_channels",
		Columns: []string{
			"arn", "name", "region", "account_id", "s3_bucket_name",
			"s3_key_prefix", "s3_kms_key_arn", "sns_topic_arn",
			"config_snapshot_delivery_properties",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := configservice.NewFromConfig(cfg)
			var results []map[string]interface{}

			channels, err := client.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{})
			if err != nil {
				return nil, fmt.Errorf("describe delivery channels: %w", err)
			}

			for _, channel := range channels.DeliveryChannels {
				name := ptrToStr(channel.Name)
				arn := fmt.Sprintf("arn:aws:config:%s:%s:delivery-channel/%s", region, e.accountID, name)

				row := map[string]interface{}{
					"_cq_id":                              arn,
					"arn":                                 arn,
					"name":                                name,
					"region":                              region,
					"account_id":                          e.accountID,
					"s3_bucket_name":                      ptrToStr(channel.S3BucketName),
					"s3_key_prefix":                       ptrToStr(channel.S3KeyPrefix),
					"s3_kms_key_arn":                      ptrToStr(channel.S3KmsKeyArn),
					"sns_topic_arn":                       ptrToStr(channel.SnsTopicARN),
					"config_snapshot_delivery_properties": channel.ConfigSnapshotDeliveryProperties,
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) configConformancePackTable() TableSpec {
	return TableSpec{
		Name: "aws_config_conformance_packs",
		Columns: []string{
			"arn", "conformance_pack_name", "region", "account_id",
			"conformance_pack_id", "delivery_s3_bucket", "delivery_s3_key_prefix",
			"conformance_pack_input_parameters", "last_update_requested_time",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := configservice.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := configservice.NewDescribeConformancePacksPaginator(client, &configservice.DescribeConformancePacksInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					// Conformance packs might not be available
					return results, nil
				}

				for _, pack := range page.ConformancePackDetails {
					arn := ptrToStr(pack.ConformancePackArn)

					row := map[string]interface{}{
						"_cq_id":                            arn,
						"arn":                               arn,
						"conformance_pack_name":             ptrToStr(pack.ConformancePackName),
						"region":                            region,
						"account_id":                        e.accountID,
						"conformance_pack_id":               ptrToStr(pack.ConformancePackId),
						"delivery_s3_bucket":                ptrToStr(pack.DeliveryS3Bucket),
						"delivery_s3_key_prefix":            ptrToStr(pack.DeliveryS3KeyPrefix),
						"conformance_pack_input_parameters": pack.ConformancePackInputParameters,
						"last_update_requested_time":        pack.LastUpdateRequestedTime,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}
