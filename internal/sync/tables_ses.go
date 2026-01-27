package sync

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// SES Identities table (email addresses and domains)
func (e *SyncEngine) sesIdentityTable() TableSpec {
	return TableSpec{
		Name: "aws_ses_identities",
		Columns: []string{
			"_cq_hash", "arn", "identity_name", "account_id", "region",
			"identity_type", "verified_for_sending_status", "dkim_attributes",
			"mail_from_attributes", "policies", "tags", "configuration_set_name",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sesv2.NewFromConfig(cfg, func(o *sesv2.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListEmailIdentities(ctx, &sesv2.ListEmailIdentitiesInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, identity := range out.EmailIdentities {
					identityName := aws.ToString(identity.IdentityName)

					// Get full details
					detail, err := client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
						EmailIdentity: aws.String(identityName),
					})
					if err != nil {
						continue
					}

					arn := fmt.Sprintf("arn:aws:ses:%s:%s:identity/%s", region, accountID, identityName)
					dkimJSON, _ := json.Marshal(detail.DkimAttributes)
					mailFromJSON, _ := json.Marshal(detail.MailFromAttributes)
					policiesJSON, _ := json.Marshal(detail.Policies)

					tags := map[string]string{}
					for _, t := range detail.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                         arn,
						"identity_name":               identityName,
						"account_id":                  accountID,
						"region":                      region,
						"identity_type":               string(detail.IdentityType),
						"verified_for_sending_status": detail.VerifiedForSendingStatus,
						"dkim_attributes":             string(dkimJSON),
						"mail_from_attributes":        string(mailFromJSON),
						"policies":                    string(policiesJSON),
						"tags":                        string(tagsJSON),
						"configuration_set_name":      aws.ToString(detail.ConfigurationSetName),
					}
					results = append(results, row)
				}

				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return results, nil
		},
	}
}

// SES Configuration Sets table
func (e *SyncEngine) sesConfigurationSetTable() TableSpec {
	return TableSpec{
		Name: "aws_ses_configuration_sets",
		Columns: []string{
			"_cq_hash", "arn", "configuration_set_name", "account_id", "region",
			"delivery_options", "reputation_options", "sending_options",
			"suppression_options", "tracking_options", "vdm_options", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := sesv2.NewFromConfig(cfg, func(o *sesv2.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListConfigurationSets(ctx, &sesv2.ListConfigurationSetsInput{
					NextToken: nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, name := range out.ConfigurationSets {
					// Get full details
					detail, err := client.GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{
						ConfigurationSetName: aws.String(name),
					})
					if err != nil {
						continue
					}

					arn := fmt.Sprintf("arn:aws:ses:%s:%s:configuration-set/%s", region, accountID, name)
					deliveryJSON, _ := json.Marshal(detail.DeliveryOptions)
					reputationJSON, _ := json.Marshal(detail.ReputationOptions)
					sendingJSON, _ := json.Marshal(detail.SendingOptions)
					suppressionJSON, _ := json.Marshal(detail.SuppressionOptions)
					trackingJSON, _ := json.Marshal(detail.TrackingOptions)
					vdmJSON, _ := json.Marshal(detail.VdmOptions)

					tags := map[string]string{}
					for _, t := range detail.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                    arn,
						"configuration_set_name": name,
						"account_id":             accountID,
						"region":                 region,
						"delivery_options":       string(deliveryJSON),
						"reputation_options":     string(reputationJSON),
						"sending_options":        string(sendingJSON),
						"suppression_options":    string(suppressionJSON),
						"tracking_options":       string(trackingJSON),
						"vdm_options":            string(vdmJSON),
						"tags":                   string(tagsJSON),
					}
					results = append(results, row)
				}

				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return results, nil
		},
	}
}
