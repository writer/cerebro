package sync

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// Route53 Hosted Zones table
func (e *SyncEngine) route53HostedZoneTable() TableSpec {
	return TableSpec{
		Name: "aws_route53_hosted_zones",
		Columns: []string{
			"_cq_hash", "id", "name", "account_id", "caller_reference",
			"config", "resource_record_set_count", "linked_service",
			"is_private", "comment", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := route53.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, zone := range page.HostedZones {
					zoneID := aws.ToString(zone.Id)
					zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")

					// Get tags
					tagsOut, _ := client.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{
						ResourceId:   aws.String(zoneID),
						ResourceType: types.TagResourceTypeHostedzone,
					})
					tags := map[string]string{}
					if tagsOut != nil && tagsOut.ResourceTagSet != nil {
						for _, t := range tagsOut.ResourceTagSet.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					configJSON, _ := json.Marshal(zone.Config)
					linkedJSON, _ := json.Marshal(zone.LinkedService)

					isPrivate := false
					comment := ""
					if zone.Config != nil {
						isPrivate = zone.Config.PrivateZone
						comment = aws.ToString(zone.Config.Comment)
					}

					row := map[string]interface{}{
						"id":                        zoneID,
						"name":                      aws.ToString(zone.Name),
						"account_id":                accountID,
						"caller_reference":          aws.ToString(zone.CallerReference),
						"config":                    string(configJSON),
						"resource_record_set_count": zone.ResourceRecordSetCount,
						"linked_service":            string(linkedJSON),
						"is_private":                isPrivate,
						"comment":                   comment,
						"tags":                      string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Route53 Record Sets table
func (e *SyncEngine) route53RecordSetTable() TableSpec {
	return TableSpec{
		Name: "aws_route53_record_sets",
		Columns: []string{
			"_cq_hash", "hosted_zone_id", "name", "type", "account_id",
			"ttl", "resource_records", "alias_target", "failover",
			"geo_location", "health_check_id", "multi_value_answer",
			"region", "set_identifier", "traffic_policy_instance_id", "weight",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := route53.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all hosted zones
			zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
			for zonesPaginator.HasMorePages() {
				zonesPage, err := zonesPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, zone := range zonesPage.HostedZones {
					zoneID := aws.ToString(zone.Id)
					zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")

					// Get record sets for this zone
					recordsPaginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
						HostedZoneId: aws.String(zoneID),
					})
					for recordsPaginator.HasMorePages() {
						recordsPage, err := recordsPaginator.NextPage(ctx)
						if err != nil {
							break
						}

						for _, record := range recordsPage.ResourceRecordSets {
							recordsJSON, _ := json.Marshal(record.ResourceRecords)
							aliasJSON, _ := json.Marshal(record.AliasTarget)
							geoJSON, _ := json.Marshal(record.GeoLocation)

							row := map[string]interface{}{
								"hosted_zone_id":             zoneID,
								"name":                       aws.ToString(record.Name),
								"type":                       string(record.Type),
								"account_id":                 accountID,
								"ttl":                        record.TTL,
								"resource_records":           string(recordsJSON),
								"alias_target":               string(aliasJSON),
								"failover":                   string(record.Failover),
								"geo_location":               string(geoJSON),
								"health_check_id":            aws.ToString(record.HealthCheckId),
								"multi_value_answer":         record.MultiValueAnswer,
								"region":                     string(record.Region),
								"set_identifier":             aws.ToString(record.SetIdentifier),
								"traffic_policy_instance_id": aws.ToString(record.TrafficPolicyInstanceId),
								"weight":                     record.Weight,
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

// Route53 Health Checks table
func (e *SyncEngine) route53HealthCheckTable() TableSpec {
	return TableSpec{
		Name: "aws_route53_health_checks",
		Columns: []string{
			"_cq_hash", "id", "account_id", "caller_reference",
			"health_check_config", "health_check_version", "cloud_watch_alarm_configuration",
			"linked_service", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := route53.NewFromConfig(cfg)
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := route53.NewListHealthChecksPaginator(client, &route53.ListHealthChecksInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, hc := range page.HealthChecks {
					// Get tags
					tagsOut, _ := client.ListTagsForResource(ctx, &route53.ListTagsForResourceInput{
						ResourceId:   hc.Id,
						ResourceType: types.TagResourceTypeHealthcheck,
					})
					tags := map[string]string{}
					if tagsOut != nil && tagsOut.ResourceTagSet != nil {
						for _, t := range tagsOut.ResourceTagSet.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)
					configJSON, _ := json.Marshal(hc.HealthCheckConfig)
					alarmJSON, _ := json.Marshal(hc.CloudWatchAlarmConfiguration)
					linkedJSON, _ := json.Marshal(hc.LinkedService)

					row := map[string]interface{}{
						"id":                              aws.ToString(hc.Id),
						"account_id":                      accountID,
						"caller_reference":                aws.ToString(hc.CallerReference),
						"health_check_config":             string(configJSON),
						"health_check_version":            hc.HealthCheckVersion,
						"cloud_watch_alarm_configuration": string(alarmJSON),
						"linked_service":                  string(linkedJSON),
						"tags":                            string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
