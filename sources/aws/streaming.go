package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsKinesisStream struct {
	Summary kinesistypes.StreamDescriptionSummary
	Tags    map[string]string
	Policy  string
}

type awsFirehoseDeliveryStream struct {
	Description firehosetypes.DeliveryStreamDescription
	Tags        map[string]string
}

type awsMSKCluster struct {
	Cluster kafkatypes.Cluster
	Tags    map[string]string
}

func listKinesisStreams(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsKinesisStream, string, error) {
	out, err := clients.kinesis.ListStreams(ctx, &kinesis.ListStreamsInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsKinesisStream, 0, len(out.StreamNames))
	for _, name := range out.StreamNames {
		describe, err := clients.kinesis.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamName: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe kinesis stream %q: %w", name, err)
		}
		if describe.StreamDescriptionSummary == nil {
			continue
		}
		record := awsKinesisStream{Summary: *describe.StreamDescriptionSummary}
		record.Tags, err = listKinesisStreamTags(ctx, clients.kinesis, name)
		if err != nil {
			return nil, "", err
		}
		if arn := awssdk.ToString(record.Summary.StreamARN); arn != "" {
			policy, err := clients.kinesis.GetResourcePolicy(ctx, &kinesis.GetResourcePolicyInput{ResourceARN: awssdk.String(arn)})
			if err == nil {
				record.Policy = awssdk.ToString(policy.Policy)
			} else if !optionalAWSError(err, "ResourceNotFoundException", "AccessDeniedException") {
				return nil, "", fmt.Errorf("get kinesis stream policy %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listFirehoseDeliveryStreams(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsFirehoseDeliveryStream, string, error) {
	out, err := clients.firehose.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{
		ExclusiveStartDeliveryStreamName: stringPtr(cursor),
		Limit:                            awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsFirehoseDeliveryStream, 0, len(out.DeliveryStreamNames))
	for _, name := range out.DeliveryStreamNames {
		describe, err := clients.firehose.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe firehose delivery stream %q: %w", name, err)
		}
		if describe.DeliveryStreamDescription == nil {
			continue
		}
		record := awsFirehoseDeliveryStream{Description: *describe.DeliveryStreamDescription}
		record.Tags, err = listFirehoseDeliveryStreamTags(ctx, clients.firehose, name)
		if err != nil {
			return nil, "", err
		}
		records = append(records, record)
	}
	next := ""
	if awssdk.ToBool(out.HasMoreDeliveryStreams) && len(out.DeliveryStreamNames) != 0 {
		next = out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1]
	}
	return records, next, nil
}

func listMSKClusters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsMSKCluster, string, error) {
	out, err := clients.kafka.ListClustersV2(ctx, &kafka.ListClustersV2Input{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsMSKCluster, 0, len(out.ClusterInfoList))
	for _, summary := range out.ClusterInfoList {
		arn := awssdk.ToString(summary.ClusterArn)
		if arn == "" {
			continue
		}
		describe, err := clients.kafka.DescribeClusterV2(ctx, &kafka.DescribeClusterV2Input{ClusterArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe msk cluster %q: %w", arn, err)
		}
		if describe.ClusterInfo == nil {
			continue
		}
		record := awsMSKCluster{Cluster: *describe.ClusterInfo, Tags: describe.ClusterInfo.Tags}
		if tags, err := clients.kafka.ListTagsForResource(ctx, &kafka.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = mergeStringMaps(record.Tags, tags.Tags)
		} else if !optionalAWSError(err, "NotFoundException", "BadRequestException") {
			return nil, "", fmt.Errorf("list msk cluster tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func kinesisStreamEvent(settings settings, record awsKinesisStream) (*primitives.Event, error) {
	stream := record.Summary
	arn := awssdk.ToString(stream.StreamARN)
	name := awssdk.ToString(stream.StreamName)
	public := policyAllowsWildcardPrincipal(record.Policy)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyKinesisStream, firstNonEmpty(arn, name), name, "kinesis_stream", record.Tags)
	attributes["arn"] = arn
	attributes["stream_arn"] = arn
	attributes["stream_name"] = name
	attributes["state"] = string(stream.StreamStatus)
	attributes["encryption"] = string(stream.EncryptionType)
	attributes["kms_key_id"] = awssdk.ToString(stream.KeyId)
	attributes["retention_hours"] = int32AttrString(stream.RetentionPeriodHours)
	attributes["retention_days"] = retentionDaysString(stream.RetentionPeriodHours)
	attributes["open_shard_count"] = int32AttrString(stream.OpenShardCount)
	attributes["consumer_count"] = int32AttrString(stream.ConsumerCount)
	attributes["stream_mode"] = kinesisStreamMode(stream.StreamModeDetails)
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "stream": stream, "policy": record.Policy, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-kinesis-stream-"+firstNonEmpty(arn, name), "aws.kinesis_stream", "aws/kinesis_stream/v1", payload, attributes, firstTime(stream.StreamCreationTimestamp))
}

func firehoseDeliveryStreamEvent(settings settings, record awsFirehoseDeliveryStream) (*primitives.Event, error) {
	stream := record.Description
	arn := awssdk.ToString(stream.DeliveryStreamARN)
	name := awssdk.ToString(stream.DeliveryStreamName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyFirehoseStream, firstNonEmpty(arn, name), name, "firehose_delivery_stream", record.Tags)
	attributes["arn"] = arn
	attributes["delivery_stream_arn"] = arn
	attributes["delivery_stream_name"] = name
	attributes["state"] = string(stream.DeliveryStreamStatus)
	attributes["delivery_stream_type"] = string(stream.DeliveryStreamType)
	attributes["source_kinesis_stream_arn"] = firehoseSourceKinesisARN(stream.Source)
	attributes["source_msk_cluster_arn"] = firehoseSourceMSKClusterARN(stream.Source)
	attributes["source_msk_topic"] = firehoseSourceMSKTopic(stream.Source)
	attributes["destination_types"] = strings.Join(firehoseDestinationTypes(stream.Destinations), ",")
	attributes["destination_bucket_arns"] = strings.Join(firehoseDestinationBucketARNs(stream.Destinations), ",")
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = attributes["public"]
	attributes["retention_hours"] = "24"
	if stream.DeliveryStreamEncryptionConfiguration != nil {
		attributes["encryption"] = string(stream.DeliveryStreamEncryptionConfiguration.Status)
		attributes["encryption_key_type"] = string(stream.DeliveryStreamEncryptionConfiguration.KeyType)
		attributes["kms_key_id"] = awssdk.ToString(stream.DeliveryStreamEncryptionConfiguration.KeyARN)
	} else {
		attributes["encryption"] = "DISABLED"
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "delivery_stream": stream, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-firehose-delivery-stream-"+firstNonEmpty(arn, name), "aws.firehose_delivery_stream", "aws/firehose_delivery_stream/v1", payload, attributes, firstTime(stream.CreateTimestamp))
}

func mskClusterEvent(settings settings, record awsMSKCluster) (*primitives.Event, error) {
	cluster := record.Cluster
	arn := awssdk.ToString(cluster.ClusterArn)
	name := awssdk.ToString(cluster.ClusterName)
	public := mskClusterPublic(cluster)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyMSKCluster, firstNonEmpty(arn, name), name, "msk_cluster", record.Tags)
	attributes["arn"] = arn
	attributes["cluster_arn"] = arn
	attributes["cluster_name"] = name
	attributes["cluster_type"] = string(cluster.ClusterType)
	attributes["state"] = string(cluster.State)
	attributes["current_version"] = awssdk.ToString(cluster.CurrentVersion)
	attributes["broker_count"] = int32AttrString(mskBrokerCount(cluster))
	attributes["broker_instance_type"] = mskBrokerInstanceType(cluster)
	attributes["kafka_version"] = mskKafkaVersion(cluster)
	attributes["subnet_ids"] = strings.Join(mskSubnetIDs(cluster), ",")
	attributes["security_group_ids"] = strings.Join(mskSecurityGroupIDs(cluster), ",")
	attributes["encryption"] = boolString(mskClusterEncrypted(cluster))
	attributes["kms_key_id"] = mskKMSKeyID(cluster)
	attributes["encryption_in_transit_client_broker"] = mskClientBrokerEncryption(cluster)
	attributes["encryption_in_transit_cluster"] = boolString(mskInClusterEncryption(cluster))
	attributes["public"] = boolString(public)
	attributes["internet_exposed"] = attributes["public"]
	attributes["retention"] = "topic_configured"
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "cluster": cluster, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-msk-cluster-"+firstNonEmpty(arn, name), "aws.msk_cluster", "aws/msk_cluster/v1", payload, attributes, firstTime(cluster.CreationTime))
}

func listKinesisStreamTags(ctx context.Context, client awsKinesisAPI, streamName string) (map[string]string, error) {
	tags := map[string]string{}
	start := ""
	for {
		out, err := client.ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{
			StreamName:           awssdk.String(streamName),
			ExclusiveStartTagKey: stringPtr(start),
			Limit:                awssdk.Int32(50),
		})
		if err != nil {
			return nil, fmt.Errorf("list kinesis stream tags %q: %w", streamName, err)
		}
		for _, tag := range out.Tags {
			if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
				tags[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
				start = key
			}
		}
		if !awssdk.ToBool(out.HasMoreTags) || start == "" {
			return tags, nil
		}
	}
}

func listFirehoseDeliveryStreamTags(ctx context.Context, client awsFirehoseAPI, streamName string) (map[string]string, error) {
	tags := map[string]string{}
	start := ""
	for {
		out, err := client.ListTagsForDeliveryStream(ctx, &firehose.ListTagsForDeliveryStreamInput{
			DeliveryStreamName:   awssdk.String(streamName),
			ExclusiveStartTagKey: stringPtr(start),
			Limit:                awssdk.Int32(50),
		})
		if err != nil {
			return nil, fmt.Errorf("list firehose delivery stream tags %q: %w", streamName, err)
		}
		for _, tag := range out.Tags {
			if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
				tags[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
				start = key
			}
		}
		if !awssdk.ToBool(out.HasMoreTags) || start == "" {
			return tags, nil
		}
	}
}

func kinesisStreamMode(details *kinesistypes.StreamModeDetails) string {
	if details == nil {
		return ""
	}
	return string(details.StreamMode)
}

func retentionDaysString(hours *int32) string {
	if hours == nil {
		return ""
	}
	return fmt.Sprintf("%.2f", float64(*hours)/24)
}

func firehoseSourceKinesisARN(source *firehosetypes.SourceDescription) string {
	if source == nil || source.KinesisStreamSourceDescription == nil {
		return ""
	}
	return awssdk.ToString(source.KinesisStreamSourceDescription.KinesisStreamARN)
}

func firehoseSourceMSKClusterARN(source *firehosetypes.SourceDescription) string {
	if source == nil || source.MSKSourceDescription == nil {
		return ""
	}
	return awssdk.ToString(source.MSKSourceDescription.MSKClusterARN)
}

func firehoseSourceMSKTopic(source *firehosetypes.SourceDescription) string {
	if source == nil || source.MSKSourceDescription == nil {
		return ""
	}
	return awssdk.ToString(source.MSKSourceDescription.TopicName)
}

func firehoseDestinationTypes(destinations []firehosetypes.DestinationDescription) []string {
	values := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		switch {
		case destination.ExtendedS3DestinationDescription != nil || destination.S3DestinationDescription != nil:
			values = append(values, "s3")
		case destination.RedshiftDestinationDescription != nil:
			values = append(values, "redshift")
		case destination.AmazonopensearchserviceDestinationDescription != nil || destination.ElasticsearchDestinationDescription != nil:
			values = append(values, "opensearch")
		case destination.AmazonOpenSearchServerlessDestinationDescription != nil:
			values = append(values, "opensearch_serverless")
		case destination.HttpEndpointDestinationDescription != nil:
			values = append(values, "http_endpoint")
		case destination.SplunkDestinationDescription != nil:
			values = append(values, "splunk")
		case destination.SnowflakeDestinationDescription != nil:
			values = append(values, "snowflake")
		case destination.IcebergDestinationDescription != nil:
			values = append(values, "iceberg")
		default:
			values = append(values, "unknown")
		}
	}
	return cleanStrings(values)
}

func firehoseDestinationBucketARNs(destinations []firehosetypes.DestinationDescription) []string {
	values := make([]string, 0, len(destinations))
	for _, destination := range destinations {
		if destination.ExtendedS3DestinationDescription != nil {
			values = append(values, awssdk.ToString(destination.ExtendedS3DestinationDescription.BucketARN))
		}
		if destination.S3DestinationDescription != nil {
			values = append(values, awssdk.ToString(destination.S3DestinationDescription.BucketARN))
		}
	}
	return cleanStrings(values)
}

func mskBrokerCount(cluster kafkatypes.Cluster) *int32 {
	if cluster.Provisioned != nil {
		return cluster.Provisioned.NumberOfBrokerNodes
	}
	return nil
}

func mskBrokerInstanceType(cluster kafkatypes.Cluster) string {
	if cluster.Provisioned == nil || cluster.Provisioned.BrokerNodeGroupInfo == nil {
		return ""
	}
	return awssdk.ToString(cluster.Provisioned.BrokerNodeGroupInfo.InstanceType)
}

func mskKafkaVersion(cluster kafkatypes.Cluster) string {
	if cluster.Provisioned == nil || cluster.Provisioned.CurrentBrokerSoftwareInfo == nil {
		return ""
	}
	return awssdk.ToString(cluster.Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion)
}

func mskSubnetIDs(cluster kafkatypes.Cluster) []string {
	switch {
	case cluster.Provisioned != nil && cluster.Provisioned.BrokerNodeGroupInfo != nil:
		return cleanStrings(cluster.Provisioned.BrokerNodeGroupInfo.ClientSubnets)
	case cluster.Serverless != nil:
		values := []string{}
		for _, config := range cluster.Serverless.VpcConfigs {
			values = append(values, config.SubnetIds...)
		}
		return cleanStrings(values)
	default:
		return nil
	}
}

func mskSecurityGroupIDs(cluster kafkatypes.Cluster) []string {
	switch {
	case cluster.Provisioned != nil && cluster.Provisioned.BrokerNodeGroupInfo != nil:
		return cleanStrings(cluster.Provisioned.BrokerNodeGroupInfo.SecurityGroups)
	case cluster.Serverless != nil:
		values := []string{}
		for _, config := range cluster.Serverless.VpcConfigs {
			values = append(values, config.SecurityGroupIds...)
		}
		return cleanStrings(values)
	default:
		return nil
	}
}

func mskClusterEncrypted(cluster kafkatypes.Cluster) bool {
	return mskKMSKeyID(cluster) != "" || mskInClusterEncryption(cluster) || mskClientBrokerEncryption(cluster) != ""
}

func mskKMSKeyID(cluster kafkatypes.Cluster) string {
	if cluster.Provisioned == nil || cluster.Provisioned.EncryptionInfo == nil || cluster.Provisioned.EncryptionInfo.EncryptionAtRest == nil {
		return ""
	}
	return awssdk.ToString(cluster.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId)
}

func mskClientBrokerEncryption(cluster kafkatypes.Cluster) string {
	if cluster.Provisioned == nil || cluster.Provisioned.EncryptionInfo == nil || cluster.Provisioned.EncryptionInfo.EncryptionInTransit == nil {
		return ""
	}
	return string(cluster.Provisioned.EncryptionInfo.EncryptionInTransit.ClientBroker)
}

func mskInClusterEncryption(cluster kafkatypes.Cluster) bool {
	if cluster.Provisioned == nil || cluster.Provisioned.EncryptionInfo == nil || cluster.Provisioned.EncryptionInfo.EncryptionInTransit == nil {
		return false
	}
	return awssdk.ToBool(cluster.Provisioned.EncryptionInfo.EncryptionInTransit.InCluster)
}

func mskClusterPublic(cluster kafkatypes.Cluster) bool {
	if cluster.Provisioned == nil || cluster.Provisioned.BrokerNodeGroupInfo == nil || cluster.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo == nil || cluster.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess == nil {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(awssdk.ToString(cluster.Provisioned.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type)), "DISABLED")
}

func mergeStringMaps(values ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, value := range values {
		for key, item := range value {
			if strings.TrimSpace(key) != "" {
				merged[key] = strings.TrimSpace(item)
			}
		}
	}
	return merged
}
