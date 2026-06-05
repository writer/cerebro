package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	lakeformationtypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"

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

type awsGlueDatabase struct {
	Database gluetypes.Database
	Tags     map[string]string
}

type awsGlueTable struct {
	DatabaseName string
	Table        gluetypes.Table
	Tags         map[string]string
}

type awsGlueCrawler struct {
	Crawler gluetypes.Crawler
	Tags    map[string]string
}

type awsGlueJob struct {
	Job  gluetypes.Job
	Tags map[string]string
}

type awsAthenaWorkgroup struct {
	WorkGroup athenatypes.WorkGroup
	Tags      map[string]string
}

type awsAthenaDataCatalog struct {
	Catalog athenatypes.DataCatalog
	Tags    map[string]string
}

type awsLakeFormationResource struct {
	Resource lakeformationtypes.ResourceInfo
}

type awsLakeFormationLFTag struct {
	Tag lakeformationtypes.LFTagPair
}

type awsLakeFormationPermission struct {
	Permission lakeformationtypes.PrincipalResourcePermissions
}

type glueTablePageCursor struct {
	DatabaseName string `json:"database_name,omitempty"`
	TableToken   string `json:"table_token,omitempty"`
}

func listKinesisStreams(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsKinesisStream, string, error) {
	out, err := clients.kinesis.ListStreams(ctx, &kinesis.ListStreamsInput{
		NextToken: stringPtr(cursor),
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
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
		tags, err := listKinesisStreamTags(ctx, clients, awssdk.ToString(record.Summary.StreamName), awssdk.ToString(record.Summary.StreamARN))
		if err != nil {
			return nil, "", err
		}
		record.Tags = tags
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

func listKinesisStreamTags(ctx context.Context, clients awsClients, name string, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var marker string
	for {
		out, err := clients.kinesis.ListTagsForStream(ctx, &kinesis.ListTagsForStreamInput{
			ExclusiveStartTagKey: stringPtr(marker),
			Limit:                awssdk.Int32(50),
			StreamARN:            stringPtr(arn),
			StreamName:           stringPtr(name),
		})
		if err != nil {
			return nil, fmt.Errorf("list kinesis tags %q: %w", firstNonEmpty(arn, name), err)
		}
		for _, tag := range out.Tags {
			key := awssdk.ToString(tag.Key)
			if key != "" {
				tags[key] = awssdk.ToString(tag.Value)
				marker = key
			}
		}
		if !awssdk.ToBool(out.HasMoreTags) || marker == "" {
			return tags, nil
		}
	}
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
		tags, err := listFirehoseTags(ctx, clients, name)
		if err != nil {
			return nil, "", err
		}
		record.Tags = tags
		records = append(records, record)
	}
	next := ""
	if awssdk.ToBool(out.HasMoreDeliveryStreams) && len(out.DeliveryStreamNames) > 0 {
		next = out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1]
	}
	return records, next, nil
}

func listFirehoseTags(ctx context.Context, clients awsClients, name string) (map[string]string, error) {
	tags := map[string]string{}
	var marker string
	for {
		out, err := clients.firehose.ListTagsForDeliveryStream(ctx, &firehose.ListTagsForDeliveryStreamInput{
			DeliveryStreamName:   awssdk.String(name),
			ExclusiveStartTagKey: stringPtr(marker),
			Limit:                awssdk.Int32(50),
		})
		if err != nil {
			return nil, fmt.Errorf("list firehose tags %q: %w", name, err)
		}
		for _, tag := range out.Tags {
			key := awssdk.ToString(tag.Key)
			if key != "" {
				tags[key] = awssdk.ToString(tag.Value)
				marker = key
			}
		}
		if !awssdk.ToBool(out.HasMoreTags) || marker == "" {
			return tags, nil
		}
	}
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
			return nil, "", fmt.Errorf("list msk tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listGlueDatabases(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueDatabase, string, error) {
	out, err := clients.glue.GetDatabases(ctx, &glue.GetDatabasesInput{
		CatalogId:  awssdk.String(settings.accountID),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueDatabase, 0, len(out.DatabaseList))
	for _, database := range out.DatabaseList {
		record := awsGlueDatabase{Database: database}
		arn := glueDatabaseARN(settings, awssdk.ToString(database.CatalogId), awssdk.ToString(database.Name))
		if arn != "" {
			tags, err := clients.glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: awssdk.String(arn)})
			if err == nil {
				record.Tags = tags.Tags
			} else if !optionalAWSError(err, "EntityNotFoundException") {
				return nil, "", fmt.Errorf("get glue database tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listGlueTables(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueTable, string, error) {
	databases, err := listAllGlueDatabaseNames(ctx, clients, settings)
	if err != nil {
		return nil, "", err
	}
	if len(databases) == 0 {
		return nil, "", nil
	}
	state, err := decodeGlueTableCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	databaseIndex := 0
	if state.DatabaseName != "" {
		found := false
		for index, databaseName := range databases {
			if databaseName == state.DatabaseName {
				databaseIndex = index
				found = true
				break
			}
			if databaseName > state.DatabaseName {
				databaseIndex = index
				state.TableToken = ""
				found = true
				break
			}
		}
		if !found {
			return nil, "", nil
		}
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsGlueTable, 0, remaining)
	for databaseIndex < len(databases) && len(records) < remaining {
		databaseName := databases[databaseIndex]
		out, err := clients.glue.GetTables(ctx, &glue.GetTablesInput{
			CatalogId:    awssdk.String(settings.accountID),
			DatabaseName: awssdk.String(databaseName),
			MaxResults:   awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:    stringPtr(state.TableToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("get glue tables for database %q: %w", databaseName, err)
		}
		for _, table := range out.TableList {
			if awssdk.ToString(table.DatabaseName) == "" {
				table.DatabaseName = awssdk.String(databaseName)
			}
			record := awsGlueTable{DatabaseName: databaseName, Table: table}
			arn := glueTableARN(settings, firstNonEmpty(awssdk.ToString(table.CatalogId), settings.accountID), databaseName, awssdk.ToString(table.Name))
			if arn != "" {
				tags, err := clients.glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: awssdk.String(arn)})
				if err == nil {
					record.Tags = tags.Tags
				} else if !optionalAWSError(err, "EntityNotFoundException") {
					return nil, "", fmt.Errorf("get glue table tags %q: %w", arn, err)
				}
			}
			records = append(records, record)
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.DatabaseName = databaseName
			state.TableToken = awssdk.ToString(out.NextToken)
			return records, encodeGlueTableCursor(state), nil
		}
		databaseIndex++
		state.TableToken = ""
	}
	if databaseIndex < len(databases) {
		state.DatabaseName = databases[databaseIndex]
		return records, encodeGlueTableCursor(state), nil
	}
	return records, "", nil
}

func listAllGlueDatabaseNames(ctx context.Context, clients awsClients, settings settings) ([]string, error) {
	var names []string
	var token string
	for {
		out, err := clients.glue.GetDatabases(ctx, &glue.GetDatabasesInput{
			CatalogId:  awssdk.String(settings.accountID),
			MaxResults: awssdk.Int32(100),
			NextToken:  stringPtr(token),
		})
		if err != nil {
			return nil, err
		}
		for _, database := range out.DatabaseList {
			if name := awssdk.ToString(database.Name); name != "" {
				names = append(names, name)
			}
		}
		token = awssdk.ToString(out.NextToken)
		if token == "" {
			sort.Strings(names)
			return names, nil
		}
	}
}

func listGlueCrawlers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueCrawler, string, error) {
	out, err := clients.glue.ListCrawlers(ctx, &glue.ListCrawlersInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueCrawler, 0, len(out.CrawlerNames))
	for _, name := range out.CrawlerNames {
		crawler, err := clients.glue.GetCrawler(ctx, &glue.GetCrawlerInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get glue crawler %q: %w", name, err)
		}
		if crawler.Crawler == nil {
			continue
		}
		record := awsGlueCrawler{Crawler: *crawler.Crawler}
		arn := glueCrawlerARN(settings, name)
		if arn != "" {
			tags, err := clients.glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: awssdk.String(arn)})
			if err == nil {
				record.Tags = tags.Tags
			} else if !optionalAWSError(err, "EntityNotFoundException") {
				return nil, "", fmt.Errorf("get glue crawler tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listGlueJobs(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueJob, string, error) {
	out, err := clients.glue.ListJobs(ctx, &glue.ListJobsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueJob, 0, len(out.JobNames))
	for _, name := range out.JobNames {
		job, err := clients.glue.GetJob(ctx, &glue.GetJobInput{JobName: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get glue job %q: %w", name, err)
		}
		if job.Job == nil {
			continue
		}
		record := awsGlueJob{Job: *job.Job}
		arn := glueJobARN(settings, name)
		if arn != "" {
			tags, err := clients.glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: awssdk.String(arn)})
			if err == nil {
				record.Tags = tags.Tags
			} else if !optionalAWSError(err, "EntityNotFoundException") {
				return nil, "", fmt.Errorf("get glue job tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listAthenaWorkgroups(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAthenaWorkgroup, string, error) {
	out, err := clients.athena.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAthenaWorkgroup, 0, len(out.WorkGroups))
	for _, summary := range out.WorkGroups {
		name := awssdk.ToString(summary.Name)
		workgroup, err := clients.athena.GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get athena workgroup %q: %w", name, err)
		}
		if workgroup.WorkGroup == nil {
			continue
		}
		record := awsAthenaWorkgroup{WorkGroup: *workgroup.WorkGroup}
		tags, err := listAthenaTags(ctx, clients, athenaWorkgroupARN(settings, name))
		if err != nil {
			return nil, "", err
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listAthenaDataCatalogs(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAthenaDataCatalog, string, error) {
	out, err := clients.athena.ListDataCatalogs(ctx, &athena.ListDataCatalogsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 2, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAthenaDataCatalog, 0, len(out.DataCatalogsSummary))
	for _, summary := range out.DataCatalogsSummary {
		name := awssdk.ToString(summary.CatalogName)
		catalog, err := clients.athena.GetDataCatalog(ctx, &athena.GetDataCatalogInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get athena data catalog %q: %w", name, err)
		}
		if catalog.DataCatalog == nil {
			continue
		}
		record := awsAthenaDataCatalog{Catalog: *catalog.DataCatalog}
		tags, err := listAthenaTags(ctx, clients, athenaDataCatalogARN(settings, name))
		if err != nil {
			return nil, "", err
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listAthenaTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var token string
	for arn != "" {
		out, err := clients.athena.ListTagsForResource(ctx, &athena.ListTagsForResourceInput{
			ResourceARN: awssdk.String(arn),
			MaxResults:  awssdk.Int32(75),
			NextToken:   stringPtr(token),
		})
		if err != nil {
			return nil, fmt.Errorf("list athena tags %q: %w", arn, err)
		}
		for _, tag := range out.Tags {
			if key := awssdk.ToString(tag.Key); key != "" {
				tags[key] = awssdk.ToString(tag.Value)
			}
		}
		token = awssdk.ToString(out.NextToken)
		if token == "" {
			return tags, nil
		}
	}
	return tags, nil
}

func listLakeFormationResources(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsLakeFormationResource, string, error) {
	out, err := clients.lake.ListResources(ctx, &lakeformation.ListResourcesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsLakeFormationResource, 0, len(out.ResourceInfoList))
	for _, resource := range out.ResourceInfoList {
		records = append(records, awsLakeFormationResource{Resource: resource})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listLakeFormationLFTags(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsLakeFormationLFTag, string, error) {
	out, err := clients.lake.ListLFTags(ctx, &lakeformation.ListLFTagsInput{
		CatalogId:  awssdk.String(settings.accountID),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsLakeFormationLFTag, 0, len(out.LFTags))
	for _, tag := range out.LFTags {
		records = append(records, awsLakeFormationLFTag{Tag: tag})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listLakeFormationPermissions(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsLakeFormationPermission, string, error) {
	out, err := clients.lake.ListPermissions(ctx, &lakeformation.ListPermissionsInput{
		CatalogId:  awssdk.String(settings.accountID),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsLakeFormationPermission, 0, len(out.PrincipalResourcePermissions))
	for _, permission := range out.PrincipalResourcePermissions {
		records = append(records, awsLakeFormationPermission{Permission: permission})
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
	attributes := commonCloudAssetAttributes(settings, settings.region, familyFirehoseDelivery, firstNonEmpty(arn, name), name, "firehose_delivery_stream", record.Tags)
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
		encryption := stream.DeliveryStreamEncryptionConfiguration
		attributes["encryption"] = string(encryption.Status)
		attributes["encryption_key_type"] = string(encryption.KeyType)
		attributes["kms_key_id"] = awssdk.ToString(encryption.KeyARN)
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

func glueDatabaseEvent(settings settings, record awsGlueDatabase) (*primitives.Event, error) {
	database := record.Database
	catalogID := firstNonEmpty(awssdk.ToString(database.CatalogId), settings.accountID)
	name := awssdk.ToString(database.Name)
	arn := glueDatabaseARN(settings, catalogID, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueDatabase, firstNonEmpty(arn, name), name, "glue_database", record.Tags)
	attributes["arn"] = arn
	attributes["catalog_id"] = catalogID
	attributes["database_name"] = name
	attributes["description"] = awssdk.ToString(database.Description)
	attributes["location_uri"] = awssdk.ToString(database.LocationUri)
	if database.TargetDatabase != nil {
		attributes["target_catalog_id"] = awssdk.ToString(database.TargetDatabase.CatalogId)
		attributes["target_database_name"] = awssdk.ToString(database.TargetDatabase.DatabaseName)
	}
	addTimeAttribute(attributes, "created_at", database.CreateTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "database": database, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-glue-database-"+firstNonEmpty(arn, name), "aws.glue_database", "aws/glue_database/v1", payload, attributes, firstTime(database.CreateTime))
}

func glueTableEvent(settings settings, record awsGlueTable) (*primitives.Event, error) {
	table := record.Table
	databaseName := firstNonEmpty(record.DatabaseName, awssdk.ToString(table.DatabaseName))
	catalogID := firstNonEmpty(awssdk.ToString(table.CatalogId), settings.accountID)
	name := awssdk.ToString(table.Name)
	arn := glueTableARN(settings, catalogID, databaseName, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueTable, firstNonEmpty(arn, glueTableResourceID(settings, record)), name, "glue_table", record.Tags)
	attributes["arn"] = arn
	attributes["catalog_id"] = catalogID
	attributes["created_by"] = awssdk.ToString(table.CreatedBy)
	attributes["database_name"] = databaseName
	attributes["description"] = awssdk.ToString(table.Description)
	attributes["is_materialized_view"] = boolString(awssdk.ToBool(table.IsMaterializedView))
	attributes["is_registered_with_lakeformation"] = boolString(table.IsRegisteredWithLakeFormation)
	attributes["table_name"] = name
	attributes["table_type"] = awssdk.ToString(table.TableType)
	attributes["owner"] = firstNonEmpty(tagLookup(record.Tags, "owner", "application_owner", "business_owner", "service_owner"), awssdk.ToString(table.Owner))
	attributes["registered_with_lakeformation"] = boolString(table.IsRegisteredWithLakeFormation)
	attributes["partition_key_count"] = strconv.Itoa(len(table.PartitionKeys))
	attributes["retention_days"] = strconv.FormatInt(int64(table.Retention), 10)
	attributes["version_id"] = awssdk.ToString(table.VersionId)
	if table.StorageDescriptor != nil {
		attributes["location"] = awssdk.ToString(table.StorageDescriptor.Location)
		attributes["location_uri"] = awssdk.ToString(table.StorageDescriptor.Location)
		attributes["input_format"] = awssdk.ToString(table.StorageDescriptor.InputFormat)
		attributes["output_format"] = awssdk.ToString(table.StorageDescriptor.OutputFormat)
		attributes["compressed"] = boolString(table.StorageDescriptor.Compressed)
		attributes["column_count"] = strconv.Itoa(len(table.StorageDescriptor.Columns))
		if table.StorageDescriptor.SerdeInfo != nil {
			attributes["serde_library"] = awssdk.ToString(table.StorageDescriptor.SerdeInfo.SerializationLibrary)
		}
	}
	if table.TargetTable != nil {
		attributes["target_catalog_id"] = awssdk.ToString(table.TargetTable.CatalogId)
		attributes["target_database_name"] = awssdk.ToString(table.TargetTable.DatabaseName)
		attributes["target_table_name"] = awssdk.ToString(table.TargetTable.Name)
	}
	addTimeAttribute(attributes, "created_at", table.CreateTime)
	addTimeAttribute(attributes, "updated_at", table.UpdateTime)
	addTimeAttribute(attributes, "last_accessed_at", table.LastAccessTime)
	addTimeAttribute(attributes, "last_analyzed_at", table.LastAnalyzedTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "database_name": databaseName, "table": table, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-glue-table-"+firstNonEmpty(arn, databaseName+"-"+name), "aws.glue_table", "aws/glue_table/v1", payload, attributes, firstTime(table.UpdateTime, table.CreateTime))
}

func glueCrawlerEvent(settings settings, record awsGlueCrawler) (*primitives.Event, error) {
	crawler := record.Crawler
	name := awssdk.ToString(crawler.Name)
	arn := glueCrawlerARN(settings, name)
	roleARN := awssdk.ToString(crawler.Role)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueCrawler, firstNonEmpty(arn, name), name, "glue_crawler", record.Tags)
	attributes["arn"] = arn
	attributes["crawler_name"] = name
	attributes["database_name"] = awssdk.ToString(crawler.DatabaseName)
	attributes["description"] = awssdk.ToString(crawler.Description)
	attributes["lineage"] = glueCrawlerLineage(crawler)
	attributes["recrawl_behavior"] = glueCrawlerRecrawlBehavior(crawler)
	attributes["relationship"] = "runs_as"
	attributes["state"] = string(crawler.State)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["schedule"] = glueCrawlerSchedule(crawler)
	attributes["security_configuration"] = awssdk.ToString(crawler.CrawlerSecurityConfiguration)
	attributes["table_prefix"] = awssdk.ToString(crawler.TablePrefix)
	attributes["target_count"] = strconv.Itoa(glueCrawlerTargetCount(crawler.Targets))
	attributes["version"] = strconv.FormatInt(crawler.Version, 10)
	if crawler.LakeFormationConfiguration != nil {
		attributes["lakeformation_credentials"] = boolString(awssdk.ToBool(crawler.LakeFormationConfiguration.UseLakeFormationCredentials))
		attributes["lakeformation_account_id"] = awssdk.ToString(crawler.LakeFormationConfiguration.AccountId)
	}
	if crawler.LastCrawl != nil {
		attributes["last_crawl_status"] = string(crawler.LastCrawl.Status)
		attributes["last_crawl_error"] = awssdk.ToString(crawler.LastCrawl.ErrorMessage)
		addTimeAttribute(attributes, "last_crawl_started_at", crawler.LastCrawl.StartTime)
	}
	addTimeAttribute(attributes, "created_at", crawler.CreationTime)
	addTimeAttribute(attributes, "updated_at", crawler.LastUpdated)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "crawler": crawler, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-glue-crawler-"+firstNonEmpty(arn, name), "aws.glue_crawler", "aws/glue_crawler/v1", payload, attributes, firstTime(crawler.LastUpdated, crawler.CreationTime))
}

func glueJobEvent(settings settings, record awsGlueJob) (*primitives.Event, error) {
	job := record.Job
	name := awssdk.ToString(job.Name)
	arn := glueJobARN(settings, name)
	roleARN := awssdk.ToString(job.Role)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueJob, firstNonEmpty(arn, name), name, "glue_job", record.Tags)
	attributes["arn"] = arn
	if job.MaxCapacity != nil {
		attributes["allocated_capacity"] = strconv.FormatFloat(awssdk.ToFloat64(job.MaxCapacity), 'f', -1, 64)
	}
	attributes["command_name"] = glueJobCommandName(job)
	attributes["description"] = awssdk.ToString(job.Description)
	attributes["execution_class"] = string(job.ExecutionClass)
	attributes["glue_version"] = awssdk.ToString(job.GlueVersion)
	attributes["job_mode"] = string(job.JobMode)
	attributes["job_name"] = name
	attributes["max_retries"] = strconv.FormatInt(int64(job.MaxRetries), 10)
	attributes["profile_name"] = awssdk.ToString(job.ProfileName)
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["script_location"] = glueJobScriptLocation(job)
	attributes["security_configuration"] = awssdk.ToString(job.SecurityConfiguration)
	attributes["worker_type"] = string(job.WorkerType)
	if job.ExecutionProperty != nil {
		attributes["max_concurrent_runs"] = strconv.FormatInt(int64(job.ExecutionProperty.MaxConcurrentRuns), 10)
	}
	if job.MaxCapacity != nil {
		attributes["max_capacity"] = strconv.FormatFloat(awssdk.ToFloat64(job.MaxCapacity), 'f', -1, 64)
	}
	if job.NumberOfWorkers != nil {
		attributes["number_of_workers"] = int32AttrString(job.NumberOfWorkers)
	}
	if job.Timeout != nil {
		attributes["timeout_minutes"] = int32AttrString(job.Timeout)
	}
	addTimeAttribute(attributes, "created_at", job.CreatedOn)
	addTimeAttribute(attributes, "updated_at", job.LastModifiedOn)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "job": job, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-glue-job-"+firstNonEmpty(arn, name), "aws.glue_job", "aws/glue_job/v1", payload, attributes, firstTime(job.LastModifiedOn, job.CreatedOn))
}

func athenaWorkgroupEvent(settings settings, record awsAthenaWorkgroup) (*primitives.Event, error) {
	workgroup := record.WorkGroup
	name := awssdk.ToString(workgroup.Name)
	arn := athenaWorkgroupARN(settings, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAthenaWorkgroup, firstNonEmpty(arn, name), name, "athena_workgroup", record.Tags)
	attributes["arn"] = arn
	attributes["description"] = awssdk.ToString(workgroup.Description)
	attributes["workgroup_name"] = name
	attributes["state"] = string(workgroup.State)
	attributes["identity_center_application_arn"] = awssdk.ToString(workgroup.IdentityCenterApplicationArn)
	if workgroup.Configuration != nil {
		config := workgroup.Configuration
		attributes["bytes_scanned_cutoff_per_query"] = int64AttrString(config.BytesScannedCutoffPerQuery)
		attributes["enforce_workgroup_configuration"] = boolString(awssdk.ToBool(config.EnforceWorkGroupConfiguration))
		attributes["minimum_encryption_enabled"] = boolString(awssdk.ToBool(config.EnableMinimumEncryptionConfiguration))
		attributes["publish_cloudwatch_metrics_enabled"] = boolString(awssdk.ToBool(config.PublishCloudWatchMetricsEnabled))
		attributes["cloudwatch_metrics_enabled"] = attributes["publish_cloudwatch_metrics_enabled"]
		attributes["requester_pays_enabled"] = boolString(awssdk.ToBool(config.RequesterPaysEnabled))
		attributes["role_arn"] = awssdk.ToString(config.ExecutionRole)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(config.ExecutionRole))
		attributes["execution_role_arn"] = attributes["role_arn"]
		if config.ResultConfiguration != nil {
			attributes["result_output_location"] = athenaResultOutputLocation(config.ResultConfiguration)
			attributes["output_location"] = attributes["result_output_location"]
			attributes["expected_bucket_owner"] = awssdk.ToString(config.ResultConfiguration.ExpectedBucketOwner)
			if config.ResultConfiguration.EncryptionConfiguration != nil {
				encryption := config.ResultConfiguration.EncryptionConfiguration
				attributes["encryption"] = string(encryption.EncryptionOption)
				attributes["encryption_type"] = string(encryption.EncryptionOption)
				attributes["kms_key_id"] = awssdk.ToString(encryption.KmsKey)
			}
		}
	}
	addTimeAttribute(attributes, "created_at", workgroup.CreationTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "workgroup": workgroup, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-athena-workgroup-"+firstNonEmpty(arn, name), "aws.athena_workgroup", "aws/athena_workgroup/v1", payload, attributes, firstTime(workgroup.CreationTime))
}

func athenaDataCatalogEvent(settings settings, record awsAthenaDataCatalog) (*primitives.Event, error) {
	catalog := record.Catalog
	name := awssdk.ToString(catalog.Name)
	arn := athenaDataCatalogARN(settings, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAthenaDataCatalog, firstNonEmpty(arn, name), name, "athena_data_catalog", record.Tags)
	attributes["arn"] = arn
	attributes["catalog_name"] = name
	attributes["catalog_type"] = string(catalog.Type)
	attributes["connection_type"] = string(catalog.ConnectionType)
	attributes["description"] = awssdk.ToString(catalog.Description)
	attributes["error"] = awssdk.ToString(catalog.Error)
	attributes["glue_catalog_id"] = catalog.Parameters["catalog-id"]
	attributes["status"] = string(catalog.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "catalog": catalog, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-athena-data-catalog-"+firstNonEmpty(arn, name), "aws.athena_data_catalog", "aws/athena_data_catalog/v1", payload, attributes, time.Now().UTC())
}

func lakeFormationResourceEvent(settings settings, record awsLakeFormationResource) (*primitives.Event, error) {
	resource := record.Resource
	arn := awssdk.ToString(resource.ResourceArn)
	name := firstNonEmpty(awsResourceName(arn), arn)
	roleARN := awssdk.ToString(resource.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyLakeFormationRes, firstNonEmpty(arn, awssdk.ToString(resource.RoleArn)), name, "lakeformation_resource", nil)
	attributes["arn"] = arn
	attributes["resource_arn"] = arn
	attributes["expected_owner_account"] = awssdk.ToString(resource.ExpectedResourceOwnerAccount)
	attributes["expected_resource_owner_account"] = awssdk.ToString(resource.ExpectedResourceOwnerAccount)
	attributes["hybrid_access_enabled"] = boolString(awssdk.ToBool(resource.HybridAccessEnabled))
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["with_federation"] = boolString(awssdk.ToBool(resource.WithFederation))
	attributes["with_privileged_access"] = boolString(awssdk.ToBool(resource.WithPrivilegedAccess))
	attributes["verification_status"] = string(resource.VerificationStatus)
	addTimeAttribute(attributes, "updated_at", resource.LastModified)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "resource": resource})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-lakeformation-resource-"+firstNonEmpty(arn, awssdk.ToString(resource.RoleArn)), "aws.lakeformation_resource", "aws/lakeformation_resource/v1", payload, attributes, firstTime(resource.LastModified))
}

func lakeFormationLFTagEvent(settings settings, record awsLakeFormationLFTag) (*primitives.Event, error) {
	tag := record.Tag
	resourceID := lakeFormationLFTagResourceID(record)
	tags := map[string]string{"lf_tag_key": awssdk.ToString(tag.TagKey)}
	attributes := commonCloudAssetAttributes(settings, settings.region, familyLakeFormationLFTag, resourceID, awssdk.ToString(tag.TagKey), "lakeformation_lf_tag", tags)
	attributes["catalog_id"] = firstNonEmpty(awssdk.ToString(tag.CatalogId), settings.accountID)
	attributes["tag_key"] = awssdk.ToString(tag.TagKey)
	attributes["tag_values"] = strings.Join(cleanStrings(tag.TagValues), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "lf_tag": tag})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-lakeformation-lf-tag-"+resourceID, "aws.lakeformation_lf_tag", "aws/lakeformation_lf_tag/v1", payload, attributes, time.Now().UTC())
}

func lakeFormationPermissionEvent(settings settings, record awsLakeFormationPermission) (*primitives.Event, error) {
	permission := record.Permission
	resourceID := lakeFormationPermissionResourceID(record)
	principal := ""
	if permission.Principal != nil {
		principal = awssdk.ToString(permission.Principal.DataLakePrincipalIdentifier)
	}
	attributes := commonCloudAssetAttributes(settings, settings.region, familyLakeFormationPerm, resourceID, principal, "lakeformation_permission", nil)
	attributes["principal"] = principal
	attributes["permissions"] = lakeFormationPermissions(permission.Permissions)
	attributes["grantable_permissions"] = lakeFormationPermissions(permission.PermissionsWithGrantOption)
	attributes["resource_ref"] = lakeFormationResourceRef(permission.Resource)
	attributes["last_updated_by"] = awssdk.ToString(permission.LastUpdatedBy)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "permission": permission})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-lakeformation-permission-"+resourceID, "aws.lakeformation_permission", "aws/lakeformation_permission/v1", payload, attributes, firstTime(permission.LastUpdated))
}

func decodeGlueTableCursor(raw string) (glueTablePageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return glueTablePageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return glueTablePageCursor{}, fmt.Errorf("parse aws glue_table cursor: %w", err)
	}
	var cursor glueTablePageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return glueTablePageCursor{}, fmt.Errorf("parse aws glue_table cursor: %w", err)
	}
	return cursor, nil
}

func encodeGlueTableCursor(cursor glueTablePageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func firehoseDestinationTypes(destinations []firehosetypes.DestinationDescription) []string {
	var values []string
	for _, destination := range destinations {
		switch {
		case destination.ExtendedS3DestinationDescription != nil, destination.S3DestinationDescription != nil:
			values = append(values, "s3")
		case destination.RedshiftDestinationDescription != nil:
			values = append(values, "redshift")
		case destination.ElasticsearchDestinationDescription != nil, destination.AmazonopensearchserviceDestinationDescription != nil:
			values = append(values, "opensearch")
		case destination.AmazonOpenSearchServerlessDestinationDescription != nil:
			values = append(values, "opensearch_serverless")
		case destination.HttpEndpointDestinationDescription != nil:
			values = append(values, "http_endpoint")
		case destination.IcebergDestinationDescription != nil:
			values = append(values, "iceberg")
		case destination.SnowflakeDestinationDescription != nil:
			values = append(values, "snowflake")
		case destination.SplunkDestinationDescription != nil:
			values = append(values, "splunk")
		default:
			values = append(values, "unknown")
		}
	}
	return cleanStrings(values)
}

func glueCrawlerTargetCount(targets *gluetypes.CrawlerTargets) int {
	if targets == nil {
		return 0
	}
	return len(targets.CatalogTargets) + len(targets.DeltaTargets) + len(targets.DynamoDBTargets) + len(targets.HudiTargets) + len(targets.IcebergTargets) + len(targets.JdbcTargets) + len(targets.MongoDBTargets) + len(targets.S3Targets)
}

func glueCrawlerLineage(crawler gluetypes.Crawler) string {
	if crawler.LineageConfiguration == nil {
		return ""
	}
	return string(crawler.LineageConfiguration.CrawlerLineageSettings)
}

func glueCrawlerRecrawlBehavior(crawler gluetypes.Crawler) string {
	if crawler.RecrawlPolicy == nil {
		return ""
	}
	return string(crawler.RecrawlPolicy.RecrawlBehavior)
}

func glueCrawlerSchedule(crawler gluetypes.Crawler) string {
	if crawler.Schedule == nil {
		return ""
	}
	return awssdk.ToString(crawler.Schedule.ScheduleExpression)
}

func glueJobCommandName(job gluetypes.Job) string {
	if job.Command == nil {
		return ""
	}
	return awssdk.ToString(job.Command.Name)
}

func glueJobScriptLocation(job gluetypes.Job) string {
	if job.Command == nil {
		return ""
	}
	return awssdk.ToString(job.Command.ScriptLocation)
}

func athenaResultOutputLocation(config *athenatypes.ResultConfiguration) string {
	if config == nil {
		return ""
	}
	return awssdk.ToString(config.OutputLocation)
}

func kinesisStreamMode(details *kinesistypes.StreamModeDetails) string {
	if details == nil {
		return ""
	}
	return string(details.StreamMode)
}

func retentionDaysString(hours *int32) string {
	if hours == nil || *hours == 0 {
		return ""
	}
	return fmt.Sprintf("%.2f", float64(*hours)/24.0)
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

func firehoseDestinationBucketARNs(destinations []firehosetypes.DestinationDescription) []string {
	values := []string{}
	for _, destination := range destinations {
		switch {
		case destination.ExtendedS3DestinationDescription != nil:
			values = append(values, awssdk.ToString(destination.ExtendedS3DestinationDescription.BucketARN))
		case destination.S3DestinationDescription != nil:
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
	if cluster.Serverless != nil {
		return true
	}
	return mskKMSKeyID(cluster) != "" || mskInClusterEncryption(cluster) || mskClientBrokerEncryption(cluster) != ""
}

func mskKMSKeyID(cluster kafkatypes.Cluster) string {
	if cluster.Provisioned == nil || cluster.Provisioned.EncryptionInfo == nil || cluster.Provisioned.EncryptionInfo.EncryptionAtRest == nil {
		return ""
	}
	return awssdk.ToString(cluster.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId)
}

func mskClientBrokerEncryption(cluster kafkatypes.Cluster) string {
	if cluster.Serverless != nil {
		return "TLS"
	}
	if cluster.Provisioned == nil || cluster.Provisioned.EncryptionInfo == nil || cluster.Provisioned.EncryptionInfo.EncryptionInTransit == nil {
		return ""
	}
	return string(cluster.Provisioned.EncryptionInfo.EncryptionInTransit.ClientBroker)
}

func mskInClusterEncryption(cluster kafkatypes.Cluster) bool {
	if cluster.Serverless != nil {
		return true
	}
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

func glueDatabaseARN(settings settings, catalogID string, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:glue:%s:%s:database/%s", settings.region, firstNonEmpty(catalogID, settings.accountID), name)
}

func glueTableARN(settings settings, catalogID string, databaseName string, tableName string) string {
	databaseName = strings.TrimSpace(databaseName)
	tableName = strings.TrimSpace(tableName)
	if databaseName == "" || tableName == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:glue:%s:%s:table/%s/%s", settings.region, firstNonEmpty(catalogID, settings.accountID), databaseName, tableName)
}

func glueTableResourceID(settings settings, table awsGlueTable) string {
	return firstNonEmpty(
		glueTableARN(settings, firstNonEmpty(awssdk.ToString(table.Table.CatalogId), settings.accountID), firstNonEmpty(table.DatabaseName, awssdk.ToString(table.Table.DatabaseName)), awssdk.ToString(table.Table.Name)),
		firstNonEmpty(table.DatabaseName, awssdk.ToString(table.Table.DatabaseName))+"/"+awssdk.ToString(table.Table.Name),
	)
}

func glueCrawlerARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:glue:%s:%s:crawler/%s", settings.region, settings.accountID, name)
}

func glueJobARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", settings.region, settings.accountID, name)
}

func athenaWorkgroupARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:athena:%s:%s:workgroup/%s", settings.region, settings.accountID, name)
}

func athenaDataCatalogARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:athena:%s:%s:datacatalog/%s", settings.region, settings.accountID, name)
}

func lakeFormationLFTagResourceID(record awsLakeFormationLFTag) string {
	return strings.Join(cleanStrings([]string{
		awssdk.ToString(record.Tag.CatalogId),
		awssdk.ToString(record.Tag.TagKey),
		strings.Join(cleanStrings(record.Tag.TagValues), "|"),
	}), ":")
}

func lakeFormationPermissionResourceID(record awsLakeFormationPermission) string {
	permission := record.Permission
	principal := ""
	if permission.Principal != nil {
		principal = awssdk.ToString(permission.Principal.DataLakePrincipalIdentifier)
	}
	return strings.Join(cleanStrings([]string{
		principal,
		lakeFormationResourceRef(permission.Resource),
		lakeFormationPermissions(permission.Permissions),
	}), ":")
}

func lakeFormationPermissions(values []lakeformationtypes.Permission) string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if string(value) != "" {
			result = append(result, string(value))
		}
	}
	sort.Strings(result)
	return strings.Join(result, ",")
}

func lakeFormationResourceRef(resource *lakeformationtypes.Resource) string {
	if resource == nil {
		return ""
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		return ""
	}
	return string(payload)
}
