package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	lakeformationtypes "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsGlueDatabase struct {
	Name     string
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

type awsGlueTableCursor struct {
	DatabaseIndex int    `json:"database_index,omitempty"`
	TableToken    string `json:"table_token,omitempty"`
}

type awsAthenaWorkGroup struct {
	WorkGroup athenatypes.WorkGroup
	Tags      map[string]string
}

type awsAthenaDataCatalog struct {
	Catalog athenatypes.DataCatalog
	Tags    map[string]string
}

func listGlueDatabases(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueDatabase, string, error) {
	output, err := clients.glue.GetDatabases(ctx, &glue.GetDatabasesInput{
		CatalogId:  awssdk.String(settings.accountID),
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueDatabase, 0, len(output.DatabaseList))
	for _, database := range output.DatabaseList {
		name := awssdk.ToString(database.Name)
		if name == "" {
			continue
		}
		record := awsGlueDatabase{Name: name, Database: database}
		tags, err := glueTags(ctx, clients, glueDatabaseARN(settings, name))
		if err != nil {
			return nil, "", fmt.Errorf("get glue database tags %q: %w", name, err)
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listGlueTables(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueTable, string, error) {
	databases, err := listAllGlueDatabases(ctx, clients, settings)
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
	if state.DatabaseIndex < 0 || state.DatabaseIndex >= len(databases) {
		state.DatabaseIndex = 0
		state.TableToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsGlueTable, 0, remaining)
	for state.DatabaseIndex < len(databases) && len(records) < remaining {
		databaseName := databases[state.DatabaseIndex]
		output, err := clients.glue.GetTables(ctx, &glue.GetTablesInput{
			CatalogId:    awssdk.String(settings.accountID),
			DatabaseName: awssdk.String(databaseName),
			MaxResults:   awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:    stringPtr(state.TableToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("get glue tables for database %q: %w", databaseName, err)
		}
		for _, table := range output.TableList {
			name := awssdk.ToString(table.Name)
			if name == "" {
				continue
			}
			record := awsGlueTable{DatabaseName: firstNonEmpty(awssdk.ToString(table.DatabaseName), databaseName), Table: table}
			tags, err := glueTags(ctx, clients, glueTableARN(settings, record.DatabaseName, name))
			if err != nil {
				return nil, "", fmt.Errorf("get glue table tags %q/%q: %w", record.DatabaseName, name, err)
			}
			record.Tags = tags
			records = append(records, record)
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.TableToken = awssdk.ToString(output.NextToken)
			return records, encodeGlueTableCursor(state), nil
		}
		state.DatabaseIndex++
		state.TableToken = ""
	}
	if state.DatabaseIndex < len(databases) {
		return records, encodeGlueTableCursor(state), nil
	}
	return records, "", nil
}

func listGlueCrawlers(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueCrawler, string, error) {
	output, err := clients.glue.GetCrawlers(ctx, &glue.GetCrawlersInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueCrawler, 0, len(output.Crawlers))
	for _, crawler := range output.Crawlers {
		name := awssdk.ToString(crawler.Name)
		if name == "" {
			continue
		}
		record := awsGlueCrawler{Crawler: crawler}
		tags, err := glueTags(ctx, clients, glueCrawlerARN(settings, crawler.Name))
		if err != nil {
			return nil, "", fmt.Errorf("get glue crawler tags %q: %w", name, err)
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listGlueJobs(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsGlueJob, string, error) {
	output, err := clients.glue.GetJobs(ctx, &glue.GetJobsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlueJob, 0, len(output.Jobs))
	for _, job := range output.Jobs {
		name := awssdk.ToString(job.Name)
		if name == "" {
			continue
		}
		record := awsGlueJob{Job: job}
		tags, err := glueTags(ctx, clients, glueJobARN(settings, job.Name))
		if err != nil {
			return nil, "", fmt.Errorf("get glue job tags %q: %w", name, err)
		}
		record.Tags = tags
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listAthenaWorkGroups(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAthenaWorkGroup, string, error) {
	output, err := clients.athena.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAthenaWorkGroup, 0, len(output.WorkGroups))
	for _, summary := range output.WorkGroups {
		name := awssdk.ToString(summary.Name)
		if name == "" {
			continue
		}
		detail, err := clients.athena.GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get athena workgroup %q: %w", name, err)
		}
		if detail.WorkGroup != nil {
			record := awsAthenaWorkGroup{WorkGroup: *detail.WorkGroup}
			tags, err := athenaTags(ctx, clients, athenaWorkGroupARN(settings, detail.WorkGroup.Name))
			if err != nil {
				return nil, "", fmt.Errorf("list athena workgroup tags %q: %w", name, err)
			}
			record.Tags = tags
			records = append(records, record)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listAthenaDataCatalogs(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAthenaDataCatalog, string, error) {
	output, err := clients.athena.ListDataCatalogs(ctx, &athena.ListDataCatalogsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAthenaDataCatalog, 0, len(output.DataCatalogsSummary))
	for _, summary := range output.DataCatalogsSummary {
		name := awssdk.ToString(summary.CatalogName)
		if name == "" {
			continue
		}
		detail, err := clients.athena.GetDataCatalog(ctx, &athena.GetDataCatalogInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get athena data catalog %q: %w", name, err)
		}
		if detail.DataCatalog != nil {
			record := awsAthenaDataCatalog{Catalog: *detail.DataCatalog}
			tags, err := athenaTags(ctx, clients, athenaDataCatalogARN(settings, detail.DataCatalog.Name))
			if err != nil {
				return nil, "", fmt.Errorf("list athena data catalog tags %q: %w", name, err)
			}
			record.Tags = tags
			records = append(records, record)
		}
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listLakeFormationResources(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]lakeformationtypes.ResourceInfo, string, error) {
	output, err := clients.lakeFormation.ListResources(ctx, &lakeformation.ListResourcesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return output.ResourceInfoList, awssdk.ToString(output.NextToken), nil
}

func glueDatabaseEvent(settings settings, record awsGlueDatabase) (*primitives.Event, error) {
	database := record.Database
	name := firstNonEmpty(record.Name, awssdk.ToString(database.Name))
	arn := glueDatabaseARN(settings, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueDatabase, arn, name, "glue_database", record.Tags)
	attributes["arn"] = arn
	attributes["catalog_id"] = firstNonEmpty(awssdk.ToString(database.CatalogId), settings.accountID)
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
	return sourceEvent(settings, "aws-glue-database-"+arn, "aws.glue_database", "aws/glue_database/v1", payload, attributes, firstTime(database.CreateTime))
}

func glueTableEvent(settings settings, record awsGlueTable) (*primitives.Event, error) {
	table := record.Table
	name := awssdk.ToString(table.Name)
	databaseName := firstNonEmpty(record.DatabaseName, awssdk.ToString(table.DatabaseName))
	arn := glueTableARN(settings, databaseName, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueTable, arn, name, "glue_table", record.Tags)
	attributes["arn"] = arn
	attributes["catalog_id"] = firstNonEmpty(awssdk.ToString(table.CatalogId), settings.accountID)
	attributes["created_by"] = awssdk.ToString(table.CreatedBy)
	attributes["database_name"] = databaseName
	attributes["description"] = awssdk.ToString(table.Description)
	attributes["is_materialized_view"] = boolString(awssdk.ToBool(table.IsMaterializedView))
	attributes["is_registered_with_lakeformation"] = boolString(table.IsRegisteredWithLakeFormation)
	attributes["owner"] = firstNonEmpty(attributes["owner"], awssdk.ToString(table.Owner))
	attributes["partition_key_count"] = strconv.Itoa(len(table.PartitionKeys))
	attributes["retention_days"] = strconv.FormatInt(int64(table.Retention), 10)
	attributes["table_name"] = name
	attributes["table_type"] = awssdk.ToString(table.TableType)
	attributes["version_id"] = awssdk.ToString(table.VersionId)
	if table.StorageDescriptor != nil {
		attributes["column_count"] = strconv.Itoa(len(table.StorageDescriptor.Columns))
		attributes["compressed"] = boolString(table.StorageDescriptor.Compressed)
		attributes["input_format"] = awssdk.ToString(table.StorageDescriptor.InputFormat)
		attributes["location_uri"] = awssdk.ToString(table.StorageDescriptor.Location)
		attributes["output_format"] = awssdk.ToString(table.StorageDescriptor.OutputFormat)
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
	return sourceEvent(settings, "aws-glue-table-"+arn, "aws.glue_table", "aws/glue_table/v1", payload, attributes, firstTime(table.UpdateTime, table.CreateTime))
}

func glueCrawlerEvent(settings settings, record awsGlueCrawler) (*primitives.Event, error) {
	crawler := record.Crawler
	name := awssdk.ToString(crawler.Name)
	arn := glueCrawlerARN(settings, crawler.Name)
	roleARN := awssdk.ToString(crawler.Role)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueCrawler, arn, name, "glue_crawler", record.Tags)
	attributes["arn"] = arn
	attributes["crawler_name"] = name
	attributes["database_name"] = awssdk.ToString(crawler.DatabaseName)
	attributes["description"] = awssdk.ToString(crawler.Description)
	attributes["lineage"] = glueCrawlerLineage(crawler)
	attributes["recrawl_behavior"] = glueCrawlerRecrawlBehavior(crawler)
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["schedule"] = glueCrawlerSchedule(crawler)
	attributes["state"] = string(crawler.State)
	attributes["table_prefix"] = awssdk.ToString(crawler.TablePrefix)
	attributes["target_count"] = strconv.Itoa(glueCrawlerTargetCount(crawler.Targets))
	attributes["version"] = strconv.FormatInt(crawler.Version, 10)
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
	return sourceEvent(settings, "aws-glue-crawler-"+arn, "aws.glue_crawler", "aws/glue_crawler/v1", payload, attributes, firstTime(crawler.LastUpdated, crawler.CreationTime))
}

func glueJobEvent(settings settings, record awsGlueJob) (*primitives.Event, error) {
	job := record.Job
	name := awssdk.ToString(job.Name)
	arn := glueJobARN(settings, job.Name)
	roleARN := awssdk.ToString(job.Role)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyGlueJob, arn, name, "glue_job", record.Tags)
	attributes["arn"] = arn
	attributes["allocated_capacity"] = strconv.FormatInt(int64(job.AllocatedCapacity), 10)
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
	return sourceEvent(settings, "aws-glue-job-"+arn, "aws.glue_job", "aws/glue_job/v1", payload, attributes, firstTime(job.LastModifiedOn, job.CreatedOn))
}

func athenaWorkGroupEvent(settings settings, record awsAthenaWorkGroup) (*primitives.Event, error) {
	workgroup := record.WorkGroup
	name := awssdk.ToString(workgroup.Name)
	arn := athenaWorkGroupARN(settings, workgroup.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAthenaWorkGroup, arn, name, "athena_workgroup", record.Tags)
	attributes["arn"] = arn
	attributes["description"] = awssdk.ToString(workgroup.Description)
	attributes["identity_center_application_arn"] = awssdk.ToString(workgroup.IdentityCenterApplicationArn)
	attributes["state"] = string(workgroup.State)
	attributes["workgroup_name"] = name
	if workgroup.Configuration != nil {
		attributes["bytes_scanned_cutoff_per_query"] = int64AttrString(workgroup.Configuration.BytesScannedCutoffPerQuery)
		attributes["enforce_workgroup_configuration"] = boolString(awssdk.ToBool(workgroup.Configuration.EnforceWorkGroupConfiguration))
		attributes["minimum_encryption_enabled"] = boolString(awssdk.ToBool(workgroup.Configuration.EnableMinimumEncryptionConfiguration))
		attributes["publish_cloudwatch_metrics_enabled"] = boolString(awssdk.ToBool(workgroup.Configuration.PublishCloudWatchMetricsEnabled))
		attributes["requester_pays_enabled"] = boolString(awssdk.ToBool(workgroup.Configuration.RequesterPaysEnabled))
		attributes["result_output_location"] = athenaResultOutputLocation(workgroup.Configuration.ResultConfiguration)
		attributes["encryption"] = athenaResultEncryption(workgroup.Configuration.ResultConfiguration)
		attributes["kms_key_id"] = athenaResultKMSKey(workgroup.Configuration.ResultConfiguration)
		attributes["role_arn"] = awssdk.ToString(workgroup.Configuration.ExecutionRole)
		attributes["role_name"] = roleNameFromARN(awssdk.ToString(workgroup.Configuration.ExecutionRole))
	}
	addTimeAttribute(attributes, "created_at", workgroup.CreationTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "workgroup": workgroup, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-athena-workgroup-"+arn, "aws.athena_workgroup", "aws/athena_workgroup/v1", payload, attributes, firstTime(workgroup.CreationTime))
}

func athenaDataCatalogEvent(settings settings, record awsAthenaDataCatalog) (*primitives.Event, error) {
	catalog := record.Catalog
	name := awssdk.ToString(catalog.Name)
	arn := athenaDataCatalogARN(settings, catalog.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAthenaDataCatalog, arn, name, "athena_data_catalog", record.Tags)
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
	return sourceEvent(settings, "aws-athena-data-catalog-"+arn, "aws.athena_data_catalog", "aws/athena_data_catalog/v1", payload, attributes, time.Now().UTC())
}

func lakeFormationResourceEvent(settings settings, resource lakeformationtypes.ResourceInfo) (*primitives.Event, error) {
	arn := awssdk.ToString(resource.ResourceArn)
	name := firstNonEmpty(awsResourceName(arn), path.Base(arn), arn)
	roleARN := awssdk.ToString(resource.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyLakeFormationResource, arn, name, "lakeformation_resource", nil)
	attributes["arn"] = arn
	attributes["expected_resource_owner_account"] = awssdk.ToString(resource.ExpectedResourceOwnerAccount)
	attributes["hybrid_access_enabled"] = boolString(awssdk.ToBool(resource.HybridAccessEnabled))
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["verification_status"] = string(resource.VerificationStatus)
	attributes["with_federation"] = boolString(awssdk.ToBool(resource.WithFederation))
	attributes["with_privileged_access"] = boolString(awssdk.ToBool(resource.WithPrivilegedAccess))
	addTimeAttribute(attributes, "updated_at", resource.LastModified)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "resource": resource})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-lakeformation-resource-"+arn, "aws.lakeformation_resource", "aws/lakeformation_resource/v1", payload, attributes, firstTime(resource.LastModified))
}

func listAllGlueDatabases(ctx context.Context, clients awsClients, settings settings) ([]string, error) {
	var databases []string
	var next *string
	for {
		output, err := clients.glue.GetDatabases(ctx, &glue.GetDatabasesInput{CatalogId: awssdk.String(settings.accountID), MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, database := range output.DatabaseList {
			if name := awssdk.ToString(database.Name); name != "" {
				databases = append(databases, name)
			}
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(databases)
	return databases, nil
}

func glueTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return nil, nil
	}
	output, err := clients.glue.GetTags(ctx, &glue.GetTagsInput{ResourceArn: awssdk.String(arn)})
	if err != nil {
		if optionalAWSError(err, "EntityNotFoundException", "ResourceNotFoundException") {
			return nil, nil
		}
		return nil, err
	}
	return output.Tags, nil
}

func athenaTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return nil, nil
	}
	tags := map[string]string{}
	var next *string
	for {
		output, err := clients.athena.ListTagsForResource(ctx, &athena.ListTagsForResourceInput{
			ResourceARN: awssdk.String(arn),
			MaxResults:  awssdk.Int32(50),
			NextToken:   next,
		})
		if err != nil {
			if optionalAWSError(err, "InvalidRequestException", "ResourceNotFoundException") {
				return nil, nil
			}
			return nil, err
		}
		for _, tag := range output.Tags {
			if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
				tags[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
			}
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return tags, nil
}

func glueDatabaseARN(settings settings, databaseName string) string {
	return awsRegionalARN("glue", settings.region, settings.accountID, "database/"+strings.TrimSpace(databaseName))
}

func glueTableARN(settings settings, databaseName string, tableName string) string {
	return awsRegionalARN("glue", settings.region, settings.accountID, "table/"+strings.TrimSpace(databaseName)+"/"+strings.TrimSpace(tableName))
}

func glueCrawlerARN(settings settings, crawlerName *string) string {
	return awsRegionalARN("glue", settings.region, settings.accountID, "crawler/"+awssdk.ToString(crawlerName))
}

func glueJobARN(settings settings, jobName *string) string {
	return awsRegionalARN("glue", settings.region, settings.accountID, "job/"+awssdk.ToString(jobName))
}

func athenaWorkGroupARN(settings settings, workgroupName *string) string {
	return awsRegionalARN("athena", settings.region, settings.accountID, "workgroup/"+awssdk.ToString(workgroupName))
}

func athenaDataCatalogARN(settings settings, catalogName *string) string {
	return awsRegionalARN("athena", settings.region, settings.accountID, "datacatalog/"+awssdk.ToString(catalogName))
}

func awsRegionalARN(service string, region string, accountID string, resource string) string {
	service = strings.TrimSpace(service)
	region = strings.TrimSpace(region)
	accountID = strings.TrimSpace(accountID)
	resource = strings.Trim(strings.TrimSpace(resource), "/")
	if service == "" || region == "" || accountID == "" || resource == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s", service, region, accountID, resource)
}

func decodeGlueTableCursor(raw string) (awsGlueTableCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return awsGlueTableCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return awsGlueTableCursor{}, fmt.Errorf("decode glue table cursor: %w", err)
	}
	var cursor awsGlueTableCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return awsGlueTableCursor{}, fmt.Errorf("parse glue table cursor: %w", err)
	}
	return cursor, nil
}

func encodeGlueTableCursor(cursor awsGlueTableCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
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

func athenaResultEncryption(config *athenatypes.ResultConfiguration) string {
	if config == nil || config.EncryptionConfiguration == nil {
		return ""
	}
	return string(config.EncryptionConfiguration.EncryptionOption)
}

func athenaResultKMSKey(config *athenatypes.ResultConfiguration) string {
	if config == nil || config.EncryptionConfiguration == nil {
		return ""
	}
	return awssdk.ToString(config.EncryptionConfiguration.KmsKey)
}

func int64AttrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
