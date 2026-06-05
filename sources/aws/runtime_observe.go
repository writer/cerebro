package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsAppRunnerService struct {
	Service apprunnertypes.Service
	Tags    map[string]string
}

type awsCloudWatchAlarm struct {
	Alarm cloudwatchtypes.MetricAlarm
	Tags  map[string]string
}

type awsCloudWatchLogGroup struct {
	LogGroup cloudwatchlogstypes.LogGroup
	Tags     map[string]string
}

type awsSSMManagedInstance struct {
	Instance ssmtypes.InstanceInformation
	Tags     map[string]string
}

type awsSSMParameter struct {
	Parameter ssmtypes.ParameterMetadata
	Tags      map[string]string
}

func listAppRunnerServices(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsAppRunnerService, string, error) {
	out, err := clients.appRunner.ListServices(ctx, &apprunner.ListServicesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 20))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAppRunnerService, 0, len(out.ServiceSummaryList))
	for _, summary := range out.ServiceSummaryList {
		arn := awssdk.ToString(summary.ServiceArn)
		if arn == "" {
			continue
		}
		record := awsAppRunnerService{Service: appRunnerServiceFromSummary(summary)}
		describe, err := clients.appRunner.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe app runner service %q: %w", arn, err)
		}
		if describe.Service != nil {
			record.Service = *describe.Service
		}
		if tags, err := clients.appRunner.ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = appRunnerTagMap(tags.Tags)
		} else if !optionalAWSError(err, "ResourceNotFoundException") {
			return nil, "", fmt.Errorf("list app runner service tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listCloudWatchAlarms(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsCloudWatchAlarm, string, error) {
	out, err := clients.cloudWatch.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []cloudwatchtypes.AlarmType{cloudwatchtypes.AlarmTypeMetricAlarm},
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsCloudWatchAlarm, 0, len(out.MetricAlarms))
	for _, alarm := range out.MetricAlarms {
		record := awsCloudWatchAlarm{Alarm: alarm}
		if arn := awssdk.ToString(alarm.AlarmArn); arn != "" {
			if tags, err := clients.cloudWatch.ListTagsForResource(ctx, &cloudwatch.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)}); err == nil {
				record.Tags = cloudWatchTagMap(tags.Tags)
			} else if !optionalAWSError(err, "ResourceNotFound", "ResourceNotFoundException") {
				return nil, "", fmt.Errorf("list cloudwatch alarm tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listCloudWatchLogGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsCloudWatchLogGroup, string, error) {
	out, err := clients.logs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsCloudWatchLogGroup, 0, len(out.LogGroups))
	for _, group := range out.LogGroups {
		record := awsCloudWatchLogGroup{LogGroup: group}
		if arn := cloudWatchLogGroupTagARN(group); arn != "" {
			if tags, err := clients.logs.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
				record.Tags = tags.Tags
			} else if !optionalAWSError(err, "ResourceNotFoundException") {
				return nil, "", fmt.Errorf("list cloudwatch log group tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSSMManagedInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSMManagedInstance, string, error) {
	out, err := clients.ssm.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 5, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSSMManagedInstance, 0, len(out.InstanceInformationList))
	for _, instance := range out.InstanceInformationList {
		record := awsSSMManagedInstance{Instance: instance}
		if tags, err := ssmResourceTags(ctx, clients, ssmtypes.ResourceTypeForTaggingManagedInstance, awssdk.ToString(instance.InstanceId)); err == nil {
			record.Tags = tags
		} else if !optionalAWSError(err, "InvalidResourceId", "InvalidResourceType") {
			return nil, "", fmt.Errorf("list ssm managed instance tags %q: %w", awssdk.ToString(instance.InstanceId), err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSSMDocuments(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ssmtypes.DocumentIdentifier, string, error) {
	out, err := clients.ssm.ListDocuments(ctx, &ssm.ListDocumentsInput{
		Filters:    []ssmtypes.DocumentKeyValuesFilter{{Key: awssdk.String("Owner"), Values: []string{"Self"}}},
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.DocumentIdentifiers, awssdk.ToString(out.NextToken), nil
}

func listSSMAssociations(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ssmtypes.Association, string, error) {
	out, err := clients.ssm.ListAssociations(ctx, &ssm.ListAssociationsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Associations, awssdk.ToString(out.NextToken), nil
}

func listSSMParameters(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSMParameter, string, error) {
	out, err := clients.ssm.DescribeParameters(ctx, &ssm.DescribeParametersInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSSMParameter, 0, len(out.Parameters))
	for _, parameter := range out.Parameters {
		record := awsSSMParameter{Parameter: parameter}
		if tags, err := ssmResourceTags(ctx, clients, ssmtypes.ResourceTypeForTaggingParameter, awssdk.ToString(parameter.Name)); err == nil {
			record.Tags = tags
		} else if !optionalAWSError(err, "ParameterNotFound", "InvalidResourceId", "InvalidResourceType") {
			return nil, "", fmt.Errorf("list ssm parameter tags %q: %w", awssdk.ToString(parameter.Name), err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func appRunnerServiceEvent(settings settings, record awsAppRunnerService) (*primitives.Event, error) {
	service := record.Service
	arn := awssdk.ToString(service.ServiceArn)
	name := awssdk.ToString(service.ServiceName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAppRunnerService, firstNonEmpty(arn, awssdk.ToString(service.ServiceId), name), name, "app_runner_service", record.Tags)
	attributes["arn"] = arn
	attributes["service_arn"] = arn
	attributes["service_id"] = awssdk.ToString(service.ServiceId)
	attributes["service_name"] = name
	attributes["service_url"] = awssdk.ToString(service.ServiceUrl)
	attributes["public_endpoint"] = awssdk.ToString(service.ServiceUrl)
	attributes["state"] = string(service.Status)
	attributes["observability_enabled"] = boolString(service.ObservabilityConfiguration != nil && service.ObservabilityConfiguration.ObservabilityEnabled)
	attributes["observability_configuration_arn"] = appRunnerObservabilityARN(service.ObservabilityConfiguration)
	attributes["public"] = boolString(appRunnerPubliclyAccessible(service))
	attributes["internet_exposed"] = attributes["public"]
	attributes["kms_key_id"] = appRunnerKMSKey(service.EncryptionConfiguration)
	attributes["encryption"] = boolString(attributes["kms_key_id"] != "")
	attributes["role_arn"] = appRunnerInstanceRoleARN(service.InstanceConfiguration)
	attributes["role_name"] = roleNameFromARN(attributes["role_arn"])
	attributes["source_type"] = appRunnerSourceType(service.SourceConfiguration)
	attributes["image_identifier"] = appRunnerImageIdentifier(service.SourceConfiguration)
	attributes["repository_url"] = appRunnerRepositoryURL(service.SourceConfiguration)
	attributes["auto_deployments_enabled"] = boolString(appRunnerAutoDeployments(service.SourceConfiguration))
	if service.NetworkConfiguration != nil && service.NetworkConfiguration.EgressConfiguration != nil {
		attributes["egress_type"] = string(service.NetworkConfiguration.EgressConfiguration.EgressType)
		attributes["vpc_connector_arn"] = awssdk.ToString(service.NetworkConfiguration.EgressConfiguration.VpcConnectorArn)
	}
	if service.NetworkConfiguration != nil {
		attributes["ip_address_type"] = string(service.NetworkConfiguration.IpAddressType)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service": service, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-app-runner-service-"+firstNonEmpty(arn, name), "aws.app_runner_service", "aws/app_runner_service/v1", payload, attributes, firstTime(service.UpdatedAt, service.CreatedAt))
}

func cloudWatchAlarmEvent(settings settings, record awsCloudWatchAlarm) (*primitives.Event, error) {
	alarm := record.Alarm
	arn := awssdk.ToString(alarm.AlarmArn)
	name := awssdk.ToString(alarm.AlarmName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCloudWatchAlarm, firstNonEmpty(arn, name), name, "cloudwatch_alarm", record.Tags)
	attributes["arn"] = arn
	attributes["alarm_arn"] = arn
	attributes["alarm_name"] = name
	attributes["state"] = string(alarm.StateValue)
	attributes["metric_namespace"] = awssdk.ToString(alarm.Namespace)
	attributes["metric_name"] = awssdk.ToString(alarm.MetricName)
	attributes["comparison_operator"] = string(alarm.ComparisonOperator)
	attributes["statistic"] = string(alarm.Statistic)
	attributes["extended_statistic"] = awssdk.ToString(alarm.ExtendedStatistic)
	attributes["threshold"] = floatAttrString(alarm.Threshold)
	attributes["evaluation_periods"] = int32AttrString(alarm.EvaluationPeriods)
	attributes["datapoints_to_alarm"] = int32AttrString(alarm.DatapointsToAlarm)
	attributes["period_seconds"] = int32AttrString(alarm.Period)
	attributes["actions_enabled"] = boolString(awssdk.ToBool(alarm.ActionsEnabled))
	attributes["alarm_actions"] = strings.Join(cleanStrings(alarm.AlarmActions), ",")
	attributes["ok_actions"] = strings.Join(cleanStrings(alarm.OKActions), ",")
	attributes["insufficient_data_actions"] = strings.Join(cleanStrings(alarm.InsufficientDataActions), ",")
	attributes["dimensions"] = strings.Join(cloudWatchDimensions(alarm.Dimensions), ",")
	attributes["treat_missing_data"] = awssdk.ToString(alarm.TreatMissingData)
	addTimeAttribute(attributes, "state_updated_at", alarm.StateUpdatedTimestamp)
	addTimeAttribute(attributes, "state_transitioned_at", alarm.StateTransitionedTimestamp)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "alarm": alarm, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudwatch-alarm-"+firstNonEmpty(arn, name), "aws.cloudwatch_alarm", "aws/cloudwatch_alarm/v1", payload, attributes, firstTime(alarm.StateUpdatedTimestamp, alarm.AlarmConfigurationUpdatedTimestamp))
}

func cloudWatchLogGroupEvent(settings settings, record awsCloudWatchLogGroup) (*primitives.Event, error) {
	group := record.LogGroup
	arn := firstNonEmpty(awssdk.ToString(group.LogGroupArn), strings.TrimSuffix(awssdk.ToString(group.Arn), ":*"), cloudWatchLogGroupARN(settings, awssdk.ToString(group.LogGroupName)))
	name := awssdk.ToString(group.LogGroupName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCloudWatchLogGroup, firstNonEmpty(arn, name), name, "cloudwatch_log_group", record.Tags)
	attributes["arn"] = arn
	attributes["log_group_arn"] = arn
	attributes["log_group_name"] = name
	attributes["log_group_class"] = string(group.LogGroupClass)
	attributes["kms_key_id"] = awssdk.ToString(group.KmsKeyId)
	attributes["encryption"] = boolString(attributes["kms_key_id"] != "")
	attributes["retention_days"] = int32AttrString(group.RetentionInDays)
	attributes["stored_bytes"] = int64AttrString(group.StoredBytes)
	attributes["metric_filter_count"] = int32AttrString(group.MetricFilterCount)
	attributes["deletion_protection"] = boolString(awssdk.ToBool(group.DeletionProtectionEnabled))
	attributes["data_protection_status"] = string(group.DataProtectionStatus)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "log_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudwatch-log-group-"+firstNonEmpty(arn, name), "aws.cloudwatch_log_group", "aws/cloudwatch_log_group/v1", payload, attributes, unixMillisAttributeTime(group.CreationTime))
}

func ssmManagedInstanceEvent(settings settings, record awsSSMManagedInstance) (*primitives.Event, error) {
	instance := record.Instance
	id := awssdk.ToString(instance.InstanceId)
	arn := ssmManagedInstanceARN(settings, id)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMManagedInstance, firstNonEmpty(arn, id), firstNonEmpty(awssdk.ToString(instance.Name), awssdk.ToString(instance.ComputerName), id), "ssm_managed_instance", record.Tags)
	attributes["arn"] = arn
	attributes["instance_id"] = id
	attributes["name"] = awssdk.ToString(instance.Name)
	attributes["computer_name"] = awssdk.ToString(instance.ComputerName)
	attributes["ip_address"] = awssdk.ToString(instance.IPAddress)
	attributes["state"] = string(instance.PingStatus)
	attributes["ping_status"] = string(instance.PingStatus)
	attributes["agent_version"] = awssdk.ToString(instance.AgentVersion)
	attributes["is_latest_version"] = boolString(awssdk.ToBool(instance.IsLatestVersion))
	attributes["platform_type"] = string(instance.PlatformType)
	attributes["platform_name"] = awssdk.ToString(instance.PlatformName)
	attributes["platform_version"] = awssdk.ToString(instance.PlatformVersion)
	attributes["resource_kind"] = string(instance.ResourceType)
	attributes["source_id"] = awssdk.ToString(instance.SourceId)
	attributes["source_type"] = string(instance.SourceType)
	attributes["iam_role"] = awssdk.ToString(instance.IamRole)
	attributes["association_status"] = awssdk.ToString(instance.AssociationStatus)
	addTimeAttribute(attributes, "last_ping_at", instance.LastPingDateTime)
	addTimeAttribute(attributes, "registration_at", instance.RegistrationDate)
	addTimeAttribute(attributes, "last_association_execution_at", instance.LastAssociationExecutionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-managed-instance-"+id, "aws.ssm_managed_instance", "aws/ssm_managed_instance/v1", payload, attributes, firstTime(instance.LastPingDateTime, instance.RegistrationDate))
}

func ssmDocumentEvent(settings settings, document ssmtypes.DocumentIdentifier) (*primitives.Event, error) {
	name := awssdk.ToString(document.Name)
	tags := ssmTagMap(document.Tags)
	arn := ssmDocumentARN(settings, name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMDocument, firstNonEmpty(arn, name), firstNonEmpty(awssdk.ToString(document.DisplayName), name), "ssm_document", tags)
	attributes["arn"] = arn
	attributes["document_name"] = name
	attributes["display_name"] = awssdk.ToString(document.DisplayName)
	attributes["document_type"] = string(document.DocumentType)
	attributes["document_format"] = string(document.DocumentFormat)
	attributes["document_version"] = awssdk.ToString(document.DocumentVersion)
	attributes["version_name"] = awssdk.ToString(document.VersionName)
	documentOwner := strings.TrimSpace(awssdk.ToString(document.Owner))
	if attributes["owner"] == "" && useSSMDocumentOwner(documentOwner, settings.accountID) {
		attributes["owner"] = documentOwner
	}
	attributes["author"] = awssdk.ToString(document.Author)
	attributes["schema_version"] = awssdk.ToString(document.SchemaVersion)
	attributes["target_type"] = awssdk.ToString(document.TargetType)
	attributes["platform_types"] = strings.Join(ssmPlatformTypes(document.PlatformTypes), ",")
	attributes["review_status"] = string(document.ReviewStatus)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "document": document})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-document-"+name, "aws.ssm_document", "aws/ssm_document/v1", payload, attributes, firstTime(document.CreatedDate))
}

func ssmAssociationEvent(settings settings, association ssmtypes.Association) (*primitives.Event, error) {
	id := awssdk.ToString(association.AssociationId)
	name := awssdk.ToString(association.AssociationName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMAssociation, firstNonEmpty(ssmAssociationARN(settings, id), id, name), firstNonEmpty(name, awssdk.ToString(association.Name)), "ssm_association", nil)
	attributes["arn"] = ssmAssociationARN(settings, id)
	attributes["association_id"] = id
	attributes["association_name"] = name
	attributes["document_name"] = awssdk.ToString(association.Name)
	attributes["document_version"] = awssdk.ToString(association.DocumentVersion)
	attributes["association_version"] = awssdk.ToString(association.AssociationVersion)
	attributes["instance_id"] = awssdk.ToString(association.InstanceId)
	attributes["schedule_expression"] = awssdk.ToString(association.ScheduleExpression)
	attributes["schedule_offset_days"] = int32AttrString(association.ScheduleOffset)
	attributes["duration_hours"] = int32AttrString(association.Duration)
	attributes["target_keys"] = strings.Join(ssmAssociationTargetKeys(association.Targets), ",")
	if association.Overview != nil {
		attributes["state"] = awssdk.ToString(association.Overview.Status)
		attributes["detailed_status"] = awssdk.ToString(association.Overview.DetailedStatus)
	}
	addTimeAttribute(attributes, "last_execution_at", association.LastExecutionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "association": association})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-association-"+firstNonEmpty(id, name, awssdk.ToString(association.Name)), "aws.ssm_association", "aws/ssm_association/v1", payload, attributes, firstTime(association.LastExecutionDate))
}

func ssmParameterEvent(settings settings, record awsSSMParameter) (*primitives.Event, error) {
	parameter := record.Parameter
	arn := firstNonEmpty(awssdk.ToString(parameter.ARN), ssmParameterARN(settings, awssdk.ToString(parameter.Name)))
	name := awssdk.ToString(parameter.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMParameter, firstNonEmpty(arn, name), name, "ssm_parameter", record.Tags)
	attributes["arn"] = arn
	attributes["parameter_arn"] = arn
	attributes["parameter_name"] = name
	attributes["parameter_type"] = string(parameter.Type)
	attributes["tier"] = string(parameter.Tier)
	attributes["data_type"] = awssdk.ToString(parameter.DataType)
	attributes["version"] = strconv.FormatInt(parameter.Version, 10)
	attributes["kms_key_id"] = awssdk.ToString(parameter.KeyId)
	attributes["encryption"] = boolString(parameter.Type == ssmtypes.ParameterTypeSecureString)
	attributes["allowed_pattern"] = awssdk.ToString(parameter.AllowedPattern)
	attributes["last_modified_user"] = awssdk.ToString(parameter.LastModifiedUser)
	addTimeAttribute(attributes, "last_modified_at", parameter.LastModifiedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "parameter": parameter, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-parameter-"+firstNonEmpty(arn, name), "aws.ssm_parameter", "aws/ssm_parameter/v1", payload, attributes, firstTime(parameter.LastModifiedDate))
}

func appRunnerServiceFromSummary(summary apprunnertypes.ServiceSummary) apprunnertypes.Service {
	return apprunnertypes.Service{
		CreatedAt:   summary.CreatedAt,
		ServiceArn:  summary.ServiceArn,
		ServiceId:   summary.ServiceId,
		ServiceName: summary.ServiceName,
		ServiceUrl:  summary.ServiceUrl,
		Status:      summary.Status,
		UpdatedAt:   summary.UpdatedAt,
	}
}

func appRunnerPubliclyAccessible(service apprunnertypes.Service) bool {
	return service.NetworkConfiguration != nil &&
		service.NetworkConfiguration.IngressConfiguration != nil &&
		service.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible
}

func appRunnerObservabilityARN(config *apprunnertypes.ServiceObservabilityConfiguration) string {
	if config == nil {
		return ""
	}
	return awssdk.ToString(config.ObservabilityConfigurationArn)
}

func appRunnerKMSKey(config *apprunnertypes.EncryptionConfiguration) string {
	if config == nil {
		return ""
	}
	return awssdk.ToString(config.KmsKey)
}

func appRunnerInstanceRoleARN(config *apprunnertypes.InstanceConfiguration) string {
	if config == nil {
		return ""
	}
	return awssdk.ToString(config.InstanceRoleArn)
}

func appRunnerAutoDeployments(config *apprunnertypes.SourceConfiguration) bool {
	return config != nil && awssdk.ToBool(config.AutoDeploymentsEnabled)
}

func appRunnerSourceType(config *apprunnertypes.SourceConfiguration) string {
	if config == nil {
		return ""
	}
	if config.ImageRepository != nil {
		return "image"
	}
	if config.CodeRepository != nil {
		return "code"
	}
	return ""
}

func appRunnerImageIdentifier(config *apprunnertypes.SourceConfiguration) string {
	if config == nil || config.ImageRepository == nil {
		return ""
	}
	return awssdk.ToString(config.ImageRepository.ImageIdentifier)
}

func appRunnerRepositoryURL(config *apprunnertypes.SourceConfiguration) string {
	if config == nil || config.CodeRepository == nil {
		return ""
	}
	return awssdk.ToString(config.CodeRepository.RepositoryUrl)
}

func appRunnerTagMap(tags []apprunnertypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func cloudWatchTagMap(tags []cloudwatchtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func ssmTagMap(tags []ssmtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func ssmResourceTags(ctx context.Context, clients awsClients, resourceType ssmtypes.ResourceTypeForTagging, resourceID string) (map[string]string, error) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return nil, nil
	}
	out, err := clients.ssm.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceId: awssdk.String(resourceID), ResourceType: resourceType})
	if err != nil {
		return nil, err
	}
	return ssmTagMap(out.TagList), nil
}

func cloudWatchDimensions(dimensions []cloudwatchtypes.Dimension) []string {
	values := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		name := strings.TrimSpace(awssdk.ToString(dimension.Name))
		value := strings.TrimSpace(awssdk.ToString(dimension.Value))
		if name == "" && value == "" {
			continue
		}
		values = append(values, name+"="+value)
	}
	return cleanStrings(values)
}

func cloudWatchLogGroupTagARN(group cloudwatchlogstypes.LogGroup) string {
	return firstNonEmpty(awssdk.ToString(group.LogGroupArn), strings.TrimSuffix(awssdk.ToString(group.Arn), ":*"))
}

func cloudWatchLogGroupARN(settings settings, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", settings.region, settings.accountID, strings.TrimSpace(name))
}

func ssmManagedInstanceARN(settings settings, id string) string {
	if strings.TrimSpace(id) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ssm:%s:%s:managed-instance/%s", settings.region, settings.accountID, strings.TrimSpace(id))
}

func ssmDocumentARN(settings settings, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ssm:%s:%s:document/%s", settings.region, settings.accountID, strings.TrimSpace(name))
}

func ssmAssociationARN(settings settings, id string) string {
	if strings.TrimSpace(id) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ssm:%s:%s:association/%s", settings.region, settings.accountID, strings.TrimSpace(id))
}

func ssmParameterARN(settings settings, name string) string {
	normalizedName := strings.TrimSpace(name)
	if normalizedName == "" {
		return ""
	}
	if !strings.HasPrefix(normalizedName, "/") {
		normalizedName = "/" + normalizedName
	}
	return fmt.Sprintf("arn:aws:ssm:%s:%s:parameter%s", settings.region, settings.accountID, normalizedName)
}

func useSSMDocumentOwner(owner, accountID string) bool {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return false
	}
	if owner == strings.TrimSpace(accountID) {
		return false
	}
	return !looksLikeAWSAccountID(owner)
}

func looksLikeAWSAccountID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 12 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func ssmPlatformTypes(values []ssmtypes.PlatformType) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return cleanStrings(out)
}

func ssmAssociationTargetKeys(targets []ssmtypes.Target) []string {
	keys := make([]string, 0, len(targets))
	for _, target := range targets {
		keys = append(keys, awssdk.ToString(target.Key))
	}
	return cleanStrings(keys)
}

func int64AttrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}

func floatAttrString(value *float64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(*value, 'f', -1, 64)
}

func unixMillisAttributeTime(value *int64) time.Time {
	if value == nil || *value <= 0 {
		return time.Now().UTC()
	}
	return time.UnixMilli(*value).UTC()
}
