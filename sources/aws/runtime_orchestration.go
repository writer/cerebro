package aws

import (
	"context"
	"encoding/base64"
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
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	pipestypes "github.com/aws/aws-sdk-go-v2/service/pipes/types"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsParentPageCursor struct {
	ParentIndex int    `json:"parent_index,omitempty"`
	NextToken   string `json:"next_token,omitempty"`
}

type awsAppRunnerService struct {
	ARN     string
	Name    string
	Service apprunnertypes.Service
	Tags    map[string]string
}

type awsStepFunctionStateMachine struct {
	ARN         string
	Name        string
	Description sfn.DescribeStateMachineOutput
	ListItem    sfntypes.StateMachineListItem
	Tags        map[string]string
}

type awsStepFunctionActivity struct {
	ARN      string
	Name     string
	Activity sfntypes.ActivityListItem
	Tags     map[string]string
}

type awsEventBridgeBus struct {
	ARN  string
	Name string
	Bus  eventbridgetypes.EventBus
	Tags map[string]string
}

type awsEventBridgeRule struct {
	ARN     string
	Name    string
	BusName string
	BusARN  string
	Rule    eventbridgetypes.Rule
	Tags    map[string]string
}

type awsEventBridgeArchive struct {
	ARN     string
	Name    string
	Archive eventbridgetypes.Archive
}

type awsEventBridgePipe struct {
	ARN         string
	Name        string
	Description pipes.DescribePipeOutput
	Summary     pipestypes.Pipe
	Tags        map[string]string
}

type awsSchedulerSchedule struct {
	ARN      string
	Name     string
	Schedule schedulertypes.ScheduleSummary
	Tags     map[string]string
}

type awsSchedulerGroup struct {
	ARN   string
	Name  string
	Group schedulertypes.ScheduleGroupSummary
	Tags  map[string]string
}

type awsCloudWatchAlarm struct {
	ARN            string
	Name           string
	Type           string
	MetricAlarm    *cloudwatchtypes.MetricAlarm
	CompositeAlarm *cloudwatchtypes.CompositeAlarm
	Tags           map[string]string
}

type awsCloudWatchLogGroup struct {
	ARN      string
	Name     string
	LogGroup cloudwatchlogstypes.LogGroup
	Tags     map[string]string
}

type awsSSMManagedInstance struct {
	ID       string
	Name     string
	Instance ssmtypes.InstanceInformation
	Tags     map[string]string
}

type awsSSMDocument struct {
	Name     string
	Document ssmtypes.DocumentIdentifier
	Tags     map[string]string
}

type awsSSMAssociation struct {
	ID          string
	Name        string
	Association ssmtypes.Association
	Tags        map[string]string
}

type awsSSMParameter struct {
	ARN       string
	Name      string
	Parameter ssmtypes.ParameterMetadata
	Tags      map[string]string
}

func listAppRunnerServices(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsAppRunnerService, string, error) {
	out, err := clients.appRunner.ListServices(ctx, &apprunner.ListServicesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAppRunnerService, 0, len(out.ServiceSummaryList))
	for _, summary := range out.ServiceSummaryList {
		arn := awssdk.ToString(summary.ServiceArn)
		record := awsAppRunnerService{ARN: arn, Name: awssdk.ToString(summary.ServiceName)}
		if arn != "" {
			describe, err := clients.appRunner.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("describe app runner service %q: %w", arn, err)
			}
			if describe.Service != nil {
				record.Service = *describe.Service
				record.ARN = firstNonEmpty(awssdk.ToString(describe.Service.ServiceArn), record.ARN)
				record.Name = firstNonEmpty(awssdk.ToString(describe.Service.ServiceName), record.Name)
			}
			tags, err := clients.appRunner.ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list app runner service tags %q: %w", arn, err)
			}
			record.Tags = appRunnerTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listStepFunctionStateMachines(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsStepFunctionStateMachine, string, error) {
	out, err := clients.stepFunctions.ListStateMachines(ctx, &sfn.ListStateMachinesInput{
		MaxResults: int32(boundedAWSPageSize(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsStepFunctionStateMachine, 0, len(out.StateMachines))
	for _, item := range out.StateMachines {
		arn := awssdk.ToString(item.StateMachineArn)
		record := awsStepFunctionStateMachine{ARN: arn, Name: awssdk.ToString(item.Name), ListItem: item}
		if arn != "" {
			describe, err := clients.stepFunctions.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: awssdk.String(arn), IncludedData: sfntypes.IncludedDataMetadataOnly})
			if err != nil {
				return nil, "", fmt.Errorf("describe step functions state machine %q: %w", arn, err)
			}
			record.Description = *describe
			record.ARN = firstNonEmpty(awssdk.ToString(describe.StateMachineArn), record.ARN)
			record.Name = firstNonEmpty(awssdk.ToString(describe.Name), record.Name)
			tags, err := clients.stepFunctions.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list step functions state machine tags %q: %w", arn, err)
			}
			record.Tags = sfnTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listStepFunctionActivities(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsStepFunctionActivity, string, error) {
	out, err := clients.stepFunctions.ListActivities(ctx, &sfn.ListActivitiesInput{
		MaxResults: int32(boundedAWSPageSize(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsStepFunctionActivity, 0, len(out.Activities))
	for _, activity := range out.Activities {
		arn := awssdk.ToString(activity.ActivityArn)
		record := awsStepFunctionActivity{ARN: arn, Name: awssdk.ToString(activity.Name), Activity: activity}
		if arn != "" {
			tags, err := clients.stepFunctions.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list step functions activity tags %q: %w", arn, err)
			}
			record.Tags = sfnTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEventBridgeBuses(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgeBus, string, error) {
	out, err := clients.eventBridge.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgeBus, 0, len(out.EventBuses))
	for _, bus := range out.EventBuses {
		arn := awssdk.ToString(bus.Arn)
		record := awsEventBridgeBus{ARN: arn, Name: awssdk.ToString(bus.Name), Bus: bus}
		if arn != "" {
			tags, err := clients.eventBridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list eventbridge bus tags %q: %w", arn, err)
			}
			record.Tags = eventBridgeTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEventBridgeRules(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsEventBridgeRule, string, error) {
	buses, err := listAllEventBridgeBuses(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(buses) == 0 {
		return nil, "", nil
	}
	state, err := decodeAWSParentCursor(cursor, "eventbridge rule")
	if err != nil {
		return nil, "", err
	}
	if state.ParentIndex < 0 || state.ParentIndex >= len(buses) {
		state = awsParentPageCursor{}
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsEventBridgeRule, 0, remaining)
	for state.ParentIndex < len(buses) && len(records) < remaining {
		bus := buses[state.ParentIndex]
		out, err := clients.eventBridge.ListRules(ctx, &eventbridge.ListRulesInput{
			EventBusName: awssdk.String(firstNonEmpty(bus.Name, bus.ARN)),
			Limit:        awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:    stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list eventbridge rules for bus %q: %w", firstNonEmpty(bus.Name, bus.ARN), err)
		}
		for _, rule := range out.Rules {
			arn := awssdk.ToString(rule.Arn)
			record := awsEventBridgeRule{ARN: arn, Name: awssdk.ToString(rule.Name), BusName: bus.Name, BusARN: bus.ARN, Rule: rule}
			if arn != "" {
				tags, err := clients.eventBridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)})
				if err != nil {
					return nil, "", fmt.Errorf("list eventbridge rule tags %q: %w", arn, err)
				}
				record.Tags = eventBridgeTagMap(tags.Tags)
			}
			records = append(records, record)
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.NextToken = awssdk.ToString(out.NextToken)
			return records, encodeAWSParentCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(buses) {
		return records, encodeAWSParentCursor(state), nil
	}
	_ = settings
	return records, "", nil
}

func listEventBridgeArchives(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsEventBridgeArchive, string, error) {
	out, err := clients.eventBridge.ListArchives(ctx, &eventbridge.ListArchivesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgeArchive, 0, len(out.Archives))
	for _, archive := range out.Archives {
		name := awssdk.ToString(archive.ArchiveName)
		records = append(records, awsEventBridgeArchive{
			ARN:     eventBridgeArchiveARN(settings, name),
			Name:    name,
			Archive: archive,
		})
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listEventBridgePipes(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgePipe, string, error) {
	out, err := clients.pipes.ListPipes(ctx, &pipes.ListPipesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgePipe, 0, len(out.Pipes))
	for _, pipe := range out.Pipes {
		name := awssdk.ToString(pipe.Name)
		arn := awssdk.ToString(pipe.Arn)
		record := awsEventBridgePipe{ARN: arn, Name: name, Summary: pipe}
		if name != "" {
			describe, err := clients.pipes.DescribePipe(ctx, &pipes.DescribePipeInput{Name: awssdk.String(name)})
			if err != nil {
				return nil, "", fmt.Errorf("describe eventbridge pipe %q: %w", name, err)
			}
			record.Description = *describe
			record.ARN = firstNonEmpty(awssdk.ToString(describe.Arn), record.ARN)
			record.Name = firstNonEmpty(awssdk.ToString(describe.Name), record.Name)
		}
		if record.ARN != "" {
			tags, err := clients.pipes.ListTagsForResource(ctx, &pipes.ListTagsForResourceInput{ResourceArn: awssdk.String(record.ARN)})
			if err != nil {
				return nil, "", fmt.Errorf("list eventbridge pipe tags %q: %w", record.ARN, err)
			}
			record.Tags = cloneAWSStringMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSchedulerSchedules(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSchedulerSchedule, string, error) {
	out, err := clients.scheduler.ListSchedules(ctx, &scheduler.ListSchedulesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSchedulerSchedule, 0, len(out.Schedules))
	for _, schedule := range out.Schedules {
		arn := awssdk.ToString(schedule.Arn)
		record := awsSchedulerSchedule{ARN: arn, Name: awssdk.ToString(schedule.Name), Schedule: schedule}
		if arn != "" {
			tags, err := clients.scheduler.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list scheduler schedule tags %q: %w", arn, err)
			}
			record.Tags = schedulerTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSchedulerGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSchedulerGroup, string, error) {
	out, err := clients.scheduler.ListScheduleGroups(ctx, &scheduler.ListScheduleGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSchedulerGroup, 0, len(out.ScheduleGroups))
	for _, group := range out.ScheduleGroups {
		arn := awssdk.ToString(group.Arn)
		record := awsSchedulerGroup{ARN: arn, Name: awssdk.ToString(group.Name), Group: group}
		if arn != "" {
			tags, err := clients.scheduler.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list scheduler group tags %q: %w", arn, err)
			}
			record.Tags = schedulerTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listCloudWatchAlarms(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsCloudWatchAlarm, string, error) {
	out, err := clients.cloudWatch.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []cloudwatchtypes.AlarmType{cloudwatchtypes.AlarmTypeMetricAlarm, cloudwatchtypes.AlarmTypeCompositeAlarm},
		MaxRecords: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsCloudWatchAlarm, 0, len(out.MetricAlarms)+len(out.CompositeAlarms))
	for _, alarm := range out.MetricAlarms {
		copy := alarm
		record := awsCloudWatchAlarm{ARN: awssdk.ToString(alarm.AlarmArn), Name: awssdk.ToString(alarm.AlarmName), Type: "metric", MetricAlarm: &copy}
		if record.ARN != "" {
			tags, err := clients.cloudWatch.ListTagsForResource(ctx, &cloudwatch.ListTagsForResourceInput{ResourceARN: awssdk.String(record.ARN)})
			if err != nil {
				return nil, "", fmt.Errorf("list cloudwatch alarm tags %q: %w", record.ARN, err)
			}
			record.Tags = cloudWatchTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	for _, alarm := range out.CompositeAlarms {
		copy := alarm
		record := awsCloudWatchAlarm{ARN: awssdk.ToString(alarm.AlarmArn), Name: awssdk.ToString(alarm.AlarmName), Type: "composite", CompositeAlarm: &copy}
		if record.ARN != "" {
			tags, err := clients.cloudWatch.ListTagsForResource(ctx, &cloudwatch.ListTagsForResourceInput{ResourceARN: awssdk.String(record.ARN)})
			if err != nil {
				return nil, "", fmt.Errorf("list cloudwatch alarm tags %q: %w", record.ARN, err)
			}
			record.Tags = cloudWatchTagMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listCloudWatchLogGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsCloudWatchLogGroup, string, error) {
	out, err := clients.cloudWatchLogs.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsCloudWatchLogGroup, 0, len(out.LogGroups))
	for _, group := range out.LogGroups {
		arn := cloudWatchLogsTagARN(group)
		record := awsCloudWatchLogGroup{ARN: arn, Name: awssdk.ToString(group.LogGroupName), LogGroup: group}
		if arn != "" {
			tags, err := clients.cloudWatchLogs.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
			if err != nil {
				return nil, "", fmt.Errorf("list cloudwatch log group tags %q: %w", arn, err)
			}
			record.Tags = cloneAWSStringMap(tags.Tags)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSSMManagedInstances(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSMManagedInstance, string, error) {
	out, err := clients.ssm.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSSMManagedInstance, 0, len(out.InstanceInformationList))
	for _, instance := range out.InstanceInformationList {
		id := awssdk.ToString(instance.InstanceId)
		record := awsSSMManagedInstance{ID: id, Name: awssdk.ToString(instance.Name), Instance: instance}
		if id != "" {
			tags, err := clients.ssm.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceId: awssdk.String(id), ResourceType: ssmtypes.ResourceTypeForTaggingManagedInstance})
			if err != nil {
				return nil, "", fmt.Errorf("list ssm managed instance tags %q: %w", id, err)
			}
			record.Tags = ssmTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSSMDocuments(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSMDocument, string, error) {
	out, err := clients.ssm.ListDocuments(ctx, &ssm.ListDocumentsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSSMDocument, 0, len(out.DocumentIdentifiers))
	for _, document := range out.DocumentIdentifiers {
		name := awssdk.ToString(document.Name)
		record := awsSSMDocument{Name: name, Document: document, Tags: ssmTagMap(document.Tags)}
		if name != "" && len(record.Tags) == 0 {
			tags, err := clients.ssm.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceId: awssdk.String(name), ResourceType: ssmtypes.ResourceTypeForTaggingDocument})
			if err != nil {
				return nil, "", fmt.Errorf("list ssm document tags %q: %w", name, err)
			}
			record.Tags = ssmTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listSSMAssociations(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSSMAssociation, string, error) {
	out, err := clients.ssm.ListAssociations(ctx, &ssm.ListAssociationsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 50))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSSMAssociation, 0, len(out.Associations))
	for _, association := range out.Associations {
		id := awssdk.ToString(association.AssociationId)
		record := awsSSMAssociation{ID: id, Name: firstNonEmpty(awssdk.ToString(association.AssociationName), awssdk.ToString(association.Name)), Association: association}
		if id != "" {
			tags, err := clients.ssm.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceId: awssdk.String(id), ResourceType: ssmtypes.ResourceTypeForTaggingAssociation})
			if err != nil {
				return nil, "", fmt.Errorf("list ssm association tags %q: %w", id, err)
			}
			record.Tags = ssmTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
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
		name := awssdk.ToString(parameter.Name)
		record := awsSSMParameter{ARN: awssdk.ToString(parameter.ARN), Name: name, Parameter: parameter}
		if name != "" {
			tags, err := clients.ssm.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{ResourceId: awssdk.String(name), ResourceType: ssmtypes.ResourceTypeForTaggingParameter})
			if err != nil {
				return nil, "", fmt.Errorf("list ssm parameter tags %q: %w", name, err)
			}
			record.Tags = ssmTagMap(tags.TagList)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func appRunnerServiceEvent(settings settings, record awsAppRunnerService) (*primitives.Event, error) {
	service := record.Service
	arn := firstNonEmpty(awssdk.ToString(service.ServiceArn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(service.ServiceName), record.Name, awsResourceName(arn))
	roleARN := ""
	if service.InstanceConfiguration != nil {
		roleARN = awssdk.ToString(service.InstanceConfiguration.InstanceRoleArn)
	}
	attributes := commonCloudAssetAttributes(settings, settings.region, familyAppRunnerService, firstNonEmpty(arn, name), name, "apprunner_service", record.Tags)
	attributes["arn"] = arn
	attributes["service_arn"] = arn
	attributes["service_id"] = awssdk.ToString(service.ServiceId)
	attributes["service_name"] = name
	attributes["service_url"] = awssdk.ToString(service.ServiceUrl)
	attributes["state"] = string(service.Status)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["runtime_role_arn"] = roleARN
	attributes["runtime_role_name"] = roleNameFromARN(roleARN)
	attributes["cpu"] = appRunnerCPU(service)
	attributes["memory"] = appRunnerMemory(service)
	attributes["egress_type"] = appRunnerEgressType(service)
	attributes["vpc_connector_arn"] = appRunnerVPCConnectorARN(service)
	attributes["public"] = boolString(appRunnerPublic(service))
	attributes["internet_exposed"] = attributes["public"]
	attributes["source_repository"] = appRunnerSourceRepository(service)
	attributes["source_image"] = appRunnerSourceImage(service)
	attributes["auto_deployments_enabled"] = appRunnerAutoDeploymentsEnabled(service)
	addTimeAttribute(attributes, "created_at", service.CreatedAt)
	addTimeAttribute(attributes, "updated_at", service.UpdatedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service": service, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-apprunner-service-"+firstNonEmpty(arn, name), "aws.apprunner_service", "aws/apprunner_service/v1", payload, attributes, firstTime(service.UpdatedAt, service.CreatedAt))
}

func stepFunctionStateMachineEvent(settings settings, record awsStepFunctionStateMachine) (*primitives.Event, error) {
	describe := record.Description
	arn := firstNonEmpty(awssdk.ToString(describe.StateMachineArn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(describe.Name), record.Name, awsResourceName(arn))
	roleARN := awssdk.ToString(describe.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyStepFunctionStateMachine, firstNonEmpty(arn, name), name, "stepfunctions_state_machine", record.Tags)
	attributes["arn"] = arn
	attributes["state_machine_arn"] = arn
	attributes["state_machine_name"] = name
	attributes["state_machine_type"] = string(describe.Type)
	attributes["state"] = string(describe.Status)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["runtime_role_arn"] = roleARN
	attributes["runtime_role_name"] = roleNameFromARN(roleARN)
	attributes["revision_id"] = awssdk.ToString(describe.RevisionId)
	attributes["tracing_enabled"] = boolString(describe.TracingConfiguration != nil && describe.TracingConfiguration.Enabled)
	addTimeAttribute(attributes, "created_at", firstTimePtr(describe.CreationDate, record.ListItem.CreationDate))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "state_machine": describe, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-stepfunctions-state-machine-"+firstNonEmpty(arn, name), "aws.stepfunctions_state_machine", "aws/stepfunctions_state_machine/v1", payload, attributes, firstTime(describe.CreationDate, record.ListItem.CreationDate))
}

func stepFunctionActivityEvent(settings settings, record awsStepFunctionActivity) (*primitives.Event, error) {
	activity := record.Activity
	arn := firstNonEmpty(awssdk.ToString(activity.ActivityArn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(activity.Name), record.Name, awsResourceName(arn))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyStepFunctionActivity, firstNonEmpty(arn, name), name, "stepfunctions_activity", record.Tags)
	attributes["arn"] = arn
	attributes["activity_arn"] = arn
	attributes["activity_name"] = name
	addTimeAttribute(attributes, "created_at", activity.CreationDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "activity": activity, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-stepfunctions-activity-"+firstNonEmpty(arn, name), "aws.stepfunctions_activity", "aws/stepfunctions_activity/v1", payload, attributes, firstTime(activity.CreationDate))
}

func eventBridgeBusEvent(settings settings, record awsEventBridgeBus) (*primitives.Event, error) {
	bus := record.Bus
	arn := firstNonEmpty(awssdk.ToString(bus.Arn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(bus.Name), record.Name, awsResourceName(arn))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeBus, firstNonEmpty(arn, name), name, "eventbridge_event_bus", record.Tags)
	attributes["arn"] = arn
	attributes["event_bus_arn"] = arn
	attributes["event_bus_name"] = name
	attributes["description"] = awssdk.ToString(bus.Description)
	attributes["public"] = boolString(policyAllowsWildcardPrincipal(awssdk.ToString(bus.Policy)))
	attributes["internet_exposed"] = attributes["public"]
	addTimeAttribute(attributes, "created_at", bus.CreationTime)
	addTimeAttribute(attributes, "modified_at", bus.LastModifiedTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "event_bus": bus, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-event-bus-"+firstNonEmpty(arn, name), "aws.eventbridge_event_bus", "aws/eventbridge_event_bus/v1", payload, attributes, firstTime(bus.LastModifiedTime, bus.CreationTime))
}

func eventBridgeRuleEvent(settings settings, record awsEventBridgeRule) (*primitives.Event, error) {
	rule := record.Rule
	arn := firstNonEmpty(awssdk.ToString(rule.Arn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(rule.Name), record.Name, awsResourceName(arn))
	roleARN := awssdk.ToString(rule.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeRule, firstNonEmpty(arn, name), name, "eventbridge_rule", record.Tags)
	attributes["arn"] = arn
	attributes["rule_arn"] = arn
	attributes["rule_name"] = name
	attributes["event_bus_arn"] = record.BusARN
	attributes["event_bus_name"] = firstNonEmpty(awssdk.ToString(rule.EventBusName), record.BusName)
	attributes["schedule_expression"] = awssdk.ToString(rule.ScheduleExpression)
	attributes["managed_by"] = awssdk.ToString(rule.ManagedBy)
	attributes["state"] = string(rule.State)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["runtime_role_arn"] = roleARN
	attributes["runtime_role_name"] = roleNameFromARN(roleARN)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "rule": rule, "event_bus_name": record.BusName, "event_bus_arn": record.BusARN, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-rule-"+firstNonEmpty(arn, name), "aws.eventbridge_rule", "aws/eventbridge_rule/v1", payload, attributes, time.Now().UTC())
}

func eventBridgeArchiveEvent(settings settings, record awsEventBridgeArchive) (*primitives.Event, error) {
	archive := record.Archive
	name := firstNonEmpty(awssdk.ToString(archive.ArchiveName), record.Name)
	arn := firstNonEmpty(record.ARN, eventBridgeArchiveARN(settings, name))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeArchive, firstNonEmpty(arn, name), name, "eventbridge_archive", nil)
	attributes["arn"] = arn
	attributes["archive_arn"] = arn
	attributes["archive_name"] = name
	attributes["event_source_arn"] = awssdk.ToString(archive.EventSourceArn)
	attributes["state"] = string(archive.State)
	attributes["retention_days"] = int32AttrString(archive.RetentionDays)
	attributes["event_count"] = strconv.FormatInt(archive.EventCount, 10)
	attributes["size_bytes"] = strconv.FormatInt(archive.SizeBytes, 10)
	addTimeAttribute(attributes, "created_at", archive.CreationTime)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "archive": archive})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-archive-"+firstNonEmpty(arn, name), "aws.eventbridge_archive", "aws/eventbridge_archive/v1", payload, attributes, firstTime(archive.CreationTime))
}

func eventBridgePipeEvent(settings settings, record awsEventBridgePipe) (*primitives.Event, error) {
	describe := record.Description
	arn := firstNonEmpty(awssdk.ToString(describe.Arn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(describe.Name), record.Name, awsResourceName(arn))
	roleARN := awssdk.ToString(describe.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgePipe, firstNonEmpty(arn, name), name, "eventbridge_pipe", record.Tags)
	attributes["arn"] = arn
	attributes["pipe_arn"] = arn
	attributes["pipe_name"] = name
	attributes["state"] = string(firstNonEmpty(string(describe.CurrentState), string(record.Summary.CurrentState)))
	attributes["desired_state"] = string(describe.DesiredState)
	attributes["source_arn"] = firstNonEmpty(awssdk.ToString(describe.Source), awssdk.ToString(record.Summary.Source))
	attributes["target_arn"] = firstNonEmpty(awssdk.ToString(describe.Target), awssdk.ToString(record.Summary.Target))
	attributes["enrichment_arn"] = firstNonEmpty(awssdk.ToString(describe.Enrichment), awssdk.ToString(record.Summary.Enrichment))
	attributes["kms_key_id"] = awssdk.ToString(describe.KmsKeyIdentifier)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["runtime_role_arn"] = roleARN
	attributes["runtime_role_name"] = roleNameFromARN(roleARN)
	addTimeAttribute(attributes, "created_at", firstTimePtr(describe.CreationTime, record.Summary.CreationTime))
	addTimeAttribute(attributes, "modified_at", firstTimePtr(describe.LastModifiedTime, record.Summary.LastModifiedTime))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "pipe": describe, "summary": record.Summary, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-pipe-"+firstNonEmpty(arn, name), "aws.eventbridge_pipe", "aws/eventbridge_pipe/v1", payload, attributes, firstTime(describe.LastModifiedTime, describe.CreationTime, record.Summary.LastModifiedTime, record.Summary.CreationTime))
}

func schedulerScheduleEvent(settings settings, record awsSchedulerSchedule) (*primitives.Event, error) {
	schedule := record.Schedule
	arn := firstNonEmpty(awssdk.ToString(schedule.Arn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(schedule.Name), record.Name, awsResourceName(arn))
	targetARN := ""
	if schedule.Target != nil {
		targetARN = awssdk.ToString(schedule.Target.Arn)
	}
	attributes := commonCloudAssetAttributes(settings, settings.region, familySchedulerSchedule, firstNonEmpty(arn, name), name, "scheduler_schedule", record.Tags)
	attributes["arn"] = arn
	attributes["schedule_arn"] = arn
	attributes["schedule_name"] = name
	attributes["schedule_group_name"] = awssdk.ToString(schedule.GroupName)
	attributes["target_arn"] = targetARN
	attributes["state"] = string(schedule.State)
	addTimeAttribute(attributes, "created_at", schedule.CreationDate)
	addTimeAttribute(attributes, "modified_at", schedule.LastModificationDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "schedule": schedule, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-scheduler-schedule-"+firstNonEmpty(arn, name), "aws.scheduler_schedule", "aws/scheduler_schedule/v1", payload, attributes, firstTime(schedule.LastModificationDate, schedule.CreationDate))
}

func schedulerGroupEvent(settings settings, record awsSchedulerGroup) (*primitives.Event, error) {
	group := record.Group
	arn := firstNonEmpty(awssdk.ToString(group.Arn), record.ARN)
	name := firstNonEmpty(awssdk.ToString(group.Name), record.Name, awsResourceName(arn))
	attributes := commonCloudAssetAttributes(settings, settings.region, familySchedulerGroup, firstNonEmpty(arn, name), name, "scheduler_schedule_group", record.Tags)
	attributes["arn"] = arn
	attributes["schedule_group_arn"] = arn
	attributes["schedule_group_name"] = name
	attributes["state"] = string(group.State)
	addTimeAttribute(attributes, "created_at", group.CreationDate)
	addTimeAttribute(attributes, "modified_at", group.LastModificationDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "schedule_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-scheduler-schedule-group-"+firstNonEmpty(arn, name), "aws.scheduler_schedule_group", "aws/scheduler_schedule_group/v1", payload, attributes, firstTime(group.LastModificationDate, group.CreationDate))
}

func cloudWatchAlarmEvent(settings settings, record awsCloudWatchAlarm) (*primitives.Event, error) {
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCloudWatchAlarm, firstNonEmpty(record.ARN, record.Name), record.Name, "cloudwatch_alarm", record.Tags)
	attributes["arn"] = record.ARN
	attributes["alarm_arn"] = record.ARN
	attributes["alarm_name"] = record.Name
	attributes["alarm_type"] = record.Type
	if record.MetricAlarm != nil {
		alarm := record.MetricAlarm
		attributes["state"] = string(alarm.StateValue)
		attributes["metric_name"] = awssdk.ToString(alarm.MetricName)
		attributes["namespace"] = awssdk.ToString(alarm.Namespace)
		attributes["comparison_operator"] = string(alarm.ComparisonOperator)
		attributes["actions_enabled"] = boolString(awssdk.ToBool(alarm.ActionsEnabled))
		addTimeAttribute(attributes, "updated_at", alarm.AlarmConfigurationUpdatedTimestamp)
	} else if record.CompositeAlarm != nil {
		alarm := record.CompositeAlarm
		attributes["state"] = string(alarm.StateValue)
		attributes["alarm_rule"] = awssdk.ToString(alarm.AlarmRule)
		attributes["actions_enabled"] = boolString(awssdk.ToBool(alarm.ActionsEnabled))
		addTimeAttribute(attributes, "updated_at", alarm.AlarmConfigurationUpdatedTimestamp)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "metric_alarm": record.MetricAlarm, "composite_alarm": record.CompositeAlarm, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudwatch-alarm-"+firstNonEmpty(record.ARN, record.Name), "aws.cloudwatch_alarm", "aws/cloudwatch_alarm/v1", payload, attributes, time.Now().UTC())
}

func cloudWatchLogGroupEvent(settings settings, record awsCloudWatchLogGroup) (*primitives.Event, error) {
	group := record.LogGroup
	arn := firstNonEmpty(record.ARN, cloudWatchLogsTagARN(group))
	name := firstNonEmpty(awssdk.ToString(group.LogGroupName), record.Name, awsResourceName(arn))
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCloudWatchLogGroup, firstNonEmpty(arn, name), name, "cloudwatch_log_group", record.Tags)
	attributes["arn"] = arn
	attributes["log_group_arn"] = arn
	attributes["log_group_name"] = name
	attributes["log_group_class"] = string(group.LogGroupClass)
	attributes["kms_key_id"] = awssdk.ToString(group.KmsKeyId)
	attributes["retention_days"] = int32AttrString(group.RetentionInDays)
	attributes["stored_bytes"] = int64PtrAttrString(group.StoredBytes)
	attributes["deletion_protection"] = boolPtrString(group.DeletionProtectionEnabled)
	attributes["data_protection_status"] = string(group.DataProtectionStatus)
	occurredAt := unixMillisTime(group.CreationTime)
	if !occurredAt.IsZero() {
		attributes["created_at"] = occurredAt.UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "log_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-cloudwatch-log-group-"+firstNonEmpty(arn, name), "aws.cloudwatch_log_group", "aws/cloudwatch_log_group/v1", payload, attributes, firstNonZeroTime(occurredAt, time.Now().UTC()))
}

func ssmManagedInstanceEvent(settings settings, record awsSSMManagedInstance) (*primitives.Event, error) {
	instance := record.Instance
	id := firstNonEmpty(awssdk.ToString(instance.InstanceId), record.ID)
	name := firstNonEmpty(awssdk.ToString(instance.Name), awssdk.ToString(instance.ComputerName), record.Name, id)
	roleARN := awssdk.ToString(instance.IamRole)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMManagedInstance, id, name, "ssm_managed_instance", record.Tags)
	attributes["managed_instance_id"] = id
	attributes["instance_id"] = id
	attributes["computer_name"] = awssdk.ToString(instance.ComputerName)
	attributes["ip_address"] = awssdk.ToString(instance.IPAddress)
	attributes["platform_name"] = awssdk.ToString(instance.PlatformName)
	attributes["platform_type"] = string(instance.PlatformType)
	attributes["platform_version"] = awssdk.ToString(instance.PlatformVersion)
	attributes["agent_version"] = awssdk.ToString(instance.AgentVersion)
	attributes["state"] = string(instance.PingStatus)
	attributes["association_status"] = awssdk.ToString(instance.AssociationStatus)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	addTimeAttribute(attributes, "last_ping_at", instance.LastPingDateTime)
	addTimeAttribute(attributes, "last_association_execution_at", instance.LastAssociationExecutionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "managed_instance": instance, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-managed-instance-"+id, "aws.ssm_managed_instance", "aws/ssm_managed_instance/v1", payload, attributes, firstTime(instance.LastPingDateTime))
}

func ssmDocumentEvent(settings settings, record awsSSMDocument) (*primitives.Event, error) {
	document := record.Document
	name := firstNonEmpty(awssdk.ToString(document.Name), record.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMDocument, name, firstNonEmpty(awssdk.ToString(document.DisplayName), name), "ssm_document", record.Tags)
	attributes["document_name"] = name
	attributes["document_type"] = string(document.DocumentType)
	attributes["document_format"] = string(document.DocumentFormat)
	attributes["document_version"] = awssdk.ToString(document.DocumentVersion)
	attributes["owner"] = firstNonEmpty(attributes["owner"], awssdk.ToString(document.Owner))
	attributes["author"] = awssdk.ToString(document.Author)
	attributes["review_status"] = string(document.ReviewStatus)
	attributes["schema_version"] = awssdk.ToString(document.SchemaVersion)
	attributes["target_type"] = awssdk.ToString(document.TargetType)
	addTimeAttribute(attributes, "created_at", document.CreatedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "document": document, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-document-"+name, "aws.ssm_document", "aws/ssm_document/v1", payload, attributes, firstTime(document.CreatedDate))
}

func ssmAssociationEvent(settings settings, record awsSSMAssociation) (*primitives.Event, error) {
	association := record.Association
	id := firstNonEmpty(awssdk.ToString(association.AssociationId), record.ID)
	name := firstNonEmpty(awssdk.ToString(association.AssociationName), record.Name, id)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMAssociation, firstNonEmpty(id, name), name, "ssm_association", record.Tags)
	attributes["association_id"] = id
	attributes["association_name"] = name
	attributes["association_version"] = awssdk.ToString(association.AssociationVersion)
	attributes["document_name"] = awssdk.ToString(association.Name)
	attributes["document_version"] = awssdk.ToString(association.DocumentVersion)
	attributes["instance_id"] = awssdk.ToString(association.InstanceId)
	attributes["schedule_expression"] = awssdk.ToString(association.ScheduleExpression)
	attributes["targets"] = encodeSSMTargets(association.Targets)
	addTimeAttribute(attributes, "last_execution_at", association.LastExecutionDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "association": association, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-association-"+firstNonEmpty(id, name), "aws.ssm_association", "aws/ssm_association/v1", payload, attributes, firstTime(association.LastExecutionDate))
}

func ssmParameterEvent(settings settings, record awsSSMParameter) (*primitives.Event, error) {
	parameter := record.Parameter
	arn := firstNonEmpty(awssdk.ToString(parameter.ARN), record.ARN)
	name := firstNonEmpty(awssdk.ToString(parameter.Name), record.Name, awsResourceName(arn))
	attributes := commonCloudAssetAttributes(settings, settings.region, familySSMParameter, firstNonEmpty(arn, name), name, "ssm_parameter", record.Tags)
	attributes["arn"] = arn
	attributes["parameter_arn"] = arn
	attributes["parameter_name"] = name
	attributes["parameter_type"] = string(parameter.Type)
	attributes["tier"] = string(parameter.Tier)
	attributes["data_type"] = awssdk.ToString(parameter.DataType)
	attributes["kms_key_id"] = awssdk.ToString(parameter.KeyId)
	attributes["encryption"] = boolString(parameter.Type == ssmtypes.ParameterTypeSecureString)
	attributes["version"] = strconv.FormatInt(parameter.Version, 10)
	attributes["last_modified_user"] = awssdk.ToString(parameter.LastModifiedUser)
	addTimeAttribute(attributes, "modified_at", parameter.LastModifiedDate)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "parameter": parameter, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-ssm-parameter-"+firstNonEmpty(arn, name), "aws.ssm_parameter", "aws/ssm_parameter/v1", payload, attributes, firstTime(parameter.LastModifiedDate))
}

func listAllEventBridgeBuses(ctx context.Context, clients awsClients) ([]awsEventBridgeBus, error) {
	var buses []awsEventBridgeBus
	var next *string
	for {
		out, err := clients.eventBridge.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{Limit: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, bus := range out.EventBuses {
			buses = append(buses, awsEventBridgeBus{ARN: awssdk.ToString(bus.Arn), Name: awssdk.ToString(bus.Name), Bus: bus})
		}
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	if len(buses) == 0 {
		return []awsEventBridgeBus{{Name: "default"}}, nil
	}
	return buses, nil
}

func appRunnerCPU(service apprunnertypes.Service) string {
	if service.InstanceConfiguration == nil {
		return ""
	}
	return awssdk.ToString(service.InstanceConfiguration.Cpu)
}

func appRunnerMemory(service apprunnertypes.Service) string {
	if service.InstanceConfiguration == nil {
		return ""
	}
	return awssdk.ToString(service.InstanceConfiguration.Memory)
}

func appRunnerEgressType(service apprunnertypes.Service) string {
	if service.NetworkConfiguration == nil || service.NetworkConfiguration.EgressConfiguration == nil {
		return ""
	}
	return string(service.NetworkConfiguration.EgressConfiguration.EgressType)
}

func appRunnerVPCConnectorARN(service apprunnertypes.Service) string {
	if service.NetworkConfiguration == nil || service.NetworkConfiguration.EgressConfiguration == nil {
		return ""
	}
	return awssdk.ToString(service.NetworkConfiguration.EgressConfiguration.VpcConnectorArn)
}

func appRunnerPublic(service apprunnertypes.Service) bool {
	if service.NetworkConfiguration == nil || service.NetworkConfiguration.IngressConfiguration == nil {
		return true
	}
	return service.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible
}

func appRunnerSourceRepository(service apprunnertypes.Service) string {
	if service.SourceConfiguration == nil || service.SourceConfiguration.CodeRepository == nil {
		return ""
	}
	return awssdk.ToString(service.SourceConfiguration.CodeRepository.RepositoryUrl)
}

func appRunnerSourceImage(service apprunnertypes.Service) string {
	if service.SourceConfiguration == nil || service.SourceConfiguration.ImageRepository == nil {
		return ""
	}
	return awssdk.ToString(service.SourceConfiguration.ImageRepository.ImageIdentifier)
}

func appRunnerAutoDeploymentsEnabled(service apprunnertypes.Service) string {
	if service.SourceConfiguration == nil || service.SourceConfiguration.AutoDeploymentsEnabled == nil {
		return ""
	}
	return boolString(awssdk.ToBool(service.SourceConfiguration.AutoDeploymentsEnabled))
}

func eventBridgeArchiveARN(settings settings, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:events:%s:%s:archive/%s", settings.region, settings.accountID, name)
}

func cloudWatchLogsTagARN(group cloudwatchlogstypes.LogGroup) string {
	if arn := awssdk.ToString(group.LogGroupArn); arn != "" {
		return strings.TrimSuffix(arn, ":*")
	}
	return strings.TrimSuffix(awssdk.ToString(group.Arn), ":*")
}

func int64PtrAttrString(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}

func boolPtrString(value *bool) string {
	if value == nil {
		return ""
	}
	return boolString(*value)
}

func cloneAWSStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func unixMillisTime(value *int64) time.Time {
	if value == nil || *value <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(*value).UTC()
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}

func firstTimePtr(values ...*time.Time) *time.Time {
	for _, value := range values {
		if value != nil && !value.IsZero() {
			return value
		}
	}
	return nil
}

func encodeSSMTargets(targets []ssmtypes.Target) string {
	if len(targets) == 0 {
		return ""
	}
	values := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		values = append(values, map[string]any{"key": awssdk.ToString(target.Key), "values": target.Values})
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(payload)
}

func appRunnerTagMap(tags []apprunnertypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func sfnTagMap(tags []sfntypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func eventBridgeTagMap(tags []eventbridgetypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func schedulerTagMap(tags []schedulertypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func cloudWatchTagMap(tags []cloudwatchtypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func ssmTagMap(tags []ssmtypes.Tag) map[string]string {
	out := map[string]string{}
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func decodeAWSParentCursor(raw string, label string) (awsParentPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return awsParentPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return awsParentPageCursor{}, fmt.Errorf("decode %s cursor: %w", label, err)
	}
	var cursor awsParentPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return awsParentPageCursor{}, fmt.Errorf("parse %s cursor: %w", label, err)
	}
	return cursor, nil
}

func encodeAWSParentCursor(cursor awsParentPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
