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
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsChildPageCursor struct {
	ParentIndex int    `json:"parent_index,omitempty"`
	NextToken   string `json:"next_token,omitempty"`
}

type awsSFNStateMachine struct {
	StateMachine sfn.DescribeStateMachineOutput
	Tags         map[string]string
}

type awsSFNActivity struct {
	Activity sfn.DescribeActivityOutput
	Tags     map[string]string
}

type awsEventBridgeBus struct {
	Bus  eventbridge.DescribeEventBusOutput
	Tags map[string]string
}

type awsEventBridgeRule struct {
	Rule    eventbridgetypes.Rule
	Targets []eventbridgetypes.Target
	Tags    map[string]string
}

type awsEventBridgeArchive struct {
	Archive eventbridge.DescribeArchiveOutput
	Tags    map[string]string
}

type awsEventBridgePipe struct {
	Pipe pipes.DescribePipeOutput
	Tags map[string]string
}

type awsSchedulerScheduleGroup struct {
	Group scheduler.GetScheduleGroupOutput
	Tags  map[string]string
}

type awsSchedulerSchedule struct {
	Schedule scheduler.GetScheduleOutput
	Tags     map[string]string
}

func listSFNStateMachines(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSFNStateMachine, string, error) {
	output, err := clients.sfn.ListStateMachines(ctx, &sfn.ListStateMachinesInput{
		MaxResults: int32(boundedAWSPageSize(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSFNStateMachine, 0, len(output.StateMachines))
	for _, summary := range output.StateMachines {
		arn := awssdk.ToString(summary.StateMachineArn)
		if arn == "" {
			continue
		}
		describe, err := clients.sfn.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: awssdk.String(arn), IncludedData: sfntypes.IncludedDataMetadataOnly})
		if err != nil {
			return nil, "", fmt.Errorf("describe step functions state machine %q: %w", arn, err)
		}
		record := awsSFNStateMachine{StateMachine: *describe}
		if tags, err := clients.sfn.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = sfnTagMap(tags.Tags)
		} else if !optionalAWSError(err, "StateMachineDoesNotExist", "ResourceNotFound") {
			return nil, "", fmt.Errorf("list step functions state machine tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listSFNActivities(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSFNActivity, string, error) {
	output, err := clients.sfn.ListActivities(ctx, &sfn.ListActivitiesInput{
		MaxResults: int32(boundedAWSPageSize(limit, 1, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSFNActivity, 0, len(output.Activities))
	for _, summary := range output.Activities {
		arn := awssdk.ToString(summary.ActivityArn)
		if arn == "" {
			continue
		}
		describe, err := clients.sfn.DescribeActivity(ctx, &sfn.DescribeActivityInput{ActivityArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe step functions activity %q: %w", arn, err)
		}
		record := awsSFNActivity{Activity: *describe}
		if tags, err := clients.sfn.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
			record.Tags = sfnTagMap(tags.Tags)
		} else if !optionalAWSError(err, "ActivityDoesNotExist", "ResourceNotFound") {
			return nil, "", fmt.Errorf("list step functions activity tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listEventBridgeBuses(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgeBus, string, error) {
	output, err := clients.eventBridge.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgeBus, 0, len(output.EventBuses))
	for _, bus := range output.EventBuses {
		name := awssdk.ToString(bus.Name)
		if name == "" {
			continue
		}
		describe, err := clients.eventBridge.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe eventbridge event bus %q: %w", name, err)
		}
		record := awsEventBridgeBus{Bus: *describe}
		if arn := awssdk.ToString(describe.Arn); arn != "" {
			if tags, err := clients.eventBridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)}); err == nil {
				record.Tags = eventBridgeTagMap(tags.Tags)
			} else if !optionalAWSError(err, "ResourceNotFoundException") {
				return nil, "", fmt.Errorf("list eventbridge event bus tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listEventBridgeRules(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgeRule, string, error) {
	buses, err := listAllEventBridgeBusNames(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(buses) == 0 {
		return nil, "", nil
	}
	state, err := decodeAWSChildCursor(cursor, "eventbridge rule")
	if err != nil {
		return nil, "", err
	}
	if state.ParentIndex < 0 || state.ParentIndex >= len(buses) {
		state.ParentIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsEventBridgeRule, 0, remaining)
	for state.ParentIndex < len(buses) && len(records) < remaining {
		busName := buses[state.ParentIndex]
		output, err := clients.eventBridge.ListRules(ctx, &eventbridge.ListRulesInput{
			EventBusName: awssdk.String(busName),
			Limit:        awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:    stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list eventbridge rules for bus %q: %w", busName, err)
		}
		for _, rule := range output.Rules {
			record := awsEventBridgeRule{Rule: rule}
			targets, err := listAllEventBridgeTargets(ctx, clients, busName, awssdk.ToString(rule.Name))
			if err != nil {
				return nil, "", err
			}
			record.Targets = targets
			if arn := awssdk.ToString(rule.Arn); arn != "" {
				if tags, err := clients.eventBridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)}); err == nil {
					record.Tags = eventBridgeTagMap(tags.Tags)
				} else if !optionalAWSError(err, "ResourceNotFoundException") {
					return nil, "", fmt.Errorf("list eventbridge rule tags %q: %w", arn, err)
				}
			}
			records = append(records, record)
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.NextToken = awssdk.ToString(output.NextToken)
			return records, encodeAWSChildCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(buses) {
		return records, encodeAWSChildCursor(state), nil
	}
	return records, "", nil
}

func listEventBridgeArchives(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgeArchive, string, error) {
	output, err := clients.eventBridge.ListArchives(ctx, &eventbridge.ListArchivesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgeArchive, 0, len(output.Archives))
	for _, archive := range output.Archives {
		name := awssdk.ToString(archive.ArchiveName)
		if name == "" {
			continue
		}
		describe, err := clients.eventBridge.DescribeArchive(ctx, &eventbridge.DescribeArchiveInput{ArchiveName: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe eventbridge archive %q: %w", name, err)
		}
		record := awsEventBridgeArchive{Archive: *describe}
		if arn := awssdk.ToString(describe.ArchiveArn); arn != "" {
			if tags, err := clients.eventBridge.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{ResourceARN: awssdk.String(arn)}); err == nil {
				record.Tags = eventBridgeTagMap(tags.Tags)
			} else if !optionalAWSError(err, "ResourceNotFoundException") {
				return nil, "", fmt.Errorf("list eventbridge archive tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listEventBridgePipes(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsEventBridgePipe, string, error) {
	output, err := clients.pipes.ListPipes(ctx, &pipes.ListPipesInput{
		Limit:     awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken: stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsEventBridgePipe, 0, len(output.Pipes))
	for _, pipe := range output.Pipes {
		name := awssdk.ToString(pipe.Name)
		if name == "" {
			continue
		}
		describe, err := clients.pipes.DescribePipe(ctx, &pipes.DescribePipeInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("describe eventbridge pipe %q: %w", name, err)
		}
		record := awsEventBridgePipe{Pipe: *describe, Tags: describe.Tags}
		if arn := awssdk.ToString(describe.Arn); arn != "" {
			if tags, err := clients.pipes.ListTagsForResource(ctx, &pipes.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
				record.Tags = tags.Tags
			} else if !optionalAWSError(err, "ResourceNotFoundException", "NotFoundException") {
				return nil, "", fmt.Errorf("list eventbridge pipe tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listSchedulerScheduleGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSchedulerScheduleGroup, string, error) {
	output, err := clients.scheduler.ListScheduleGroups(ctx, &scheduler.ListScheduleGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsSchedulerScheduleGroup, 0, len(output.ScheduleGroups))
	for _, group := range output.ScheduleGroups {
		name := awssdk.ToString(group.Name)
		if name == "" {
			continue
		}
		describe, err := clients.scheduler.GetScheduleGroup(ctx, &scheduler.GetScheduleGroupInput{Name: awssdk.String(name)})
		if err != nil {
			return nil, "", fmt.Errorf("get scheduler schedule group %q: %w", name, err)
		}
		record := awsSchedulerScheduleGroup{Group: *describe}
		if arn := awssdk.ToString(describe.Arn); arn != "" {
			if tags, err := clients.scheduler.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
				record.Tags = schedulerTagMap(tags.Tags)
			} else if !optionalAWSError(err, "ResourceNotFoundException", "NotFoundException") {
				return nil, "", fmt.Errorf("list scheduler schedule group tags %q: %w", arn, err)
			}
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(output.NextToken), nil
}

func listSchedulerSchedules(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsSchedulerSchedule, string, error) {
	groups, err := listAllSchedulerScheduleGroupNames(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	if len(groups) == 0 {
		return nil, "", nil
	}
	state, err := decodeAWSChildCursor(cursor, "scheduler schedule")
	if err != nil {
		return nil, "", err
	}
	if state.ParentIndex < 0 || state.ParentIndex >= len(groups) {
		state.ParentIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsSchedulerSchedule, 0, remaining)
	for state.ParentIndex < len(groups) && len(records) < remaining {
		groupName := groups[state.ParentIndex]
		output, err := clients.scheduler.ListSchedules(ctx, &scheduler.ListSchedulesInput{
			GroupName:  awssdk.String(groupName),
			MaxResults: awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:  stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list scheduler schedules for group %q: %w", groupName, err)
		}
		for _, summary := range output.Schedules {
			name := awssdk.ToString(summary.Name)
			if name == "" {
				continue
			}
			describe, err := clients.scheduler.GetSchedule(ctx, &scheduler.GetScheduleInput{Name: awssdk.String(name), GroupName: awssdk.String(groupName)})
			if err != nil {
				return nil, "", fmt.Errorf("get scheduler schedule %q/%q: %w", groupName, name, err)
			}
			record := awsSchedulerSchedule{Schedule: *describe}
			if arn := awssdk.ToString(describe.Arn); arn != "" {
				if tags, err := clients.scheduler.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)}); err == nil {
					record.Tags = schedulerTagMap(tags.Tags)
				} else if !optionalAWSError(err, "ResourceNotFoundException", "NotFoundException") {
					return nil, "", fmt.Errorf("list scheduler schedule tags %q: %w", arn, err)
				}
			}
			records = append(records, record)
		}
		if awssdk.ToString(output.NextToken) != "" {
			state.NextToken = awssdk.ToString(output.NextToken)
			return records, encodeAWSChildCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(groups) {
		return records, encodeAWSChildCursor(state), nil
	}
	return records, "", nil
}

func sfnStateMachineEvent(settings settings, record awsSFNStateMachine) (*primitives.Event, error) {
	stateMachine := record.StateMachine
	arn := awssdk.ToString(stateMachine.StateMachineArn)
	name := awssdk.ToString(stateMachine.Name)
	roleARN := awssdk.ToString(stateMachine.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySFNStateMachine, firstNonEmpty(arn, name), name, "sfn_state_machine", record.Tags)
	attributes["arn"] = arn
	attributes["state_machine_arn"] = arn
	attributes["state_machine_name"] = name
	attributes["state_machine_type"] = string(stateMachine.Type)
	attributes["state"] = string(stateMachine.Status)
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["relationship"] = "runs_as"
	attributes["revision_id"] = awssdk.ToString(stateMachine.RevisionId)
	attributes["tracing_enabled"] = boolString(stateMachine.TracingConfiguration != nil && stateMachine.TracingConfiguration.Enabled)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "state_machine": stateMachine, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sfn-state-machine-"+firstNonEmpty(arn, name), "aws.sfn_state_machine", "aws/sfn_state_machine/v1", payload, attributes, firstTime(stateMachine.CreationDate))
}

func sfnActivityEvent(settings settings, record awsSFNActivity) (*primitives.Event, error) {
	activity := record.Activity
	arn := awssdk.ToString(activity.ActivityArn)
	name := awssdk.ToString(activity.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySFNActivity, firstNonEmpty(arn, name), name, "sfn_activity", record.Tags)
	attributes["arn"] = arn
	attributes["activity_arn"] = arn
	attributes["activity_name"] = name
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "activity": activity, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-sfn-activity-"+firstNonEmpty(arn, name), "aws.sfn_activity", "aws/sfn_activity/v1", payload, attributes, firstTime(activity.CreationDate))
}

func eventBridgeBusEvent(settings settings, record awsEventBridgeBus) (*primitives.Event, error) {
	bus := record.Bus
	arn := awssdk.ToString(bus.Arn)
	name := awssdk.ToString(bus.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeBus, firstNonEmpty(arn, name), name, "eventbridge_event_bus", record.Tags)
	attributes["arn"] = arn
	attributes["event_bus_arn"] = arn
	attributes["event_bus_name"] = name
	attributes["description"] = awssdk.ToString(bus.Description)
	attributes["kms_key_id"] = awssdk.ToString(bus.KmsKeyIdentifier)
	attributes["encryption"] = boolString(awssdk.ToString(bus.KmsKeyIdentifier) != "")
	attributes["public"] = boolString(policyAllowsWildcardPrincipal(awssdk.ToString(bus.Policy)))
	attributes["internet_exposed"] = attributes["public"]
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "event_bus": bus, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-event-bus-"+firstNonEmpty(arn, name), "aws.eventbridge_event_bus", "aws/eventbridge_event_bus/v1", payload, attributes, firstTime(bus.LastModifiedTime, bus.CreationTime))
}

func eventBridgeRuleEvent(settings settings, record awsEventBridgeRule) (*primitives.Event, error) {
	rule := record.Rule
	arn := awssdk.ToString(rule.Arn)
	name := awssdk.ToString(rule.Name)
	roleARN := awssdk.ToString(rule.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeRule, firstNonEmpty(arn, name), name, "eventbridge_rule", record.Tags)
	attributes["arn"] = arn
	attributes["event_bus_name"] = awssdk.ToString(rule.EventBusName)
	attributes["event_pattern"] = awssdk.ToString(rule.EventPattern)
	attributes["managed_by"] = awssdk.ToString(rule.ManagedBy)
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["rule_arn"] = arn
	attributes["rule_name"] = name
	attributes["schedule_expression"] = awssdk.ToString(rule.ScheduleExpression)
	attributes["state"] = string(rule.State)
	attributes["target_arns"] = strings.Join(eventBridgeTargetARNs(record.Targets), ",")
	attributes["target_ids"] = strings.Join(eventBridgeTargetIDs(record.Targets), ",")
	attributes["target_role_arns"] = strings.Join(eventBridgeTargetRoleARNs(record.Targets), ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "rule": rule, "targets": record.Targets, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-rule-"+firstNonEmpty(arn, name), "aws.eventbridge_rule", "aws/eventbridge_rule/v1", payload, attributes, time.Now().UTC())
}

func eventBridgeArchiveEvent(settings settings, record awsEventBridgeArchive) (*primitives.Event, error) {
	archive := record.Archive
	arn := awssdk.ToString(archive.ArchiveArn)
	name := awssdk.ToString(archive.ArchiveName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgeArchive, firstNonEmpty(arn, name), name, "eventbridge_archive", record.Tags)
	attributes["arn"] = arn
	attributes["archive_arn"] = arn
	attributes["archive_name"] = name
	attributes["event_count"] = strconv.FormatInt(archive.EventCount, 10)
	attributes["event_pattern"] = awssdk.ToString(archive.EventPattern)
	attributes["event_source_arn"] = awssdk.ToString(archive.EventSourceArn)
	attributes["kms_key_id"] = awssdk.ToString(archive.KmsKeyIdentifier)
	attributes["retention_days"] = int32AttrString(archive.RetentionDays)
	attributes["size_bytes"] = strconv.FormatInt(archive.SizeBytes, 10)
	attributes["state"] = string(archive.State)
	attributes["state_reason"] = awssdk.ToString(archive.StateReason)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "archive": archive, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-archive-"+firstNonEmpty(arn, name), "aws.eventbridge_archive", "aws/eventbridge_archive/v1", payload, attributes, firstTime(archive.CreationTime))
}

func eventBridgePipeEvent(settings settings, record awsEventBridgePipe) (*primitives.Event, error) {
	pipe := record.Pipe
	arn := awssdk.ToString(pipe.Arn)
	name := awssdk.ToString(pipe.Name)
	roleARN := awssdk.ToString(pipe.RoleArn)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyEventBridgePipe, firstNonEmpty(arn, name), name, "eventbridge_pipe", record.Tags)
	attributes["arn"] = arn
	attributes["current_state"] = string(pipe.CurrentState)
	attributes["desired_state"] = string(pipe.DesiredState)
	attributes["enrichment_arn"] = awssdk.ToString(pipe.Enrichment)
	attributes["kms_key_id"] = awssdk.ToString(pipe.KmsKeyIdentifier)
	attributes["pipe_arn"] = arn
	attributes["pipe_name"] = name
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["source_arn"] = awssdk.ToString(pipe.Source)
	attributes["state"] = string(pipe.CurrentState)
	attributes["state_reason"] = awssdk.ToString(pipe.StateReason)
	attributes["target_arn"] = awssdk.ToString(pipe.Target)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "pipe": pipe, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-eventbridge-pipe-"+firstNonEmpty(arn, name), "aws.eventbridge_pipe", "aws/eventbridge_pipe/v1", payload, attributes, firstTime(pipe.LastModifiedTime, pipe.CreationTime))
}

func schedulerScheduleGroupEvent(settings settings, record awsSchedulerScheduleGroup) (*primitives.Event, error) {
	group := record.Group
	arn := awssdk.ToString(group.Arn)
	name := awssdk.ToString(group.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySchedulerScheduleGroup, firstNonEmpty(arn, name), name, "scheduler_schedule_group", record.Tags)
	attributes["arn"] = arn
	attributes["schedule_group_arn"] = arn
	attributes["schedule_group_name"] = name
	attributes["state"] = string(group.State)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "schedule_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-scheduler-schedule-group-"+firstNonEmpty(arn, name), "aws.scheduler_schedule_group", "aws/scheduler_schedule_group/v1", payload, attributes, firstTime(group.LastModificationDate, group.CreationDate))
}

func schedulerScheduleEvent(settings settings, record awsSchedulerSchedule) (*primitives.Event, error) {
	schedule := record.Schedule
	arn := awssdk.ToString(schedule.Arn)
	name := awssdk.ToString(schedule.Name)
	groupName := firstNonEmpty(awssdk.ToString(schedule.GroupName), "default")
	roleARN := schedulerScheduleRoleARN(schedule)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySchedulerSchedule, firstNonEmpty(arn, path.Join(groupName, name)), name, "scheduler_schedule", record.Tags)
	attributes["action_after_completion"] = string(schedule.ActionAfterCompletion)
	attributes["arn"] = arn
	attributes["end_at"] = timeAttributeString(schedule.EndDate)
	attributes["flexible_time_window_mode"] = schedulerFlexibleTimeWindowMode(schedule.FlexibleTimeWindow)
	attributes["group_name"] = groupName
	attributes["kms_key_id"] = awssdk.ToString(schedule.KmsKeyArn)
	attributes["relationship"] = "runs_as"
	attributes["role_arn"] = roleARN
	attributes["role_name"] = roleNameFromARN(roleARN)
	attributes["schedule_arn"] = arn
	attributes["schedule_expression"] = awssdk.ToString(schedule.ScheduleExpression)
	attributes["schedule_expression_timezone"] = awssdk.ToString(schedule.ScheduleExpressionTimezone)
	attributes["schedule_name"] = name
	attributes["start_at"] = timeAttributeString(schedule.StartDate)
	attributes["state"] = string(schedule.State)
	attributes["target_arn"] = schedulerScheduleTargetARN(schedule)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "schedule": schedule, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-scheduler-schedule-"+firstNonEmpty(arn, path.Join(groupName, name)), "aws.scheduler_schedule", "aws/scheduler_schedule/v1", payload, attributes, firstTime(schedule.LastModificationDate, schedule.CreationDate))
}

func listAllEventBridgeBusNames(ctx context.Context, clients awsClients) ([]string, error) {
	var names []string
	var next *string
	for {
		output, err := clients.eventBridge.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{Limit: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, bus := range output.EventBuses {
			if name := awssdk.ToString(bus.Name); name != "" {
				names = append(names, name)
			}
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(names)
	return names, nil
}

func listAllEventBridgeTargets(ctx context.Context, clients awsClients, busName string, ruleName string) ([]eventbridgetypes.Target, error) {
	if ruleName == "" {
		return nil, nil
	}
	var targets []eventbridgetypes.Target
	var next *string
	for {
		output, err := clients.eventBridge.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			EventBusName: awssdk.String(busName),
			Rule:         awssdk.String(ruleName),
			Limit:        awssdk.Int32(100),
			NextToken:    next,
		})
		if err != nil {
			return nil, fmt.Errorf("list eventbridge rule targets %q/%q: %w", busName, ruleName, err)
		}
		targets = append(targets, output.Targets...)
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	return targets, nil
}

func listAllSchedulerScheduleGroupNames(ctx context.Context, clients awsClients) ([]string, error) {
	var names []string
	var next *string
	for {
		output, err := clients.scheduler.ListScheduleGroups(ctx, &scheduler.ListScheduleGroupsInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, group := range output.ScheduleGroups {
			if name := awssdk.ToString(group.Name); name != "" {
				names = append(names, name)
			}
		}
		if awssdk.ToString(output.NextToken) == "" {
			break
		}
		next = output.NextToken
	}
	sort.Strings(names)
	return names, nil
}

func eventBridgeTargetARNs(targets []eventbridgetypes.Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, awssdk.ToString(target.Arn))
	}
	return cleanStrings(out)
}

func eventBridgeTargetIDs(targets []eventbridgetypes.Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, awssdk.ToString(target.Id))
	}
	return cleanStrings(out)
}

func eventBridgeTargetRoleARNs(targets []eventbridgetypes.Target) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, awssdk.ToString(target.RoleArn))
	}
	return cleanStrings(out)
}

func schedulerScheduleRoleARN(schedule scheduler.GetScheduleOutput) string {
	if schedule.Target == nil {
		return ""
	}
	return awssdk.ToString(schedule.Target.RoleArn)
}

func schedulerScheduleTargetARN(schedule scheduler.GetScheduleOutput) string {
	if schedule.Target == nil {
		return ""
	}
	return awssdk.ToString(schedule.Target.Arn)
}

func schedulerFlexibleTimeWindowMode(window *schedulertypes.FlexibleTimeWindow) string {
	if window == nil {
		return ""
	}
	return string(window.Mode)
}

func timeAttributeString(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func sfnTagMap(tags []sfntypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func eventBridgeTagMap(tags []eventbridgetypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func schedulerTagMap(tags []schedulertypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func decodeAWSChildCursor(raw string, label string) (awsChildPageCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return awsChildPageCursor{}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return awsChildPageCursor{}, fmt.Errorf("decode %s cursor: %w", label, err)
	}
	var cursor awsChildPageCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return awsChildPageCursor{}, fmt.Errorf("parse %s cursor: %w", label, err)
	}
	return cursor, nil
}

func encodeAWSChildCursor(cursor awsChildPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
