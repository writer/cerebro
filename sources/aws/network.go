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
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsParentPageCursor struct {
	ParentIndex int    `json:"parent_index,omitempty"`
	NextToken   string `json:"next_token,omitempty"`
}

type awsGlobalAcceleratorAccelerator struct {
	Accelerator globalacceleratortypes.Accelerator
	Tags        map[string]string
}

type awsGlobalAcceleratorListener struct {
	AcceleratorARN string
	Listener       globalacceleratortypes.Listener
	Tags           map[string]string
}

type awsGlobalAcceleratorEndpointGroup struct {
	AcceleratorARN string
	ListenerARN    string
	EndpointGroup  globalacceleratortypes.EndpointGroup
	Tags           map[string]string
}

type awsVPCLatticeService struct {
	Service vpclattice.GetServiceOutput
	Tags    map[string]string
}

type awsVPCLatticeListener struct {
	ServiceARN string
	ServiceID  string
	Listener   vpclattice.GetListenerOutput
	Tags       map[string]string
}

type awsVPCLatticeTargetGroup struct {
	TargetGroup vpclattice.GetTargetGroupOutput
	Targets     []vpclatticetypes.TargetSummary
	Tags        map[string]string
}

func listGlobalAcceleratorAccelerators(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsGlobalAcceleratorAccelerator, string, error) {
	out, err := clients.globalAccelerator.ListAccelerators(ctx, &globalaccelerator.ListAcceleratorsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsGlobalAcceleratorAccelerator, 0, len(out.Accelerators))
	for _, accelerator := range out.Accelerators {
		record := awsGlobalAcceleratorAccelerator{Accelerator: accelerator}
		if arn := awssdk.ToString(accelerator.AcceleratorArn); arn != "" {
			tags, err := listGlobalAcceleratorTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list global accelerator tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listGlobalAcceleratorListeners(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsGlobalAcceleratorListener, string, error) {
	accelerators, err := listAllGlobalAcceleratorARNs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeAWSParentPageCursor(cursor, "global accelerator listener")
	if err != nil {
		return nil, "", err
	}
	return listGlobalAcceleratorListenersFromAccelerators(ctx, clients, accelerators, state, limit)
}

func listGlobalAcceleratorEndpointGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsGlobalAcceleratorEndpointGroup, string, error) {
	listeners, err := listAllGlobalAcceleratorListenerRefs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeAWSParentPageCursor(cursor, "global accelerator endpoint group")
	if err != nil {
		return nil, "", err
	}
	if state.ParentIndex < 0 || state.ParentIndex >= len(listeners) {
		state.ParentIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsGlobalAcceleratorEndpointGroup, 0, remaining)
	for state.ParentIndex < len(listeners) && len(records) < remaining {
		parent := listeners[state.ParentIndex]
		out, err := clients.globalAccelerator.ListEndpointGroups(ctx, &globalaccelerator.ListEndpointGroupsInput{
			ListenerArn: awssdk.String(parent.ListenerARN),
			MaxResults:  awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:   stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list endpoint groups for listener %q: %w", parent.ListenerARN, err)
		}
		for _, group := range out.EndpointGroups {
			record := awsGlobalAcceleratorEndpointGroup{AcceleratorARN: parent.AcceleratorARN, ListenerARN: parent.ListenerARN, EndpointGroup: group}
			if arn := awssdk.ToString(group.EndpointGroupArn); arn != "" {
				tags, err := listGlobalAcceleratorTags(ctx, clients, arn)
				if err != nil {
					return nil, "", fmt.Errorf("list global accelerator endpoint group tags %q: %w", arn, err)
				}
				record.Tags = tags
			}
			records = append(records, record)
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.NextToken = awssdk.ToString(out.NextToken)
			return records, encodeAWSParentPageCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(listeners) {
		return records, encodeAWSParentPageCursor(state), nil
	}
	return records, "", nil
}

func listVPCLatticeServices(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsVPCLatticeService, string, error) {
	out, err := clients.vpcLattice.ListServices(ctx, &vpclattice.ListServicesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsVPCLatticeService, 0, len(out.Items))
	for _, summary := range out.Items {
		identifier := firstNonEmpty(awssdk.ToString(summary.Arn), awssdk.ToString(summary.Id))
		if identifier == "" {
			continue
		}
		service, err := clients.vpcLattice.GetService(ctx, &vpclattice.GetServiceInput{ServiceIdentifier: awssdk.String(identifier)})
		if err != nil {
			return nil, "", fmt.Errorf("get vpc lattice service %q: %w", identifier, err)
		}
		record := awsVPCLatticeService{Service: *service}
		if arn := awssdk.ToString(service.Arn); arn != "" {
			tags, err := listVPCLatticeTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list vpc lattice service tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listVPCLatticeListeners(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsVPCLatticeListener, string, error) {
	services, err := listAllVPCLatticeServiceRefs(ctx, clients)
	if err != nil {
		return nil, "", err
	}
	state, err := decodeAWSParentPageCursor(cursor, "vpc lattice listener")
	if err != nil {
		return nil, "", err
	}
	if state.ParentIndex < 0 || state.ParentIndex >= len(services) {
		state.ParentIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsVPCLatticeListener, 0, remaining)
	for state.ParentIndex < len(services) && len(records) < remaining {
		service := services[state.ParentIndex]
		out, err := clients.vpcLattice.ListListeners(ctx, &vpclattice.ListListenersInput{
			ServiceIdentifier: awssdk.String(service.Identifier),
			MaxResults:        awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:         stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list vpc lattice listeners for service %q: %w", service.Identifier, err)
		}
		for _, summary := range out.Items {
			listenerID := firstNonEmpty(awssdk.ToString(summary.Arn), awssdk.ToString(summary.Id))
			if listenerID == "" {
				continue
			}
			listener, err := clients.vpcLattice.GetListener(ctx, &vpclattice.GetListenerInput{ServiceIdentifier: awssdk.String(service.Identifier), ListenerIdentifier: awssdk.String(listenerID)})
			if err != nil {
				return nil, "", fmt.Errorf("get vpc lattice listener %q/%q: %w", service.Identifier, listenerID, err)
			}
			record := awsVPCLatticeListener{ServiceARN: service.ARN, ServiceID: service.ID, Listener: *listener}
			if arn := awssdk.ToString(listener.Arn); arn != "" {
				tags, err := listVPCLatticeTags(ctx, clients, arn)
				if err != nil {
					return nil, "", fmt.Errorf("list vpc lattice listener tags %q: %w", arn, err)
				}
				record.Tags = tags
			}
			records = append(records, record)
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.NextToken = awssdk.ToString(out.NextToken)
			return records, encodeAWSParentPageCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(services) {
		return records, encodeAWSParentPageCursor(state), nil
	}
	return records, "", nil
}

func listVPCLatticeTargetGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsVPCLatticeTargetGroup, string, error) {
	out, err := clients.vpcLattice.ListTargetGroups(ctx, &vpclattice.ListTargetGroupsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsVPCLatticeTargetGroup, 0, len(out.Items))
	for _, summary := range out.Items {
		identifier := firstNonEmpty(awssdk.ToString(summary.Arn), awssdk.ToString(summary.Id))
		if identifier == "" {
			continue
		}
		group, err := clients.vpcLattice.GetTargetGroup(ctx, &vpclattice.GetTargetGroupInput{TargetGroupIdentifier: awssdk.String(identifier)})
		if err != nil {
			return nil, "", fmt.Errorf("get vpc lattice target group %q: %w", identifier, err)
		}
		targets, err := listAllVPCLatticeTargets(ctx, clients, identifier)
		if err != nil {
			return nil, "", fmt.Errorf("list vpc lattice targets %q: %w", identifier, err)
		}
		record := awsVPCLatticeTargetGroup{TargetGroup: *group, Targets: targets}
		if arn := awssdk.ToString(group.Arn); arn != "" {
			tags, err := listVPCLatticeTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list vpc lattice target group tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func globalAcceleratorAcceleratorEvent(settings settings, record awsGlobalAcceleratorAccelerator) (*primitives.Event, error) {
	accelerator := record.Accelerator
	arn := awssdk.ToString(accelerator.AcceleratorArn)
	name := awssdk.ToString(accelerator.Name)
	attributes := commonCloudAssetAttributes(settings, "global", familyGlobalAcceleratorAccelerator, firstNonEmpty(arn, name), name, "global_accelerator", record.Tags)
	attributes["arn"] = arn
	attributes["accelerator_arn"] = arn
	attributes["accelerator_name"] = name
	attributes["dns_name"] = awssdk.ToString(accelerator.DnsName)
	attributes["dual_stack_dns_name"] = awssdk.ToString(accelerator.DualStackDnsName)
	attributes["enabled"] = boolString(awssdk.ToBool(accelerator.Enabled))
	attributes["ip_address_type"] = string(accelerator.IpAddressType)
	attributes["ip_addresses"] = strings.Join(globalAcceleratorIPAddresses(accelerator.IpSets), ",")
	attributes["ip_families"] = strings.Join(globalAcceleratorIPFamilies(accelerator.IpSets), ",")
	attributes["public"] = boolString(true)
	attributes["internet_exposed"] = boolString(true)
	attributes["state"] = string(accelerator.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "accelerator": accelerator, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-global-accelerator-"+firstNonEmpty(arn, name), "aws.global_accelerator_accelerator", "aws/global_accelerator_accelerator/v1", payload, attributes, firstTime(accelerator.LastModifiedTime, accelerator.CreatedTime))
}

func globalAcceleratorListenerEvent(settings settings, record awsGlobalAcceleratorListener) (*primitives.Event, error) {
	listener := record.Listener
	arn := awssdk.ToString(listener.ListenerArn)
	attributes := commonCloudAssetAttributes(settings, "global", familyGlobalAcceleratorListener, arn, globalAcceleratorListenerName(arn), "global_accelerator_listener", record.Tags)
	attributes["arn"] = arn
	attributes["accelerator_arn"] = record.AcceleratorARN
	attributes["client_affinity"] = string(listener.ClientAffinity)
	attributes["listener_arn"] = arn
	attributes["port_ranges"] = strings.Join(globalAcceleratorPortRanges(listener.PortRanges), ",")
	attributes["protocol"] = string(listener.Protocol)
	attributes["public"] = boolString(true)
	attributes["internet_exposed"] = boolString(true)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": "global", "accelerator_arn": record.AcceleratorARN, "listener": listener, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-global-accelerator-listener-"+arn, "aws.global_accelerator_listener", "aws/global_accelerator_listener/v1", payload, attributes, time.Now().UTC())
}

func globalAcceleratorEndpointGroupEvent(settings settings, record awsGlobalAcceleratorEndpointGroup) (*primitives.Event, error) {
	group := record.EndpointGroup
	arn := awssdk.ToString(group.EndpointGroupArn)
	attributes := commonCloudAssetAttributes(settings, awssdk.ToString(group.EndpointGroupRegion), familyGlobalAcceleratorEndpointGroup, arn, globalAcceleratorListenerName(arn), "global_accelerator_endpoint_group", record.Tags)
	attributes["arn"] = arn
	attributes["accelerator_arn"] = record.AcceleratorARN
	attributes["endpoint_group_arn"] = arn
	attributes["endpoint_group_region"] = awssdk.ToString(group.EndpointGroupRegion)
	attributes["endpoint_ids"] = strings.Join(globalAcceleratorEndpointIDs(group.EndpointDescriptions), ",")
	attributes["endpoint_health_states"] = strings.Join(globalAcceleratorEndpointHealthStates(group.EndpointDescriptions), ",")
	attributes["endpoint_weights"] = strings.Join(globalAcceleratorEndpointWeights(group.EndpointDescriptions), ",")
	attributes["health_check_interval_seconds"] = int32AttrString(group.HealthCheckIntervalSeconds)
	attributes["health_check_path"] = awssdk.ToString(group.HealthCheckPath)
	attributes["health_check_port"] = int32AttrString(group.HealthCheckPort)
	attributes["health_check_protocol"] = string(group.HealthCheckProtocol)
	attributes["listener_arn"] = record.ListenerARN
	attributes["threshold_count"] = int32AttrString(group.ThresholdCount)
	attributes["traffic_dial_percentage"] = float32AttrString(group.TrafficDialPercentage)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": awssdk.ToString(group.EndpointGroupRegion), "accelerator_arn": record.AcceleratorARN, "listener_arn": record.ListenerARN, "endpoint_group": group, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-global-accelerator-endpoint-group-"+arn, "aws.global_accelerator_endpoint_group", "aws/global_accelerator_endpoint_group/v1", payload, attributes, time.Now().UTC())
}

func vpcLatticeServiceEvent(settings settings, record awsVPCLatticeService) (*primitives.Event, error) {
	service := record.Service
	arn := awssdk.ToString(service.Arn)
	name := awssdk.ToString(service.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeService, firstNonEmpty(arn, awssdk.ToString(service.Id), name), name, "vpc_lattice_service", record.Tags)
	attributes["arn"] = arn
	attributes["auth_type"] = string(service.AuthType)
	attributes["certificate_arn"] = awssdk.ToString(service.CertificateArn)
	attributes["custom_domain_name"] = awssdk.ToString(service.CustomDomainName)
	attributes["dns_name"] = vpcLatticeDNSEntryName(service.DnsEntry)
	attributes["hosted_zone_id"] = vpcLatticeDNSEntryZoneID(service.DnsEntry)
	attributes["service_arn"] = arn
	attributes["service_id"] = awssdk.ToString(service.Id)
	attributes["service_name"] = name
	attributes["state"] = string(service.Status)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service": service, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpc-lattice-service-"+firstNonEmpty(arn, awssdk.ToString(service.Id), name), "aws.vpc_lattice_service", "aws/vpc_lattice_service/v1", payload, attributes, firstTime(service.LastUpdatedAt, service.CreatedAt))
}

func vpcLatticeListenerEvent(settings settings, record awsVPCLatticeListener) (*primitives.Event, error) {
	listener := record.Listener
	arn := awssdk.ToString(listener.Arn)
	name := awssdk.ToString(listener.Name)
	targetGroupIDs, targetGroupWeights, actionType, fixedStatus := vpcLatticeRuleActionSummary(listener.DefaultAction)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeListener, firstNonEmpty(arn, awssdk.ToString(listener.Id), name), name, "vpc_lattice_listener", record.Tags)
	attributes["arn"] = arn
	attributes["default_action"] = actionType
	attributes["fixed_response_status_code"] = fixedStatus
	attributes["listener_arn"] = arn
	attributes["listener_id"] = awssdk.ToString(listener.Id)
	attributes["listener_name"] = name
	attributes["port"] = int32AttrString(listener.Port)
	attributes["protocol"] = string(listener.Protocol)
	attributes["service_arn"] = firstNonEmpty(awssdk.ToString(listener.ServiceArn), record.ServiceARN)
	attributes["service_id"] = firstNonEmpty(awssdk.ToString(listener.ServiceId), record.ServiceID)
	attributes["target_group_ids"] = strings.Join(targetGroupIDs, ",")
	attributes["target_group_weights"] = strings.Join(targetGroupWeights, ",")
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "service_arn": attributes["service_arn"], "listener": listener, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpc-lattice-listener-"+firstNonEmpty(arn, awssdk.ToString(listener.Id), name), "aws.vpc_lattice_listener", "aws/vpc_lattice_listener/v1", payload, attributes, firstTime(listener.LastUpdatedAt, listener.CreatedAt))
}

func vpcLatticeTargetGroupEvent(settings settings, record awsVPCLatticeTargetGroup) (*primitives.Event, error) {
	group := record.TargetGroup
	arn := awssdk.ToString(group.Arn)
	name := awssdk.ToString(group.Name)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCLatticeTargetGroup, firstNonEmpty(arn, awssdk.ToString(group.Id), name), name, "vpc_lattice_target_group", record.Tags)
	attributes["arn"] = arn
	if group.Config != nil {
		attributes["health_check_enabled"] = vpcLatticeHealthCheckEnabled(group.Config.HealthCheck)
		attributes["ip_address_type"] = string(group.Config.IpAddressType)
		attributes["lambda_event_structure_version"] = string(group.Config.LambdaEventStructureVersion)
		attributes["port"] = int32AttrString(group.Config.Port)
		attributes["protocol"] = string(group.Config.Protocol)
		attributes["protocol_version"] = string(group.Config.ProtocolVersion)
		attributes["vpc_id"] = awssdk.ToString(group.Config.VpcIdentifier)
	}
	attributes["service_arns"] = strings.Join(cleanStrings(group.ServiceArns), ",")
	attributes["state"] = string(group.Status)
	attributes["target_group_arn"] = arn
	attributes["target_group_id"] = awssdk.ToString(group.Id)
	attributes["target_group_name"] = name
	attributes["target_ids"] = strings.Join(vpcLatticeTargetIDs(record.Targets), ",")
	attributes["target_statuses"] = strings.Join(vpcLatticeTargetStatuses(record.Targets), ",")
	attributes["target_type"] = string(group.Type)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "target_group": group, "targets": record.Targets, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-vpc-lattice-target-group-"+firstNonEmpty(arn, awssdk.ToString(group.Id), name), "aws.vpc_lattice_target_group", "aws/vpc_lattice_target_group/v1", payload, attributes, firstTime(group.LastUpdatedAt, group.CreatedAt))
}

func listAllGlobalAcceleratorARNs(ctx context.Context, clients awsClients) ([]string, error) {
	var arns []string
	var next *string
	for {
		out, err := clients.globalAccelerator.ListAccelerators(ctx, &globalaccelerator.ListAcceleratorsInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, accelerator := range out.Accelerators {
			if arn := awssdk.ToString(accelerator.AcceleratorArn); arn != "" {
				arns = append(arns, arn)
			}
		}
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	sort.Strings(arns)
	return arns, nil
}

type globalAcceleratorListenerRef struct {
	AcceleratorARN string
	ListenerARN    string
}

func listAllGlobalAcceleratorListenerRefs(ctx context.Context, clients awsClients) ([]globalAcceleratorListenerRef, error) {
	accelerators, err := listAllGlobalAcceleratorARNs(ctx, clients)
	if err != nil {
		return nil, err
	}
	var refs []globalAcceleratorListenerRef
	state := awsParentPageCursor{}
	for {
		listeners, next, err := listGlobalAcceleratorListenersFromAccelerators(ctx, clients, accelerators, state, 100)
		if err != nil {
			return nil, err
		}
		for _, listener := range listeners {
			if arn := awssdk.ToString(listener.Listener.ListenerArn); arn != "" {
				refs = append(refs, globalAcceleratorListenerRef{AcceleratorARN: listener.AcceleratorARN, ListenerARN: arn})
			}
		}
		if next == "" {
			break
		}
		state, err = decodeAWSParentPageCursor(next, "global accelerator listener")
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(refs, func(i int, j int) bool {
		return refs[i].AcceleratorARN+"/"+refs[i].ListenerARN < refs[j].AcceleratorARN+"/"+refs[j].ListenerARN
	})
	return refs, nil
}

func listGlobalAcceleratorListenersFromAccelerators(ctx context.Context, clients awsClients, accelerators []string, state awsParentPageCursor, limit int) ([]awsGlobalAcceleratorListener, string, error) {
	if state.ParentIndex < 0 || state.ParentIndex >= len(accelerators) {
		state.ParentIndex = 0
		state.NextToken = ""
	}
	remaining := limit
	if remaining <= 0 {
		remaining = defaultPageSize
	}
	records := make([]awsGlobalAcceleratorListener, 0, remaining)
	for state.ParentIndex < len(accelerators) && len(records) < remaining {
		acceleratorARN := accelerators[state.ParentIndex]
		out, err := clients.globalAccelerator.ListListeners(ctx, &globalaccelerator.ListListenersInput{
			AcceleratorArn: awssdk.String(acceleratorARN),
			MaxResults:     awssdk.Int32(int32(boundedAWSPageSize(remaining-len(records), 1, 100))),
			NextToken:      stringPtr(state.NextToken),
		})
		if err != nil {
			return nil, "", fmt.Errorf("list listeners for accelerator %q: %w", acceleratorARN, err)
		}
		for _, listener := range out.Listeners {
			record := awsGlobalAcceleratorListener{AcceleratorARN: acceleratorARN, Listener: listener}
			if arn := awssdk.ToString(listener.ListenerArn); arn != "" {
				tags, err := listGlobalAcceleratorTags(ctx, clients, arn)
				if err != nil {
					return nil, "", fmt.Errorf("list global accelerator listener tags %q: %w", arn, err)
				}
				record.Tags = tags
			}
			records = append(records, record)
		}
		if awssdk.ToString(out.NextToken) != "" {
			state.NextToken = awssdk.ToString(out.NextToken)
			return records, encodeAWSParentPageCursor(state), nil
		}
		state.ParentIndex++
		state.NextToken = ""
	}
	if state.ParentIndex < len(accelerators) {
		return records, encodeAWSParentPageCursor(state), nil
	}
	return records, "", nil
}

type vpcLatticeServiceRef struct {
	Identifier string
	ARN        string
	ID         string
}

func listAllVPCLatticeServiceRefs(ctx context.Context, clients awsClients) ([]vpcLatticeServiceRef, error) {
	var refs []vpcLatticeServiceRef
	var next *string
	for {
		out, err := clients.vpcLattice.ListServices(ctx, &vpclattice.ListServicesInput{MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		for _, service := range out.Items {
			arn := awssdk.ToString(service.Arn)
			id := awssdk.ToString(service.Id)
			if identifier := firstNonEmpty(arn, id); identifier != "" {
				refs = append(refs, vpcLatticeServiceRef{Identifier: identifier, ARN: arn, ID: id})
			}
		}
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	sort.Slice(refs, func(i int, j int) bool { return refs[i].Identifier < refs[j].Identifier })
	return refs, nil
}

func listAllVPCLatticeTargets(ctx context.Context, clients awsClients, targetGroupID string) ([]vpclatticetypes.TargetSummary, error) {
	var targets []vpclatticetypes.TargetSummary
	var next *string
	for {
		out, err := clients.vpcLattice.ListTargets(ctx, &vpclattice.ListTargetsInput{TargetGroupIdentifier: awssdk.String(targetGroupID), MaxResults: awssdk.Int32(100), NextToken: next})
		if err != nil {
			return nil, err
		}
		targets = append(targets, out.Items...)
		if awssdk.ToString(out.NextToken) == "" {
			break
		}
		next = out.NextToken
	}
	return targets, nil
}

func listGlobalAcceleratorTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	out, err := clients.globalAccelerator.ListTagsForResource(ctx, &globalaccelerator.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
	if err != nil {
		return nil, err
	}
	return globalAcceleratorTagMap(out.Tags), nil
}

func listVPCLatticeTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	out, err := clients.vpcLattice.ListTagsForResource(ctx, &vpclattice.ListTagsForResourceInput{ResourceArn: awssdk.String(arn)})
	if err != nil {
		return nil, err
	}
	return out.Tags, nil
}

func globalAcceleratorTagMap(tags []globalacceleratortypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func globalAcceleratorIPAddresses(sets []globalacceleratortypes.IpSet) []string {
	var values []string
	for _, set := range sets {
		values = append(values, set.IpAddresses...)
	}
	return cleanStrings(values)
}

func globalAcceleratorIPFamilies(sets []globalacceleratortypes.IpSet) []string {
	values := make([]string, 0, len(sets))
	for _, set := range sets {
		values = append(values, string(set.IpAddressFamily))
	}
	return cleanStrings(values)
}

func globalAcceleratorPortRanges(ranges []globalacceleratortypes.PortRange) []string {
	values := make([]string, 0, len(ranges))
	for _, portRange := range ranges {
		from := awssdk.ToInt32(portRange.FromPort)
		to := awssdk.ToInt32(portRange.ToPort)
		if from == 0 && to == 0 {
			continue
		}
		if from == to || to == 0 {
			values = append(values, strconv.FormatInt(int64(from), 10))
			continue
		}
		values = append(values, strconv.FormatInt(int64(from), 10)+"-"+strconv.FormatInt(int64(to), 10))
	}
	return values
}

func globalAcceleratorEndpointIDs(endpoints []globalacceleratortypes.EndpointDescription) []string {
	values := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		values = append(values, awssdk.ToString(endpoint.EndpointId))
	}
	return cleanStrings(values)
}

func globalAcceleratorEndpointHealthStates(endpoints []globalacceleratortypes.EndpointDescription) []string {
	values := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		values = append(values, string(endpoint.HealthState))
	}
	return cleanStrings(values)
}

func globalAcceleratorEndpointWeights(endpoints []globalacceleratortypes.EndpointDescription) []string {
	values := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Weight != nil {
			values = append(values, int32AttrString(endpoint.Weight))
		}
	}
	return cleanStrings(values)
}

func globalAcceleratorListenerName(arn string) string {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return ""
	}
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func vpcLatticeRuleActionSummary(action vpclatticetypes.RuleAction) ([]string, []string, string, string) {
	switch value := action.(type) {
	case *vpclatticetypes.RuleActionMemberForward:
		ids := make([]string, 0, len(value.Value.TargetGroups))
		weights := make([]string, 0, len(value.Value.TargetGroups))
		for _, group := range value.Value.TargetGroups {
			ids = append(ids, awssdk.ToString(group.TargetGroupIdentifier))
			weights = append(weights, int32AttrString(group.Weight))
		}
		return cleanStrings(ids), cleanStrings(weights), "forward", ""
	case *vpclatticetypes.RuleActionMemberFixedResponse:
		return nil, nil, "fixed_response", int32AttrString(value.Value.StatusCode)
	default:
		return nil, nil, "", ""
	}
}

func vpcLatticeDNSEntryName(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.DomainName)
}

func vpcLatticeDNSEntryZoneID(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.HostedZoneId)
}

func vpcLatticeHealthCheckEnabled(config *vpclatticetypes.HealthCheckConfig) string {
	if config == nil || config.Enabled == nil {
		return ""
	}
	return boolString(awssdk.ToBool(config.Enabled))
}

func vpcLatticeTargetIDs(targets []vpclatticetypes.TargetSummary) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, awssdk.ToString(target.Id))
	}
	return cleanStrings(values)
}

func vpcLatticeTargetStatuses(targets []vpclatticetypes.TargetSummary) []string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, string(target.Status))
	}
	return cleanStrings(values)
}

func float32AttrString(value *float32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*value), 'f', -1, 32)
}

func decodeAWSParentPageCursor(raw string, label string) (awsParentPageCursor, error) {
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

func encodeAWSParentPageCursor(cursor awsParentPageCursor) string {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}
