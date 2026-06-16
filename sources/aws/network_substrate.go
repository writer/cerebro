package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/sources/internal/awsnetwork"
)

func listVPCs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.Vpc, string, error) {
	out, err := clients.ec2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Vpcs, awssdk.ToString(out.NextToken), nil
}

func listSubnets(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.Subnet, string, error) {
	out, err := clients.ec2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.Subnets, awssdk.ToString(out.NextToken), nil
}

func listSecurityGroups(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.SecurityGroup, string, error) {
	out, err := clients.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.SecurityGroups, awssdk.ToString(out.NextToken), nil
}

func listRouteTables(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.RouteTable, string, error) {
	out, err := clients.ec2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 100)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.RouteTables, awssdk.ToString(out.NextToken), nil
}

func listNetworkACLs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.NetworkAcl, string, error) {
	out, err := clients.ec2.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.NetworkAcls, awssdk.ToString(out.NextToken), nil
}

func listInternetGateways(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.InternetGateway, string, error) {
	out, err := clients.ec2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.InternetGateways, awssdk.ToString(out.NextToken), nil
}

func listNATGateways(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.NatGateway, string, error) {
	out, err := clients.ec2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.NatGateways, awssdk.ToString(out.NextToken), nil
}

func listVPCFlowLogs(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.FlowLog, string, error) {
	out, err := clients.ec2.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.FlowLogs, awssdk.ToString(out.NextToken), nil
}

func listVPCEndpoints(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]ec2types.VpcEndpoint, string, error) {
	out, err := clients.ec2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
		MaxResults: awssdk.Int32(boundedAWSPageSizeInt32(limit, 5, 1000)),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	return out.VpcEndpoints, awssdk.ToString(out.NextToken), nil
}

func vpcEvent(settings settings, vpc ec2types.Vpc) (*primitives.Event, error) {
	id := awssdk.ToString(vpc.VpcId)
	tags := ec2Tags(vpc.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPC, id, firstNonEmpty(ec2NameTag(vpc.Tags), id), "vpc", tags)
	attributes["arn"] = ec2RegionalARN(settings, "vpc", id)
	attributes["cidr_block"] = awssdk.ToString(vpc.CidrBlock)
	attributes["cidr_blocks"] = strings.Join(awsnetwork.VPCCIDRBlocks(vpc), ",")
	attributes["dhcp_options_id"] = awssdk.ToString(vpc.DhcpOptionsId)
	attributes["instance_tenancy"] = string(vpc.InstanceTenancy)
	attributes["is_default"] = boolString(awssdk.ToBool(vpc.IsDefault))
	attributes["owner_id"] = awssdk.ToString(vpc.OwnerId)
	attributes["state"] = string(vpc.State)
	return networkSubstrateEvent(settings, "vpc", id, "aws.vpc", "aws/vpc/v1", map[string]any{"vpc": vpc}, attributes)
}

func subnetEvent(settings settings, subnet ec2types.Subnet) (*primitives.Event, error) {
	id := awssdk.ToString(subnet.SubnetId)
	tags := ec2Tags(subnet.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySubnet, id, firstNonEmpty(ec2NameTag(subnet.Tags), id), "subnet", tags)
	attributes["arn"] = ec2RegionalARN(settings, "subnet", id)
	attributes["availability_zone"] = awssdk.ToString(subnet.AvailabilityZone)
	attributes["availability_zone_id"] = awssdk.ToString(subnet.AvailabilityZoneId)
	attributes["available_ip_address_count"] = int32AttrString(subnet.AvailableIpAddressCount)
	attributes["cidr_block"] = awssdk.ToString(subnet.CidrBlock)
	attributes["cidr_blocks"] = strings.Join(awsnetwork.SubnetCIDRBlocks(subnet), ",")
	attributes["default_for_az"] = boolString(awssdk.ToBool(subnet.DefaultForAz))
	attributes["map_public_ip_on_launch"] = boolString(awssdk.ToBool(subnet.MapPublicIpOnLaunch))
	attributes["owner_id"] = awssdk.ToString(subnet.OwnerId)
	attributes["state"] = string(subnet.State)
	attributes["subnet_id"] = id
	attributes["vpc_id"] = awssdk.ToString(subnet.VpcId)
	return networkSubstrateEvent(settings, "subnet", id, "aws.subnet", "aws/subnet/v1", map[string]any{"subnet": subnet}, attributes)
}

func securityGroupEvent(settings settings, group ec2types.SecurityGroup) (*primitives.Event, error) {
	id := awssdk.ToString(group.GroupId)
	tags := ec2Tags(group.Tags)
	publicIngress := awsnetwork.SecurityGroupHasPublicIngress(group)
	attributes := commonCloudAssetAttributes(settings, settings.region, familySecurityGroup, id, firstNonEmpty(ec2NameTag(group.Tags), awssdk.ToString(group.GroupName), id), "security_group", tags)
	attributes["arn"] = firstNonEmpty(awssdk.ToString(group.SecurityGroupArn), ec2RegionalARN(settings, "security-group", id))
	attributes["description"] = awssdk.ToString(group.Description)
	attributes["group_id"] = id
	attributes["group_name"] = awssdk.ToString(group.GroupName)
	attributes["inbound_rule_count"] = strconv.Itoa(len(group.IpPermissions))
	attributes["outbound_rule_count"] = strconv.Itoa(len(group.IpPermissionsEgress))
	attributes["owner_id"] = awssdk.ToString(group.OwnerId)
	attributes["public_ingress"] = boolString(publicIngress)
	attributes["public"] = boolString(publicIngress)
	attributes["internet_exposed"] = attributes["public"]
	attributes["security_group_id"] = id
	attributes["vpc_id"] = awssdk.ToString(group.VpcId)
	return networkSubstrateEvent(settings, "security-group", id, "aws.security_group", "aws/security_group/v1", map[string]any{"security_group": group}, attributes)
}

func routeTableEvent(settings settings, table ec2types.RouteTable) (*primitives.Event, error) {
	id := awssdk.ToString(table.RouteTableId)
	tags := ec2Tags(table.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyRouteTable, id, firstNonEmpty(ec2NameTag(table.Tags), id), "route_table", tags)
	attributes["arn"] = ec2RegionalARN(settings, "route-table", id)
	attributes["association_count"] = strconv.Itoa(len(table.Associations))
	attributes["gateway_ids"] = strings.Join(awsnetwork.RouteGatewayIDs(table.Routes), ",")
	attributes["internet_gateway_ids"] = strings.Join(awsnetwork.RouteInternetGatewayIDs(table.Routes), ",")
	attributes["nat_gateway_ids"] = strings.Join(awsnetwork.RouteNATGatewayIDs(table.Routes), ",")
	attributes["route_count"] = strconv.Itoa(len(table.Routes))
	attributes["route_table_id"] = id
	attributes["subnet_ids"] = strings.Join(awsnetwork.RouteTableSubnetIDs(table.Associations), ",")
	attributes["vpc_id"] = awssdk.ToString(table.VpcId)
	return networkSubstrateEvent(settings, "route-table", id, "aws.route_table", "aws/route_table/v1", map[string]any{"route_table": table}, attributes)
}

func networkACLEvent(settings settings, acl ec2types.NetworkAcl) (*primitives.Event, error) {
	id := awssdk.ToString(acl.NetworkAclId)
	tags := ec2Tags(acl.Tags)
	subnetIDs := awsnetwork.NetworkACLSubnetIDs(acl.Associations)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNetworkACL, id, firstNonEmpty(ec2NameTag(acl.Tags), id), "network_acl", tags)
	attributes["allows_admin_ports_from_internet"] = boolString(awsnetwork.NetworkACLAllowsAdminPortsFromInternet(acl))
	attributes["arn"] = ec2RegionalARN(settings, "network-acl", id)
	attributes["association_count"] = strconv.Itoa(len(acl.Associations))
	attributes["egress_rule_count"] = strconv.Itoa(awsnetwork.NetworkACLRuleCount(acl.Entries, true))
	attributes["entry_count"] = strconv.Itoa(len(acl.Entries))
	attributes["ingress_rule_count"] = strconv.Itoa(awsnetwork.NetworkACLRuleCount(acl.Entries, false))
	attributes["is_default"] = boolString(awssdk.ToBool(acl.IsDefault))
	attributes["network_acl_id"] = id
	attributes["owner_id"] = awssdk.ToString(acl.OwnerId)
	attributes["subnet_id"] = firstNonEmpty(subnetIDs...)
	attributes["subnet_ids"] = strings.Join(subnetIDs, ",")
	attributes["vpc_id"] = awssdk.ToString(acl.VpcId)
	return networkSubstrateEvent(settings, "network-acl", id, "aws.network_acl", "aws/network_acl/v1", map[string]any{"network_acl": acl}, attributes)
}

func internetGatewayEvent(settings settings, gateway ec2types.InternetGateway) (*primitives.Event, error) {
	id := awssdk.ToString(gateway.InternetGatewayId)
	tags := ec2Tags(gateway.Tags)
	vpcIDs := awsnetwork.InternetGatewayVPCIDs(gateway.Attachments)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyInternetGateway, id, firstNonEmpty(ec2NameTag(gateway.Tags), id), "internet_gateway", tags)
	attributes["arn"] = ec2RegionalARN(settings, "internet-gateway", id)
	attributes["attachment_states"] = strings.Join(awsnetwork.InternetGatewayAttachmentStates(gateway.Attachments), ",")
	attributes["internet_gateway_id"] = id
	attributes["vpc_id"] = firstNonEmpty(vpcIDs...)
	attributes["vpc_ids"] = strings.Join(vpcIDs, ",")
	return networkSubstrateEvent(settings, "internet-gateway", id, "aws.internet_gateway", "aws/internet_gateway/v1", map[string]any{"internet_gateway": gateway}, attributes)
}

func natGatewayEvent(settings settings, gateway ec2types.NatGateway) (*primitives.Event, error) {
	id := awssdk.ToString(gateway.NatGatewayId)
	tags := ec2Tags(gateway.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNATGateway, id, firstNonEmpty(ec2NameTag(gateway.Tags), id), "nat_gateway", tags)
	attributes["arn"] = ec2RegionalARN(settings, "natgateway", id)
	attributes["connectivity_type"] = string(gateway.ConnectivityType)
	attributes["nat_gateway_id"] = id
	attributes["private_ips"] = strings.Join(awsnetwork.NATGatewayPrivateIPs(gateway.NatGatewayAddresses), ",")
	attributes["public_ips"] = strings.Join(awsnetwork.NATGatewayPublicIPs(gateway.NatGatewayAddresses), ",")
	attributes["state"] = string(gateway.State)
	attributes["subnet_id"] = awssdk.ToString(gateway.SubnetId)
	attributes["vpc_id"] = awssdk.ToString(gateway.VpcId)
	return networkSubstrateEvent(settings, "nat-gateway", id, "aws.nat_gateway", "aws/nat_gateway/v1", map[string]any{"nat_gateway": gateway}, attributes)
}

func vpcFlowLogEvent(settings settings, flowLog ec2types.FlowLog) (*primitives.Event, error) {
	id := awssdk.ToString(flowLog.FlowLogId)
	tags := ec2Tags(flowLog.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCFlowLog, id, id, "vpc_flow_log", tags)
	attributes["arn"] = ec2RegionalARN(settings, "vpc-flow-log", id)
	attributes["deliver_cross_account_role"] = awssdk.ToString(flowLog.DeliverCrossAccountRole)
	attributes["deliver_logs_error_message"] = awssdk.ToString(flowLog.DeliverLogsErrorMessage)
	attributes["deliver_logs_permission_arn"] = awssdk.ToString(flowLog.DeliverLogsPermissionArn)
	attributes["deliver_logs_status"] = awssdk.ToString(flowLog.DeliverLogsStatus)
	attributes["destination_file_format"] = string(awsnetwork.FlowLogDestinationFileFormat(flowLog))
	attributes["flow_log_id"] = id
	attributes["flow_log_status"] = awssdk.ToString(flowLog.FlowLogStatus)
	attributes["hive_compatible_partitions"] = boolString(awsnetwork.FlowLogHiveCompatiblePartitions(flowLog))
	attributes["log_destination"] = awssdk.ToString(flowLog.LogDestination)
	attributes["log_destination_type"] = string(flowLog.LogDestinationType)
	attributes["log_format"] = awssdk.ToString(flowLog.LogFormat)
	attributes["log_group_name"] = awssdk.ToString(flowLog.LogGroupName)
	attributes["max_aggregation_interval"] = int32AttrString(flowLog.MaxAggregationInterval)
	attributes["monitored_resource_id"] = awssdk.ToString(flowLog.ResourceId)
	attributes["per_hour_partition"] = boolString(awsnetwork.FlowLogPerHourPartition(flowLog))
	attributes["traffic_type"] = string(flowLog.TrafficType)
	attributes["vpc_id"] = awsnetwork.FlowLogVPCID(flowLog)
	return networkSubstrateEvent(settings, "vpc-flow-log", id, "aws.vpc_flow_log", "aws/vpc_flow_log/v1", map[string]any{"vpc_flow_log": flowLog}, attributes)
}

func vpcEndpointEvent(settings settings, endpoint ec2types.VpcEndpoint) (*primitives.Event, error) {
	id := awssdk.ToString(endpoint.VpcEndpointId)
	tags := ec2Tags(endpoint.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCEndpoint, id, firstNonEmpty(ec2NameTag(endpoint.Tags), id), "vpc_endpoint", tags)
	attributes["arn"] = ec2RegionalARN(settings, "vpc-endpoint", id)
	attributes["dns_names"] = strings.Join(awsnetwork.VPCEndpointDNSNames(endpoint.DnsEntries), ",")
	attributes["network_interface_ids"] = strings.Join(cleanStrings(endpoint.NetworkInterfaceIds), ",")
	attributes["policy_document"] = awssdk.ToString(endpoint.PolicyDocument)
	attributes["private_dns_enabled"] = boolString(awssdk.ToBool(endpoint.PrivateDnsEnabled))
	attributes["route_table_ids"] = strings.Join(cleanStrings(endpoint.RouteTableIds), ",")
	attributes["security_group_ids"] = strings.Join(awsnetwork.VPCEndpointSecurityGroupIDs(endpoint.Groups), ",")
	attributes["service_name"] = awssdk.ToString(endpoint.ServiceName)
	attributes["state"] = string(endpoint.State)
	attributes["subnet_ids"] = strings.Join(cleanStrings(endpoint.SubnetIds), ",")
	attributes["vpc_endpoint_id"] = id
	attributes["vpc_endpoint_type"] = string(endpoint.VpcEndpointType)
	attributes["vpc_id"] = awssdk.ToString(endpoint.VpcId)
	return networkSubstrateEvent(settings, "vpc-endpoint", id, "aws.vpc_endpoint", "aws/vpc_endpoint/v1", map[string]any{"vpc_endpoint": endpoint}, attributes)
}

func networkSubstrateEvent(settings settings, prefix string, id string, kind string, schema string, payload map[string]any, attributes map[string]string) (*primitives.Event, error) {
	payload["account_id"] = settings.accountID
	payload["region"] = settings.region
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-"+prefix+"-"+id, kind, schema, encoded, attributes, time.Now().UTC())
}

func ec2RegionalARN(settings settings, resourceType string, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", settings.region, settings.accountID, resourceType, id)
}
