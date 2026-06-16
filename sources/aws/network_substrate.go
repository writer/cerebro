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
	attributes["cidr_blocks"] = strings.Join(vpcCIDRBlocks(vpc), ",")
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
	attributes["cidr_blocks"] = strings.Join(subnetCIDRBlocks(subnet), ",")
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
	publicIngress := securityGroupHasPublicIngress(group)
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
	attributes["gateway_ids"] = strings.Join(routeGatewayIDs(table.Routes), ",")
	attributes["internet_gateway_ids"] = strings.Join(routeInternetGatewayIDs(table.Routes), ",")
	attributes["nat_gateway_ids"] = strings.Join(routeNATGatewayIDs(table.Routes), ",")
	attributes["route_count"] = strconv.Itoa(len(table.Routes))
	attributes["route_table_id"] = id
	attributes["subnet_ids"] = strings.Join(routeTableSubnetIDs(table.Associations), ",")
	attributes["vpc_id"] = awssdk.ToString(table.VpcId)
	return networkSubstrateEvent(settings, "route-table", id, "aws.route_table", "aws/route_table/v1", map[string]any{"route_table": table}, attributes)
}

func networkACLEvent(settings settings, acl ec2types.NetworkAcl) (*primitives.Event, error) {
	id := awssdk.ToString(acl.NetworkAclId)
	tags := ec2Tags(acl.Tags)
	adminPorts := networkACLAdminPortsFromInternet(acl.Entries)
	public := len(adminPorts) > 0
	attributes := commonCloudAssetAttributes(settings, settings.region, familyNetworkACL, id, firstNonEmpty(ec2NameTag(acl.Tags), id), "network_acl", tags)
	attributes["admin_ports_from_internet"] = strings.Join(adminPorts, ",")
	attributes["allows_admin_ports_from_internet"] = boolString(public)
	attributes["arn"] = ec2RegionalARN(settings, "network-acl", id)
	attributes["association_count"] = strconv.Itoa(len(acl.Associations))
	attributes["entry_count"] = strconv.Itoa(len(acl.Entries))
	attributes["internet_exposed"] = boolString(public)
	attributes["is_default"] = boolString(awssdk.ToBool(acl.IsDefault))
	attributes["network_acl_id"] = id
	attributes["public"] = boolString(public)
	attributes["subnet_ids"] = strings.Join(networkACLSubnetIDs(acl.Associations), ",")
	attributes["vpc_id"] = awssdk.ToString(acl.VpcId)
	return networkSubstrateEvent(settings, "network-acl", id, "aws.network_acl", "aws/network_acl/v1", map[string]any{"network_acl": acl}, attributes)
}

func internetGatewayEvent(settings settings, gateway ec2types.InternetGateway) (*primitives.Event, error) {
	id := awssdk.ToString(gateway.InternetGatewayId)
	tags := ec2Tags(gateway.Tags)
	vpcIDs := internetGatewayVPCIDs(gateway.Attachments)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyInternetGateway, id, firstNonEmpty(ec2NameTag(gateway.Tags), id), "internet_gateway", tags)
	attributes["arn"] = ec2RegionalARN(settings, "internet-gateway", id)
	attributes["attachment_states"] = strings.Join(internetGatewayAttachmentStates(gateway.Attachments), ",")
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
	attributes["private_ips"] = strings.Join(natGatewayPrivateIPs(gateway.NatGatewayAddresses), ",")
	attributes["public_ips"] = strings.Join(natGatewayPublicIPs(gateway.NatGatewayAddresses), ",")
	attributes["state"] = string(gateway.State)
	attributes["subnet_id"] = awssdk.ToString(gateway.SubnetId)
	attributes["vpc_id"] = awssdk.ToString(gateway.VpcId)
	return networkSubstrateEvent(settings, "nat-gateway", id, "aws.nat_gateway", "aws/nat_gateway/v1", map[string]any{"nat_gateway": gateway}, attributes)
}

func vpcEndpointEvent(settings settings, endpoint ec2types.VpcEndpoint) (*primitives.Event, error) {
	id := awssdk.ToString(endpoint.VpcEndpointId)
	tags := ec2Tags(endpoint.Tags)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyVPCEndpoint, id, firstNonEmpty(ec2NameTag(endpoint.Tags), id), "vpc_endpoint", tags)
	attributes["arn"] = ec2RegionalARN(settings, "vpc-endpoint", id)
	attributes["dns_names"] = strings.Join(vpcEndpointDNSNames(endpoint.DnsEntries), ",")
	attributes["network_interface_ids"] = strings.Join(cleanStrings(endpoint.NetworkInterfaceIds), ",")
	attributes["policy_document"] = awssdk.ToString(endpoint.PolicyDocument)
	attributes["private_dns_enabled"] = boolString(awssdk.ToBool(endpoint.PrivateDnsEnabled))
	attributes["route_table_ids"] = strings.Join(cleanStrings(endpoint.RouteTableIds), ",")
	attributes["security_group_ids"] = strings.Join(vpcEndpointSecurityGroupIDs(endpoint.Groups), ",")
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

func vpcCIDRBlocks(vpc ec2types.Vpc) []string {
	values := []string{awssdk.ToString(vpc.CidrBlock)}
	for _, block := range vpc.CidrBlockAssociationSet {
		values = append(values, awssdk.ToString(block.CidrBlock))
	}
	return cleanStrings(values)
}

func subnetCIDRBlocks(subnet ec2types.Subnet) []string {
	values := []string{awssdk.ToString(subnet.CidrBlock)}
	for _, block := range subnet.Ipv6CidrBlockAssociationSet {
		values = append(values, awssdk.ToString(block.Ipv6CidrBlock))
	}
	return cleanStrings(values)
}

func securityGroupHasPublicIngress(group ec2types.SecurityGroup) bool {
	for _, permission := range group.IpPermissions {
		for _, cidr := range permission.IpRanges {
			if awssdk.ToString(cidr.CidrIp) == "0.0.0.0/0" {
				return true
			}
		}
		for _, cidr := range permission.Ipv6Ranges {
			if awssdk.ToString(cidr.CidrIpv6) == "::/0" {
				return true
			}
		}
	}
	return false
}

func routeTableSubnetIDs(associations []ec2types.RouteTableAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		values = append(values, awssdk.ToString(association.SubnetId))
	}
	return cleanStrings(values)
}

func routeGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, awssdk.ToString(route.GatewayId))
	}
	return cleanStrings(values)
}

func routeInternetGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, id := range routeGatewayIDs(routes) {
		if strings.HasPrefix(id, "igw-") {
			values = append(values, id)
		}
	}
	return cleanStrings(values)
}

func routeNATGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, awssdk.ToString(route.NatGatewayId))
	}
	return cleanStrings(values)
}

func networkACLSubnetIDs(associations []ec2types.NetworkAclAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		values = append(values, awssdk.ToString(association.SubnetId))
	}
	return cleanStrings(values)
}

func networkACLAdminPortsFromInternet(entries []ec2types.NetworkAclEntry) []string {
	ports := make([]string, 0, 2)
	if networkACLAllowsPublicPort(entries, 22) {
		ports = append(ports, "22")
	}
	if networkACLAllowsPublicPort(entries, 3389) {
		ports = append(ports, "3389")
	}
	return ports
}

func networkACLAllowsPublicPort(entries []ec2types.NetworkAclEntry, port int32) bool {
	return networkACLAllowsPublicPortCIDR(entries, port, false) || networkACLAllowsPublicPortCIDR(entries, port, true)
}

func networkACLAllowsPublicPortCIDR(entries []ec2types.NetworkAclEntry, port int32, ipv6 bool) bool {
	matched := false
	bestRuleNumber := int32(1<<31 - 1)
	bestAction := ec2types.RuleAction("")
	for _, entry := range entries {
		if awssdk.ToBool(entry.Egress) || !networkACLPublicCIDR(entry, ipv6) || !networkACLEntryMatchesPort(entry, port) {
			continue
		}
		ruleNumber := networkACLRuleNumber(entry)
		if !matched || ruleNumber < bestRuleNumber {
			matched = true
			bestRuleNumber = ruleNumber
			bestAction = entry.RuleAction
		}
	}
	return matched && bestAction == ec2types.RuleActionAllow
}

func networkACLPublicCIDR(entry ec2types.NetworkAclEntry, ipv6 bool) bool {
	if ipv6 {
		return awssdk.ToString(entry.Ipv6CidrBlock) == "::/0"
	}
	return awssdk.ToString(entry.CidrBlock) == "0.0.0.0/0"
}

func networkACLRuleNumber(entry ec2types.NetworkAclEntry) int32 {
	if entry.RuleNumber == nil {
		return 1<<31 - 1
	}
	return awssdk.ToInt32(entry.RuleNumber)
}

func networkACLEntryMatchesPort(entry ec2types.NetworkAclEntry, port int32) bool {
	protocol := strings.TrimSpace(awssdk.ToString(entry.Protocol))
	if protocol == "-1" {
		return true
	}
	if protocol != "6" && !strings.EqualFold(protocol, "tcp") {
		return false
	}
	if entry.PortRange == nil {
		return true
	}
	from := awssdk.ToInt32(entry.PortRange.From)
	to := awssdk.ToInt32(entry.PortRange.To)
	if to < from {
		to = from
	}
	return port >= from && port <= to
}

func internetGatewayVPCIDs(attachments []ec2types.InternetGatewayAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, awssdk.ToString(attachment.VpcId))
	}
	return cleanStrings(values)
}

func internetGatewayAttachmentStates(attachments []ec2types.InternetGatewayAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, string(attachment.State))
	}
	return cleanStrings(values)
}

func natGatewayPrivateIPs(addresses []ec2types.NatGatewayAddress) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, awssdk.ToString(address.PrivateIp))
	}
	return cleanStrings(values)
}

func natGatewayPublicIPs(addresses []ec2types.NatGatewayAddress) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, awssdk.ToString(address.PublicIp))
	}
	return cleanStrings(values)
}

func vpcEndpointSecurityGroupIDs(groups []ec2types.SecurityGroupIdentifier) []string {
	values := make([]string, 0, len(groups))
	for _, group := range groups {
		values = append(values, awssdk.ToString(group.GroupId))
	}
	return cleanStrings(values)
}

func vpcEndpointDNSNames(entries []ec2types.DnsEntry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, awssdk.ToString(entry.DnsName))
	}
	return cleanStrings(values)
}
