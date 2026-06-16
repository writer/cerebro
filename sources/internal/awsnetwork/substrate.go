package awsnetwork

import (
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func VPCCIDRBlocks(vpc ec2types.Vpc) []string {
	values := []string{awssdk.ToString(vpc.CidrBlock)}
	for _, block := range vpc.CidrBlockAssociationSet {
		values = append(values, awssdk.ToString(block.CidrBlock))
	}
	return cleanStrings(values)
}

func SubnetCIDRBlocks(subnet ec2types.Subnet) []string {
	values := []string{awssdk.ToString(subnet.CidrBlock)}
	for _, block := range subnet.Ipv6CidrBlockAssociationSet {
		values = append(values, awssdk.ToString(block.Ipv6CidrBlock))
	}
	return cleanStrings(values)
}

func SecurityGroupHasPublicIngress(group ec2types.SecurityGroup) bool {
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

func RouteTableSubnetIDs(associations []ec2types.RouteTableAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		values = append(values, awssdk.ToString(association.SubnetId))
	}
	return cleanStrings(values)
}

func NetworkACLSubnetIDs(associations []ec2types.NetworkAclAssociation) []string {
	values := make([]string, 0, len(associations))
	for _, association := range associations {
		values = append(values, awssdk.ToString(association.SubnetId))
	}
	return cleanStrings(values)
}

func NetworkACLRuleCount(entries []ec2types.NetworkAclEntry, egress bool) int {
	count := 0
	for _, entry := range entries {
		if awssdk.ToBool(entry.Egress) == egress {
			count++
		}
	}
	return count
}

func NetworkACLAllowsAdminPortsFromInternet(acl ec2types.NetworkAcl) bool {
	entries := append([]ec2types.NetworkAclEntry(nil), acl.Entries...)
	sort.SliceStable(entries, func(i int, j int) bool {
		return awssdk.ToInt32(entries[i].RuleNumber) < awssdk.ToInt32(entries[j].RuleNumber)
	})
	for _, port := range []int32{22, 3389} {
		if allowed, matched := networkACLAdminPortInternetDecision(entries, port); matched && allowed {
			return true
		}
	}
	return false
}

func networkACLAdminPortInternetDecision(entries []ec2types.NetworkAclEntry, port int32) (bool, bool) {
	for _, entry := range entries {
		if networkACLEntryMatchesAdminPortFromInternet(entry, port) {
			return entry.RuleAction == ec2types.RuleActionAllow, true
		}
	}
	return false, false
}

func networkACLEntryMatchesAdminPortFromInternet(entry ec2types.NetworkAclEntry, port int32) bool {
	return !awssdk.ToBool(entry.Egress) &&
		(cidrIsInternet(awssdk.ToString(entry.CidrBlock)) || cidrIsInternet(awssdk.ToString(entry.Ipv6CidrBlock))) &&
		networkACLProtocolAllowsPort(entry, port)
}

func networkACLProtocolAllowsPort(entry ec2types.NetworkAclEntry, port int32) bool {
	protocol := strings.ToLower(strings.TrimSpace(awssdk.ToString(entry.Protocol)))
	switch protocol {
	case "-1", "all":
		return true
	case "6", "tcp":
		if entry.PortRange == nil {
			return true
		}
		return portRangeContains(awssdk.ToInt32(entry.PortRange.From), awssdk.ToInt32(entry.PortRange.To), port)
	default:
		return false
	}
}

func RouteGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, awssdk.ToString(route.GatewayId))
	}
	return cleanStrings(values)
}

func RouteInternetGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, id := range RouteGatewayIDs(routes) {
		if strings.HasPrefix(id, "igw-") {
			values = append(values, id)
		}
	}
	return cleanStrings(values)
}

func RouteNATGatewayIDs(routes []ec2types.Route) []string {
	values := make([]string, 0, len(routes))
	for _, route := range routes {
		values = append(values, awssdk.ToString(route.NatGatewayId))
	}
	return cleanStrings(values)
}

func InternetGatewayVPCIDs(attachments []ec2types.InternetGatewayAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, awssdk.ToString(attachment.VpcId))
	}
	return cleanStrings(values)
}

func InternetGatewayAttachmentStates(attachments []ec2types.InternetGatewayAttachment) []string {
	values := make([]string, 0, len(attachments))
	for _, attachment := range attachments {
		values = append(values, string(attachment.State))
	}
	return cleanStrings(values)
}

func NATGatewayPrivateIPs(addresses []ec2types.NatGatewayAddress) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, awssdk.ToString(address.PrivateIp))
	}
	return cleanStrings(values)
}

func NATGatewayPublicIPs(addresses []ec2types.NatGatewayAddress) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, awssdk.ToString(address.PublicIp))
	}
	return cleanStrings(values)
}

func FlowLogDestinationFileFormat(flowLog ec2types.FlowLog) ec2types.DestinationFileFormat {
	if flowLog.DestinationOptions == nil {
		return ""
	}
	return flowLog.DestinationOptions.FileFormat
}

func FlowLogHiveCompatiblePartitions(flowLog ec2types.FlowLog) bool {
	return flowLog.DestinationOptions != nil && awssdk.ToBool(flowLog.DestinationOptions.HiveCompatiblePartitions)
}

func FlowLogPerHourPartition(flowLog ec2types.FlowLog) bool {
	return flowLog.DestinationOptions != nil && awssdk.ToBool(flowLog.DestinationOptions.PerHourPartition)
}

func FlowLogVPCID(flowLog ec2types.FlowLog) string {
	resourceID := awssdk.ToString(flowLog.ResourceId)
	if strings.HasPrefix(resourceID, "vpc-") {
		return resourceID
	}
	return ""
}

func VPCEndpointSecurityGroupIDs(groups []ec2types.SecurityGroupIdentifier) []string {
	values := make([]string, 0, len(groups))
	for _, group := range groups {
		values = append(values, awssdk.ToString(group.GroupId))
	}
	return cleanStrings(values)
}

func VPCEndpointDNSNames(entries []ec2types.DnsEntry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, awssdk.ToString(entry.DnsName))
	}
	return cleanStrings(values)
}

func cidrIsInternet(cidr string) bool {
	switch strings.TrimSpace(cidr) {
	case "0.0.0.0/0", "::/0":
		return true
	default:
		return false
	}
}

func portRangeContains(from int32, to int32, port int32) bool {
	if from == 0 && to == 0 {
		return false
	}
	return from <= port && port <= to
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
