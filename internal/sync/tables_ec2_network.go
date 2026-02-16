package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2 AMIs
func (e *SyncEngine) ec2ImageTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_images",
		Columns: []string{"arn", "account_id", "region", "image_id", "name", "description", "state", "owner_id", "public", "architecture", "platform", "root_device_type", "virtualization_type", "creation_date", "tags"},
		Fetch:   e.fetchEC2Images,
	}
}

func (e *SyncEngine) fetchEC2Images(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.Images))
	for _, img := range out.Images {
		imageID := aws.ToString(img.ImageId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:image/%s", region, accountID, imageID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":              arn,
			"arn":                 arn,
			"account_id":          accountID,
			"region":              region,
			"image_id":            imageID,
			"name":                aws.ToString(img.Name),
			"description":         aws.ToString(img.Description),
			"state":               string(img.State),
			"owner_id":            aws.ToString(img.OwnerId),
			"public":              aws.ToBool(img.Public),
			"architecture":        string(img.Architecture),
			"platform":            string(img.Platform),
			"root_device_type":    string(img.RootDeviceType),
			"virtualization_type": string(img.VirtualizationType),
			"creation_date":       aws.ToString(img.CreationDate),
			"tags":                img.Tags,
		})
	}
	return rows, nil
}

// EC2 Elastic IPs
func (e *SyncEngine) ec2EipTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_eips",
		Columns: []string{"arn", "account_id", "region", "allocation_id", "public_ip", "private_ip_address", "instance_id", "association_id", "domain", "network_interface_id", "tags"},
		Fetch:   e.fetchEC2Eips,
	}
}

func (e *SyncEngine) fetchEC2Eips(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.Addresses))
	for _, addr := range out.Addresses {
		allocationID := aws.ToString(addr.AllocationId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:elastic-ip/%s", region, accountID, allocationID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":               arn,
			"arn":                  arn,
			"account_id":           accountID,
			"region":               region,
			"allocation_id":        allocationID,
			"public_ip":            aws.ToString(addr.PublicIp),
			"private_ip_address":   aws.ToString(addr.PrivateIpAddress),
			"instance_id":          aws.ToString(addr.InstanceId),
			"association_id":       aws.ToString(addr.AssociationId),
			"domain":               string(addr.Domain),
			"network_interface_id": aws.ToString(addr.NetworkInterfaceId),
			"tags":                 addr.Tags,
		})
	}
	return rows, nil
}

// EC2 Key Pairs
func (e *SyncEngine) ec2KeyPairTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_key_pairs",
		Columns: []string{"arn", "account_id", "region", "key_pair_id", "key_name", "key_fingerprint", "key_type", "create_time", "tags"},
		Fetch:   e.fetchEC2KeyPairs,
	}
}

func (e *SyncEngine) fetchEC2KeyPairs(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.KeyPairs))
	for _, kp := range out.KeyPairs {
		keyPairID := aws.ToString(kp.KeyPairId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:key-pair/%s", region, accountID, keyPairID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":          arn,
			"arn":             arn,
			"account_id":      accountID,
			"region":          region,
			"key_pair_id":     keyPairID,
			"key_name":        aws.ToString(kp.KeyName),
			"key_fingerprint": aws.ToString(kp.KeyFingerprint),
			"key_type":        string(kp.KeyType),
			"create_time":     kp.CreateTime,
			"tags":            kp.Tags,
		})
	}
	return rows, nil
}

// EC2 Launch Templates
func (e *SyncEngine) ec2LaunchTemplateTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_launch_templates",
		Columns: []string{"arn", "account_id", "region", "launch_template_id", "launch_template_name", "default_version_number", "latest_version_number", "created_by", "create_time", "tags"},
		Fetch:   e.fetchEC2LaunchTemplates,
	}
}

func (e *SyncEngine) fetchEC2LaunchTemplates(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.LaunchTemplates))
	for _, lt := range out.LaunchTemplates {
		ltID := aws.ToString(lt.LaunchTemplateId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:launch-template/%s", region, accountID, ltID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                 arn,
			"arn":                    arn,
			"account_id":             accountID,
			"region":                 region,
			"launch_template_id":     ltID,
			"launch_template_name":   aws.ToString(lt.LaunchTemplateName),
			"default_version_number": lt.DefaultVersionNumber,
			"latest_version_number":  lt.LatestVersionNumber,
			"created_by":             aws.ToString(lt.CreatedBy),
			"create_time":            lt.CreateTime,
			"tags":                   lt.Tags,
		})
	}
	return rows, nil
}

// EC2 Network Interfaces
func (e *SyncEngine) ec2NetworkInterfaceTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_network_interfaces",
		Columns: []string{"arn", "account_id", "region", "network_interface_id", "subnet_id", "vpc_id", "availability_zone", "description", "owner_id", "private_ip_address", "private_dns_name", "source_dest_check", "status", "interface_type", "security_groups", "attachment", "tags"},
		Fetch:   e.fetchEC2NetworkInterfaces,
	}
}

func (e *SyncEngine) fetchEC2NetworkInterfaces(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.NetworkInterfaces))
	for _, ni := range out.NetworkInterfaces {
		niID := aws.ToString(ni.NetworkInterfaceId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:network-interface/%s", region, accountID, niID)

		var attachment interface{}
		if ni.Attachment != nil {
			attachment = map[string]interface{}{
				"attachment_id":         aws.ToString(ni.Attachment.AttachmentId),
				"instance_id":           aws.ToString(ni.Attachment.InstanceId),
				"instance_owner_id":     aws.ToString(ni.Attachment.InstanceOwnerId),
				"device_index":          ni.Attachment.DeviceIndex,
				"status":                string(ni.Attachment.Status),
				"delete_on_termination": aws.ToBool(ni.Attachment.DeleteOnTermination),
			}
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":               arn,
			"arn":                  arn,
			"account_id":           accountID,
			"region":               region,
			"network_interface_id": niID,
			"subnet_id":            aws.ToString(ni.SubnetId),
			"vpc_id":               aws.ToString(ni.VpcId),
			"availability_zone":    aws.ToString(ni.AvailabilityZone),
			"description":          aws.ToString(ni.Description),
			"owner_id":             aws.ToString(ni.OwnerId),
			"private_ip_address":   aws.ToString(ni.PrivateIpAddress),
			"private_dns_name":     aws.ToString(ni.PrivateDnsName),
			"source_dest_check":    aws.ToBool(ni.SourceDestCheck),
			"status":               string(ni.Status),
			"interface_type":       string(ni.InterfaceType),
			"security_groups":      ni.Groups,
			"attachment":           attachment,
			"tags":                 ni.TagSet,
		})
	}
	return rows, nil
}

// EC2 Flow Logs
func (e *SyncEngine) ec2FlowLogTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_flow_logs",
		Columns: []string{"arn", "account_id", "region", "flow_log_id", "flow_log_status", "resource_id", "traffic_type", "log_destination_type", "log_destination", "log_group_name", "deliver_logs_permission_arn", "creation_time", "tags"},
		Fetch:   e.fetchEC2FlowLogs,
	}
}

func (e *SyncEngine) fetchEC2FlowLogs(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.FlowLogs))
	for _, fl := range out.FlowLogs {
		flowLogID := aws.ToString(fl.FlowLogId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-flow-log/%s", region, accountID, flowLogID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                      arn,
			"arn":                         arn,
			"account_id":                  accountID,
			"region":                      region,
			"flow_log_id":                 flowLogID,
			"flow_log_status":             aws.ToString(fl.FlowLogStatus),
			"resource_id":                 aws.ToString(fl.ResourceId),
			"traffic_type":                string(fl.TrafficType),
			"log_destination_type":        string(fl.LogDestinationType),
			"log_destination":             aws.ToString(fl.LogDestination),
			"log_group_name":              aws.ToString(fl.LogGroupName),
			"deliver_logs_permission_arn": aws.ToString(fl.DeliverLogsPermissionArn),
			"creation_time":               fl.CreationTime,
			"tags":                        fl.Tags,
		})
	}
	return rows, nil
}

// EC2 VPC Endpoints
func (e *SyncEngine) ec2VpcEndpointTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_vpc_endpoints",
		Columns: []string{"arn", "account_id", "region", "vpc_endpoint_id", "vpc_id", "service_name", "state", "vpc_endpoint_type", "policy_document", "route_table_ids", "subnet_ids", "private_dns_enabled", "creation_timestamp", "tags"},
		Fetch:   e.fetchEC2VpcEndpoints,
	}
}

func (e *SyncEngine) fetchEC2VpcEndpoints(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.VpcEndpoints))
	for _, ep := range out.VpcEndpoints {
		epID := aws.ToString(ep.VpcEndpointId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-endpoint/%s", region, accountID, epID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":              arn,
			"arn":                 arn,
			"account_id":          accountID,
			"region":              region,
			"vpc_endpoint_id":     epID,
			"vpc_id":              aws.ToString(ep.VpcId),
			"service_name":        aws.ToString(ep.ServiceName),
			"state":               string(ep.State),
			"vpc_endpoint_type":   string(ep.VpcEndpointType),
			"policy_document":     aws.ToString(ep.PolicyDocument),
			"route_table_ids":     ep.RouteTableIds,
			"subnet_ids":          ep.SubnetIds,
			"private_dns_enabled": aws.ToBool(ep.PrivateDnsEnabled),
			"creation_timestamp":  ep.CreationTimestamp,
			"tags":                ep.Tags,
		})
	}
	return rows, nil
}

// EC2 VPC Peering Connections
func (e *SyncEngine) ec2VpcPeeringConnectionTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_vpc_peering_connections",
		Columns: []string{"arn", "account_id", "region", "vpc_peering_connection_id", "status_code", "status_message", "requester_vpc_info", "accepter_vpc_info", "expiration_time", "tags"},
		Fetch:   e.fetchEC2VpcPeeringConnections,
	}
}

func (e *SyncEngine) fetchEC2VpcPeeringConnections(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.VpcPeeringConnections))
	for _, pc := range out.VpcPeeringConnections {
		pcID := aws.ToString(pc.VpcPeeringConnectionId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc-peering-connection/%s", region, accountID, pcID)

		var requesterInfo, accepterInfo interface{}
		if pc.RequesterVpcInfo != nil {
			requesterInfo = map[string]interface{}{
				"vpc_id":     aws.ToString(pc.RequesterVpcInfo.VpcId),
				"owner_id":   aws.ToString(pc.RequesterVpcInfo.OwnerId),
				"cidr_block": aws.ToString(pc.RequesterVpcInfo.CidrBlock),
				"region":     aws.ToString(pc.RequesterVpcInfo.Region),
			}
		}
		if pc.AccepterVpcInfo != nil {
			accepterInfo = map[string]interface{}{
				"vpc_id":     aws.ToString(pc.AccepterVpcInfo.VpcId),
				"owner_id":   aws.ToString(pc.AccepterVpcInfo.OwnerId),
				"cidr_block": aws.ToString(pc.AccepterVpcInfo.CidrBlock),
				"region":     aws.ToString(pc.AccepterVpcInfo.Region),
			}
		}

		var statusCode, statusMessage string
		if pc.Status != nil {
			statusCode = string(pc.Status.Code)
			statusMessage = aws.ToString(pc.Status.Message)
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                    arn,
			"arn":                       arn,
			"account_id":                accountID,
			"region":                    region,
			"vpc_peering_connection_id": pcID,
			"status_code":               statusCode,
			"status_message":            statusMessage,
			"requester_vpc_info":        requesterInfo,
			"accepter_vpc_info":         accepterInfo,
			"expiration_time":           pc.ExpirationTime,
			"tags":                      pc.Tags,
		})
	}
	return rows, nil
}

// EC2 Transit Gateways
func (e *SyncEngine) ec2TransitGatewayTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_transit_gateways",
		Columns: []string{"arn", "account_id", "region", "transit_gateway_id", "state", "owner_id", "description", "amazon_side_asn", "auto_accept_shared_attachments", "default_route_table_association", "default_route_table_propagation", "vpn_ecmp_support", "dns_support", "creation_time", "tags"},
		Fetch:   e.fetchEC2TransitGateways,
	}
}

func (e *SyncEngine) fetchEC2TransitGateways(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.TransitGateways))
	for _, tgw := range out.TransitGateways {
		tgwID := aws.ToString(tgw.TransitGatewayId)
		tgwArn := aws.ToString(tgw.TransitGatewayArn)
		if tgwArn == "" {
			tgwArn = fmt.Sprintf("arn:aws:ec2:%s:%s:transit-gateway/%s", region, accountID, tgwID)
		}

		var autoAccept, defaultAssoc, defaultProp, vpnEcmp, dnsSupport string
		if tgw.Options != nil {
			autoAccept = string(tgw.Options.AutoAcceptSharedAttachments)
			defaultAssoc = string(tgw.Options.DefaultRouteTableAssociation)
			defaultProp = string(tgw.Options.DefaultRouteTablePropagation)
			vpnEcmp = string(tgw.Options.VpnEcmpSupport)
			dnsSupport = string(tgw.Options.DnsSupport)
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                          tgwArn,
			"arn":                             tgwArn,
			"account_id":                      accountID,
			"region":                          region,
			"transit_gateway_id":              tgwID,
			"state":                           string(tgw.State),
			"owner_id":                        aws.ToString(tgw.OwnerId),
			"description":                     aws.ToString(tgw.Description),
			"amazon_side_asn":                 tgw.Options.AmazonSideAsn,
			"auto_accept_shared_attachments":  autoAccept,
			"default_route_table_association": defaultAssoc,
			"default_route_table_propagation": defaultProp,
			"vpn_ecmp_support":                vpnEcmp,
			"dns_support":                     dnsSupport,
			"creation_time":                   tgw.CreationTime,
			"tags":                            tgw.Tags,
		})
	}
	return rows, nil
}

// EC2 Transit Gateway Attachments
func (e *SyncEngine) ec2TransitGatewayAttachmentTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_transit_gateway_attachments",
		Columns: []string{
			"arn", "account_id", "region", "transit_gateway_attachment_id", "transit_gateway_id",
			"transit_gateway_owner_id", "resource_id", "resource_owner_id", "resource_type", "state",
			"association_state", "association_transit_gateway_route_table_id", "creation_time", "tags",
		},
		Fetch: e.fetchEC2TransitGatewayAttachments,
	}
}

func (e *SyncEngine) fetchEC2TransitGatewayAttachments(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(client, &ec2.DescribeTransitGatewayAttachmentsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, attachment := range page.TransitGatewayAttachments {
			attachmentID := aws.ToString(attachment.TransitGatewayAttachmentId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:transit-gateway-attachment/%s", region, accountID, attachmentID)
			associationState := ""
			associationRouteTableID := ""
			if attachment.Association != nil {
				associationState = string(attachment.Association.State)
				associationRouteTableID = aws.ToString(attachment.Association.TransitGatewayRouteTableId)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                        arn,
				"arn":                           arn,
				"account_id":                    accountID,
				"region":                        region,
				"transit_gateway_attachment_id": attachmentID,
				"transit_gateway_id":            aws.ToString(attachment.TransitGatewayId),
				"transit_gateway_owner_id":      aws.ToString(attachment.TransitGatewayOwnerId),
				"resource_id":                   aws.ToString(attachment.ResourceId),
				"resource_owner_id":             aws.ToString(attachment.ResourceOwnerId),
				"resource_type":                 string(attachment.ResourceType),
				"state":                         string(attachment.State),
				"association_state":             associationState,
				"association_transit_gateway_route_table_id": associationRouteTableID,
				"creation_time": attachment.CreationTime,
				"tags":          attachment.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 Transit Gateway Route Tables
func (e *SyncEngine) ec2TransitGatewayRouteTableTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_transit_gateway_route_tables",
		Columns: []string{
			"arn", "account_id", "region", "transit_gateway_route_table_id", "transit_gateway_id",
			"state", "default_association_route_table", "default_propagation_route_table", "creation_time", "tags",
		},
		Fetch: e.fetchEC2TransitGatewayRouteTables,
	}
}

func (e *SyncEngine) fetchEC2TransitGatewayRouteTables(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(client, &ec2.DescribeTransitGatewayRouteTablesInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, routeTable := range page.TransitGatewayRouteTables {
			routeTableID := aws.ToString(routeTable.TransitGatewayRouteTableId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:transit-gateway-route-table/%s", region, accountID, routeTableID)
			rows = append(rows, map[string]interface{}{
				"_cq_id":                          arn,
				"arn":                             arn,
				"account_id":                      accountID,
				"region":                          region,
				"transit_gateway_route_table_id":  routeTableID,
				"transit_gateway_id":              aws.ToString(routeTable.TransitGatewayId),
				"state":                           string(routeTable.State),
				"default_association_route_table": aws.ToBool(routeTable.DefaultAssociationRouteTable),
				"default_propagation_route_table": aws.ToBool(routeTable.DefaultPropagationRouteTable),
				"creation_time":                   routeTable.CreationTime,
				"tags":                            routeTable.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 Managed Prefix Lists
func (e *SyncEngine) ec2ManagedPrefixListTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_managed_prefix_lists",
		Columns: []string{
			"arn", "account_id", "region", "prefix_list_id", "prefix_list_name", "address_family",
			"max_entries", "state", "state_message", "version", "owner_id", "tags",
		},
		Fetch: e.fetchEC2ManagedPrefixLists,
	}
}

func (e *SyncEngine) fetchEC2ManagedPrefixLists(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeManagedPrefixListsPaginator(client, &ec2.DescribeManagedPrefixListsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, pl := range page.PrefixLists {
			prefixListID := aws.ToString(pl.PrefixListId)
			arn := aws.ToString(pl.PrefixListArn)
			if arn == "" {
				arn = fmt.Sprintf("arn:aws:ec2:%s:%s:prefix-list/%s", region, accountID, prefixListID)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":           arn,
				"arn":              arn,
				"account_id":       accountID,
				"region":           region,
				"prefix_list_id":   prefixListID,
				"prefix_list_name": aws.ToString(pl.PrefixListName),
				"address_family":   aws.ToString(pl.AddressFamily),
				"max_entries":      pl.MaxEntries,
				"state":            string(pl.State),
				"state_message":    aws.ToString(pl.StateMessage),
				"version":          pl.Version,
				"owner_id":         aws.ToString(pl.OwnerId),
				"tags":             pl.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 Client VPN Endpoints
func (e *SyncEngine) ec2ClientVpnEndpointTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_client_vpn_endpoints",
		Columns: []string{
			"arn", "account_id", "region", "client_vpn_endpoint_id", "description", "client_cidr_block",
			"server_certificate_arn", "authentication_options", "connection_log_options", "dns_servers",
			"split_tunnel", "vpc_id", "security_group_ids", "transport_protocol", "vpn_port",
			"status_code", "status_message", "creation_time", "tags",
		},
		Fetch: e.fetchEC2ClientVpnEndpoints,
	}
}

func (e *SyncEngine) fetchEC2ClientVpnEndpoints(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeClientVpnEndpointsPaginator(client, &ec2.DescribeClientVpnEndpointsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, endpoint := range page.ClientVpnEndpoints {
			endpointID := aws.ToString(endpoint.ClientVpnEndpointId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:client-vpn-endpoint/%s", region, accountID, endpointID)
			statusCode := ""
			statusMessage := ""
			if endpoint.Status != nil {
				statusCode = string(endpoint.Status.Code)
				statusMessage = aws.ToString(endpoint.Status.Message)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                 arn,
				"arn":                    arn,
				"account_id":             accountID,
				"region":                 region,
				"client_vpn_endpoint_id": endpointID,
				"description":            aws.ToString(endpoint.Description),
				"client_cidr_block":      aws.ToString(endpoint.ClientCidrBlock),
				"server_certificate_arn": aws.ToString(endpoint.ServerCertificateArn),
				"authentication_options": endpoint.AuthenticationOptions,
				"connection_log_options": endpoint.ConnectionLogOptions,
				"dns_servers":            endpoint.DnsServers,
				"split_tunnel":           aws.ToBool(endpoint.SplitTunnel),
				"vpc_id":                 aws.ToString(endpoint.VpcId),
				"security_group_ids":     endpoint.SecurityGroupIds,
				"transport_protocol":     string(endpoint.TransportProtocol),
				"vpn_port":               endpoint.VpnPort,
				"status_code":            statusCode,
				"status_message":         statusMessage,
				"creation_time":          endpoint.CreationTime,
				"tags":                   endpoint.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 Dedicated Hosts
func (e *SyncEngine) ec2DedicatedHostTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_dedicated_hosts",
		Columns: []string{
			"arn", "account_id", "region", "host_id", "availability_zone", "state",
			"auto_placement", "host_recovery", "allocation_time", "release_time",
			"instance_family", "instance_type", "host_properties", "host_reservation_id", "tags",
		},
		Fetch: e.fetchEC2DedicatedHosts,
	}
}

func (e *SyncEngine) fetchEC2DedicatedHosts(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeHostsPaginator(client, &ec2.DescribeHostsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, host := range page.Hosts {
			hostID := aws.ToString(host.HostId)
			arn := fmt.Sprintf("arn:aws:ec2:%s:%s:dedicated-host/%s", region, accountID, hostID)
			instanceFamily := ""
			instanceType := ""
			if host.HostProperties != nil {
				instanceFamily = aws.ToString(host.HostProperties.InstanceFamily)
				instanceType = aws.ToString(host.HostProperties.InstanceType)
			}
			rows = append(rows, map[string]interface{}{
				"_cq_id":              arn,
				"arn":                 arn,
				"account_id":          accountID,
				"region":              region,
				"host_id":             hostID,
				"availability_zone":   aws.ToString(host.AvailabilityZone),
				"state":               string(host.State),
				"auto_placement":      string(host.AutoPlacement),
				"host_recovery":       string(host.HostRecovery),
				"allocation_time":     host.AllocationTime,
				"release_time":        host.ReleaseTime,
				"instance_family":     instanceFamily,
				"instance_type":       instanceType,
				"host_properties":     host.HostProperties,
				"host_reservation_id": aws.ToString(host.HostReservationId),
				"tags":                host.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 IPAMs
func (e *SyncEngine) ec2IpamTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_ipams",
		Columns: []string{
			"arn", "account_id", "region", "ipam_id", "ipam_region", "owner_id", "description",
			"state", "state_message", "operating_regions", "private_default_scope_id", "public_default_scope_id",
			"scope_count", "tier", "metered_account", "default_resource_discovery_id",
			"default_resource_discovery_association_id", "resource_discovery_association_count",
			"enable_private_gua", "tags",
		},
		Fetch: e.fetchEC2Ipams,
	}
}

func (e *SyncEngine) fetchEC2Ipams(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeIpamsPaginator(client, &ec2.DescribeIpamsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, ipam := range page.Ipams {
			ipamID := aws.ToString(ipam.IpamId)
			arn := aws.ToString(ipam.IpamArn)
			if arn == "" {
				arn = fmt.Sprintf("arn:aws:ec2:%s:%s:ipam/%s", region, accountID, ipamID)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                        arn,
				"arn":                           arn,
				"account_id":                    accountID,
				"region":                        region,
				"ipam_id":                       ipamID,
				"ipam_region":                   aws.ToString(ipam.IpamRegion),
				"owner_id":                      aws.ToString(ipam.OwnerId),
				"description":                   aws.ToString(ipam.Description),
				"state":                         string(ipam.State),
				"state_message":                 aws.ToString(ipam.StateMessage),
				"operating_regions":             ipam.OperatingRegions,
				"private_default_scope_id":      aws.ToString(ipam.PrivateDefaultScopeId),
				"public_default_scope_id":       aws.ToString(ipam.PublicDefaultScopeId),
				"scope_count":                   ipam.ScopeCount,
				"tier":                          string(ipam.Tier),
				"metered_account":               string(ipam.MeteredAccount),
				"default_resource_discovery_id": aws.ToString(ipam.DefaultResourceDiscoveryId),
				"default_resource_discovery_association_id": aws.ToString(ipam.DefaultResourceDiscoveryAssociationId),
				"resource_discovery_association_count":      ipam.ResourceDiscoveryAssociationCount,
				"enable_private_gua":                        aws.ToBool(ipam.EnablePrivateGua),
				"tags":                                      ipam.Tags,
			})
		}
	}

	return rows, nil
}

// EC2 Reserved Instances
func (e *SyncEngine) ec2ReservedInstanceTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_reserved_instances",
		Columns: []string{"arn", "account_id", "region", "reserved_instances_id", "instance_type", "instance_count", "state", "availability_zone", "duration", "start_time", "end_time", "fixed_price", "usage_price", "currency_code", "offering_type", "product_description", "tags"},
		Fetch:   e.fetchEC2ReservedInstances,
	}
}

func (e *SyncEngine) fetchEC2ReservedInstances(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeReservedInstances(ctx, &ec2.DescribeReservedInstancesInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.ReservedInstances))
	for _, ri := range out.ReservedInstances {
		riID := aws.ToString(ri.ReservedInstancesId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:reserved-instances/%s", region, accountID, riID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                arn,
			"arn":                   arn,
			"account_id":            accountID,
			"region":                region,
			"reserved_instances_id": riID,
			"instance_type":         string(ri.InstanceType),
			"instance_count":        ri.InstanceCount,
			"state":                 string(ri.State),
			"availability_zone":     aws.ToString(ri.AvailabilityZone),
			"duration":              ri.Duration,
			"start_time":            ri.Start,
			"end_time":              ri.End,
			"fixed_price":           ri.FixedPrice,
			"usage_price":           ri.UsagePrice,
			"currency_code":         string(ri.CurrencyCode),
			"offering_type":         string(ri.OfferingType),
			"product_description":   string(ri.ProductDescription),
			"tags":                  ri.Tags,
		})
	}
	return rows, nil
}

// EC2 Capacity Reservations
func (e *SyncEngine) ec2CapacityReservationTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_capacity_reservations",
		Columns: []string{"arn", "account_id", "region", "capacity_reservation_id", "instance_type", "instance_platform", "availability_zone", "tenancy", "total_instance_count", "available_instance_count", "ebs_optimized", "ephemeral_storage", "state", "start_date", "end_date", "end_date_type", "instance_match_criteria", "tags"},
		Fetch:   e.fetchEC2CapacityReservations,
	}
}

func (e *SyncEngine) fetchEC2CapacityReservations(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeCapacityReservations(ctx, &ec2.DescribeCapacityReservationsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.CapacityReservations))
	for _, cr := range out.CapacityReservations {
		crID := aws.ToString(cr.CapacityReservationId)
		crArn := aws.ToString(cr.CapacityReservationArn)
		if crArn == "" {
			crArn = fmt.Sprintf("arn:aws:ec2:%s:%s:capacity-reservation/%s", region, accountID, crID)
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                   crArn,
			"arn":                      crArn,
			"account_id":               accountID,
			"region":                   region,
			"capacity_reservation_id":  crID,
			"instance_type":            aws.ToString(cr.InstanceType),
			"instance_platform":        string(cr.InstancePlatform),
			"availability_zone":        aws.ToString(cr.AvailabilityZone),
			"tenancy":                  string(cr.Tenancy),
			"total_instance_count":     cr.TotalInstanceCount,
			"available_instance_count": cr.AvailableInstanceCount,
			"ebs_optimized":            aws.ToBool(cr.EbsOptimized),
			"ephemeral_storage":        aws.ToBool(cr.EphemeralStorage),
			"state":                    string(cr.State),
			"start_date":               cr.StartDate,
			"end_date":                 cr.EndDate,
			"end_date_type":            string(cr.EndDateType),
			"instance_match_criteria":  string(cr.InstanceMatchCriteria),
			"tags":                     cr.Tags,
		})
	}
	return rows, nil
}

// EC2 Spot Instance Requests
func (e *SyncEngine) ec2SpotInstanceRequestTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_spot_instance_requests",
		Columns: []string{"arn", "account_id", "region", "spot_instance_request_id", "instance_id", "state", "status_code", "status_message", "spot_price", "type", "launched_availability_zone", "instance_type", "product_description", "valid_from", "valid_until", "create_time", "tags"},
		Fetch:   e.fetchEC2SpotInstanceRequests,
	}
}

func (e *SyncEngine) fetchEC2SpotInstanceRequests(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeSpotInstanceRequests(ctx, &ec2.DescribeSpotInstanceRequestsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.SpotInstanceRequests))
	for _, sir := range out.SpotInstanceRequests {
		sirID := aws.ToString(sir.SpotInstanceRequestId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:spot-instance-request/%s", region, accountID, sirID)

		var statusCode, statusMessage string
		if sir.Status != nil {
			statusCode = aws.ToString(sir.Status.Code)
			statusMessage = aws.ToString(sir.Status.Message)
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":                     arn,
			"arn":                        arn,
			"account_id":                 accountID,
			"region":                     region,
			"spot_instance_request_id":   sirID,
			"instance_id":                aws.ToString(sir.InstanceId),
			"state":                      string(sir.State),
			"status_code":                statusCode,
			"status_message":             statusMessage,
			"spot_price":                 aws.ToString(sir.SpotPrice),
			"type":                       string(sir.Type),
			"launched_availability_zone": aws.ToString(sir.LaunchedAvailabilityZone),
			"instance_type":              string(sir.LaunchSpecification.InstanceType),
			"product_description":        string(sir.ProductDescription),
			"valid_from":                 sir.ValidFrom,
			"valid_until":                sir.ValidUntil,
			"create_time":                sir.CreateTime,
			"tags":                       sir.Tags,
		})
	}
	return rows, nil
}

// EC2 Customer Gateways (VPN)
func (e *SyncEngine) ec2CustomerGatewayTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_customer_gateways",
		Columns: []string{"arn", "account_id", "region", "customer_gateway_id", "state", "type", "ip_address", "bgp_asn", "certificate_arn", "device_name", "tags"},
		Fetch:   e.fetchEC2CustomerGateways,
	}
}

func (e *SyncEngine) fetchEC2CustomerGateways(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeCustomerGateways(ctx, &ec2.DescribeCustomerGatewaysInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.CustomerGateways))
	for _, cgw := range out.CustomerGateways {
		cgwID := aws.ToString(cgw.CustomerGatewayId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:customer-gateway/%s", region, accountID, cgwID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":              arn,
			"arn":                 arn,
			"account_id":          accountID,
			"region":              region,
			"customer_gateway_id": cgwID,
			"state":               aws.ToString(cgw.State),
			"type":                aws.ToString(cgw.Type),
			"ip_address":          aws.ToString(cgw.IpAddress),
			"bgp_asn":             aws.ToString(cgw.BgpAsn),
			"certificate_arn":     aws.ToString(cgw.CertificateArn),
			"device_name":         aws.ToString(cgw.DeviceName),
			"tags":                cgw.Tags,
		})
	}
	return rows, nil
}

// EC2 VPN Gateways
func (e *SyncEngine) ec2VpnGatewayTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_vpn_gateways",
		Columns: []string{"arn", "account_id", "region", "vpn_gateway_id", "state", "type", "amazon_side_asn", "availability_zone", "vpc_attachments", "tags"},
		Fetch:   e.fetchEC2VpnGateways,
	}
}

func (e *SyncEngine) fetchEC2VpnGateways(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.VpnGateways))
	for _, vgw := range out.VpnGateways {
		vgwID := aws.ToString(vgw.VpnGatewayId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpn-gateway/%s", region, accountID, vgwID)

		var attachments []map[string]interface{}
		for _, att := range vgw.VpcAttachments {
			attachments = append(attachments, map[string]interface{}{
				"vpc_id": aws.ToString(att.VpcId),
				"state":  string(att.State),
			})
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":            arn,
			"arn":               arn,
			"account_id":        accountID,
			"region":            region,
			"vpn_gateway_id":    vgwID,
			"state":             string(vgw.State),
			"type":              string(vgw.Type),
			"amazon_side_asn":   vgw.AmazonSideAsn,
			"availability_zone": aws.ToString(vgw.AvailabilityZone),
			"vpc_attachments":   attachments,
			"tags":              vgw.Tags,
		})
	}
	return rows, nil
}

// EC2 VPN Connections
func (e *SyncEngine) ec2VpnConnectionTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_vpn_connections",
		Columns: []string{"arn", "account_id", "region", "vpn_connection_id", "state", "type", "customer_gateway_id", "vpn_gateway_id", "transit_gateway_id", "customer_gateway_configuration", "category", "tags"},
		Fetch:   e.fetchEC2VpnConnections,
	}
}

func (e *SyncEngine) fetchEC2VpnConnections(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.VpnConnections))
	for _, vpn := range out.VpnConnections {
		vpnID := aws.ToString(vpn.VpnConnectionId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpn-connection/%s", region, accountID, vpnID)

		rows = append(rows, map[string]interface{}{
			"_cq_id":                         arn,
			"arn":                            arn,
			"account_id":                     accountID,
			"region":                         region,
			"vpn_connection_id":              vpnID,
			"state":                          string(vpn.State),
			"type":                           string(vpn.Type),
			"customer_gateway_id":            aws.ToString(vpn.CustomerGatewayId),
			"vpn_gateway_id":                 aws.ToString(vpn.VpnGatewayId),
			"transit_gateway_id":             aws.ToString(vpn.TransitGatewayId),
			"customer_gateway_configuration": aws.ToString(vpn.CustomerGatewayConfiguration),
			"category":                       aws.ToString(vpn.Category),
			"tags":                           vpn.Tags,
		})
	}
	return rows, nil
}

// EC2 DHCP Options
func (e *SyncEngine) ec2DhcpOptionsTable() TableSpec {
	return TableSpec{
		Name:    "aws_ec2_dhcp_options",
		Columns: []string{"arn", "account_id", "region", "dhcp_options_id", "owner_id", "dhcp_configurations", "tags"},
		Fetch:   e.fetchEC2DhcpOptions,
	}
}

func (e *SyncEngine) fetchEC2DhcpOptions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	out, err := client.DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{})
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]interface{}, 0, len(out.DhcpOptions))
	for _, dhcp := range out.DhcpOptions {
		dhcpID := aws.ToString(dhcp.DhcpOptionsId)
		arn := fmt.Sprintf("arn:aws:ec2:%s:%s:dhcp-options/%s", region, accountID, dhcpID)

		var configs []map[string]interface{}
		for _, cfg := range dhcp.DhcpConfigurations {
			var values []string
			for _, v := range cfg.Values {
				values = append(values, aws.ToString(v.Value))
			}
			configs = append(configs, map[string]interface{}{
				"key":    aws.ToString(cfg.Key),
				"values": values,
			})
		}

		rows = append(rows, map[string]interface{}{
			"_cq_id":              arn,
			"arn":                 arn,
			"account_id":          accountID,
			"region":              region,
			"dhcp_options_id":     dhcpID,
			"owner_id":            aws.ToString(dhcp.OwnerId),
			"dhcp_configurations": configs,
			"tags":                dhcp.Tags,
		})
	}
	return rows, nil
}

// Ensure types package is used (required for type assertions in fetch functions)
var _ types.InstanceType
