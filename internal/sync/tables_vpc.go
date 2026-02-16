package sync

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func (e *SyncEngine) ec2SecurityGroupTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_security_groups",
		Columns: []string{
			"arn", "group_id", "group_name", "description", "region", "account_id",
			"vpc_id", "owner_id", "ip_permissions", "ip_permissions_egress", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe security groups: %w", err)
				}

				for _, sg := range page.SecurityGroups {
					groupID := ptrToStr(sg.GroupId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, ptrToStr(sg.OwnerId), groupID)

					tags := make(map[string]string)
					for _, t := range sg.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":                arn,
						"arn":                   arn,
						"group_id":              groupID,
						"group_name":            ptrToStr(sg.GroupName),
						"description":           ptrToStr(sg.Description),
						"region":                region,
						"account_id":            ptrToStr(sg.OwnerId),
						"vpc_id":                ptrToStr(sg.VpcId),
						"owner_id":              ptrToStr(sg.OwnerId),
						"ip_permissions":        sg.IpPermissions,
						"ip_permissions_egress": sg.IpPermissionsEgress,
						"tags":                  tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2SecurityGroupRuleTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_security_group_rules",
		Columns: []string{
			"arn", "account_id", "region", "security_group_id", "security_group_name",
			"direction", "protocol", "from_port", "to_port",
			"ip_ranges", "ipv6_ranges", "prefix_list_ids", "user_id_group_pairs",
		},
		Fetch: e.fetchEC2SecurityGroupRules,
	}
}

func (e *SyncEngine) fetchEC2SecurityGroupRules(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			groupID := ptrToStr(sg.GroupId)
			groupName := ptrToStr(sg.GroupName)

			for _, perm := range sg.IpPermissions {
				rows = append(rows, buildSecurityGroupRuleRow(accountID, region, groupID, groupName, "ingress", perm))
			}
			for _, perm := range sg.IpPermissionsEgress {
				rows = append(rows, buildSecurityGroupRuleRow(accountID, region, groupID, groupName, "egress", perm))
			}
		}
	}

	return rows, nil
}

func buildSecurityGroupRuleRow(accountID, region, groupID, groupName, direction string, perm types.IpPermission) map[string]interface{} {
	protocol := aws.ToString(perm.IpProtocol)

	var fromPort interface{}
	if perm.FromPort != nil {
		fromPort = *perm.FromPort
	}
	var toPort interface{}
	if perm.ToPort != nil {
		toPort = *perm.ToPort
	}

	ipRangeKeys := make([]string, 0, len(perm.IpRanges))
	for _, r := range perm.IpRanges {
		ipRangeKeys = append(ipRangeKeys, fmt.Sprintf("%s|%s", aws.ToString(r.CidrIp), aws.ToString(r.Description)))
	}
	sort.Strings(ipRangeKeys)

	ipv6RangeKeys := make([]string, 0, len(perm.Ipv6Ranges))
	for _, r := range perm.Ipv6Ranges {
		ipv6RangeKeys = append(ipv6RangeKeys, fmt.Sprintf("%s|%s", aws.ToString(r.CidrIpv6), aws.ToString(r.Description)))
	}
	sort.Strings(ipv6RangeKeys)

	prefixListKeys := make([]string, 0, len(perm.PrefixListIds))
	for _, p := range perm.PrefixListIds {
		prefixListKeys = append(prefixListKeys, fmt.Sprintf("%s|%s", aws.ToString(p.PrefixListId), aws.ToString(p.Description)))
	}
	sort.Strings(prefixListKeys)

	userGroupKeys := make([]string, 0, len(perm.UserIdGroupPairs))
	for _, pair := range perm.UserIdGroupPairs {
		userGroupKeys = append(userGroupKeys, fmt.Sprintf("%s|%s|%s|%s|%s|%s",
			aws.ToString(pair.GroupId),
			aws.ToString(pair.GroupName),
			aws.ToString(pair.UserId),
			aws.ToString(pair.VpcId),
			aws.ToString(pair.VpcPeeringConnectionId),
			aws.ToString(pair.Description),
		))
	}
	sort.Strings(userGroupKeys)

	idData := map[string]interface{}{
		"security_group_id":   groupID,
		"direction":           direction,
		"protocol":            protocol,
		"from_port":           fromPort,
		"to_port":             toPort,
		"ip_ranges":           ipRangeKeys,
		"ipv6_ranges":         ipv6RangeKeys,
		"prefix_list_ids":     prefixListKeys,
		"user_id_group_pairs": userGroupKeys,
	}

	ruleHash := hashRowContent(idData)
	arn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group-rule/%s/%s/%s", region, accountID, groupID, direction, ruleHash)

	return map[string]interface{}{
		"_cq_id":              arn,
		"arn":                 arn,
		"account_id":          accountID,
		"region":              region,
		"security_group_id":   groupID,
		"security_group_name": groupName,
		"direction":           direction,
		"protocol":            protocol,
		"from_port":           fromPort,
		"to_port":             toPort,
		"ip_ranges":           perm.IpRanges,
		"ipv6_ranges":         perm.Ipv6Ranges,
		"prefix_list_ids":     perm.PrefixListIds,
		"user_id_group_pairs": perm.UserIdGroupPairs,
	}
}

func (e *SyncEngine) ec2VpcTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_vpcs",
		Columns: []string{
			"arn", "vpc_id", "region", "account_id", "cidr_block",
			"cidr_block_association_set", "dhcp_options_id", "instance_tenancy",
			"ipv6_cidr_block_association_set", "is_default", "owner_id", "state", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeVpcsPaginator(client, &ec2.DescribeVpcsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe vpcs: %w", err)
				}

				for _, vpc := range page.Vpcs {
					vpcID := ptrToStr(vpc.VpcId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, ptrToStr(vpc.OwnerId), vpcID)

					tags := make(map[string]string)
					for _, t := range vpc.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":                          arn,
						"arn":                             arn,
						"vpc_id":                          vpcID,
						"region":                          region,
						"account_id":                      ptrToStr(vpc.OwnerId),
						"cidr_block":                      ptrToStr(vpc.CidrBlock),
						"cidr_block_association_set":      vpc.CidrBlockAssociationSet,
						"dhcp_options_id":                 ptrToStr(vpc.DhcpOptionsId),
						"instance_tenancy":                string(vpc.InstanceTenancy),
						"ipv6_cidr_block_association_set": vpc.Ipv6CidrBlockAssociationSet,
						"is_default":                      vpc.IsDefault,
						"owner_id":                        ptrToStr(vpc.OwnerId),
						"state":                           string(vpc.State),
						"tags":                            tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2NaclTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_network_acls",
		Columns: []string{
			"arn", "network_acl_id", "region", "account_id", "vpc_id",
			"is_default", "entries", "associations", "owner_id", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeNetworkAclsPaginator(client, &ec2.DescribeNetworkAclsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe network acls: %w", err)
				}

				for _, nacl := range page.NetworkAcls {
					naclID := ptrToStr(nacl.NetworkAclId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:network-acl/%s", region, ptrToStr(nacl.OwnerId), naclID)

					tags := make(map[string]string)
					for _, t := range nacl.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":         arn,
						"arn":            arn,
						"network_acl_id": naclID,
						"region":         region,
						"account_id":     ptrToStr(nacl.OwnerId),
						"vpc_id":         ptrToStr(nacl.VpcId),
						"is_default":     nacl.IsDefault,
						"entries":        nacl.Entries,
						"associations":   nacl.Associations,
						"owner_id":       ptrToStr(nacl.OwnerId),
						"tags":           tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2SubnetTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_subnets",
		Columns: []string{
			"arn", "subnet_id", "region", "account_id", "vpc_id",
			"availability_zone", "availability_zone_id", "cidr_block",
			"default_for_az", "map_public_ip_on_launch", "state",
			"available_ip_address_count", "owner_id", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe subnets: %w", err)
				}

				for _, subnet := range page.Subnets {
					subnetID := ptrToStr(subnet.SubnetId)
					arn := ptrToStr(subnet.SubnetArn)
					if arn == "" {
						arn = fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", region, ptrToStr(subnet.OwnerId), subnetID)
					}

					tags := make(map[string]string)
					for _, t := range subnet.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":                     arn,
						"arn":                        arn,
						"subnet_id":                  subnetID,
						"region":                     region,
						"account_id":                 ptrToStr(subnet.OwnerId),
						"vpc_id":                     ptrToStr(subnet.VpcId),
						"availability_zone":          ptrToStr(subnet.AvailabilityZone),
						"availability_zone_id":       ptrToStr(subnet.AvailabilityZoneId),
						"cidr_block":                 ptrToStr(subnet.CidrBlock),
						"default_for_az":             subnet.DefaultForAz,
						"map_public_ip_on_launch":    subnet.MapPublicIpOnLaunch,
						"state":                      string(subnet.State),
						"available_ip_address_count": subnet.AvailableIpAddressCount,
						"owner_id":                   ptrToStr(subnet.OwnerId),
						"tags":                       tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2RouteTableTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_route_tables",
		Columns: []string{
			"arn", "route_table_id", "region", "account_id", "vpc_id",
			"routes", "associations", "propagating_vgws", "owner_id", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe route tables: %w", err)
				}

				for _, rt := range page.RouteTables {
					rtID := ptrToStr(rt.RouteTableId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:route-table/%s", region, ptrToStr(rt.OwnerId), rtID)

					tags := make(map[string]string)
					for _, t := range rt.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":           arn,
						"arn":              arn,
						"route_table_id":   rtID,
						"region":           region,
						"account_id":       ptrToStr(rt.OwnerId),
						"vpc_id":           ptrToStr(rt.VpcId),
						"routes":           rt.Routes,
						"associations":     rt.Associations,
						"propagating_vgws": rt.PropagatingVgws,
						"owner_id":         ptrToStr(rt.OwnerId),
						"tags":             tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2InternetGatewayTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_internet_gateways",
		Columns: []string{
			"arn", "internet_gateway_id", "region", "account_id",
			"attachments", "owner_id", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeInternetGatewaysPaginator(client, &ec2.DescribeInternetGatewaysInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe internet gateways: %w", err)
				}

				for _, igw := range page.InternetGateways {
					igwID := ptrToStr(igw.InternetGatewayId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:internet-gateway/%s", region, ptrToStr(igw.OwnerId), igwID)

					tags := make(map[string]string)
					for _, t := range igw.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":              arn,
						"arn":                 arn,
						"internet_gateway_id": igwID,
						"region":              region,
						"account_id":          ptrToStr(igw.OwnerId),
						"attachments":         igw.Attachments,
						"owner_id":            ptrToStr(igw.OwnerId),
						"tags":                tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2NatGatewayTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_nat_gateways",
		Columns: []string{
			"arn", "nat_gateway_id", "region", "account_id", "vpc_id",
			"subnet_id", "state", "connectivity_type", "nat_gateway_addresses",
			"create_time", "delete_time", "failure_code", "failure_message", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeNatGatewaysPaginator(client, &ec2.DescribeNatGatewaysInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe nat gateways: %w", err)
				}

				for _, ngw := range page.NatGateways {
					ngwID := ptrToStr(ngw.NatGatewayId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:natgateway/%s", region, e.accountID, ngwID)

					tags := make(map[string]string)
					for _, t := range ngw.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":                arn,
						"arn":                   arn,
						"nat_gateway_id":        ngwID,
						"region":                region,
						"account_id":            e.accountID,
						"vpc_id":                ptrToStr(ngw.VpcId),
						"subnet_id":             ptrToStr(ngw.SubnetId),
						"state":                 string(ngw.State),
						"connectivity_type":     string(ngw.ConnectivityType),
						"nat_gateway_addresses": ngw.NatGatewayAddresses,
						"create_time":           ngw.CreateTime,
						"delete_time":           ngw.DeleteTime,
						"failure_code":          ptrToStr(ngw.FailureCode),
						"failure_message":       ptrToStr(ngw.FailureMessage),
						"tags":                  tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2EbsVolumeTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_ebs_volumes",
		Columns: []string{
			"arn", "volume_id", "region", "account_id", "availability_zone",
			"size", "state", "volume_type", "iops", "throughput", "encrypted",
			"kms_key_id", "snapshot_id", "create_time", "attachments", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe volumes: %w", err)
				}

				for _, vol := range page.Volumes {
					volID := ptrToStr(vol.VolumeId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:volume/%s", region, e.accountID, volID)

					tags := make(map[string]string)
					for _, t := range vol.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":            arn,
						"arn":               arn,
						"volume_id":         volID,
						"region":            region,
						"account_id":        e.accountID,
						"availability_zone": ptrToStr(vol.AvailabilityZone),
						"size":              vol.Size,
						"state":             string(vol.State),
						"volume_type":       string(vol.VolumeType),
						"iops":              vol.Iops,
						"throughput":        vol.Throughput,
						"encrypted":         vol.Encrypted,
						"kms_key_id":        ptrToStr(vol.KmsKeyId),
						"snapshot_id":       ptrToStr(vol.SnapshotId),
						"create_time":       vol.CreateTime,
						"attachments":       vol.Attachments,
						"tags":              tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) ec2EbsSnapshotTable() TableSpec {
	return TableSpec{
		Name: "aws_ec2_ebs_snapshots",
		Columns: []string{
			"arn", "snapshot_id", "region", "account_id", "volume_id",
			"volume_size", "state", "progress", "encrypted", "kms_key_id",
			"owner_id", "owner_alias", "description", "start_time", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := ec2.NewFromConfig(cfg)
			var results []map[string]interface{}

			// Only get snapshots owned by this account
			paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
				OwnerIds: []string{"self"},
			})

			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describe snapshots: %w", err)
				}

				for _, snap := range page.Snapshots {
					snapID := ptrToStr(snap.SnapshotId)
					arn := fmt.Sprintf("arn:aws:ec2:%s:%s:snapshot/%s", region, ptrToStr(snap.OwnerId), snapID)

					tags := make(map[string]string)
					for _, t := range snap.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}

					row := map[string]interface{}{
						"_cq_id":      arn,
						"arn":         arn,
						"snapshot_id": snapID,
						"region":      region,
						"account_id":  ptrToStr(snap.OwnerId),
						"volume_id":   ptrToStr(snap.VolumeId),
						"volume_size": snap.VolumeSize,
						"state":       string(snap.State),
						"progress":    ptrToStr(snap.Progress),
						"encrypted":   snap.Encrypted,
						"kms_key_id":  ptrToStr(snap.KmsKeyId),
						"owner_id":    ptrToStr(snap.OwnerId),
						"owner_alias": ptrToStr(snap.OwnerAlias),
						"description": ptrToStr(snap.Description),
						"start_time":  snap.StartTime,
						"tags":        tags,
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}
