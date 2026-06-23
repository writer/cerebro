package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	resourcegroupstaggingapitypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
)

func listAssetMetadata(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsAssetMetadata, string, error) {
	out, err := clients.tagging.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
		PaginationToken:  stringPtr(cursor),
		ResourcesPerPage: int32Ptr(assetMetadataPageSize(limit)),
	})
	var expired *resourcegroupstaggingapitypes.PaginationTokenExpiredException
	if err != nil && strings.TrimSpace(cursor) != "" && errors.As(err, &expired) {
		out, err = clients.tagging.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
			ResourcesPerPage: int32Ptr(assetMetadataPageSize(limit)),
		})
	}
	if err != nil {
		return nil, "", err
	}
	records := make([]awsAssetMetadata, 0, len(out.ResourceTagMappingList))
	for _, mapping := range out.ResourceTagMappingList {
		arn := awssdk.ToString(mapping.ResourceARN)
		resourceType, resourceID, resourceName, region := awsAssetMetadataIdentity(settings, arn)
		tags := awsAssetTagMap(mapping.Tags)
		records = append(records, awsAssetMetadata{
			ResourceARN:  arn,
			ResourceID:   resourceID,
			ResourceName: firstNonEmpty(tagLookup(tags, "Name"), resourceName, resourceID),
			ResourceType: resourceType,
			Region:       firstNonEmpty(region, settings.region),
			Tags:         tags,
		})
	}
	return records, awssdk.ToString(out.PaginationToken), nil
}

func listResourceExposures(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsResourceExposure, string, error) {
	out, err := clients.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: stringPtr(cursor), MaxResults: int32Ptr(ec2PageSize(limit))})
	if err != nil {
		return nil, "", err
	}
	exposures := make([]awsResourceExposure, 0)
	for _, group := range out.SecurityGroups {
		for permissionIndex, permission := range group.IpPermissions {
			for _, ipRange := range permission.IpRanges {
				cidr := awssdk.ToString(ipRange.CidrIp)
				if !publicCIDR(cidr) {
					continue
				}
				exposures = append(exposures, securityGroupExposure(settings, group, permission, cidr, permissionIndex))
			}
			for _, ipRange := range permission.Ipv6Ranges {
				cidr := awssdk.ToString(ipRange.CidrIpv6)
				if !publicCIDR(cidr) {
					continue
				}
				exposures = append(exposures, securityGroupExposure(settings, group, permission, cidr, permissionIndex))
			}
		}
	}
	return exposures, awssdk.ToString(out.NextToken), nil
}

func listPublicEndpoints(ctx context.Context, clients awsClients, settings settings, cursor string, limit int) ([]awsPublicEndpoint, string, error) {
	state, err := parsePublicEndpointCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	for {
		switch state.Stage {
		case publicEndpointStageRoute53:
			if !settings.includeGlobal {
				state = publicEndpointCursor{Stage: publicEndpointStageCloudFront}
				continue
			}
			endpoints, next, err := listRoute53PublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageCloudFront}
		case publicEndpointStageCloudFront:
			if !settings.includeGlobal {
				state = publicEndpointCursor{Stage: publicEndpointStageELB}
				continue
			}
			endpoints, next, err := listCloudFrontPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageELB}
		case publicEndpointStageELB:
			endpoints, next, err := listELBPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGateway}
		case publicEndpointStageAPIGateway:
			endpoints, next, err := listAPIGatewayPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayRestAPI}
		case publicEndpointStageAPIGatewayRestAPI:
			endpoints, next, err := listAPIGatewayRestAPIPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2}
		case publicEndpointStageAPIGatewayV2:
			endpoints, next, err := listAPIGatewayV2PublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageAPIGatewayV2API}
		case publicEndpointStageAPIGatewayV2API:
			endpoints, next, err := listAPIGatewayV2APIPublicEndpoints(ctx, clients, settings, state, limit)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageEIP}
		case publicEndpointStageEIP:
			endpoints, next, err := listAddressPublicEndpoints(ctx, clients, settings)
			if err != nil || len(endpoints) != 0 {
				return endpoints, next, err
			}
			if next != "" {
				state, err = parsePublicEndpointCursor(next)
				if err != nil {
					return nil, "", err
				}
				continue
			}
			state = publicEndpointCursor{Stage: publicEndpointStageENI}
		case publicEndpointStageENI:
			return listNetworkInterfacePublicEndpoints(ctx, clients, settings, state, limit)
		default:
			return nil, "", fmt.Errorf("unknown aws public_endpoint cursor stage %q", state.Stage)
		}
	}
}
