package awsnetwork

import (
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	globalacceleratortypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"
)

func GlobalAcceleratorPortRanges(values []globalacceleratortypes.PortRange) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		from := awssdk.ToInt32(value.FromPort)
		to := awssdk.ToInt32(value.ToPort)
		if from == 0 && to == 0 {
			continue
		}
		if from == to || to == 0 {
			parts = append(parts, strconv.Itoa(int(from)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", from, to))
	}
	return strings.Join(parts, ",")
}

func GlobalAcceleratorEndpointIDs(values []globalacceleratortypes.EndpointDescription) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		if id := strings.TrimSpace(awssdk.ToString(value.EndpointId)); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func ELBV2ActionTargetGroupARNs(actions []elbv2types.Action) []string {
	var arns []string
	for _, action := range actions {
		arns = appendClean(arns, awssdk.ToString(action.TargetGroupArn))
		if action.ForwardConfig != nil {
			for _, group := range action.ForwardConfig.TargetGroups {
				arns = appendClean(arns, awssdk.ToString(group.TargetGroupArn))
			}
		}
	}
	return arns
}

func ELBV2AvailabilityZoneNames(values []elbv2types.AvailabilityZone) []string {
	zones := make([]string, 0, len(values))
	for _, value := range values {
		zones = appendClean(zones, awssdk.ToString(value.ZoneName))
	}
	return zones
}

func CloudFrontAliases(aliases *cloudfronttypes.Aliases) []string {
	if aliases == nil {
		return nil
	}
	return clean(aliases.Items)
}

func CloudFrontOriginDomains(origins *cloudfronttypes.Origins) []string {
	if origins == nil {
		return nil
	}
	domains := make([]string, 0, len(origins.Items))
	for _, origin := range origins.Items {
		domains = appendClean(domains, awssdk.ToString(origin.DomainName))
	}
	return domains
}

func Float32AttrString(value *float32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*value), 'f', -1, 32)
}

func VPCLatticeDNSName(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.DomainName)
}

func VPCLatticeHostedZoneID(entry *vpclatticetypes.DnsEntry) string {
	if entry == nil {
		return ""
	}
	return awssdk.ToString(entry.HostedZoneId)
}

func appendClean(values []string, value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return values
	}
	for _, existing := range values {
		if existing == trimmed {
			return values
		}
	}
	return append(values, trimmed)
}
