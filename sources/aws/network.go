package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	route53resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsACMCertificate struct {
	Certificate acmtypes.CertificateDetail
	Tags        map[string]string
}

type awsRoute53ResolverEndpoint struct {
	Endpoint route53resolvertypes.ResolverEndpoint
	Tags     map[string]string
}

type awsRoute53ResolverRule struct {
	Rule route53resolvertypes.ResolverRule
	Tags map[string]string
}

func listACMCertificates(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsACMCertificate, string, error) {
	out, err := clients.acm.ListCertificates(ctx, &acm.ListCertificatesInput{
		CertificateStatuses: acmtypes.CertificateStatus("").Values(),
		MaxItems:            awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 1000))),
		NextToken:           stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsACMCertificate, 0, len(out.CertificateSummaryList))
	for _, summary := range out.CertificateSummaryList {
		arn := awssdk.ToString(summary.CertificateArn)
		if arn == "" {
			continue
		}
		describe, err := clients.acm.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: awssdk.String(arn)})
		if err != nil {
			return nil, "", fmt.Errorf("describe acm certificate %q: %w", arn, err)
		}
		if describe.Certificate == nil {
			continue
		}
		record := awsACMCertificate{Certificate: *describe.Certificate}
		if tags, err := clients.acm.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{CertificateArn: awssdk.String(arn)}); err == nil {
			record.Tags = acmTagMap(tags.Tags)
		} else if !optionalAWSError(err, "ResourceNotFoundException") {
			return nil, "", fmt.Errorf("list acm certificate tags %q: %w", arn, err)
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listRoute53ResolverEndpoints(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsRoute53ResolverEndpoint, string, error) {
	out, err := clients.route53Resolver.ListResolverEndpoints(ctx, &route53resolver.ListResolverEndpointsInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsRoute53ResolverEndpoint, 0, len(out.ResolverEndpoints))
	for _, endpoint := range out.ResolverEndpoints {
		record := awsRoute53ResolverEndpoint{Endpoint: endpoint}
		if arn := awssdk.ToString(endpoint.Arn); arn != "" {
			tags, err := listRoute53ResolverTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list route53 resolver endpoint tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listRoute53ResolverRules(ctx context.Context, clients awsClients, _ settings, cursor string, limit int) ([]awsRoute53ResolverRule, string, error) {
	out, err := clients.route53Resolver.ListResolverRules(ctx, &route53resolver.ListResolverRulesInput{
		MaxResults: awssdk.Int32(int32(boundedAWSPageSize(limit, 1, 100))),
		NextToken:  stringPtr(cursor),
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsRoute53ResolverRule, 0, len(out.ResolverRules))
	for _, rule := range out.ResolverRules {
		record := awsRoute53ResolverRule{Rule: rule}
		if arn := awssdk.ToString(rule.Arn); arn != "" {
			tags, err := listRoute53ResolverTags(ctx, clients, arn)
			if err != nil {
				return nil, "", fmt.Errorf("list route53 resolver rule tags %q: %w", arn, err)
			}
			record.Tags = tags
		}
		records = append(records, record)
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func listRoute53ResolverTags(ctx context.Context, clients awsClients, arn string) (map[string]string, error) {
	tags := map[string]string{}
	var next *string
	for {
		out, err := clients.route53Resolver.ListTagsForResource(ctx, &route53resolver.ListTagsForResourceInput{
			ResourceArn: awssdk.String(arn),
			MaxResults:  awssdk.Int32(100),
			NextToken:   next,
		})
		if err != nil {
			return nil, err
		}
		for key, value := range route53ResolverTagMap(out.Tags) {
			tags[key] = value
		}
		if awssdk.ToString(out.NextToken) == "" {
			return tags, nil
		}
		next = out.NextToken
	}
}

func acmCertificateEvent(settings settings, record awsACMCertificate) (*primitives.Event, error) {
	certificate := record.Certificate
	arn := awssdk.ToString(certificate.CertificateArn)
	domainName := awssdk.ToString(certificate.DomainName)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyACMCertificate, firstNonEmpty(arn, domainName), domainName, "acm_certificate", record.Tags)
	attributes["arn"] = arn
	attributes["certificate_arn"] = arn
	attributes["certificate_authority_arn"] = awssdk.ToString(certificate.CertificateAuthorityArn)
	attributes["domain_name"] = domainName
	attributes["failure_reason"] = string(certificate.FailureReason)
	attributes["in_use_by"] = strings.Join(cleanStrings(certificate.InUseBy), ",")
	attributes["issuer"] = awssdk.ToString(certificate.Issuer)
	attributes["key_algorithm"] = string(certificate.KeyAlgorithm)
	attributes["managed_by"] = string(certificate.ManagedBy)
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = boolString(false)
	attributes["renewal_eligibility"] = string(certificate.RenewalEligibility)
	attributes["revocation_reason"] = string(certificate.RevocationReason)
	attributes["serial"] = awssdk.ToString(certificate.Serial)
	attributes["signature_algorithm"] = awssdk.ToString(certificate.SignatureAlgorithm)
	attributes["status"] = string(certificate.Status)
	attributes["subject"] = awssdk.ToString(certificate.Subject)
	attributes["subject_alternative_names"] = strings.Join(cleanStrings(certificate.SubjectAlternativeNames), ",")
	attributes["type"] = string(certificate.Type)
	addTimeAttribute(attributes, "created_at", certificate.CreatedAt)
	addTimeAttribute(attributes, "imported_at", certificate.ImportedAt)
	addTimeAttribute(attributes, "issued_at", certificate.IssuedAt)
	addTimeAttribute(attributes, "not_after", certificate.NotAfter)
	addTimeAttribute(attributes, "not_before", certificate.NotBefore)
	addTimeAttribute(attributes, "revoked_at", certificate.RevokedAt)
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "certificate": certificate, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-acm-certificate-"+firstNonEmpty(arn, domainName), "aws.acm_certificate", "aws/acm_certificate/v1", payload, attributes, firstTime(certificate.CreatedAt, certificate.ImportedAt, certificate.IssuedAt, certificate.NotBefore))
}

func route53ResolverEndpointEvent(settings settings, record awsRoute53ResolverEndpoint) (*primitives.Event, error) {
	endpoint := record.Endpoint
	arn := awssdk.ToString(endpoint.Arn)
	endpointID := awssdk.ToString(endpoint.Id)
	name := firstNonEmpty(awssdk.ToString(endpoint.Name), endpointID)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyRoute53ResolverEndpoint, firstNonEmpty(arn, endpointID), name, "route53_resolver_endpoint", record.Tags)
	attributes["arn"] = arn
	attributes["endpoint_arn"] = arn
	attributes["endpoint_id"] = endpointID
	attributes["endpoint_name"] = name
	attributes["direction"] = string(endpoint.Direction)
	attributes["dns64_enabled"] = boolString(awssdk.ToBool(endpoint.Dns64Enabled))
	attributes["host_vpc_id"] = awssdk.ToString(endpoint.HostVPCId)
	attributes["ip_address_count"] = int32AttrString(endpoint.IpAddressCount)
	attributes["ipv6_internet_access_enabled"] = boolString(awssdk.ToBool(endpoint.Ipv6InternetAccessEnabled))
	attributes["outpost_arn"] = awssdk.ToString(endpoint.OutpostArn)
	attributes["preferred_instance_type"] = awssdk.ToString(endpoint.PreferredInstanceType)
	attributes["protocols"] = strings.Join(route53ResolverProtocols(endpoint.Protocols), ",")
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = boolString(false)
	attributes["resolver_endpoint_type"] = string(endpoint.ResolverEndpointType)
	attributes["rni_enhanced_metrics_enabled"] = boolString(awssdk.ToBool(endpoint.RniEnhancedMetricsEnabled))
	attributes["security_group_ids"] = strings.Join(cleanStrings(endpoint.SecurityGroupIds), ",")
	attributes["status"] = string(endpoint.Status)
	attributes["status_message"] = awssdk.ToString(endpoint.StatusMessage)
	attributes["target_name_server_metrics_enabled"] = boolString(awssdk.ToBool(endpoint.TargetNameServerMetricsEnabled))
	addAWSStringTimeAttribute(attributes, "created_at", awssdk.ToString(endpoint.CreationTime))
	addAWSStringTimeAttribute(attributes, "modified_at", awssdk.ToString(endpoint.ModificationTime))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "endpoint": endpoint, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-route53-resolver-endpoint-"+firstNonEmpty(arn, endpointID), "aws.route53_resolver_endpoint", "aws/route53_resolver_endpoint/v1", payload, attributes, firstAWSStringTime(awssdk.ToString(endpoint.CreationTime), awssdk.ToString(endpoint.ModificationTime)))
}

func route53ResolverRuleEvent(settings settings, record awsRoute53ResolverRule) (*primitives.Event, error) {
	rule := record.Rule
	arn := awssdk.ToString(rule.Arn)
	ruleID := awssdk.ToString(rule.Id)
	name := firstNonEmpty(awssdk.ToString(rule.Name), ruleID)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyRoute53ResolverRule, firstNonEmpty(arn, ruleID), name, "route53_resolver_rule", record.Tags)
	attributes["arn"] = arn
	attributes["rule_arn"] = arn
	attributes["rule_id"] = ruleID
	attributes["rule_name"] = name
	attributes["delegation_record"] = awssdk.ToString(rule.DelegationRecord)
	attributes["domain_name"] = awssdk.ToString(rule.DomainName)
	attributes["owner_id"] = awssdk.ToString(rule.OwnerId)
	attributes["public"] = boolString(false)
	attributes["internet_exposed"] = boolString(false)
	attributes["resolver_endpoint_id"] = awssdk.ToString(rule.ResolverEndpointId)
	attributes["rule_type"] = string(rule.RuleType)
	attributes["share_status"] = string(rule.ShareStatus)
	attributes["status"] = string(rule.Status)
	attributes["status_message"] = awssdk.ToString(rule.StatusMessage)
	attributes["target_ips"] = strings.Join(route53ResolverTargetIPs(rule.TargetIps), ",")
	attributes["target_ports"] = strings.Join(route53ResolverTargetPorts(rule.TargetIps), ",")
	attributes["target_protocols"] = strings.Join(route53ResolverTargetProtocols(rule.TargetIps), ",")
	addAWSStringTimeAttribute(attributes, "created_at", awssdk.ToString(rule.CreationTime))
	addAWSStringTimeAttribute(attributes, "modified_at", awssdk.ToString(rule.ModificationTime))
	payload, err := json.Marshal(map[string]any{"account_id": settings.accountID, "region": settings.region, "rule": rule, "tags": record.Tags})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-route53-resolver-rule-"+firstNonEmpty(arn, ruleID), "aws.route53_resolver_rule", "aws/route53_resolver_rule/v1", payload, attributes, firstAWSStringTime(awssdk.ToString(rule.CreationTime), awssdk.ToString(rule.ModificationTime)))
}

func acmTagMap(tags []acmtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func route53ResolverTagMap(tags []route53resolvertypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func route53ResolverProtocols(values []route53resolvertypes.Protocol) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	return cleanStrings(result)
}

func route53ResolverTargetIPs(values []route53resolvertypes.TargetAddress) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, firstNonEmpty(awssdk.ToString(value.Ip), awssdk.ToString(value.Ipv6)))
	}
	return cleanStrings(result)
}

func route53ResolverTargetPorts(values []route53resolvertypes.TargetAddress) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.Port != nil {
			result = append(result, strconv.FormatInt(int64(awssdk.ToInt32(value.Port)), 10))
		}
	}
	return cleanStrings(result)
}

func route53ResolverTargetProtocols(values []route53resolvertypes.TargetAddress) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value.Protocol))
	}
	return cleanStrings(result)
}

func addAWSStringTimeAttribute(attributes map[string]string, key string, value string) {
	parsed := parseAWSStringTime(value)
	if parsed.IsZero() {
		return
	}
	attributes[key] = parsed.UTC().Format(time.RFC3339)
}

func firstAWSStringTime(values ...string) time.Time {
	for _, value := range values {
		if parsed := parseAWSStringTime(value); !parsed.IsZero() {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}
