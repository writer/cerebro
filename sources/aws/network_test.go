package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	route53resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestReadAWSNetworkManagerInventoryEvents(t *testing.T) {
	acmARN := "arn:aws:acm:us-east-1:123456789012:certificate/cert-123"
	endpointARN := "arn:aws:route53resolver:us-east-1:123456789012:resolver-endpoint/rslvr-in-123"
	ruleARN := "arn:aws:route53resolver:us-east-1:123456789012:resolver-rule/rslvr-rr-123"
	source := newNetworkManagerTestSource(t, fakeAWSNetworkManager{
		certificates: []acmtypes.CertificateDetail{{
			CertificateArn:          awssdk.String(acmARN),
			DomainName:              awssdk.String("api.writer.com"),
			Status:                  acmtypes.CertificateStatusIssued,
			Type:                    acmtypes.CertificateTypeAmazonIssued,
			KeyAlgorithm:            acmtypes.KeyAlgorithmRsa2048,
			SubjectAlternativeNames: []string{"api.writer.com", "www.writer.com"},
			InUseBy:                 []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/api/abc"},
			CreatedAt:               timePtr("2026-04-23T00:00:00Z"),
			NotAfter:                timePtr("2027-04-23T00:00:00Z"),
		}},
		acmTags: map[string][]acmtypes.Tag{acmARN: {{Key: awssdk.String("Team"), Value: awssdk.String("edge")}}},
		resolverEndpoints: []route53resolvertypes.ResolverEndpoint{{
			Arn:                            awssdk.String(endpointARN),
			Id:                             awssdk.String("rslvr-in-123"),
			Name:                           awssdk.String("corp-inbound"),
			Direction:                      route53resolvertypes.ResolverEndpointDirection("INBOUND"),
			HostVPCId:                      awssdk.String("vpc-123"),
			IpAddressCount:                 awssdk.Int32(2),
			Protocols:                      []route53resolvertypes.Protocol{route53resolvertypes.Protocol("Do53")},
			SecurityGroupIds:               []string{"sg-53"},
			Status:                         route53resolvertypes.ResolverEndpointStatus("OPERATIONAL"),
			CreationTime:                   awssdk.String("2026-04-23T00:00:00Z"),
			RniEnhancedMetricsEnabled:      awssdk.Bool(true),
			TargetNameServerMetricsEnabled: awssdk.Bool(false),
			Ipv6InternetAccessEnabled:      awssdk.Bool(false),
		}},
		resolverRules: []route53resolvertypes.ResolverRule{{
			Arn:                awssdk.String(ruleARN),
			Id:                 awssdk.String("rslvr-rr-123"),
			Name:               awssdk.String("corp-example"),
			DomainName:         awssdk.String("corp.example.com."),
			ResolverEndpointId: awssdk.String("rslvr-out-123"),
			RuleType:           route53resolvertypes.RuleTypeOption("FORWARD"),
			Status:             route53resolvertypes.ResolverRuleStatus("COMPLETE"),
			ShareStatus:        route53resolvertypes.ShareStatus("NOT_SHARED"),
			TargetIps:          []route53resolvertypes.TargetAddress{{Ip: awssdk.String("10.0.0.10"), Port: awssdk.Int32(53), Protocol: route53resolvertypes.Protocol("Do53")}},
			CreationTime:       awssdk.String("2026-04-23T00:00:00Z"),
		}},
		resolverTags: map[string][]route53resolvertypes.Tag{
			endpointARN: {{Key: awssdk.String("Team"), Value: awssdk.String("network")}},
			ruleARN:     {{Key: awssdk.String("Team"), Value: awssdk.String("network")}},
		},
	})

	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familyACMCertificate, kind: "aws.acm_certificate", attr: "status", want: "ISSUED"},
		{family: familyRoute53ResolverEndpoint, kind: "aws.route53_resolver_endpoint", attr: "host_vpc_id", want: "vpc-123"},
		{family: familyRoute53ResolverRule, kind: "aws.route53_resolver_rule", attr: "target_ips", want: "10.0.0.10"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"account_id": "123456789012", "family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func newNetworkManagerTestSource(t *testing.T, fake fakeAWSNetworkManager) *Source {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatalf("loadSpec() error = %v", err)
	}
	source := &Source{spec: spec, clients: func(context.Context, settings) (awsClients, error) {
		return awsClients{acm: fake, route53Resolver: fake}, nil
	}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		t.Fatalf("newFamilyEngine() error = %v", err)
	}
	return source
}

type fakeAWSNetworkManager struct {
	certificates      []acmtypes.CertificateDetail
	acmTags           map[string][]acmtypes.Tag
	resolverEndpoints []route53resolvertypes.ResolverEndpoint
	resolverRules     []route53resolvertypes.ResolverRule
	resolverTags      map[string][]route53resolvertypes.Tag
}

func (f fakeAWSNetworkManager) ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	summaries := make([]acmtypes.CertificateSummary, 0, len(f.certificates))
	for _, certificate := range f.certificates {
		summaries = append(summaries, acmtypes.CertificateSummary{CertificateArn: certificate.CertificateArn, DomainName: certificate.DomainName})
	}
	return &acm.ListCertificatesOutput{CertificateSummaryList: summaries}, nil
}

func (f fakeAWSNetworkManager) DescribeCertificate(_ context.Context, input *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	for _, certificate := range f.certificates {
		if awssdk.ToString(certificate.CertificateArn) == awssdk.ToString(input.CertificateArn) {
			copy := certificate
			return &acm.DescribeCertificateOutput{Certificate: &copy}, nil
		}
	}
	return &acm.DescribeCertificateOutput{}, nil
}

func (f fakeAWSNetworkManager) ListTagsForCertificate(_ context.Context, input *acm.ListTagsForCertificateInput, _ ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
	return &acm.ListTagsForCertificateOutput{Tags: f.acmTags[awssdk.ToString(input.CertificateArn)]}, nil
}

func (f fakeAWSNetworkManager) ListResolverEndpoints(context.Context, *route53resolver.ListResolverEndpointsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverEndpointsOutput, error) {
	return &route53resolver.ListResolverEndpointsOutput{ResolverEndpoints: f.resolverEndpoints}, nil
}

func (f fakeAWSNetworkManager) ListResolverRules(context.Context, *route53resolver.ListResolverRulesInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverRulesOutput, error) {
	return &route53resolver.ListResolverRulesOutput{ResolverRules: f.resolverRules}, nil
}

func (f fakeAWSNetworkManager) ListTagsForResource(_ context.Context, input *route53resolver.ListTagsForResourceInput, _ ...func(*route53resolver.Options)) (*route53resolver.ListTagsForResourceOutput, error) {
	return &route53resolver.ListTagsForResourceOutput{Tags: f.resolverTags[awssdk.ToString(input.ResourceArn)]}, nil
}
