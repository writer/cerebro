package sync

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestSplitArn(t *testing.T) {
	got := splitArn("arn:aws:sns:us-east-1:123456789012:topic/security-alerts")
	want := []string{"arn", "aws", "sns", "us-east-1", "123456789012", "topic", "security-alerts"}
	if len(got) != len(want) {
		t.Fatalf("unexpected parts length %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected part %d: got %q want %q (%v)", i, got[i], want[i], got)
		}
	}
}

func TestBuildSecurityGroupRuleRowStableAcrossInputOrder(t *testing.T) {
	permA := types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpRanges: []types.IpRange{
			{CidrIp: aws.String("10.0.0.0/24"), Description: aws.String("office")},
			{CidrIp: aws.String("0.0.0.0/0"), Description: aws.String("world")},
		},
		Ipv6Ranges: []types.Ipv6Range{
			{CidrIpv6: aws.String("::/0"), Description: aws.String("internet")},
		},
		PrefixListIds: []types.PrefixListId{
			{PrefixListId: aws.String("pl-123"), Description: aws.String("s3")},
		},
		UserIdGroupPairs: []types.UserIdGroupPair{
			{
				GroupId:                aws.String("sg-1"),
				GroupName:              aws.String("db"),
				UserId:                 aws.String("123456789012"),
				VpcId:                  aws.String("vpc-1"),
				VpcPeeringConnectionId: aws.String("pcx-1"),
				Description:            aws.String("peer"),
			},
		},
	}
	permB := types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(443),
		ToPort:     aws.Int32(443),
		IpRanges: []types.IpRange{
			{CidrIp: aws.String("0.0.0.0/0"), Description: aws.String("world")},
			{CidrIp: aws.String("10.0.0.0/24"), Description: aws.String("office")},
		},
		Ipv6Ranges: []types.Ipv6Range{
			{CidrIpv6: aws.String("::/0"), Description: aws.String("internet")},
		},
		PrefixListIds: []types.PrefixListId{
			{PrefixListId: aws.String("pl-123"), Description: aws.String("s3")},
		},
		UserIdGroupPairs: []types.UserIdGroupPair{
			{
				GroupId:                aws.String("sg-1"),
				GroupName:              aws.String("db"),
				UserId:                 aws.String("123456789012"),
				VpcId:                  aws.String("vpc-1"),
				VpcPeeringConnectionId: aws.String("pcx-1"),
				Description:            aws.String("peer"),
			},
		},
	}

	rowA := buildSecurityGroupRuleRow("123456789012", "us-east-1", "sg-main", "main", "ingress", permA)
	rowB := buildSecurityGroupRuleRow("123456789012", "us-east-1", "sg-main", "main", "ingress", permB)

	if rowA["arn"] != rowB["arn"] {
		t.Fatalf("expected stable ARN hash across ordering changes, got %q vs %q", rowA["arn"], rowB["arn"])
	}
	if rowA["security_group_id"] != "sg-main" || rowA["direction"] != "ingress" {
		t.Fatalf("unexpected identity fields in row: %+v", rowA)
	}
	if rowA["from_port"] != int32(443) || rowA["to_port"] != int32(443) {
		t.Fatalf("unexpected port fields in row: %+v", rowA)
	}
}
