package awsnetwork

import (
	"reflect"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func TestCleanStringsTrimsAndDeduplicates(t *testing.T) {
	got := cleanStrings([]string{" subnet-1 ", "", "subnet-1", "subnet-2", "subnet-2 "})
	want := []string{"subnet-1", "subnet-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanStrings() = %#v, want %#v", got, want)
	}
}

func TestELBV2ActionTargetGroupARNsDeduplicates(t *testing.T) {
	got := ELBV2ActionTargetGroupARNs([]elbv2types.Action{{
		TargetGroupArn: awssdk.String("arn:target/orders"),
		ForwardConfig: &elbv2types.ForwardActionConfig{TargetGroups: []elbv2types.TargetGroupTuple{
			{TargetGroupArn: awssdk.String("arn:target/orders")},
			{TargetGroupArn: awssdk.String(" arn:target/payments ")},
		}},
	}})
	want := []string{"arn:target/orders", "arn:target/payments"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ELBV2ActionTargetGroupARNs() = %#v, want %#v", got, want)
	}
}

func TestNetworkACLAllowsAdminPortsRespectsDenyPrecedence(t *testing.T) {
	acl := ec2types.NetworkAcl{Entries: []ec2types.NetworkAclEntry{
		{
			CidrBlock:  awssdk.String("0.0.0.0/0"),
			Egress:     awssdk.Bool(false),
			PortRange:  &ec2types.PortRange{From: awssdk.Int32(22), To: awssdk.Int32(22)},
			Protocol:   awssdk.String("6"),
			RuleAction: ec2types.RuleActionDeny,
			RuleNumber: awssdk.Int32(50),
		},
		{
			CidrBlock:  awssdk.String("0.0.0.0/0"),
			Egress:     awssdk.Bool(false),
			PortRange:  &ec2types.PortRange{From: awssdk.Int32(22), To: awssdk.Int32(22)},
			Protocol:   awssdk.String("6"),
			RuleAction: ec2types.RuleActionAllow,
			RuleNumber: awssdk.Int32(100),
		},
	}}
	if NetworkACLAllowsAdminPortsFromInternet(acl) {
		t.Fatalf("NetworkACLAllowsAdminPortsFromInternet() = true, want false when lower-numbered deny matches first")
	}
}

func TestNetworkACLAllowsAdminPortsChecksEachAdminPort(t *testing.T) {
	acl := ec2types.NetworkAcl{Entries: []ec2types.NetworkAclEntry{
		{
			CidrBlock:  awssdk.String("0.0.0.0/0"),
			Egress:     awssdk.Bool(false),
			PortRange:  &ec2types.PortRange{From: awssdk.Int32(22), To: awssdk.Int32(22)},
			Protocol:   awssdk.String("6"),
			RuleAction: ec2types.RuleActionDeny,
			RuleNumber: awssdk.Int32(50),
		},
		{
			CidrBlock:  awssdk.String("0.0.0.0/0"),
			Egress:     awssdk.Bool(false),
			PortRange:  &ec2types.PortRange{From: awssdk.Int32(3389), To: awssdk.Int32(3389)},
			Protocol:   awssdk.String("6"),
			RuleAction: ec2types.RuleActionAllow,
			RuleNumber: awssdk.Int32(60),
		},
	}}
	if !NetworkACLAllowsAdminPortsFromInternet(acl) {
		t.Fatalf("NetworkACLAllowsAdminPortsFromInternet() = false, want true when RDP is allowed from internet")
	}
}
