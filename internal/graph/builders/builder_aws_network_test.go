package builders

import (
	"context"
	"strings"
	"testing"
)

func TestBuilderBuild_AWSNetworkExposureCreatesInternetEdgeForPublicInstance(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-web",
			"instance_id":       "i-web",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "203.0.113.10",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-web",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-web",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-web",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-web",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         443,
			"to_port":           443,
			"ip_ranges":         []any{map[string]any{"CidrIp": "0.0.0.0/0"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"subnet_id":  "subnet-public",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-public",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "igw-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-public"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	g := builder.Graph()
	edge := findNetworkEdge(g, "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-web", EdgeKindExposedTo)
	if edge == nil {
		t.Fatal("expected internet exposure edge for public instance")
	}

	if got := toString(edge.Properties["public_endpoint"]); got != "203.0.113.10" {
		t.Fatalf("expected public endpoint to be recorded, got %q", got)
	}

	pathSummary := toString(edge.Properties["path_summary"])
	for _, expected := range []string{"igw-123", "rtb-public", "subnet-public", "sg-web", "i-web"} {
		if !strings.Contains(pathSummary, expected) {
			t.Fatalf("expected path summary %q to include %q", pathSummary, expected)
		}
	}
}

func TestBuilderBuild_AWSNetworkExposureSuppressesHeuristicForPrivateSubnetInstance(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-private",
			"instance_id":       "i-private",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "198.51.100.20",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-private",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-private",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-private",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-private",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         22,
			"to_port":           22,
			"ip_ranges":         []any{map[string]any{"CidrIp": "0.0.0.0/0"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private",
			"subnet_id":  "subnet-private",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-private",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "nat-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-private"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-private", EdgeKindExposedTo); edge != nil {
		t.Fatalf("did not expect internet exposure edge for instance in a private subnet: %+v", edge.Properties)
	}
}

func TestBuilderBuild_AWSNetworkExposureSuppressesHeuristicForEgressOnlySecurityGroup(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-egress-only",
			"instance_id":       "i-egress-only",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "198.51.100.30",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-egress-only",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-egress-only",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-egress-only",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-egress-only",
			"direction":         "egress",
			"protocol":          "-1",
			"from_port":         nil,
			"to_port":           nil,
			"ip_ranges":         []any{map[string]any{"CidrIp": "0.0.0.0/0"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"subnet_id":  "subnet-public",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-public",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "igw-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-public"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-egress-only", EdgeKindExposedTo); edge != nil {
		t.Fatalf("did not expect internet exposure edge for instance with only egress security group rules: %+v", edge.Properties)
	}
}

func TestBuilderBuild_AWSNetworkExposureUsesObservedPublicSecurityGroupEvenWhenAnotherGroupIsMissing(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-mixed-sg",
			"instance_id":       "i-mixed-sg",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "203.0.113.40",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-mixed-sg",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-public",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-mixed-sg",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-missing",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-mixed-sg",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-public",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         443,
			"to_port":           443,
			"ip_ranges":         []any{map[string]any{"CidrIp": "0.0.0.0/0"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-public",
			"subnet_id":  "subnet-public",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-public",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "igw-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-public"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-mixed-sg", EdgeKindExposedTo)
	if edge == nil {
		t.Fatal("expected internet exposure edge")
	}
	if got := toString(edge.Properties["exposure_source"]); got != "aws_network_reachability" {
		t.Fatalf("expected path-aware network exposure edge, got exposure_source=%q properties=%#v", got, edge.Properties)
	}
}

func TestBuilderBuild_AWSNetworkExposureSuppressesHeuristicForPrivateSubnetEvenWhenSecurityGroupsAreMissing(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-private-topology",
			"instance_id":       "i-private-topology",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "198.51.100.40",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-private-topology",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-missing",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-private-topology",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-other",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         80,
			"to_port":           80,
			"ip_ranges":         []any{map[string]any{"CidrIp": "10.0.0.0/8"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private",
			"subnet_id":  "subnet-private",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-private",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "nat-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-private"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-private-topology", EdgeKindExposedTo); edge != nil {
		t.Fatalf("did not expect internet exposure edge when subnet topology proves the subnet is private: %+v", edge.Properties)
	}
}

func TestBuilderBuild_AWSNetworkExposureFallsBackToHeuristicWhenSubnetCoverageIsPartial(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-partial-subnets",
			"instance_id":       "i-partial-subnets",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "203.0.113.50",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-partial-subnets",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-public",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-partial-subnets",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private-observed",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-partial-subnets",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-missing",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-public",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         443,
			"to_port":           443,
			"ip_ranges":         []any{map[string]any{"CidrIp": "0.0.0.0/0"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private-observed",
			"subnet_id":  "subnet-private-observed",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-private",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-123",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "nat-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-private-observed"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-partial-subnets", EdgeKindExposedTo)
	if edge == nil {
		t.Fatal("expected heuristic internet exposure edge when subnet coverage is partial")
	}
	if got := toString(edge.Properties["exposure_source"]); got != "" {
		t.Fatalf("expected heuristic fallback edge without network metadata, got exposure_source=%q properties=%#v", got, edge.Properties)
	}
}

func TestBuilderBuild_AWSNetworkExposureFallsBackToHeuristicWhenSubnetRouteTopologyIsUnknown(t *testing.T) {
	t.Parallel()

	source := newCDCRoutingSource()
	source.routes["from aws_ec2_instances"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":               "arn:aws:ec2:us-east-1:111111111111:instance/i-unknown-topology",
			"instance_id":       "i-unknown-topology",
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"public_ip_address": "203.0.113.60",
		},
	}}
	source.routes["from resource_relationships"] = &DataQueryResult{Rows: []map[string]any{
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-unknown-topology",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:security-group/sg-missing",
			"target_type": "aws:ec2:security_group",
			"rel_type":    "MEMBER_OF",
		},
		{
			"source_id":   "arn:aws:ec2:us-east-1:111111111111:instance/i-unknown-topology",
			"source_type": "aws:ec2:instance",
			"target_id":   "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-unknown",
			"target_type": "aws:ec2:subnet",
			"rel_type":    "IN_SUBNET",
		},
	}}
	source.routes["from aws_ec2_security_group_rules"] = &DataQueryResult{Rows: []map[string]any{
		{
			"account_id":        "111111111111",
			"region":            "us-east-1",
			"security_group_id": "sg-other",
			"direction":         "ingress",
			"protocol":          "tcp",
			"from_port":         80,
			"to_port":           80,
			"ip_ranges":         []any{map[string]any{"CidrIp": "10.0.0.0/8"}},
			"ipv6_ranges":       []any{},
		},
	}}
	source.routes["from aws_ec2_subnets"] = &DataQueryResult{Rows: []map[string]any{
		{
			"arn":        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-unknown",
			"subnet_id":  "subnet-unknown",
			"account_id": "111111111111",
			"region":     "us-east-1",
			"vpc_id":     "vpc-123",
		},
	}}
	source.routes["from aws_ec2_route_tables"] = &DataQueryResult{Rows: []map[string]any{
		{
			"route_table_id": "rtb-other",
			"account_id":     "111111111111",
			"region":         "us-east-1",
			"vpc_id":         "vpc-other",
			"routes": []any{
				map[string]any{
					"DestinationCidrBlock": "0.0.0.0/0",
					"GatewayId":            "nat-123",
					"State":                "active",
				},
			},
			"associations": []any{map[string]any{"SubnetId": "subnet-other"}},
		},
	}}

	builder := NewBuilder(source, nil)
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	edge := findNetworkEdge(builder.Graph(), "internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-unknown-topology", EdgeKindExposedTo)
	if edge == nil {
		t.Fatal("expected heuristic internet exposure edge when route-table coverage is missing for the subnet")
	}
	if got := toString(edge.Properties["exposure_source"]); got != "" {
		t.Fatalf("expected heuristic fallback edge without network metadata, got exposure_source=%q properties=%#v", got, edge.Properties)
	}
}

func findNetworkEdge(g *Graph, source, target string, kind EdgeKind) *Edge {
	for _, edge := range g.GetOutEdges(source) {
		if edge.Target == target && edge.Kind == kind {
			return edge
		}
	}
	return nil
}
