package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectAWSGlobalAcceleratorNetworkRelationships(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	acceleratorARN := "arn:aws:globalaccelerator::123456789012:accelerator/ga-123"
	listenerARN := acceleratorARN + "/listener/listener-123"
	endpointGroupARN := listenerARN + "/endpoint-group/eg-123"
	endpointARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/orders/abc"

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "ga-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.globalaccelerator_accelerator",
			Attributes: map[string]string{
				"accelerator_arn":   acceleratorARN,
				"domain":            "123456789012",
				"resource_id":       acceleratorARN,
				"resource_name":     "edge-prod",
				"resource_provider": "aws",
				"resource_type":     "globalaccelerator",
			},
		},
		{
			Id:       "ga-listener-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.globalaccelerator_listener",
			Attributes: map[string]string{
				"accelerator_arn":   acceleratorARN,
				"domain":            "123456789012",
				"listener_arn":      listenerARN,
				"resource_id":       listenerARN,
				"resource_provider": "aws",
				"resource_type":     "globalaccelerator_listener",
			},
		},
		{
			Id:       "ga-eg-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.globalaccelerator_endpoint_group",
			Attributes: map[string]string{
				"accelerator_arn":       acceleratorARN,
				"domain":                "123456789012",
				"endpoint_group_arn":    endpointGroupARN,
				"endpoint_group_region": "us-east-1",
				"endpoint_ids":          endpointARN,
				"listener_arn":          listenerARN,
				"resource_id":           endpointGroupARN,
				"resource_provider":     "aws",
				"resource_type":         "globalaccelerator_endpoint_group",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	acceleratorURN := "urn:cerebro:writer:aws_globalaccelerator_accelerator:" + acceleratorARN
	listenerURNProjected := "urn:cerebro:writer:aws_globalaccelerator_listener:" + listenerARN
	endpointGroupURNProjected := "urn:cerebro:writer:aws_globalaccelerator_endpoint_group:" + endpointGroupARN
	endpointURNProjected := "urn:cerebro:writer:aws_globalaccelerator_endpoint:" + endpointARN
	accountURN := "urn:cerebro:writer:cloud_account:123456789012"
	classificationURN := "urn:cerebro:writer:data_classification"
	assertProjectedLinkSet(t, state,
		wantProjectedLink(acceleratorURN, relationBelongsTo, accountURN),
		wantProjectedLink(acceleratorURN, relationHasClassification, classificationURN),
		wantProjectedLink(listenerURNProjected, relationBelongsTo, accountURN),
		wantProjectedLink(listenerURNProjected, relationBelongsTo, acceleratorURN),
		wantProjectedLink(listenerURNProjected, relationHasClassification, classificationURN),
		wantProjectedLink(endpointGroupURNProjected, relationBelongsTo, accountURN),
		wantProjectedLink(endpointGroupURNProjected, relationBelongsTo, listenerURNProjected),
		wantProjectedLink(endpointGroupURNProjected, relationHasClassification, classificationURN),
		wantProjectedLink(endpointGroupURNProjected, relationTargeted, endpointURNProjected),
	)
}

func TestProjectAWSVPCLatticeNetworkRelationships(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	serviceARN := "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
	listenerARN := serviceARN + "/listener/listener-123"
	targetGroupARN := "arn:aws:vpc-lattice:us-east-1:123456789012:targetgroup/tg-123"

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "lattice-service-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpclattice_service",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       serviceARN,
				"resource_name":     "orders",
				"resource_provider": "aws",
				"resource_type":     "vpclattice_service",
				"service_arn":       serviceARN,
			},
		},
		{
			Id:       "lattice-listener-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpclattice_listener",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"listener_arn":      listenerARN,
				"resource_id":       listenerARN,
				"resource_provider": "aws",
				"resource_type":     "vpclattice_listener",
				"service_arn":       serviceARN,
			},
		},
		{
			Id:       "lattice-tg-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpclattice_target_group",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       targetGroupARN,
				"resource_provider": "aws",
				"resource_type":     "vpclattice_target_group",
				"service_arns":      serviceARN,
				"target_group_arn":  targetGroupARN,
				"target_group_id":   "tg-123",
				"target_type":       "INSTANCE",
				"vpc_id":            "vpc-1",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	serviceURNProjected := "urn:cerebro:writer:aws_vpclattice_service:" + serviceARN
	listenerURNProjected := "urn:cerebro:writer:aws_vpclattice_listener:" + listenerARN
	targetGroupURNProjected := "urn:cerebro:writer:aws_vpclattice_target_group:" + targetGroupARN
	accountURN := "urn:cerebro:writer:cloud_account:123456789012"
	classificationURN := "urn:cerebro:writer:data_classification"
	vpcURN := "urn:cerebro:writer:aws_vpc:vpc-1"
	assertProjectedLinkSet(t, state,
		wantProjectedLink(serviceURNProjected, relationBelongsTo, accountURN),
		wantProjectedLink(serviceURNProjected, relationHasClassification, classificationURN),
		wantProjectedLink(listenerURNProjected, relationBelongsTo, accountURN),
		wantProjectedLink(listenerURNProjected, relationBelongsTo, serviceURNProjected),
		wantProjectedLink(listenerURNProjected, relationHasClassification, classificationURN),
		wantProjectedLink(targetGroupURNProjected, relationBelongsTo, accountURN),
		wantProjectedLink(targetGroupURNProjected, relationBelongsTo, serviceURNProjected),
		wantProjectedLink(targetGroupURNProjected, relationBelongsTo, vpcURN),
		wantProjectedLink(targetGroupURNProjected, relationHasClassification, classificationURN),
		wantProjectedLink(vpcURN, relationBelongsTo, accountURN),
	)
}

func TestProjectAWSNetworkSubstrateRelationships(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "subnet-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.subnet",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       "subnet-123",
				"resource_provider": "aws",
				"resource_type":     "subnet",
				"subnet_id":         "subnet-123",
				"vpc_id":            "vpc-123",
			},
		},
		{
			Id:       "sg-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.security_group",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       "sg-123",
				"resource_provider": "aws",
				"resource_type":     "security_group",
				"security_group_id": "sg-123",
				"vpc_id":            "vpc-123",
			},
		},
		{
			Id:       "route-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.route_table",
			Attributes: map[string]string{
				"domain":               "123456789012",
				"internet_gateway_ids": "igw-123",
				"nat_gateway_ids":      "nat-123",
				"resource_id":          "rtb-123",
				"resource_provider":    "aws",
				"resource_type":        "route_table",
				"subnet_ids":           "subnet-123",
				"vpc_id":               "vpc-123",
			},
		},
		{
			Id:       "nacl-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.network_acl",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"network_acl_id":    "acl-123",
				"resource_id":       "acl-123",
				"resource_provider": "aws",
				"resource_type":     "network_acl",
				"subnet_ids":        "subnet-123",
				"vpc_id":            "vpc-123",
			},
		},
		{
			Id:       "flow-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpc_flow_log",
			Attributes: map[string]string{
				"domain":                "123456789012",
				"flow_log_id":           "fl-123",
				"monitored_resource_id": "vpc-123",
				"resource_id":           "fl-123",
				"resource_provider":     "aws",
				"resource_type":         "vpc_flow_log",
				"vpc_id":                "vpc-123",
			},
		},
		{
			Id:       "endpoint-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpc_endpoint",
			Attributes: map[string]string{
				"domain":             "123456789012",
				"resource_id":        "vpce-123",
				"resource_provider":  "aws",
				"resource_type":      "vpc_endpoint",
				"route_table_ids":    "rtb-123",
				"security_group_ids": "sg-123",
				"subnet_ids":         "subnet-123",
				"vpc_id":             "vpc-123",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	subnetURN := "urn:cerebro:writer:aws_subnet:subnet-123"
	securityGroupURN := "urn:cerebro:writer:aws_security_group:sg-123"
	routeTableURN := "urn:cerebro:writer:aws_route_table:rtb-123"
	networkACLURN := "urn:cerebro:writer:aws_network_acl:acl-123"
	vpcFlowLogURN := "urn:cerebro:writer:aws_vpc_flow_log:fl-123"
	vpcEndpointURN := "urn:cerebro:writer:aws_vpc_endpoint:vpce-123"
	vpcURN := "urn:cerebro:writer:aws_vpc:vpc-123"
	accountURN := "urn:cerebro:writer:cloud_account:123456789012"
	classificationURN := "urn:cerebro:writer:data_classification"
	assertProjectedLinkSet(t, state,
		wantProjectedLink(subnetURN, relationBelongsTo, accountURN),
		wantProjectedLink(subnetURN, relationBelongsTo, vpcURN),
		wantProjectedLink(subnetURN, relationHasClassification, classificationURN),
		wantProjectedLink(securityGroupURN, relationBelongsTo, accountURN),
		wantProjectedLink(securityGroupURN, relationBelongsTo, vpcURN),
		wantProjectedLink(securityGroupURN, relationHasClassification, classificationURN),
		wantProjectedLink(routeTableURN, relationBelongsTo, accountURN),
		wantProjectedLink(routeTableURN, relationBelongsTo, vpcURN),
		wantProjectedLink(routeTableURN, relationHasClassification, classificationURN),
		wantProjectedLink(vpcURN, relationBelongsTo, accountURN),
		wantProjectedLink(routeTableURN, relationAssociatedWith, subnetURN),
		wantProjectedLink(routeTableURN, relationDependsOn, "urn:cerebro:writer:aws_internet_gateway:igw-123"),
		wantProjectedLink(routeTableURN, relationDependsOn, "urn:cerebro:writer:aws_nat_gateway:nat-123"),
		wantProjectedLink(networkACLURN, relationBelongsTo, accountURN),
		wantProjectedLink(networkACLURN, relationBelongsTo, vpcURN),
		wantProjectedLink(networkACLURN, relationHasClassification, classificationURN),
		wantProjectedLink(networkACLURN, relationAssociatedWith, subnetURN),
		wantProjectedLink(vpcFlowLogURN, relationBelongsTo, accountURN),
		wantProjectedLink(vpcFlowLogURN, relationHasClassification, classificationURN),
		wantProjectedLink(vpcFlowLogURN, relationAssociatedWith, vpcURN),
		wantProjectedLink(vpcEndpointURN, relationBelongsTo, accountURN),
		wantProjectedLink(vpcEndpointURN, relationBelongsTo, vpcURN),
		wantProjectedLink(vpcEndpointURN, relationBelongsTo, subnetURN),
		wantProjectedLink(vpcEndpointURN, relationHasClassification, classificationURN),
		wantProjectedLink(vpcEndpointURN, relationMemberOf, securityGroupURN),
		wantProjectedLink(vpcEndpointURN, relationAssociatedWith, routeTableURN),
	)
}
