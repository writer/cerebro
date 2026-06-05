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
			Kind:     "aws.global_accelerator_accelerator",
			Attributes: map[string]string{
				"accelerator_arn":   acceleratorARN,
				"domain":            "123456789012",
				"resource_id":       acceleratorARN,
				"resource_name":     "edge-prod",
				"resource_provider": "aws",
				"resource_type":     "global_accelerator",
			},
		},
		{
			Id:       "ga-listener-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.global_accelerator_listener",
			Attributes: map[string]string{
				"accelerator_arn":   acceleratorARN,
				"domain":            "123456789012",
				"listener_arn":      listenerARN,
				"resource_id":       listenerARN,
				"resource_provider": "aws",
				"resource_type":     "global_accelerator_listener",
			},
		},
		{
			Id:       "ga-eg-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.global_accelerator_endpoint_group",
			Attributes: map[string]string{
				"accelerator_arn":       acceleratorARN,
				"domain":                "123456789012",
				"endpoint_group_arn":    endpointGroupARN,
				"endpoint_group_region": "us-east-1",
				"endpoint_ids":          endpointARN,
				"listener_arn":          listenerARN,
				"resource_id":           endpointGroupARN,
				"resource_provider":     "aws",
				"resource_type":         "global_accelerator_endpoint_group",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	acceleratorURN := "urn:cerebro:writer:aws_global_accelerator_accelerator:" + acceleratorARN
	listenerURNProjected := "urn:cerebro:writer:aws_global_accelerator_listener:" + listenerARN
	endpointGroupURNProjected := "urn:cerebro:writer:aws_global_accelerator_endpoint_group:" + endpointGroupARN
	endpointURNProjected := "urn:cerebro:writer:aws_global_accelerator_endpoint:" + endpointARN
	assertProjectedLink(t, state, listenerURNProjected, relationBelongsTo, acceleratorURN)
	assertProjectedLink(t, state, endpointGroupURNProjected, relationBelongsTo, listenerURNProjected)
	assertProjectedLink(t, state, endpointGroupURNProjected, relationTargeted, endpointURNProjected)
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
			Kind:     "aws.vpc_lattice_service",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       serviceARN,
				"resource_name":     "orders",
				"resource_provider": "aws",
				"resource_type":     "vpc_lattice_service",
				"service_arn":       serviceARN,
			},
		},
		{
			Id:       "lattice-listener-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpc_lattice_listener",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"listener_arn":      listenerARN,
				"resource_id":       listenerARN,
				"resource_provider": "aws",
				"resource_type":     "vpc_lattice_listener",
				"service_arn":       serviceARN,
				"target_group_ids":  targetGroupARN,
			},
		},
		{
			Id:       "lattice-tg-1",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.vpc_lattice_target_group",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       targetGroupARN,
				"resource_provider": "aws",
				"resource_type":     "vpc_lattice_target_group",
				"service_arns":      serviceARN,
				"target_group_arn":  targetGroupARN,
				"target_group_id":   "tg-123",
				"target_ids":        "i-123",
				"target_type":       "INSTANCE",
				"vpc_id":            "vpc-1",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	serviceURNProjected := "urn:cerebro:writer:aws_vpc_lattice_service:" + serviceARN
	listenerURNProjected := "urn:cerebro:writer:aws_vpc_lattice_listener:" + listenerARN
	targetGroupURNProjected := "urn:cerebro:writer:aws_vpc_lattice_target_group:" + targetGroupARN
	targetURN := "urn:cerebro:writer:aws_vpc_lattice_target:tg-123:i-123"
	assertProjectedLink(t, state, listenerURNProjected, relationBelongsTo, serviceURNProjected)
	assertProjectedLink(t, state, listenerURNProjected, relationDependsOn, targetGroupURNProjected)
	assertProjectedLink(t, state, targetGroupURNProjected, relationBelongsTo, serviceURNProjected)
	assertProjectedLink(t, state, targetGroupURNProjected, relationBelongsTo, "urn:cerebro:writer:aws_vpc:vpc-1")
	assertProjectedLink(t, state, targetGroupURNProjected, relationTargeted, targetURN)
}
