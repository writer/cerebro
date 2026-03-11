package sync

import "testing"

func TestRegionsForTableOverride(t *testing.T) {
	configured := []string{"us-east-1", "us-west-2"}
	regions := regionsForTable("aws_iam_users", configured)
	if len(regions) != 1 || regions[0] != "us-east-1" {
		t.Fatalf("expected us-east-1 override, got %v", regions)
	}
}

func TestRegionsForTableIdentityCenterOverride(t *testing.T) {
	configured := []string{"eu-west-1"}
	regions := regionsForTable("aws_identitycenter_permission_set_permission_usage", configured)
	if len(regions) != 1 || regions[0] != "eu-west-1" {
		t.Fatalf("expected identity center to use configured seed region, got %v", regions)
	}
}

func TestRegionsForTableNoOverride(t *testing.T) {
	configured := []string{"us-east-1", "us-west-2"}
	regions := regionsForTable("aws_ec2_instances", configured)
	if len(regions) != len(configured) {
		t.Fatalf("expected all regions, got %v", regions)
	}
	for i, region := range configured {
		if regions[i] != region {
			t.Fatalf("expected region %s at %d, got %s", region, i, regions[i])
		}
	}
}

func TestRegionsForTableNoIntersection(t *testing.T) {
	configured := []string{"eu-west-1"}
	regions := regionsForTable("aws_iam_users", configured)
	if len(regions) != 0 {
		t.Fatalf("expected no regions, got %v", regions)
	}
}

func TestServiceLimitForTable(t *testing.T) {
	key, limit := serviceLimitForTable("aws_iam_users")
	if key == "" {
		t.Fatalf("expected service key for iam")
	}
	if limit != 2 {
		t.Fatalf("expected limit 2, got %d", limit)
	}
}

func TestServiceLimitForIdentityCenterTable(t *testing.T) {
	key, limit := serviceLimitForTable("aws_identitycenter_permission_set_permission_usage")
	if key == "" {
		t.Fatalf("expected service key for identity center")
	}
	if limit != 1 {
		t.Fatalf("expected limit 1, got %d", limit)
	}
}

func TestBuildServiceLimitersRespectsGlobalLimit(t *testing.T) {
	limiters := buildServiceLimiters(1)
	limiter := limiters["aws_s3_"]
	if limiter == nil {
		t.Fatalf("expected limiter for aws_s3_")
	}
	if cap(limiter) != 1 {
		t.Fatalf("expected limiter capacity 1, got %d", cap(limiter))
	}
}
