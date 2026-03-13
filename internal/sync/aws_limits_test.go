package sync

import "testing"

func TestSyncEngineRegionsForTable(t *testing.T) {
	engine := &SyncEngine{regions: []string{"us-east-1", "us-west-2"}}
	regions := engine.regionsForTable(TableSpec{Name: "aws_route53_zones"})
	if len(regions) != 1 || regions[0] != "us-east-1" {
		t.Fatalf("expected global-table region restriction, got %v", regions)
	}
}

func TestRegionsForTableOverride(t *testing.T) {
	configured := []string{"us-east-1", "us-west-2"}
	regions := regionsForTable("aws_iam_users", configured)
	if len(regions) != 1 || regions[0] != "us-east-1" {
		t.Fatalf("expected us-east-1 override, got %v", regions)
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

func TestRegionsForTableEmptyConfigured(t *testing.T) {
	if regions := regionsForTable("aws_iam_users", nil); regions != nil {
		t.Fatalf("expected nil regions for empty config, got %v", regions)
	}
}

func TestIntersectRegionsWithoutAllowList(t *testing.T) {
	configured := []string{"us-east-1", "us-west-2"}
	regions := intersectRegions(configured, nil)
	if len(regions) != len(configured) {
		t.Fatalf("expected configured regions to pass through, got %v", regions)
	}
}

func TestIsGlobalTableName(t *testing.T) {
	if !isGlobalTableName("aws_organizations_accounts") {
		t.Fatalf("expected organizations table to be global")
	}
	if isGlobalTableName("aws_ec2_instances") {
		t.Fatalf("did not expect ec2 table to be global")
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

func TestServiceLimitForUnknownTable(t *testing.T) {
	key, limit := serviceLimitForTable("aws_ec2_instances")
	if key != "" || limit != 0 {
		t.Fatalf("expected no limit for unknown table, got %q %d", key, limit)
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

func TestBuildServiceLimitersWithoutGlobalLimit(t *testing.T) {
	limiters := buildServiceLimiters(0)
	if limiters == nil {
		t.Fatalf("expected limiters to be created")
	}
	if cap(limiters["aws_iam_"]) != 2 {
		t.Fatalf("expected native aws_iam_ limit 2, got %d", cap(limiters["aws_iam_"]))
	}
}
