package sync

import "strings"

type tableRegionOverride struct {
	prefix  string
	regions []string
}

var awsTableRegionOverrides = []tableRegionOverride{
	{prefix: "aws_iam_", regions: []string{"us-east-1"}},
	{prefix: "aws_identitycenter_", regions: []string{"us-east-1"}},
	{prefix: "aws_organizations_", regions: []string{"us-east-1"}},
	{prefix: "aws_cloudfront_", regions: []string{"us-east-1"}},
	{prefix: "aws_route53_", regions: []string{"us-east-1"}},
	{prefix: "aws_s3_buckets", regions: []string{"us-east-1"}},
	{prefix: "aws_ecr_public_", regions: []string{"us-east-1"}},
}

type serviceConcurrencyLimit struct {
	prefix string
	limit  int
}

var awsServiceConcurrencyLimits = []serviceConcurrencyLimit{
	{prefix: "aws_iam_", limit: 2},
	{prefix: "aws_identitycenter_", limit: 1},
	{prefix: "aws_organizations_", limit: 1},
	{prefix: "aws_route53_", limit: 2},
	{prefix: "aws_cloudfront_", limit: 2},
	{prefix: "aws_cloudtrail_", limit: 2},
	{prefix: "aws_config_", limit: 2},
	{prefix: "aws_securityhub_", limit: 2},
	{prefix: "aws_guardduty_", limit: 2},
	{prefix: "aws_accessanalyzer_", limit: 2},
	{prefix: "aws_s3_", limit: 4},
}

func (e *SyncEngine) regionsForTable(table TableSpec) []string {
	return regionsForTable(table.Name, e.regions)
}

func regionsForTable(tableName string, configured []string) []string {
	if len(configured) == 0 {
		return nil
	}
	if strings.HasPrefix(tableName, "aws_identitycenter_") {
		for _, region := range configured {
			if strings.TrimSpace(region) != "" {
				return []string{region}
			}
		}
		return nil
	}
	for _, override := range awsTableRegionOverrides {
		if strings.HasPrefix(tableName, override.prefix) {
			return intersectRegions(configured, override.regions)
		}
	}
	return configured
}

func isGlobalTableName(tableName string) bool {
	for _, override := range awsTableRegionOverrides {
		if strings.HasPrefix(tableName, override.prefix) {
			return true
		}
	}
	return false
}

func intersectRegions(configured, allowed []string) []string {
	if len(configured) == 0 {
		return nil
	}
	if len(allowed) == 0 {
		return configured
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, region := range allowed {
		allowedSet[strings.ToLower(region)] = struct{}{}
	}
	result := make([]string, 0, len(configured))
	for _, region := range configured {
		if _, ok := allowedSet[strings.ToLower(region)]; ok {
			result = append(result, region)
		}
	}
	return result
}

func serviceLimitForTable(tableName string) (string, int) {
	for _, limit := range awsServiceConcurrencyLimits {
		if strings.HasPrefix(tableName, limit.prefix) {
			return limit.prefix, limit.limit
		}
	}
	return "", 0
}

func buildServiceLimiters(globalLimit int) map[string]chan struct{} {
	if len(awsServiceConcurrencyLimits) == 0 {
		return nil
	}
	limiters := make(map[string]chan struct{}, len(awsServiceConcurrencyLimits))
	for _, limit := range awsServiceConcurrencyLimits {
		capacity := limit.limit
		if globalLimit > 0 && capacity > globalLimit {
			capacity = globalLimit
		}
		if capacity <= 0 {
			continue
		}
		limiters[limit.prefix] = make(chan struct{}, capacity)
	}
	if len(limiters) == 0 {
		return nil
	}
	return limiters
}
