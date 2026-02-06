package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// WAFv2 Web ACLs
func (e *SyncEngine) wafv2WebAclTable() TableSpec {
	return TableSpec{
		Name:    "aws_wafv2_web_acls",
		Columns: []string{"arn", "account_id", "region", "id", "name", "description", "scope", "capacity", "default_action", "rules", "visibility_config", "managed_by_firewall_manager"},
		Fetch:   e.fetchWAFv2WebAcls,
	}
}

func (e *SyncEngine) fetchWAFv2WebAcls(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := wafv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}

	// Fetch REGIONAL scope Web ACLs
	regionalOut, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
		Scope: types.ScopeRegional,
	})
	if err == nil {
		for _, acl := range regionalOut.WebACLs {
			aclArn := aws.ToString(acl.ARN)

			// Get full details
			getOut, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{
				Id:    acl.Id,
				Name:  acl.Name,
				Scope: types.ScopeRegional,
			})
			if err != nil {
				continue
			}

			webAcl := getOut.WebACL
			var defaultAction string
			if webAcl.DefaultAction != nil {
				if webAcl.DefaultAction.Allow != nil {
					defaultAction = "ALLOW"
				} else if webAcl.DefaultAction.Block != nil {
					defaultAction = "BLOCK"
				}
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                      aclArn,
				"arn":                         aclArn,
				"account_id":                  accountID,
				"region":                      region,
				"id":                          aws.ToString(webAcl.Id),
				"name":                        aws.ToString(webAcl.Name),
				"description":                 aws.ToString(webAcl.Description),
				"scope":                       "REGIONAL",
				"capacity":                    webAcl.Capacity,
				"default_action":              defaultAction,
				"rules":                       webAcl.Rules,
				"visibility_config":           webAcl.VisibilityConfig,
				"managed_by_firewall_manager": webAcl.ManagedByFirewallManager,
			})
		}
	}

	// Fetch CLOUDFRONT scope Web ACLs (only in us-east-1)
	if region == "us-east-1" {
		cloudfrontOut, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope: types.ScopeCloudfront,
		})
		if err == nil {
			for _, acl := range cloudfrontOut.WebACLs {
				aclArn := aws.ToString(acl.ARN)

				getOut, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{
					Id:    acl.Id,
					Name:  acl.Name,
					Scope: types.ScopeCloudfront,
				})
				if err != nil {
					continue
				}

				webAcl := getOut.WebACL
				var defaultAction string
				if webAcl.DefaultAction != nil {
					if webAcl.DefaultAction.Allow != nil {
						defaultAction = "ALLOW"
					} else if webAcl.DefaultAction.Block != nil {
						defaultAction = "BLOCK"
					}
				}

				rows = append(rows, map[string]interface{}{
					"_cq_id":                      aclArn,
					"arn":                         aclArn,
					"account_id":                  accountID,
					"region":                      "global",
					"id":                          aws.ToString(webAcl.Id),
					"name":                        aws.ToString(webAcl.Name),
					"description":                 aws.ToString(webAcl.Description),
					"scope":                       "CLOUDFRONT",
					"capacity":                    webAcl.Capacity,
					"default_action":              defaultAction,
					"rules":                       webAcl.Rules,
					"visibility_config":           webAcl.VisibilityConfig,
					"managed_by_firewall_manager": webAcl.ManagedByFirewallManager,
				})
			}
		}
	}

	return rows, nil
}

// WAFv2 IP Sets
func (e *SyncEngine) wafv2IpSetTable() TableSpec {
	return TableSpec{
		Name:    "aws_wafv2_ipsets",
		Columns: []string{"arn", "account_id", "region", "id", "name", "description", "scope", "ip_address_version", "addresses"},
		Fetch:   e.fetchWAFv2IpSets,
	}
}

func (e *SyncEngine) fetchWAFv2IpSets(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := wafv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}

	// Fetch REGIONAL scope IP Sets
	regionalOut, err := client.ListIPSets(ctx, &wafv2.ListIPSetsInput{
		Scope: types.ScopeRegional,
	})
	if err == nil {
		for _, ipSet := range regionalOut.IPSets {
			ipSetArn := aws.ToString(ipSet.ARN)

			getOut, err := client.GetIPSet(ctx, &wafv2.GetIPSetInput{
				Id:    ipSet.Id,
				Name:  ipSet.Name,
				Scope: types.ScopeRegional,
			})
			if err != nil {
				continue
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":             ipSetArn,
				"arn":                ipSetArn,
				"account_id":         accountID,
				"region":             region,
				"id":                 aws.ToString(getOut.IPSet.Id),
				"name":               aws.ToString(getOut.IPSet.Name),
				"description":        aws.ToString(getOut.IPSet.Description),
				"scope":              "REGIONAL",
				"ip_address_version": string(getOut.IPSet.IPAddressVersion),
				"addresses":          getOut.IPSet.Addresses,
			})
		}
	}

	return rows, nil
}

// WAFv2 Rule Groups
func (e *SyncEngine) wafv2RuleGroupTable() TableSpec {
	return TableSpec{
		Name:    "aws_wafv2_rule_groups",
		Columns: []string{"arn", "account_id", "region", "id", "name", "description", "scope", "capacity", "rules", "visibility_config"},
		Fetch:   e.fetchWAFv2RuleGroups,
	}
}

func (e *SyncEngine) fetchWAFv2RuleGroups(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := wafv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}

	regionalOut, err := client.ListRuleGroups(ctx, &wafv2.ListRuleGroupsInput{
		Scope: types.ScopeRegional,
	})
	if err == nil {
		for _, rg := range regionalOut.RuleGroups {
			rgArn := aws.ToString(rg.ARN)

			getOut, err := client.GetRuleGroup(ctx, &wafv2.GetRuleGroupInput{
				Id:    rg.Id,
				Name:  rg.Name,
				Scope: types.ScopeRegional,
			})
			if err != nil {
				continue
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":            rgArn,
				"arn":               rgArn,
				"account_id":        accountID,
				"region":            region,
				"id":                aws.ToString(getOut.RuleGroup.Id),
				"name":              aws.ToString(getOut.RuleGroup.Name),
				"description":       aws.ToString(getOut.RuleGroup.Description),
				"scope":             "REGIONAL",
				"capacity":          getOut.RuleGroup.Capacity,
				"rules":             getOut.RuleGroup.Rules,
				"visibility_config": getOut.RuleGroup.VisibilityConfig,
			})
		}
	}

	return rows, nil
}

// WAFv2 Regex Pattern Sets
func (e *SyncEngine) wafv2RegexPatternSetTable() TableSpec {
	return TableSpec{
		Name:    "aws_wafv2_regex_pattern_sets",
		Columns: []string{"arn", "account_id", "region", "id", "name", "description", "scope", "regular_expression_list"},
		Fetch:   e.fetchWAFv2RegexPatternSets,
	}
}

func (e *SyncEngine) fetchWAFv2RegexPatternSets(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := wafv2.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}

	regionalOut, err := client.ListRegexPatternSets(ctx, &wafv2.ListRegexPatternSetsInput{
		Scope: types.ScopeRegional,
	})
	if err == nil {
		for _, rps := range regionalOut.RegexPatternSets {
			rpsArn := aws.ToString(rps.ARN)

			getOut, err := client.GetRegexPatternSet(ctx, &wafv2.GetRegexPatternSetInput{
				Id:    rps.Id,
				Name:  rps.Name,
				Scope: types.ScopeRegional,
			})
			if err != nil {
				continue
			}

			var patterns []string
			for _, re := range getOut.RegexPatternSet.RegularExpressionList {
				patterns = append(patterns, aws.ToString(re.RegexString))
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":                  rpsArn,
				"arn":                     rpsArn,
				"account_id":              accountID,
				"region":                  region,
				"id":                      aws.ToString(getOut.RegexPatternSet.Id),
				"name":                    aws.ToString(getOut.RegexPatternSet.Name),
				"description":             aws.ToString(getOut.RegexPatternSet.Description),
				"scope":                   "REGIONAL",
				"regular_expression_list": patterns,
			})
		}
	}

	return rows, nil
}
