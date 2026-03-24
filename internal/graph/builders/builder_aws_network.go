package builders

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

const (
	awsSecurityGroupRulesExposureQuery = `
		SELECT account_id, region, security_group_id, direction, protocol, from_port, to_port, ip_ranges, ipv6_ranges
		FROM aws_ec2_security_group_rules
	`
	awsSubnetExposureQuery = `
		SELECT arn, subnet_id, account_id, region, vpc_id
		FROM aws_ec2_subnets
	`
	awsRouteTableExposureQuery = `
		SELECT route_table_id, account_id, region, vpc_id, routes, associations
		FROM aws_ec2_route_tables
	`
)

type awsIngressRule struct {
	SecurityGroupARN string
	SecurityGroupID  string
	CIDR             string
	Protocol         string
	FromPort         any
	ToPort           any
}

type awsPublicSubnetPath struct {
	SubnetARN         string
	SubnetID          string
	VPCID             string
	RouteTableID      string
	InternetGatewayID string
}

type awsSubnetRoutePath struct {
	RouteTableID      string
	InternetGatewayID string
	IsPublic          bool
}

func (b *Builder) buildAWSNetworkExposureEdges(ctx context.Context) (map[string]struct{}, int) {
	sgRules, sgObserved, sgReady := b.loadAWSPublicSecurityGroupRules(ctx)
	publicSubnets, subnetTopologyObserved, subnetsReady := b.loadAWSPublicSubnetPaths(ctx)
	if !sgReady && !subnetsReady {
		return map[string]struct{}{}, 0
	}

	handled := make(map[string]struct{})
	count := 0

	for _, node := range b.graph.GetAllNodes() {
		if !awsDirectInternetCandidate(node) || !awsNodeHasDirectInternetEndpoint(node) {
			continue
		}

		securityGroups := b.awsRelationshipTargets(node.ID, "MEMBER_OF", "security-group/")
		subnets := b.awsRelationshipTargets(node.ID, "IN_SUBNET", "subnet/")
		if len(securityGroups) == 0 || len(subnets) == 0 {
			continue
		}

		matchedRules := awsCollectIngressRules(securityGroups, sgRules)
		subnetPath, hasPublicSubnet := awsFirstPublicSubnetPath(subnets, publicSubnets)
		sgFullyObserved := sgReady && awsAllObserved(securityGroups, sgObserved)
		subnetsFullyObserved := subnetsReady && awsAllObserved(subnets, subnetTopologyObserved)

		// Positive inference only needs one observed public SG rule and one observed
		// public subnet path. Negative suppression only needs a fully observed side
		// of the path to conclusively rule internet reachability out.
		switch {
		case len(matchedRules) > 0 && hasPublicSubnet:
			handled[node.ID] = struct{}{}
		case sgFullyObserved && len(matchedRules) == 0:
			handled[node.ID] = struct{}{}
			continue
		case subnetsFullyObserved && !hasPublicSubnet:
			handled[node.ID] = struct{}{}
			continue
		default:
			continue
		}

		props := map[string]any{
			"exposure_source":      "aws_network_reachability",
			"public_endpoint":      awsNodePublicEndpoint(node),
			"subnet_id":            subnetPath.SubnetID,
			"route_table_id":       subnetPath.RouteTableID,
			"internet_gateway_id":  subnetPath.InternetGatewayID,
			"security_group_rules": awsIngressRuleProperties(matchedRules),
			"network_path": []string{
				"internet",
				subnetPath.InternetGatewayID,
				subnetPath.RouteTableID,
				subnetPath.SubnetID,
				matchedRules[0].SecurityGroupID,
				node.ID,
			},
			"path_summary": awsSummarizeNetworkPath(subnetPath, matchedRules[0], node),
		}

		if b.addEdgeIfMissing(&Edge{
			ID:         "internet->" + node.ID + ":aws-network",
			Source:     "internet",
			Target:     node.ID,
			Kind:       EdgeKindExposedTo,
			Effect:     EdgeEffectAllow,
			Risk:       RiskHigh,
			Properties: props,
		}) {
			count++
		}
	}

	return handled, count
}

func (b *Builder) loadAWSPublicSecurityGroupRules(ctx context.Context) (map[string][]awsIngressRule, map[string]struct{}, bool) {
	rows, err := b.queryIfExists(ctx, "aws_ec2_security_group_rules", awsSecurityGroupRulesExposureQuery)
	if err != nil {
		b.logger.Warn("failed to query aws security group rules", "error", err)
		return nil, nil, false
	}
	if len(rows.Rows) == 0 {
		return nil, nil, false
	}

	publicRules := make(map[string][]awsIngressRule)
	observed := make(map[string]struct{})

	for _, row := range rows.Rows {
		accountID := queryRowString(row, "account_id")
		region := queryRowString(row, "region")
		securityGroupID := queryRowString(row, "security_group_id")
		if securityGroupID == "" || region == "" || accountID == "" {
			continue
		}

		sgARN := awsSecurityGroupARN(region, accountID, securityGroupID)
		observed[sgARN] = struct{}{}

		if !strings.EqualFold(queryRowString(row, "direction"), "ingress") {
			continue
		}

		cidr, ok := awsPublicCIDR(queryRow(row, "ip_ranges"), "CidrIp", "cidr_ip", "cidr")
		if !ok {
			cidr, ok = awsPublicCIDR(queryRow(row, "ipv6_ranges"), "CidrIpv6", "cidr_ipv6", "cidr")
		}
		if !ok {
			continue
		}

		publicRules[sgARN] = append(publicRules[sgARN], awsIngressRule{
			SecurityGroupARN: sgARN,
			SecurityGroupID:  securityGroupID,
			CIDR:             cidr,
			Protocol:         queryRowString(row, "protocol"),
			FromPort:         queryRow(row, "from_port"),
			ToPort:           queryRow(row, "to_port"),
		})
	}

	if len(observed) == 0 {
		return nil, nil, false
	}
	return publicRules, observed, true
}

func (b *Builder) loadAWSPublicSubnetPaths(ctx context.Context) (map[string]awsPublicSubnetPath, map[string]struct{}, bool) {
	subnets, err := b.queryIfExists(ctx, "aws_ec2_subnets", awsSubnetExposureQuery)
	if err != nil {
		b.logger.Warn("failed to query aws subnets", "error", err)
		return nil, nil, false
	}
	routeTables, err := b.queryIfExists(ctx, "aws_ec2_route_tables", awsRouteTableExposureQuery)
	if err != nil {
		b.logger.Warn("failed to query aws route tables", "error", err)
		return nil, nil, len(subnets.Rows) > 0
	}
	if len(subnets.Rows) == 0 {
		return nil, nil, false
	}

	subnetMetadata := make(map[string]awsPublicSubnetPath, len(subnets.Rows))
	for _, row := range subnets.Rows {
		subnetARN := queryRowString(row, "arn")
		subnetID := queryRowString(row, "subnet_id")
		accountID := queryRowString(row, "account_id")
		region := queryRowString(row, "region")
		vpcID := queryRowString(row, "vpc_id")
		if subnetARN == "" && subnetID != "" && accountID != "" && region != "" {
			subnetARN = awsSubnetARN(region, accountID, subnetID)
		}
		if subnetARN == "" || subnetID == "" || vpcID == "" {
			continue
		}

		subnetMetadata[subnetARN] = awsPublicSubnetPath{
			SubnetARN: subnetARN,
			SubnetID:  subnetID,
			VPCID:     vpcID,
		}
	}

	if len(subnetMetadata) == 0 {
		return nil, nil, false
	}

	explicitRoutes := make(map[string]awsSubnetRoutePath)
	mainRoutesByVPC := make(map[string]awsSubnetRoutePath)

	for _, row := range routeTables.Rows {
		routeTableID := queryRowString(row, "route_table_id")
		accountID := queryRowString(row, "account_id")
		region := queryRowString(row, "region")
		vpcID := queryRowString(row, "vpc_id")
		if routeTableID == "" || accountID == "" || region == "" || vpcID == "" {
			continue
		}
		igwID, isPublic := awsInternetGatewayRoute(queryRow(row, "routes"))

		for _, assoc := range awsAsSlice(queryRow(row, "associations")) {
			assocMap := awsAsMap(assoc)
			if assocMap == nil {
				continue
			}

			if subnetID := awsGetStringAny(assocMap, "SubnetId", "subnet_id", "subnetId"); subnetID != "" {
				subnetARN := awsSubnetARN(region, accountID, subnetID)
				explicitRoutes[subnetARN] = awsSubnetRoutePath{
					RouteTableID:      routeTableID,
					InternetGatewayID: igwID,
					IsPublic:          isPublic,
				}
				continue
			}

			if awsGetBoolAny(assocMap, "Main", "main") {
				mainRoutesByVPC[vpcID] = awsSubnetRoutePath{
					RouteTableID:      routeTableID,
					InternetGatewayID: igwID,
					IsPublic:          isPublic,
				}
			}
		}
	}

	publicSubnets := make(map[string]awsPublicSubnetPath)
	topologyObserved := make(map[string]struct{})
	for subnetARN, subnet := range subnetMetadata {
		routePath, ok := explicitRoutes[subnetARN]
		if !ok {
			routePath, ok = mainRoutesByVPC[subnet.VPCID]
		}
		if !ok {
			continue
		}

		topologyObserved[subnetARN] = struct{}{}
		if !routePath.IsPublic {
			continue
		}

		publicSubnets[subnetARN] = awsPublicSubnetPath{
			SubnetARN:         subnetARN,
			SubnetID:          subnet.SubnetID,
			VPCID:             subnet.VPCID,
			RouteTableID:      routePath.RouteTableID,
			InternetGatewayID: routePath.InternetGatewayID,
		}
	}

	return publicSubnets, topologyObserved, true
}

func awsDirectInternetCandidate(node *Node) bool {
	if node == nil || node.Provider != "aws" {
		return false
	}
	switch node.Kind {
	case NodeKindInstance, NodeKindDatabase:
		return true
	default:
		return false
	}
}

func awsNodeHasDirectInternetEndpoint(node *Node) bool {
	if node == nil {
		return false
	}
	if pip := node.PropertyString("public_ip"); isValidPublicIP(pip) {
		return true
	}
	if value, ok := node.PropertyBool("public"); ok {
		return value
	}
	return false
}

func awsNodePublicEndpoint(node *Node) string {
	if node == nil {
		return ""
	}
	if pip := node.PropertyString("public_ip"); isValidPublicIP(pip) {
		return pip
	}
	if value, ok := node.PropertyBool("public"); ok && value {
		return "publicly_accessible"
	}
	return ""
}

func (b *Builder) awsRelationshipTargets(nodeID, relationshipType, resourceFragment string) []string {
	targets := make([]string, 0, 2)
	seen := make(map[string]struct{})
	for _, edge := range b.graph.GetOutEdges(nodeID) {
		if edge == nil || edge.Kind != EdgeKindConnectsTo {
			continue
		}
		if strings.ToUpper(toString(edge.Properties["relationship_type"])) != relationshipType {
			continue
		}
		if resourceFragment != "" && !strings.Contains(edge.Target, resourceFragment) {
			continue
		}
		if _, ok := seen[edge.Target]; ok {
			continue
		}
		seen[edge.Target] = struct{}{}
		targets = append(targets, edge.Target)
	}
	return targets
}

func awsCollectIngressRules(securityGroups []string, rulesBySG map[string][]awsIngressRule) []awsIngressRule {
	matched := make([]awsIngressRule, 0, len(securityGroups))
	for _, securityGroup := range securityGroups {
		matched = append(matched, rulesBySG[securityGroup]...)
	}
	return matched
}

func awsIngressRuleProperties(rules []awsIngressRule) []map[string]any {
	props := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		props = append(props, map[string]any{
			"security_group_arn": rule.SecurityGroupARN,
			"security_group_id":  rule.SecurityGroupID,
			"cidr":               rule.CIDR,
			"protocol":           rule.Protocol,
			"from_port":          rule.FromPort,
			"to_port":            rule.ToPort,
		})
	}
	return props
}

func awsFirstPublicSubnetPath(subnets []string, publicSubnets map[string]awsPublicSubnetPath) (awsPublicSubnetPath, bool) {
	for _, subnetARN := range subnets {
		if path, ok := publicSubnets[subnetARN]; ok {
			return path, true
		}
	}
	return awsPublicSubnetPath{}, false
}

func awsSummarizeNetworkPath(subnetPath awsPublicSubnetPath, rule awsIngressRule, node *Node) string {
	if node == nil {
		return ""
	}
	return fmt.Sprintf(
		"internet -> %s -> %s -> %s -> %s -> %s",
		subnetPath.InternetGatewayID,
		subnetPath.RouteTableID,
		subnetPath.SubnetID,
		rule.SecurityGroupID,
		node.Name,
	)
}

func awsAllObserved(values []string, observed map[string]struct{}) bool {
	if len(values) == 0 || len(observed) == 0 {
		return false
	}
	for _, value := range values {
		if _, ok := observed[value]; !ok {
			return false
		}
	}
	return true
}

func awsInternetGatewayRoute(routes any) (string, bool) {
	for _, route := range awsAsSlice(routes) {
		routeMap := awsAsMap(route)
		if routeMap == nil {
			continue
		}

		if state := awsGetStringAny(routeMap, "State", "state"); state != "" && !strings.EqualFold(state, "active") {
			continue
		}

		gatewayID := awsGetStringAny(routeMap, "GatewayId", "gateway_id")
		if !strings.HasPrefix(gatewayID, "igw-") {
			continue
		}

		if cidr, ok := awsGetString(routeMap, "DestinationCidrBlock", "destination_cidr_block"); ok && cidr == "0.0.0.0/0" {
			return gatewayID, true
		}
		if cidr, ok := awsGetString(routeMap, "DestinationIpv6CidrBlock", "destination_ipv6_cidr_block"); ok && cidr == "::/0" {
			return gatewayID, true
		}
	}
	return "", false
}

func awsPublicCIDR(ranges any, keys ...string) (string, bool) {
	for _, entry := range awsAsSlice(ranges) {
		switch value := entry.(type) {
		case string:
			if value == "0.0.0.0/0" || value == "::/0" {
				return value, true
			}
		default:
			entryMap := awsAsMap(value)
			if entryMap == nil {
				continue
			}
			cidr, ok := awsGetString(entryMap, keys...)
			if ok && (cidr == "0.0.0.0/0" || cidr == "::/0") {
				return cidr, true
			}
		}
	}
	return "", false
}

func awsSecurityGroupARN(region, accountID, securityGroupID string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, accountID, securityGroupID)
}

func awsSubnetARN(region, accountID, subnetID string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", region, accountID, subnetID)
}

func awsGetStringAny(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := queryRowValue(m, key); ok {
			if s := toString(value); s != "" {
				return s
			}
		}
	}
	return ""
}

func awsGetString(m map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := queryRowValue(m, key); ok {
			if s := toString(value); s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func awsGetBoolAny(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := queryRowValue(m, key); ok {
			return toBool(value)
		}
	}
	return false
}

func awsAsMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	switch value := v.(type) {
	case map[string]any:
		return value
	case string:
		var decoded map[string]any
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			return decoded
		}
	case []byte:
		var decoded map[string]any
		if err := json.Unmarshal(value, &decoded); err == nil {
			return decoded
		}
	}

	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.Kind() != reflect.Map {
		return nil
	}

	decoded := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		if iter.Key().Kind() != reflect.String {
			return nil
		}
		decoded[iter.Key().String()] = iter.Value().Interface()
	}
	return decoded
}

func awsAsSlice(v any) []any {
	if v == nil {
		return nil
	}
	switch value := v.(type) {
	case []any:
		return value
	case []string:
		out := make([]any, 0, len(value))
		for _, item := range value {
			out = append(out, item)
		}
		return out
	case string:
		var decoded []any
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			return decoded
		}
	case []byte:
		var decoded []any
		if err := json.Unmarshal(value, &decoded); err == nil {
			return decoded
		}
	}

	rv := reflect.ValueOf(v)
	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		return nil
	}

	out := make([]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out = append(out, rv.Index(i).Interface())
	}
	return out
}
