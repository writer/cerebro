package sourceprojection

import (
	"strings"
)

func grcAWSResourceTypeFromARN(resourceID string) string {
	_, service, _, _, resource, ok := grcAWSARNParts(resourceID)
	if !ok {
		return ""
	}
	resourceType := strings.TrimLeft(resource, "/")
	if before, _, ok := strings.Cut(resourceType, "/"); ok {
		resourceType = before
	}
	if before, _, ok := strings.Cut(resourceType, ":"); ok {
		resourceType = before
	}
	switch service {
	case "ec2":
		switch resourceType {
		case "security-group":
			return "security_group"
		case "network-interface":
			return "network_interface"
		case "instance":
			return "ec2_instance"
		default:
			return normalizeCloudType(resourceType)
		}
	case "elasticloadbalancing":
		switch {
		case strings.HasPrefix(resource, "loadbalancer/app/"):
			return "application_load_balancer"
		case strings.HasPrefix(resource, "loadbalancer/net/"):
			return "network_load_balancer"
		default:
			return "load_balancer"
		}
	case "cloudfront":
		if resourceType == "distribution" {
			return "cloudfront_distribution"
		}
	case "apigateway":
		if resourceType == "domainname" || resourceType == "domainnames" {
			return "apigateway_domain"
		}
	}
	if resourceType != "" {
		return normalizeCloudType(service + "_" + resourceType)
	}
	return normalizeCloudType(service)
}

func grcAWSARNParts(resourceID string) (partition string, service string, region string, accountID string, resource string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(resourceID), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") {
		return "", "", "", "", "", false
	}
	return parts[1], parts[2], parts[3], parts[4], parts[5], true
}
