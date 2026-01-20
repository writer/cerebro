package findings

import (
	"fmt"
	"net/url"
	"strings"
)

// EnrichFinding populates additional metadata fields on a finding from its resource data
func EnrichFinding(f *Finding) {
	if f.Resource == nil {
		return
	}

	// Extract resource metadata
	if f.ResourceExternalID == "" {
		f.ResourceExternalID = extractString(f.Resource, "arn", "_cq_id")
	}
	if f.ResourceName == "" {
		f.ResourceName = extractString(f.Resource, "name", "role_name", "bucket_name", "function_name", "instance_id")
	}
	if f.ResourceRegion == "" {
		f.ResourceRegion = extractString(f.Resource, "region", "location")
	}
	if f.ResourcePlatform == "" {
		f.ResourcePlatform = detectPlatform(f.Resource)
	}
	if f.ResourceStatus == "" {
		f.ResourceStatus = extractString(f.Resource, "state", "status")
	}

	// Extract account/subscription info
	if f.SubscriptionID == "" {
		f.SubscriptionID = extractString(f.Resource, "account_id", "project_id", "subscription_id")
	}

	// Extract tags
	if f.ResourceTags == nil {
		f.ResourceTags = extractTags(f.Resource)
	}

	// Generate cloud provider URL
	if f.CloudProviderURL == "" {
		f.CloudProviderURL = GenerateCloudProviderURL(f.Resource, f.ResourceType, f.ResourcePlatform)
	}

	// Store full resource JSON for export
	if f.ResourceJSON == nil {
		f.ResourceJSON = f.Resource
	}

	// Set timestamps
	if f.CreatedAt.IsZero() && !f.FirstSeen.IsZero() {
		f.CreatedAt = f.FirstSeen
	}
	if f.UpdatedAt.IsZero() && !f.LastSeen.IsZero() {
		f.UpdatedAt = f.LastSeen
	}
}

// extractString tries multiple keys to extract a string value
func extractString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
}

// detectPlatform determines the cloud provider from resource data
func detectPlatform(data map[string]interface{}) string {
	// Check for ARN (AWS)
	if arn, ok := data["arn"].(string); ok && strings.HasPrefix(arn, "arn:aws:") {
		return "AWS"
	}
	// Check for GCP resource paths
	if _, ok := data["project_id"]; ok {
		return "GCP"
	}
	// Check for Azure resource IDs
	if id, ok := data["id"].(string); ok && strings.Contains(id, "/subscriptions/") {
		return "Azure"
	}
	// Check account_id (likely AWS)
	if _, ok := data["account_id"]; ok {
		return "AWS"
	}
	return ""
}

// extractTags extracts tags from resource data
func extractTags(data map[string]interface{}) map[string]string {
	tags := make(map[string]string)

	// AWS-style tags (array of {Key, Value})
	if tagList, ok := data["tags"].([]interface{}); ok {
		for _, t := range tagList {
			if tagMap, ok := t.(map[string]interface{}); ok {
				key := extractString(tagMap, "Key", "key")
				val := extractString(tagMap, "Value", "value")
				if key != "" {
					tags[key] = val
				}
			}
		}
	}

	// GCP/Azure style tags (direct map)
	if tagMap, ok := data["tags"].(map[string]interface{}); ok {
		for k, v := range tagMap {
			if str, ok := v.(string); ok {
				tags[k] = str
			}
		}
	}

	// Also check "labels" (GCP)
	if labelMap, ok := data["labels"].(map[string]interface{}); ok {
		for k, v := range labelMap {
			if str, ok := v.(string); ok {
				tags[k] = str
			}
		}
	}

	if len(tags) == 0 {
		return nil
	}
	return tags
}

// GenerateCloudProviderURL creates a direct link to the resource in the cloud console
func GenerateCloudProviderURL(data map[string]interface{}, resourceType, platform string) string {
	switch platform {
	case "AWS":
		return generateAWSConsoleURL(data, resourceType)
	case "GCP":
		return generateGCPConsoleURL(data, resourceType)
	case "Azure":
		return generateAzurePortalURL(data)
	}
	return ""
}

func generateAWSConsoleURL(data map[string]interface{}, resourceType string) string {
	region := extractString(data, "region")
	if region == "" {
		region = "us-east-1"
	}

	// Parse resource type (aws::service::type)
	parts := strings.Split(resourceType, "::")
	if len(parts) < 3 {
		return ""
	}
	service := parts[1]
	resType := parts[2]

	baseURL := fmt.Sprintf("https://%s.console.aws.amazon.com", region)

	switch service {
	case "iam":
		switch resType {
		case "role":
			name := extractString(data, "role_name", "name")
			if name != "" {
				return fmt.Sprintf("https://console.aws.amazon.com/iam/home#/roles/%s", url.PathEscape(name))
			}
		case "user":
			name := extractString(data, "user_name", "name")
			if name != "" {
				return fmt.Sprintf("https://console.aws.amazon.com/iam/home#/users/%s", url.PathEscape(name))
			}
		case "policy":
			arn := extractString(data, "arn")
			if arn != "" {
				return fmt.Sprintf("https://console.aws.amazon.com/iam/home#/policies/%s", url.PathEscape(arn))
			}
		}

	case "s3":
		name := extractString(data, "name", "bucket_name")
		if name != "" {
			return fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s", url.PathEscape(name))
		}

	case "ec2":
		switch resType {
		case "instance", "instances":
			id := extractString(data, "instance_id", "id")
			if id != "" {
				return fmt.Sprintf("%s/ec2/home#InstanceDetails:instanceId=%s", baseURL, url.QueryEscape(id))
			}
		case "security_group", "security-group", "securitygroup":
			id := extractString(data, "group_id", "id")
			if id != "" {
				return fmt.Sprintf("%s/ec2/home#SecurityGroup:groupId=%s", baseURL, url.QueryEscape(id))
			}
		case "vpc":
			id := extractString(data, "vpc_id", "id")
			if id != "" {
				return fmt.Sprintf("%s/vpc/home#VpcDetails:VpcId=%s", baseURL, url.QueryEscape(id))
			}
		}

	case "lambda":
		name := extractString(data, "function_name", "name")
		if name != "" {
			return fmt.Sprintf("%s/lambda/home#/functions/%s", baseURL, url.PathEscape(name))
		}

	case "rds":
		id := extractString(data, "db_instance_identifier", "id", "name")
		if id != "" {
			return fmt.Sprintf("%s/rds/home#database:id=%s", baseURL, url.QueryEscape(id))
		}

	case "eks":
		name := extractString(data, "name", "cluster_name")
		if name != "" {
			return fmt.Sprintf("%s/eks/home#/clusters/%s", baseURL, url.PathEscape(name))
		}

	case "ecs":
		switch resType {
		case "cluster":
			name := extractString(data, "cluster_name", "name")
			if name != "" {
				return fmt.Sprintf("%s/ecs/home#/clusters/%s", baseURL, url.PathEscape(name))
			}
		case "service":
			cluster := extractString(data, "cluster_name", "cluster")
			service := extractString(data, "service_name", "name")
			if cluster != "" && service != "" {
				return fmt.Sprintf("%s/ecs/home#/clusters/%s/services/%s", baseURL, url.PathEscape(cluster), url.PathEscape(service))
			}
		}

	case "kms":
		id := extractString(data, "key_id", "id")
		if id != "" {
			return fmt.Sprintf("%s/kms/home#/kms/keys/%s", baseURL, url.QueryEscape(id))
		}

	case "secretsmanager":
		name := extractString(data, "name", "secret_name")
		arn := extractString(data, "arn")
		if arn != "" {
			return fmt.Sprintf("%s/secretsmanager/home#!/secret?name=%s", baseURL, url.QueryEscape(arn))
		} else if name != "" {
			return fmt.Sprintf("%s/secretsmanager/home#!/secret?name=%s", baseURL, url.QueryEscape(name))
		}

	case "sns":
		arn := extractString(data, "arn", "topic_arn")
		if arn != "" {
			return fmt.Sprintf("%s/sns/home#/topic/%s", baseURL, url.QueryEscape(arn))
		}

	case "sqs":
		url := extractString(data, "queue_url", "url")
		if url != "" {
			return fmt.Sprintf("%s/sqs/home#queues", baseURL)
		}
	}

	return ""
}

func generateGCPConsoleURL(data map[string]interface{}, resourceType string) string {
	project := extractString(data, "project_id", "project")
	if project == "" {
		return ""
	}

	parts := strings.Split(resourceType, "::")
	if len(parts) < 3 {
		return ""
	}
	service := parts[1]
	resType := parts[2]

	switch service {
	case "compute":
		zone := extractString(data, "zone")
		switch resType {
		case "instance":
			name := extractString(data, "name")
			if name != "" && zone != "" {
				return fmt.Sprintf("https://console.cloud.google.com/compute/instancesDetail/zones/%s/instances/%s?project=%s",
					zone, name, project)
			}
		}
	case "storage":
		name := extractString(data, "name")
		if name != "" {
			return fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s?project=%s", name, project)
		}
	case "iam":
		email := extractString(data, "email")
		if email != "" {
			return fmt.Sprintf("https://console.cloud.google.com/iam-admin/serviceaccounts/details/%s?project=%s",
				url.PathEscape(email), project)
		}
	}

	return ""
}

func generateAzurePortalURL(data map[string]interface{}) string {
	resourceID := extractString(data, "id")
	if resourceID == "" || !strings.HasPrefix(resourceID, "/subscriptions/") {
		return ""
	}

	// Azure Portal URL format
	return fmt.Sprintf("https://portal.azure.com/#@/resource%s", resourceID)
}
