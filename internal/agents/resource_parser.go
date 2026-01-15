package agents

import (
	"fmt"
	"strings"
)

// AWSArn represents parsed components of an AWS ARN.
type AWSArn struct {
	Partition    string
	Service      string
	Region       string
	Account      string
	Resource     string
	ResourceType string
	ResourceID   string
}

func parseAWSArn(value string) (*AWSArn, error) {
	parts := strings.SplitN(value, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return nil, fmt.Errorf("invalid ARN: %s", value)
	}

	resource := parts[5]
	resourceType := ""
	resourceID := resource
	if strings.Contains(resource, "/") {
		segments := strings.SplitN(resource, "/", 2)
		resourceType = segments[0]
		resourceID = segments[1]
	} else if strings.Contains(resource, ":") {
		segments := strings.SplitN(resource, ":", 2)
		resourceType = segments[0]
		resourceID = segments[1]
	}

	return &AWSArn{
		Partition:    parts[1],
		Service:      parts[2],
		Region:       parts[3],
		Account:      parts[4],
		Resource:     resource,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}, nil
}

func parseS3URI(value string) (string, bool) {
	if !strings.HasPrefix(value, "s3://") {
		return "", false
	}
	bucket := strings.TrimPrefix(value, "s3://")
	if bucket == "" {
		return "", false
	}
	bucket = strings.SplitN(bucket, "/", 2)[0]
	return bucket, bucket != ""
}

func parseGCSURI(value string) (string, bool) {
	if !strings.HasPrefix(value, "gs://") {
		return "", false
	}
	bucket := strings.TrimPrefix(value, "gs://")
	if bucket == "" {
		return "", false
	}
	bucket = strings.SplitN(bucket, "/", 2)[0]
	return bucket, bucket != ""
}

func parseGCSURL(value string) (string, bool) {
	if !strings.Contains(value, "storage.googleapis.com/") {
		return "", false
	}
	parts := strings.SplitN(value, "storage.googleapis.com/", 2)
	if len(parts) != 2 {
		return "", false
	}
	bucket := strings.SplitN(parts[1], "/", 2)[0]
	return bucket, bucket != ""
}

func parseGCPProjectPath(value string) (string, bool) {
	idx := strings.Index(value, "projects/")
	if idx == -1 {
		return "", false
	}
	start := idx + len("projects/")
	remaining := value[start:]
	if remaining == "" {
		return "", false
	}
	project := strings.FieldsFunc(remaining, func(r rune) bool {
		return r == '/' || r == '"' || r == '\'' || r == ')' || r == '(' || r == '>' || r == '<'
	})
	if len(project) == 0 {
		return "", false
	}
	return project[0], true
}

func parseECSServiceResource(resource string) (string, string) {
	resource = strings.TrimPrefix(resource, "service/")
	parts := strings.Split(resource, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
