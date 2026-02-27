package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var inspectSupportedProviders = []string{"aws", "gcp"}
var inspectGCPSupportedServices = []string{"storage", "compute", "resourcemanager"}

type resourceDescriptor struct {
	Provider     string
	Service      string
	ResourceType string
	Identifier   string
	Region       string
	Account      string
	Project      string
	Cluster      string
	Zone         string
	Raw          string
}

type inspectParams struct {
	Resource   string                 `json:"resource"`
	Provider   string                 `json:"provider"`
	Service    string                 `json:"service"`
	Identifier string                 `json:"identifier"`
	Account    string                 `json:"account"`
	Project    string                 `json:"project"`
	Region     string                 `json:"region"`
	Cluster    string                 `json:"cluster"`
	Zone       string                 `json:"zone"`
	Action     string                 `json:"action"`
	Params     map[string]interface{} `json:"params"`
}

type InspectCloudResourceParams struct {
	Resource   string                 `json:"resource"`
	Provider   string                 `json:"provider"`
	Service    string                 `json:"service"`
	Identifier string                 `json:"identifier"`
	Account    string                 `json:"account"`
	Project    string                 `json:"project"`
	Region     string                 `json:"region"`
	Cluster    string                 `json:"cluster"`
	Zone       string                 `json:"zone"`
	Action     string                 `json:"action"`
	Params     map[string]interface{} `json:"params"`
}

func (st *SecurityTools) InspectCloudResource(ctx context.Context, params InspectCloudResourceParams) (string, error) {
	payload := inspectParams(params)

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return st.inspectCloudResource(ctx, raw)
}

func (st *SecurityTools) inspectCloudResource(ctx context.Context, args json.RawMessage) (string, error) {
	var params inspectParams
	if err := json.Unmarshal(args, &params); err != nil {
		return "", err
	}

	if params.Resource == "" && params.Identifier == "" {
		return "", fmt.Errorf("resource or identifier is required")
	}

	if params.Action != "" && params.Service != "" {
		return st.runDirectInspection(ctx, params)
	}

	descriptor, err := resolveResourceDescriptor(params)
	if err != nil {
		return "", err
	}

	switch descriptor.Provider {
	case "aws":
		return st.inspectAWSResource(ctx, descriptor)
	case "gcp":
		return st.inspectGCPResource(ctx, descriptor)
	default:
		return "", UnsupportedProviderError(descriptor.Provider, inspectSupportedProviders)
	}
}

func (st *SecurityTools) runDirectInspection(ctx context.Context, params inspectParams) (string, error) {
	provider := strings.ToLower(params.Provider)
	if provider == "" {
		if strings.HasPrefix(params.Resource, "arn:aws:") || strings.HasPrefix(params.Resource, "s3://") {
			provider = "aws"
		} else if strings.HasPrefix(params.Resource, "gs://") || strings.Contains(params.Resource, "storage.googleapis.com") {
			provider = "gcp"
		}
	}
	if provider == "" {
		return "", fmt.Errorf("provider is required when using action override")
	}

	payload := map[string]interface{}{
		"service": params.Service,
		"action":  params.Action,
		"params":  params.Params,
	}
	if params.Params == nil {
		payload["params"] = map[string]interface{}{}
	}

	if provider == "aws" {
		raw, _ := json.Marshal(payload)
		return st.awsInspect(ctx, raw)
	}

	if provider == "gcp" {
		payload["project"] = params.Project
		raw, _ := json.Marshal(payload)
		return st.gcpInspect(ctx, raw)
	}

	return "", UnsupportedProviderError(provider, inspectSupportedProviders)
}

func resolveResourceDescriptor(params inspectParams) (resourceDescriptor, error) {
	desc := resourceDescriptor{
		Provider:   strings.ToLower(params.Provider),
		Service:    strings.ToLower(params.Service),
		Identifier: params.Identifier,
		Region:     params.Region,
		Project:    params.Project,
		Cluster:    params.Cluster,
		Zone:       params.Zone,
		Raw:        params.Resource,
	}

	resource := params.Resource
	if resource != "" {
		if strings.HasPrefix(resource, "arn:aws:") {
			arn, err := parseAWSArn(resource)
			if err != nil {
				return resourceDescriptor{}, err
			}
			desc.Provider = "aws"
			desc.Service = arn.Service
			desc.Region = arn.Region
			desc.Account = arn.Account
			desc.ResourceType = arn.ResourceType
			desc.Identifier = arn.ResourceID
			if arn.Service == "s3" && desc.ResourceType == "" {
				desc.ResourceType = "bucket"
			}
			if arn.Service == "iam" && arn.ResourceType == "policy" {
				desc.Identifier = resource
			}
			if arn.Service == "ecs" && strings.HasPrefix(arn.Resource, "service/") {
				cluster, service := parseECSServiceResource(arn.Resource)
				desc.Cluster = cluster
				desc.Identifier = service
				desc.ResourceType = "service"
			}
		} else if bucket, ok := parseS3URI(resource); ok {
			desc.Provider = "aws"
			desc.Service = "s3"
			desc.ResourceType = "bucket"
			desc.Identifier = bucket
		} else if bucket, ok := parseGCSURI(resource); ok {
			desc.Provider = "gcp"
			desc.Service = "storage"
			desc.ResourceType = "bucket"
			desc.Identifier = bucket
		} else if bucket, ok := parseGCSURL(resource); ok {
			desc.Provider = "gcp"
			desc.Service = "storage"
			desc.ResourceType = "bucket"
			desc.Identifier = bucket
		} else if project, ok := parseGCPProjectPath(resource); ok {
			desc.Provider = "gcp"
			desc.Service = "resourcemanager"
			desc.ResourceType = "project"
			desc.Identifier = project
		}
	}

	if desc.Account == "" && params.Account != "" {
		desc.Account = params.Account
	}

	if desc.Provider == "" {
		return resourceDescriptor{}, fmt.Errorf("unable to determine provider for resource")
	}
	if desc.Identifier == "" {
		return resourceDescriptor{}, fmt.Errorf("unable to determine resource identifier")
	}
	return desc, nil
}

func (st *SecurityTools) inspectAWSResource(ctx context.Context, desc resourceDescriptor) (string, error) {
	opts := []func(*config.LoadOptions) error{}
	if desc.Region != "" {
		opts = append(opts, config.WithRegion(desc.Region))
	}
	if !containsString(awsSupportedServices, desc.Service) {
		return "", UnsupportedServiceError("aws", desc.Service, awsSupportedServices)
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	if desc.Account != "" {
		cfg, err = assumeRoleForAccount(ctx, cfg, desc.Account)
		if err != nil {
			return "", fmt.Errorf("cross-account assume role for %s: %w", desc.Account, err)
		}
	}

	result := map[string]interface{}{
		"provider":      "aws",
		"service":       desc.Service,
		"resource_type": desc.ResourceType,
		"identifier":    desc.Identifier,
		"region":        desc.Region,
	}
	checks := map[string]interface{}{}
	errorDetails := map[string]interface{}{}

	runAWS := func(action string, params map[string]interface{}) {
		if params == nil {
			params = map[string]interface{}{}
		}
		value, err := st.awsAction(ctx, cfg, desc.Service, action, params)
		if err != nil {
			errorDetails[action] = toolErrorValue(err)
			return
		}
		checks[action] = value
	}

	switch desc.Service {
	case "s3":
		bucket := desc.Identifier
		runAWS("get-public-access-block", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-policy-status", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-policy", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-acl", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-encryption", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-versioning", map[string]interface{}{"Bucket": bucket})
		runAWS("get-bucket-logging", map[string]interface{}{"Bucket": bucket})
	case "lambda":
		name := desc.Identifier
		runAWS("get-function-configuration", map[string]interface{}{"FunctionName": name})
		runAWS("get-policy", map[string]interface{}{"FunctionName": name})
	case "ecs":
		switch desc.ResourceType {
		case "service":
			if desc.Cluster == "" {
				errorDetails["describe-services"] = "cluster name required for ECS service inspection"
				break
			}
			runAWS("describe-services", map[string]interface{}{
				"Cluster":  desc.Cluster,
				"Services": []string{desc.Identifier},
			})
		case "cluster", "":
			runAWS("describe-clusters", map[string]interface{}{"Clusters": []string{desc.Identifier}})
		default:
			errorDetails["inspect"] = UnsupportedResourceTypeError("ecs", desc.ResourceType, []string{"service", "cluster"}).AsMap()
		}
	case "iam":
		switch desc.ResourceType {
		case "role", "":
			role := desc.Identifier
			runAWS("get-role", map[string]interface{}{"RoleName": role})
			runAWS("list-attached-role-policies", map[string]interface{}{"RoleName": role})
			runAWS("list-role-policies", map[string]interface{}{"RoleName": role})
		case "policy":
			runAWS("get-policy", map[string]interface{}{"PolicyArn": desc.Identifier})
		default:
			errorDetails["inspect"] = UnsupportedResourceTypeError("iam", desc.ResourceType, []string{"role", "policy"}).AsMap()
		}
	default:
		return "", UnsupportedServiceError("aws", desc.Service, awsSupportedServices)
	}

	result["checks"] = checks
	if len(errorDetails) > 0 {
		result["errors"] = errorDetails
	}

	return toJSON(result)
}

func (st *SecurityTools) inspectGCPResource(ctx context.Context, desc resourceDescriptor) (string, error) {
	if !containsString(inspectGCPSupportedServices, desc.Service) {
		return "", UnsupportedServiceError("gcp", desc.Service, inspectGCPSupportedServices)
	}

	result := map[string]interface{}{
		"provider":      "gcp",
		"service":       desc.Service,
		"resource_type": desc.ResourceType,
		"identifier":    desc.Identifier,
		"project":       desc.Project,
	}
	checks := map[string]interface{}{}
	errorDetails := map[string]interface{}{}

	runGCP := func(action string, params map[string]interface{}) {
		if params == nil {
			params = map[string]interface{}{}
		}
		payload := map[string]interface{}{
			"service": desc.Service,
			"action":  action,
			"project": desc.Project,
			"params":  params,
		}
		raw, _ := json.Marshal(payload)
		value, err := st.gcpInspect(ctx, raw)
		if err != nil {
			errorDetails[action] = toolErrorValue(err)
			return
		}
		checks[action] = decodeJSON(value)
	}

	switch desc.Service {
	case "storage":
		if desc.Project == "" {
			return "", fmt.Errorf("project is required for GCP storage inspection")
		}
		bucket := desc.Identifier
		runGCP("get-bucket-attrs", map[string]interface{}{"bucket": bucket})
		runGCP("get-bucket-iam", map[string]interface{}{"bucket": bucket})
	case "compute":
		if desc.Project == "" {
			return "", fmt.Errorf("project is required for compute inspection")
		}
		if desc.Zone == "" {
			return "", fmt.Errorf("zone is required for compute instance inspection")
		}
		runGCP("get-instance", map[string]interface{}{"instance": desc.Identifier, "zone": desc.Zone})
	case "resourcemanager":
		if desc.Project == "" {
			desc.Project = desc.Identifier
		}
		runGCP("get-project", map[string]interface{}{"project": desc.Project})
		runGCP("get-project-iam", map[string]interface{}{"project": desc.Project})
	default:
		return "", UnsupportedServiceError("gcp", desc.Service, inspectGCPSupportedServices)
	}

	result["checks"] = checks
	if len(errorDetails) > 0 {
		result["errors"] = errorDetails
	}
	return toJSON(result)
}

func (st *SecurityTools) awsAction(ctx context.Context, cfg aws.Config, service, action string, params map[string]interface{}) (interface{}, error) {
	raw, _ := json.Marshal(params)
	var out string
	var err error

	switch service {
	case "s3":
		out, err = st.handleS3(ctx, cfg, action, raw)
	case "lambda":
		out, err = st.handleLambda(ctx, cfg, action, raw)
	case "ecs":
		out, err = st.handleECS(ctx, cfg, action, raw)
	case "iam":
		out, err = st.handleIAM(ctx, cfg, action, raw)
	default:
		return nil, UnsupportedServiceError("aws", service, awsSupportedServices)
	}
	if err != nil {
		return nil, err
	}
	return decodeJSON(out), nil
}

func decodeJSON(value string) interface{} {
	var out interface{}
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return value
	}
	return out
}

func assumeRoleForAccount(ctx context.Context, cfg aws.Config, targetAccount string) (aws.Config, error) {
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return cfg, fmt.Errorf("get caller identity: %w", err)
	}

	if aws.ToString(identity.Account) == targetAccount {
		return cfg, nil
	}

	partition := "aws"
	if callerARN := aws.ToString(identity.Arn); callerARN != "" {
		if parsed, parseErr := parseAWSArn(callerARN); parseErr == nil {
			partition = parsed.Partition
		}
	}

	scanRoleName := os.Getenv("CEREBRO_AWS_SCAN_ROLE_NAME")
	if scanRoleName == "" {
		scanRoleName = "cerebro-org-scan-role"
	}

	roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, targetAccount, scanRoleName)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "cerebro-inspect"
	})
	assumed := cfg.Copy()
	assumed.Credentials = aws.NewCredentialsCache(provider)
	return assumed, nil
}
