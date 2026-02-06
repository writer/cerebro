package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type CodeToCloudOptions struct {
	RepoURL      string
	Resource     string
	MaxResources int
	AWSRegion    string
	GCPProject   string
	GCPZone      string
}

type CodeToCloudReport struct {
	RepoURL        string               `json:"repo_url,omitempty"`
	StartedAt      time.Time            `json:"started_at"`
	CompletedAt    time.Time            `json:"completed_at"`
	Duration       time.Duration        `json:"duration"`
	Analysis       *RepoAnalysis        `json:"analysis,omitempty"`
	TotalResources int                  `json:"total_resources"`
	Inspected      int                  `json:"inspected"`
	Successful     int                  `json:"successful"`
	Failed         int                  `json:"failed"`
	Truncated      bool                 `json:"truncated"`
	Inspections    []ResourceInspection `json:"inspections"`
	Errors         []string             `json:"errors,omitempty"`
}

type ResourceInspection struct {
	Resource     RepoResource `json:"resource"`
	Provider     string       `json:"provider,omitempty"`
	Service      string       `json:"service,omitempty"`
	ResourceType string       `json:"resource_type,omitempty"`
	Identifier   string       `json:"identifier,omitempty"`
	Region       string       `json:"region,omitempty"`
	Project      string       `json:"project,omitempty"`
	Cluster      string       `json:"cluster,omitempty"`
	Zone         string       `json:"zone,omitempty"`
	Result       interface{}  `json:"result,omitempty"`
	Error        string       `json:"error,omitempty"`
}

func RunCodeToCloudFlow(ctx context.Context, tools *SecurityTools, opts CodeToCloudOptions) (*CodeToCloudReport, error) {
	if tools == nil {
		return nil, fmt.Errorf("tools not configured")
	}
	if opts.RepoURL == "" && opts.Resource == "" {
		return nil, fmt.Errorf("repo_url or resource is required")
	}

	report := &CodeToCloudReport{
		RepoURL:   opts.RepoURL,
		StartedAt: time.Now().UTC(),
	}

	resources := make([]RepoResource, 0)
	if opts.RepoURL != "" {
		analysis, err := tools.analyzeRepository(ctx, opts.RepoURL)
		if err != nil {
			return nil, err
		}
		report.Analysis = analysis
		report.TotalResources = analysis.TotalResources
		report.Truncated = analysis.Truncated
		resources = append(resources, analysis.Resources...)
	}

	if opts.Resource != "" {
		resources = []RepoResource{selectResource(resources, opts.Resource)}
		if report.TotalResources == 0 {
			report.TotalResources = len(resources)
		}
	}

	if opts.MaxResources > 0 && len(resources) > opts.MaxResources {
		resources = resources[:opts.MaxResources]
		report.Truncated = true
	}

	if len(resources) == 0 {
		report.Errors = append(report.Errors, "no resources found to inspect")
	}

	report.Inspections = make([]ResourceInspection, 0, len(resources))
	for _, res := range resources {
		inspection := ResourceInspection{Resource: res}
		params := inspectParams{
			Resource:   res.Resource,
			Provider:   res.Provider,
			Service:    res.Service,
			Identifier: res.Identifier,
			Project:    opts.GCPProject,
			Region:     opts.AWSRegion,
			Zone:       opts.GCPZone,
		}
		if params.Resource == "" {
			params.Resource = res.Identifier
		}

		desc, err := resolveResourceDescriptor(params)
		if err != nil {
			inspection.Error = err.Error()
			report.Errors = append(report.Errors, err.Error())
			report.Failed++
			report.Inspections = append(report.Inspections, inspection)
			continue
		}

		if desc.Provider == "aws" && desc.Region == "" && opts.AWSRegion != "" {
			desc.Region = opts.AWSRegion
		}
		if desc.Provider == "gcp" && desc.Project == "" {
			desc.Project = opts.GCPProject
		}
		if desc.Provider == "gcp" && desc.Service == "compute" && desc.Zone == "" {
			desc.Zone = opts.GCPZone
		}

		if desc.Provider == "gcp" && desc.Project == "" {
			gcpErr := fmt.Errorf("gcp project is required for %s", desc.Identifier)
			inspection.Error = gcpErr.Error()
			report.Errors = append(report.Errors, gcpErr.Error())
			report.Failed++
			report.Inspections = append(report.Inspections, inspection)
			continue
		}
		if desc.Provider == "gcp" && desc.Service == "compute" && desc.Zone == "" {
			zoneErr := fmt.Errorf("gcp zone is required for compute instance %s", desc.Identifier)
			inspection.Error = zoneErr.Error()
			report.Errors = append(report.Errors, zoneErr.Error())
			report.Failed++
			report.Inspections = append(report.Inspections, inspection)
			continue
		}

		inspection.Provider = desc.Provider
		inspection.Service = desc.Service
		inspection.ResourceType = desc.ResourceType
		inspection.Identifier = desc.Identifier
		inspection.Region = desc.Region
		inspection.Project = desc.Project
		inspection.Cluster = desc.Cluster
		inspection.Zone = desc.Zone

		var raw string
		switch desc.Provider {
		case "aws":
			raw, err = tools.inspectAWSResource(ctx, desc)
		case "gcp":
			raw, err = tools.inspectGCPResource(ctx, desc)
		default:
			err = UnsupportedProviderError(desc.Provider, inspectSupportedProviders)
		}
		if err != nil {
			toolErr := toolErrorOutput(err)
			inspection.Error = toolErr
			report.Errors = append(report.Errors, toolErr)
			report.Failed++
			report.Inspections = append(report.Inspections, inspection)
			continue
		}

		var result interface{}
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			result = raw
		}
		inspection.Result = result
		report.Successful++
		report.Inspections = append(report.Inspections, inspection)
	}

	report.Inspected = len(report.Inspections)
	report.CompletedAt = time.Now().UTC()
	report.Duration = report.CompletedAt.Sub(report.StartedAt)

	return report, nil
}

func selectResource(resources []RepoResource, resource string) RepoResource {
	for _, res := range resources {
		if res.Resource == resource || res.Identifier == resource {
			return res
		}
	}

	return RepoResource{
		Resource:   resource,
		Identifier: resource,
		Confidence: "manual",
	}
}
