package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
)

func (e *SyncEngine) codebuildProjectTable() TableSpec {
	return TableSpec{
		Name: "aws_codebuild_projects",
		Columns: []string{
			"arn", "name", "region", "account_id", "description",
			"source", "secondary_sources", "environment", "service_role",
			"timeout_in_minutes", "encryption_key", "artifacts", "cache",
			"logs_config", "badge", "vpc_config", "created", "last_modified",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := codebuild.NewFromConfig(cfg)
			var results []map[string]interface{}

			// List all projects
			listOut, err := client.ListProjects(ctx, &codebuild.ListProjectsInput{})
			if err != nil {
				return nil, fmt.Errorf("list projects: %w", err)
			}

			if len(listOut.Projects) == 0 {
				return results, nil
			}

			// Batch get project details
			batchOut, err := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
				Names: listOut.Projects,
			})
			if err != nil {
				return nil, fmt.Errorf("batch get projects: %w", err)
			}

			for _, project := range batchOut.Projects {
				arn := ptrToStr(project.Arn)
				name := ptrToStr(project.Name)

				row := map[string]interface{}{
					"_cq_id":             arn,
					"arn":                arn,
					"name":               name,
					"region":             region,
					"account_id":         e.accountID,
					"description":        ptrToStr(project.Description),
					"source":             project.Source,
					"secondary_sources":  project.SecondarySources,
					"environment":        project.Environment,
					"service_role":       ptrToStr(project.ServiceRole),
					"timeout_in_minutes": project.TimeoutInMinutes,
					"encryption_key":     ptrToStr(project.EncryptionKey),
					"artifacts":          project.Artifacts,
					"cache":              project.Cache,
					"logs_config":        project.LogsConfig,
					"badge":              project.Badge,
					"vpc_config":         project.VpcConfig,
					"created":            project.Created,
					"last_modified":      project.LastModified,
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *SyncEngine) codebuildSourceCredentialTable() TableSpec {
	return TableSpec{
		Name: "aws_codebuild_source_credentials",
		Columns: []string{
			"arn", "region", "account_id", "server_type", "auth_type",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := codebuild.NewFromConfig(cfg)
			var results []map[string]interface{}

			listOut, err := client.ListSourceCredentials(ctx, &codebuild.ListSourceCredentialsInput{})
			if err != nil {
				return nil, fmt.Errorf("list source credentials: %w", err)
			}

			for _, cred := range listOut.SourceCredentialsInfos {
				arn := ptrToStr(cred.Arn)

				row := map[string]interface{}{
					"_cq_id":      arn,
					"arn":         arn,
					"region":      region,
					"account_id":  e.accountID,
					"server_type": string(cred.ServerType),
					"auth_type":   string(cred.AuthType),
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}
