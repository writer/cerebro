package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsCodeBuildProject struct {
	Project codebuildtypes.Project
	Tags    map[string]string
}

type awsCodeBuildSourceCredential struct {
	Credential codebuildtypes.SourceCredentialsInfo
}

func listCodeBuildSourceCredentials(ctx context.Context, clients awsClients, _ settings, _ string, _ int) ([]awsCodeBuildSourceCredential, string, error) {
	out, err := clients.codeBuild.ListSourceCredentials(ctx, &codebuild.ListSourceCredentialsInput{})
	if err != nil {
		return nil, "", err
	}
	credentials := append([]codebuildtypes.SourceCredentialsInfo(nil), out.SourceCredentialsInfos...)
	sort.Slice(credentials, func(i, j int) bool {
		return codeBuildSourceCredentialIdentity(credentials[i]) < codeBuildSourceCredentialIdentity(credentials[j])
	})
	records := make([]awsCodeBuildSourceCredential, 0, len(credentials))
	for _, credential := range credentials {
		records = append(records, awsCodeBuildSourceCredential{Credential: credential})
	}
	return records, "", nil
}

func listCodeBuildProjects(ctx context.Context, clients awsClients, _ settings, cursor string, _ int) ([]awsCodeBuildProject, string, error) {
	out, err := clients.codeBuild.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: stringPtr(cursor)})
	if err != nil {
		return nil, "", err
	}
	names := cleanStrings(out.Projects)
	records := make([]awsCodeBuildProject, 0, len(names))
	for _, batch := range stringBatches(names, 100) {
		details, err := clients.codeBuild.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: batch})
		if err != nil {
			return nil, "", err
		}
		for _, project := range details.Projects {
			records = append(records, awsCodeBuildProject{Project: project, Tags: codeBuildTagMap(project.Tags)})
		}
	}
	return records, awssdk.ToString(out.NextToken), nil
}

func codeBuildSourceCredentialEvent(settings settings, record awsCodeBuildSourceCredential) (*primitives.Event, error) {
	credential := record.Credential
	arn := awssdk.ToString(credential.Arn)
	resource := awssdk.ToString(credential.Resource)
	authType := string(credential.AuthType)
	serverType := string(credential.ServerType)
	identity := codeBuildSourceCredentialIdentity(credential)
	name := firstNonEmpty(awsResourceName(arn), strings.ToLower(strings.Join(cleanStrings([]string{serverType, authType}), "-")), awsResourceName(resource), identity)
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCodeBuildSourceCredential, identity, name, "codebuild_source_credential", nil)
	attributes["arn"] = arn
	attributes["auth_type"] = authType
	attributes["resource"] = resource
	attributes["server_type"] = serverType
	payload, err := json.Marshal(map[string]any{
		"account_id":  settings.accountID,
		"arn":         arn,
		"auth_type":   authType,
		"region":      settings.region,
		"resource":    resource,
		"server_type": serverType,
	})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-codebuild-source-credential-"+identity, "aws.codebuild_source_credential", "aws/codebuild_source_credential/v1", payload, attributes, firstTime())
}

func codeBuildProjectEvent(settings settings, record awsCodeBuildProject) (*primitives.Event, error) {
	project := record.Project
	arn := awssdk.ToString(project.Arn)
	name := awssdk.ToString(project.Name)
	publicTrigger := codeBuildPublicWebhook(project.Source, project.Webhook)
	public := project.ProjectVisibility == codebuildtypes.ProjectVisibilityTypePublicRead || awssdk.ToString(project.PublicProjectAlias) != ""
	attributes := commonCloudAssetAttributes(settings, settings.region, familyCodeBuildProject, firstNonEmpty(arn, codeBuildProjectARN(settings, name), name), name, "codebuild_project", record.Tags)
	attributes["arn"] = arn
	attributes["build_timeout_minutes"] = int32AttrString(project.TimeoutInMinutes)
	attributes["cloudwatch_logs_status"] = codeBuildCloudWatchLogsStatus(project.LogsConfig)
	attributes["compute_type"] = codeBuildEnvironmentComputeType(project.Environment)
	attributes["encryption_key"] = awssdk.ToString(project.EncryptionKey)
	attributes["environment_type"] = codeBuildEnvironmentType(project.Environment)
	attributes["environment_variable_names"] = strings.Join(codeBuildEnvironmentVariableNames(project.Environment, ""), ",")
	attributes["image_pull_credentials_type"] = codeBuildImagePullCredentialsType(project.Environment)
	attributes["internet_exposed"] = boolString(public || publicTrigger)
	attributes["plaintext_environment_variable_names"] = strings.Join(codeBuildEnvironmentVariableNames(project.Environment, string(codebuildtypes.EnvironmentVariableTypePlaintext)), ",")
	attributes["project_name"] = name
	attributes["project_visibility"] = string(project.ProjectVisibility)
	attributes["public"] = boolString(public)
	attributes["public_project_alias"] = awssdk.ToString(project.PublicProjectAlias)
	attributes["privileged_mode"] = boolString(codeBuildPrivilegedMode(project.Environment))
	attributes["queued_timeout_minutes"] = int32AttrString(project.QueuedTimeoutInMinutes)
	attributes["service_role"] = awssdk.ToString(project.ServiceRole)
	attributes["s3_logs_encryption_disabled"] = boolString(codeBuildS3LogsEncryptionDisabled(project.LogsConfig))
	attributes["s3_logs_status"] = codeBuildS3LogsStatus(project.LogsConfig)
	attributes["source_type"] = codeBuildSourceType(project.Source)
	attributes["webhook"] = boolString(project.Webhook != nil)
	attributes["webhook_public_trigger"] = boolString(publicTrigger)
	attributes["webhook_status"] = codeBuildWebhookStatus(project.Webhook)
	payload, err := json.Marshal(codeBuildProjectPayload(settings, project, record.Tags))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-codebuild-project-"+firstNonEmpty(arn, name), "aws.codebuild_project", "aws/codebuild_project/v1", payload, attributes, firstTime(project.Created, project.LastModified))
}

func codeBuildProjectPayload(settings settings, project codebuildtypes.Project, tags map[string]string) map[string]any {
	return map[string]any{
		"account_id":           settings.accountID,
		"arn":                  awssdk.ToString(project.Arn),
		"environment":          codeBuildEnvironmentPayload(project.Environment),
		"logs_config":          codeBuildLogsPayload(project.LogsConfig),
		"name":                 awssdk.ToString(project.Name),
		"project_visibility":   string(project.ProjectVisibility),
		"public_project_alias": awssdk.ToString(project.PublicProjectAlias),
		"region":               settings.region,
		"service_role":         awssdk.ToString(project.ServiceRole),
		"source":               codeBuildSourcePayload(project.Source),
		"tags":                 tags,
		"webhook":              codeBuildWebhookPayload(project.Webhook),
	}
}

func codeBuildEnvironmentPayload(environment *codebuildtypes.ProjectEnvironment) map[string]any {
	if environment == nil {
		return nil
	}
	return map[string]any{
		"compute_type":                string(environment.ComputeType),
		"environment_variables":       codeBuildEnvironmentVariablesPayload(environment.EnvironmentVariables),
		"image":                       awssdk.ToString(environment.Image),
		"image_pull_credentials_type": string(environment.ImagePullCredentialsType),
		"privileged_mode":             awssdk.ToBool(environment.PrivilegedMode),
		"type":                        string(environment.Type),
	}
}

func codeBuildEnvironmentVariablesPayload(values []codebuildtypes.EnvironmentVariable) []map[string]string {
	out := make([]map[string]string, 0, len(values))
	for _, value := range values {
		if name := strings.TrimSpace(awssdk.ToString(value.Name)); name != "" {
			out = append(out, map[string]string{"name": name, "type": string(value.Type)})
		}
	}
	return out
}

func codeBuildSourcePayload(source *codebuildtypes.ProjectSource) map[string]any {
	if source == nil {
		return nil
	}
	return map[string]any{
		"insecure_ssl": awssdk.ToBool(source.InsecureSsl),
		"type":         string(source.Type),
	}
}

func codeBuildWebhookPayload(webhook *codebuildtypes.Webhook) map[string]any {
	if webhook == nil {
		return nil
	}
	return map[string]any{
		"filter_groups":   codeBuildWebhookFilterGroupsPayload(webhook.FilterGroups),
		"manual_creation": awssdk.ToBool(webhook.ManualCreation),
		"status":          string(webhook.Status),
	}
}

func codeBuildWebhookFilterGroupsPayload(groups [][]codebuildtypes.WebhookFilter) [][]map[string]string {
	out := make([][]map[string]string, 0, len(groups))
	for _, group := range groups {
		filters := make([]map[string]string, 0, len(group))
		for _, filter := range group {
			filters = append(filters, map[string]string{"type": string(filter.Type), "pattern": awssdk.ToString(filter.Pattern)})
		}
		out = append(out, filters)
	}
	return out
}

func codeBuildLogsPayload(logs *codebuildtypes.LogsConfig) map[string]any {
	if logs == nil {
		return nil
	}
	return map[string]any{
		"cloud_watch_logs": map[string]any{
			"group_name":  codeBuildCloudWatchLogsGroup(logs),
			"status":      codeBuildCloudWatchLogsStatus(logs),
			"stream_name": codeBuildCloudWatchLogsStream(logs),
		},
		"s3_logs": map[string]any{
			"encryption_disabled": codeBuildS3LogsEncryptionDisabled(logs),
			"location":            codeBuildS3LogsLocation(logs),
			"status":              codeBuildS3LogsStatus(logs),
		},
	}
}

func codeBuildTagMap(tags []codebuildtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		if key := strings.TrimSpace(awssdk.ToString(tag.Key)); key != "" {
			out[key] = strings.TrimSpace(awssdk.ToString(tag.Value))
		}
	}
	return out
}

func codeBuildProjectARN(settings settings, name string) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:codebuild:%s:%s:project/%s", settings.region, settings.accountID, name)
}

func codeBuildSourceCredentialIdentity(credential codebuildtypes.SourceCredentialsInfo) string {
	return firstNonEmpty(awssdk.ToString(credential.Arn), strings.Join(cleanStrings([]string{string(credential.ServerType), string(credential.AuthType), awssdk.ToString(credential.Resource)}), ":"), "unknown")
}

func codeBuildEnvironmentType(environment *codebuildtypes.ProjectEnvironment) string {
	if environment == nil {
		return ""
	}
	return string(environment.Type)
}

func codeBuildEnvironmentComputeType(environment *codebuildtypes.ProjectEnvironment) string {
	if environment == nil {
		return ""
	}
	return string(environment.ComputeType)
}

func codeBuildImagePullCredentialsType(environment *codebuildtypes.ProjectEnvironment) string {
	if environment == nil {
		return ""
	}
	return string(environment.ImagePullCredentialsType)
}

func codeBuildPrivilegedMode(environment *codebuildtypes.ProjectEnvironment) bool {
	return environment != nil && awssdk.ToBool(environment.PrivilegedMode)
}

func codeBuildEnvironmentVariableNames(environment *codebuildtypes.ProjectEnvironment, varType string) []string {
	if environment == nil {
		return nil
	}
	names := make([]string, 0, len(environment.EnvironmentVariables))
	for _, value := range environment.EnvironmentVariables {
		if varType == "" || string(value.Type) == varType {
			names = append(names, awssdk.ToString(value.Name))
		}
	}
	return cleanStrings(names)
}

func codeBuildSourceType(source *codebuildtypes.ProjectSource) string {
	if source == nil {
		return ""
	}
	return string(source.Type)
}

func codeBuildWebhookStatus(webhook *codebuildtypes.Webhook) string {
	if webhook == nil {
		return ""
	}
	return string(webhook.Status)
}

func codeBuildPublicWebhook(source *codebuildtypes.ProjectSource, webhook *codebuildtypes.Webhook) bool {
	if webhook == nil || !codeBuildExternalSource(source) {
		return false
	}
	for _, group := range webhook.FilterGroups {
		for _, filter := range group {
			if filter.Type == codebuildtypes.WebhookFilterTypeEvent && strings.Contains(awssdk.ToString(filter.Pattern), "PULL_REQUEST") {
				return true
			}
		}
	}
	return false
}

func codeBuildExternalSource(source *codebuildtypes.ProjectSource) bool {
	switch codeBuildSourceType(source) {
	case string(codebuildtypes.SourceTypeGithub), string(codebuildtypes.SourceTypeBitbucket), string(codebuildtypes.SourceTypeGitlab), string(codebuildtypes.SourceTypeGithubEnterprise), string(codebuildtypes.SourceTypeGitlabSelfManaged):
		return true
	default:
		return false
	}
}

func codeBuildCloudWatchLogsStatus(logs *codebuildtypes.LogsConfig) string {
	if logs == nil || logs.CloudWatchLogs == nil {
		return ""
	}
	return string(logs.CloudWatchLogs.Status)
}

func codeBuildCloudWatchLogsGroup(logs *codebuildtypes.LogsConfig) string {
	if logs == nil || logs.CloudWatchLogs == nil {
		return ""
	}
	return awssdk.ToString(logs.CloudWatchLogs.GroupName)
}

func codeBuildCloudWatchLogsStream(logs *codebuildtypes.LogsConfig) string {
	if logs == nil || logs.CloudWatchLogs == nil {
		return ""
	}
	return awssdk.ToString(logs.CloudWatchLogs.StreamName)
}

func codeBuildS3LogsStatus(logs *codebuildtypes.LogsConfig) string {
	if logs == nil || logs.S3Logs == nil {
		return ""
	}
	return string(logs.S3Logs.Status)
}

func codeBuildS3LogsEncryptionDisabled(logs *codebuildtypes.LogsConfig) bool {
	return logs != nil && logs.S3Logs != nil && awssdk.ToBool(logs.S3Logs.EncryptionDisabled)
}

func codeBuildS3LogsLocation(logs *codebuildtypes.LogsConfig) string {
	if logs == nil || logs.S3Logs == nil {
		return ""
	}
	return awssdk.ToString(logs.S3Logs.Location)
}
