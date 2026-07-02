package aws_bedrock

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID                          = "aws_bedrock"
	defaultFamily                     = familyFoundationModels
	defaultHealthPath                 = "/foundation-models"
	defaultBaseURLTemplate            = "https://bedrock.${config.region}.amazonaws.com"
	tokenHeader                       = ""
	tokenScheme                       = "AWS4-HMAC-SHA256"
	familyFoundationModels            = "foundation_models"
	familyCustomModels                = "custom_models"
	familyProvisionedModelThroughputs = "provisioned_model_throughputs"
	familyModelCustomizationJobs      = "model_customization_jobs"
	familyGuardrails                  = "guardrails"
)

var templateKeys = []string{"region", "service", "access_key", "secret_key"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "aws_sigv4",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyFoundationModels,
				Path:             "/foundation-models",
				URNKind:          "aws_bedrock_foundation_models",
				IDKeys:           []string{"modelId", "modelArn", "modelName", "id", "urn", "resource_urn", "name"},
				DisablePageSize:  true,
				ListKeys:         []string{"modelSummaries"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "modelId", "resource_name": "modelName", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "modelId|modelArn|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "foundation_model", "schema": "foundation_models", "source_system": "aws_bedrock"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "aws_bedrock_foundation_models"},
			},
			{
				Name:             familyCustomModels,
				Path:             "/custom-models",
				URNKind:          "aws_bedrock_custom_models",
				IDKeys:           []string{"modelArn", "modelName", "id", "urn", "resource_urn", "name"},
				CursorParam:      "nextToken",
				NextCursorKeys:   []string{"nextToken"},
				PageSizeParams:   []string{"maxResults"},
				ListKeys:         []string{"modelSummaries"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "modelArn", "resource_name": "modelName", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "modelArn|modelId|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "custom_model", "schema": "custom_models", "source_system": "aws_bedrock"},
				Config:           jsonapi.FamilyConfig{EncodeURNID: true, ResourceURNKind: "aws_bedrock_custom_models"},
			},
			{
				Name:             familyProvisionedModelThroughputs,
				Path:             "/provisioned-model-throughputs",
				URNKind:          "aws_bedrock_provisioned_model_throughputs",
				IDKeys:           []string{"provisionedModelArn", "provisionedModelName", "deployment_id", "id", "name", "url", "uid"},
				CursorParam:      "nextToken",
				NextCursorKeys:   []string{"nextToken"},
				PageSizeParams:   []string{"maxResults"},
				ListKeys:         []string{"provisionedModelSummaries"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "creationTime|created_at|created|date_created", "deployment_environment": "environment|env|stage|target", "deployment_id": "provisionedModelArn", "deployment_name": "provisionedModelName", "deployment_status": "status|state|ready", "deployment_updated_at": "lastModifiedTime|updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "provisionedModelArn|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "schema": "provisioned_model_throughputs", "source_system": "aws_bedrock"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"deployment_environment": "region"}},
			},
			{
				Name:             familyModelCustomizationJobs,
				Path:             "/model-customization-jobs",
				URNKind:          "aws_bedrock_model_customization_jobs",
				IDKeys:           []string{"jobArn", "jobName", "deployment_id", "id", "name", "url", "uid"},
				CursorParam:      "nextToken",
				NextCursorKeys:   []string{"nextToken"},
				PageSizeParams:   []string{"maxResults"},
				ListKeys:         []string{"modelCustomizationJobSummaries"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "creationTime|created_at|created|date_created", "deployment_environment": "environment|env|stage|target", "deployment_id": "jobArn", "deployment_name": "jobName", "deployment_status": "status|state|ready", "deployment_updated_at": "endTime|lastModifiedTime|updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "jobArn|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "schema": "model_customization_jobs", "source_system": "aws_bedrock"},
				Config:           jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"deployment_environment": "region"}},
			},
			{
				Name:             familyGuardrails,
				Path:             "/guardrails",
				URNKind:          "aws_bedrock_guardrails",
				IDKeys:           []string{"id", "name", "policy_id", "key", "control_id"},
				CursorParam:      "nextToken",
				NextCursorKeys:   []string{"nextToken"},
				PageSizeParams:   []string{"maxResults"},
				ListKeys:         []string{"guardrails"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "policy_created_at": "createdAt|created_at|created|date_created", "policy_description": "description|summary|body", "policy_id": "id", "policy_name": "name", "policy_severity": "severity|risk|priority", "policy_status": "policy_status|status|state|enabled", "policy_type": "policy_type|type|kind|category", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"policy_type": "bedrock_guardrail", "record_class": "policy", "schema": "guardrails", "source_system": "aws_bedrock"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
