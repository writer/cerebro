package qdrant_cloud

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
	sourceID               = "qdrant_cloud"
	defaultFamily          = familyAccounts
	defaultHealthPath      = "/api/account/v1/accounts"
	defaultBaseURLTemplate = "https://api.cloud.qdrant.io"
	tokenHeader            = "Authorization"
	tokenScheme            = "apikey"
	familyAccounts         = "accounts"
	familyAccountMembers   = "account_members"
	familyClusters         = "clusters"
	familyDatabaseApiKeys  = "database_api_keys"
	familyBackups          = "backups"
	familyBackupRestores   = "backup_restores"
	familyBackupSchedules  = "backup_schedules"
	familyRoles            = "roles"
)

var templateKeys = []string{"account_id", "cluster_id", "api_key"}

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
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyAccounts,
				Path:             "/api/account/v1/accounts",
				URNKind:          "qdrant_cloud_accounts",
				IDKeys:           []string{"id", "name"},
				DisablePageSize:  true,
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"lastModifiedAt", "createdAt", "last_modified_at", "created_at"},
				Attributes:       map[string]string{"account_owner_email": "ownerEmail|owner_email", "company_domain": "company.domain", "company_name": "company.name", "observed_at": "lastModifiedAt|createdAt|last_modified_at|created_at", "resource_id": "id", "resource_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "account", "schema": "accounts", "source_system": "qdrant_cloud"},
				Config:           qdrantFamilyConfig("qdrant_cloud_accounts"),
			},
			{
				Name:             familyAccountMembers,
				Path:             "/api/account/v1/accounts/${config.account_id}/members",
				URNKind:          "qdrant_cloud_account_members",
				IDKeys:           []string{"accountMember.id", "account_member.id", "accountMember.email", "account_member.email"},
				DisablePageSize:  true,
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"accountMember.lastModifiedAt", "accountMember.createdAt", "account_member.last_modified_at", "account_member.created_at"},
				Attributes:       map[string]string{"created_at": "accountMember.createdAt|account_member.created_at", "default_account_id": "accountMember.defaultAccountId|account_member.default_account_id", "display_name": "accountMember.email|account_member.email", "email": "accountMember.email|account_member.email", "is_owner": "isOwner|is_owner", "observed_at": "accountMember.lastModifiedAt|accountMember.createdAt|account_member.last_modified_at|account_member.created_at", "primary_email": "accountMember.email|account_member.email", "resource_id": "accountMember.id|account_member.id", "resource_name": "accountMember.email|account_member.email", "source_event_id": "accountMember.id|account_member.id", "status": "accountMember.status|account_member.status", "user_id": "accountMember.id|account_member.id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "account_member", "schema": "account_members", "source_system": "qdrant_cloud"},
				Config:           qdrantFamilyConfig("qdrant_cloud_account_members"),
			},
			{
				Name:             familyClusters,
				Path:             "/api/cluster/v1/accounts/${config.account_id}/clusters",
				URNKind:          "qdrant_cloud_clusters",
				IDKeys:           []string{"id", "name", "state.endpoint.url"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken", "next_page_token"},
				PageSizeParams:   []string{"pageSize", "page_size"},
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"configuration.lastModifiedAt", "state.restartedAt", "createdAt", "configuration.last_modified_at", "state.restarted_at", "created_at"},
				Attributes:       map[string]string{"cloud_provider_id": "cloudProviderId|cloud_provider_id", "cloud_provider_region_id": "cloudProviderRegionId|cloud_provider_region_id", "deployment_created_at": "createdAt|created_at", "deployment_environment": "cloudProviderRegionId|cloud_provider_region_id|cloudProviderId|cloud_provider_id", "deployment_id": "id", "deployment_name": "name", "deployment_status": "state.phase|phase", "deployment_updated_at": "configuration.lastModifiedAt|state.restartedAt|configuration.last_modified_at|state.restarted_at|createdAt|created_at", "deployment_url": "state.endpoint.url|endpoint.url", "observed_at": "configuration.lastModifiedAt|state.restartedAt|createdAt|configuration.last_modified_at|state.restarted_at|created_at", "qdrant_version": "state.version|configuration.version|version", "resource_id": "id", "resource_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "resource_type": "cluster", "schema": "clusters", "source_system": "qdrant_cloud"},
				Config:           qdrantFamilyConfig("qdrant_cloud_clusters"),
			},
			{
				Name:             familyDatabaseApiKeys,
				Path:             "/api/cluster/auth/v2/accounts/${config.account_id}/database-api-keys",
				URNKind:          "qdrant_cloud_database_api_keys",
				IDKeys:           []string{"id", "name", "postfix"},
				DisablePageSize:  true,
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"createdAt", "created_at", "expiresAt", "expires_at"},
				Attributes:       map[string]string{"cluster_id": "clusterId|cluster_id", "created_by_email": "createdByEmail|created_by_email", "expires_at": "expiresAt|expires_at", "observed_at": "createdAt|created_at", "postfix": "postfix", "resource_id": "id", "resource_name": "name", "secret_created_at": "createdAt|created_at", "secret_id": "id", "secret_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "secret", "resource_type": "database_api_key", "schema": "database_api_keys", "secret_type": "database_api_key", "source_system": "qdrant_cloud"},
				Config:           qdrantClusterQueryConfig("qdrant_cloud_database_api_keys"),
			},
			{
				Name:           familyBackups,
				Path:           "/api/cluster/backup/v1/accounts/${config.account_id}/backups",
				URNKind:        "qdrant_cloud_backups",
				IDKeys:         []string{"id", "name"},
				CursorParam:    "pageToken",
				NextCursorKeys: []string{"nextPageToken", "next_page_token"},
				PageSizeParams: []string{"pageSize", "page_size"},
				ListKeys:       []string{"items"},
				TimestampKeys:  []string{"deletedAt", "createdAt", "deleted_at", "created_at"},
				Attributes: map[string]string{
					"backup_duration":    "backupDuration|backup_duration",
					"backup_schedule_id": "backupScheduleId|backup_schedule_id",
					"backup_status":      "status",
					"cluster_id":         "clusterId|cluster_id",
					"observed_at":        "deletedAt|createdAt|deleted_at|created_at",
					"resource_id":        "id",
					"resource_name":      "name",
					"retention_period":   "retentionPeriod|retention_period",
					"source_event_id":    "id",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "backup", "schema": "backups", "source_system": "qdrant_cloud"},
				Config:           qdrantClusterQueryConfig("qdrant_cloud_backups"),
			},
			{
				Name:           familyBackupRestores,
				Path:           "/api/cluster/backup/v1/accounts/${config.account_id}/backup_restores",
				URNKind:        "qdrant_cloud_backup_restores",
				IDKeys:         []string{"id", "backupId", "backup_id"},
				CursorParam:    "pageToken",
				NextCursorKeys: []string{"nextPageToken", "next_page_token"},
				PageSizeParams: []string{"pageSize", "page_size"},
				ListKeys:       []string{"items"},
				TimestampKeys:  []string{"deletedAt", "createdAt", "deleted_at", "created_at"},
				Attributes: map[string]string{
					"backup_id":             "backupId|backup_id",
					"cluster_id":            "clusterId|cluster_id",
					"deployment_created_at": "createdAt|created_at",
					"deployment_id":         "id",
					"deployment_name":       "backupId|backup_id",
					"deployment_status":     "status",
					"deployment_updated_at": "deletedAt|createdAt|deleted_at|created_at",
					"observed_at":           "deletedAt|createdAt|deleted_at|created_at",
					"resource_id":           "id",
					"source_event_id":       "id",
				},
				StaticAttributes: map[string]string{"record_class": "deployment", "resource_type": "backup_restore", "schema": "backup_restores", "source_system": "qdrant_cloud"},
				Config:           qdrantClusterQueryConfig("qdrant_cloud_backup_restores"),
			},
			{
				Name:           familyBackupSchedules,
				Path:           "/api/cluster/backup/v1/accounts/${config.account_id}/backup_schedules",
				URNKind:        "qdrant_cloud_backup_schedules",
				IDKeys:         []string{"id", "schedule"},
				CursorParam:    "pageToken",
				NextCursorKeys: []string{"nextPageToken", "next_page_token"},
				PageSizeParams: []string{"pageSize", "page_size"},
				ListKeys:       []string{"items"},
				TimestampKeys:  []string{"deletedAt", "createdAt", "deleted_at", "created_at"},
				Attributes: map[string]string{
					"cluster_id":        "clusterId|cluster_id",
					"observed_at":       "deletedAt|createdAt|deleted_at|created_at",
					"policy_created_at": "createdAt|created_at",
					"policy_id":         "id",
					"policy_name":       "schedule",
					"policy_status":     "status",
					"resource_id":       "id",
					"resource_name":     "schedule",
					"retention_period":  "retentionPeriod|retention_period",
					"source_event_id":   "id",
				},
				StaticAttributes: map[string]string{"policy_type": "backup_schedule", "record_class": "policy", "resource_type": "backup_schedule", "schema": "backup_schedules", "source_system": "qdrant_cloud"},
				Config:           qdrantClusterQueryConfig("qdrant_cloud_backup_schedules"),
			},
			{
				Name:            familyRoles,
				Path:            "/api/iam/v1/accounts/${config.account_id}/roles",
				URNKind:         "qdrant_cloud_roles",
				IDKeys:          []string{"id", "name"},
				DisablePageSize: true,
				ListKeys:        []string{"items"},
				TimestampKeys:   []string{"lastModifiedAt", "createdAt", "last_modified_at", "created_at"},
				Attributes: map[string]string{
					"description":     "description",
					"group_id":        "id",
					"group_name":      "name",
					"observed_at":     "lastModifiedAt|createdAt|last_modified_at|created_at",
					"permissions":     "permissions.value",
					"resource_id":     "id",
					"resource_name":   "name",
					"role_type":       "roleType|role_type",
					"source_event_id": "id",
				},
				StaticAttributes: map[string]string{"record_class": "identity_group", "resource_type": "role", "schema": "roles", "source_system": "qdrant_cloud"},
				Config:           qdrantFamilyConfig("qdrant_cloud_roles"),
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

func qdrantFamilyConfig(resourceURNKind string) jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{ConfigAttributes: map[string]string{"tenant_id": "tenant_id"}, ResourceURNKind: resourceURNKind}
}

func qdrantClusterQueryConfig(resourceURNKind string) jsonapi.FamilyConfig {
	config := qdrantFamilyConfig(resourceURNKind)
	config.ConfigQuery = map[string]string{"clusterId": "cluster_id"}
	return config
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
