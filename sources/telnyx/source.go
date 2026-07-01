package telnyx

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
	sourceID                         = "telnyx"
	defaultFamily                    = familyCallEvent
	defaultHealthPath                = "/call_events"
	defaultBaseURLTemplate           = "https://api.telnyx.com/v2"
	tokenHeader                      = ""
	tokenScheme                      = "Bearer"
	familyCallEvent                  = "call_event"
	familyBillingGroup               = "billing_group"
	familyCredentialConnection       = "credential_connection"
	familyManagedAccount             = "managed_account"
	familyCallControlApplication     = "call_control_application"
	familyNotificationChannel        = "notification_channel"
	familyDetailRecordsReport        = "detail_records_report"
	familyNotificationEvent          = "notification_event"
	familyNotificationEventCondition = "notification_event_condition"
	familyWirelessConnectivityLog    = "wireless_connectivity_log"
	familySimCardGroup               = "sim_card_group"
	familySimCardGroupAction         = "sim_card_group_action"
)

var templateKeys = []string{"sim_card_id", "token"}

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
		AuthModel:       "bearer_token",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: applyTelnyxDefaults([]jsonapi.Family{
			{
				Name:             familyCallEvent,
				Path:             "/call_events",
				URNKind:          "telnyx_call_event",
				IDKeys:           []string{"event_timestamp", "call_leg_id", "call_session_id", "name"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"event_timestamp", "updated_at", "created_at"},
				Attributes:       map[string]string{"actor_id": "call_session_id|call_leg_id", "event_type": "name|type", "id": "call_leg_id", "name": "name", "observed_at": "event_timestamp|updated_at|created_at", "provider_id": "call_leg_id", "resource_id": "call_leg_id", "resource_name": "name", "resource_type": "record_type|type", "source_event_id": "call_leg_id|call_session_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "call_event", "source_system": "telnyx"},
			},
			{
				Name:             familyBillingGroup,
				Path:             "/billing_groups",
				URNKind:          "telnyx_billing_group",
				IDKeys:           []string{"id", "name", "group_id", "group_email", "email"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"group_id": "id", "group_name": "name", "id": "id", "name": "name", "observed_at": "updated_at|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "name", "resource_type": "record_type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "billing_group", "source_system": "telnyx"},
			},
			{
				Name:             familyCredentialConnection,
				Path:             "/credential_connections",
				URNKind:          "telnyx_credential_connection",
				IDKeys:           []string{"id", "connection_name", "user_name"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"id": "id", "name": "connection_name|user_name|id", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "connection_name|user_name|id", "resource_type": "record_type", "secret_created_at": "created_at", "secret_id": "id", "secret_name": "connection_name|user_name|id", "secret_type": "record_type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "credential_connection", "secret_status": "active", "source_system": "telnyx"},
			},
			{
				Name:             familyManagedAccount,
				Path:             "/managed_accounts",
				URNKind:          "telnyx_managed_account",
				IDKeys:           []string{"id", "email", "user_id", "primary_email", "login"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at", "display_name": "organization_name|email", "email": "email", "id": "id", "login": "api_user|email", "name": "organization_name|email", "observed_at": "updated_at|created_at", "primary_email": "email", "provider_id": "id", "resource_id": "id", "resource_name": "organization_name|email", "resource_type": "record_type", "source_event_id": "id", "status": "status", "user_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "managed_account", "source_system": "telnyx"},
			},
			{
				Name:             familyCallControlApplication,
				Path:             "/call_control_applications",
				URNKind:          "telnyx_call_control_application",
				IDKeys:           []string{"id", "application_name"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"id": "id", "name": "application_name|id", "observed_at": "updated_at|created_at", "policy_created_at": "created_at", "policy_description": "webhook_event_url", "policy_id": "id", "policy_name": "application_name|id", "policy_type": "record_type", "resource_id": "id", "resource_name": "application_name|id", "resource_type": "record_type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"policy_status": "active", "record_class": "policy", "schema": "call_control_application", "source_system": "telnyx"},
			},
			{
				Name:             familyNotificationChannel,
				Path:             "/notification_channels",
				URNKind:          "telnyx_notification_channel",
				IDKeys:           []string{"id", "channel_destination", "alert_id", "sid", "incident_id", "uuid"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"alert_fired_at": "created_at", "alert_id": "id", "alert_name": "channel_destination|id", "alert_source": "notification_profile_id", "alert_type": "channel_type_id", "id": "id", "name": "channel_destination|id", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "channel_destination|id", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "alert", "resource_type": "notification_channel", "schema": "notification_channel", "source_system": "telnyx"},
			},
			{
				Name:             familyDetailRecordsReport,
				Path:             "/wireless/detail_records_reports",
				URNKind:          "telnyx_detail_records_report",
				IDKeys:           []string{"id", "created_at", "urn", "resource_urn", "name"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"id": "id", "name": "id", "observed_at": "updated_at|created_at", "resource_id": "id", "resource_name": "id", "resource_type": "record_type|status", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "detail_records_report", "source_system": "telnyx"},
			},
			{
				Name:             familyNotificationEvent,
				Path:             "/notification_events",
				URNKind:          "telnyx_notification_event",
				IDKeys:           []string{"id", "name", "event_id", "uuid", "request_id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_id": "id", "event_type": "name|notification_category", "id": "id", "name": "name", "observed_at": "updated_at|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "notification_event", "schema": "notification_event", "source_system": "telnyx"},
			},
			{
				Name:             familyNotificationEventCondition,
				Path:             "/notification_event_conditions",
				URNKind:          "telnyx_notification_event_condition",
				IDKeys:           []string{"id", "name", "event_id", "uuid", "request_id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_id": "notification_event_id|id", "event_type": "name|associated_record_type", "id": "id", "name": "name", "observed_at": "updated_at|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "name", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "notification_event_condition", "schema": "notification_event_condition", "source_system": "telnyx"},
			},
			{
				Name:             familyWirelessConnectivityLog,
				Path:             "/sim_cards/${config.sim_card_id}/wireless_connectivity_logs",
				URNKind:          "telnyx_wireless_connectivity_log",
				IDKeys:           []string{"id", "apn", "event_id", "uuid", "request_id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"start_time", "last_seen", "updated_at", "created_at"},
				Attributes:       map[string]string{"actor_id": "sim_card_id", "event_type": "log_type", "id": "id", "name": "apn|log_type", "observed_at": "start_time|last_seen|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "apn|sim_card_id", "resource_type": "record_type|log_type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "wireless_connectivity_log", "source_system": "telnyx"},
			},
			{
				Name:             familySimCardGroup,
				Path:             "/sim_card_groups",
				URNKind:          "telnyx_sim_card_group",
				IDKeys:           []string{"id", "name", "group_id", "group_email", "email"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"group_id": "id", "group_name": "name", "id": "id", "name": "name", "observed_at": "updated_at|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "name", "resource_type": "record_type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "sim_card_group", "source_system": "telnyx"},
			},
			{
				Name:             familySimCardGroupAction,
				Path:             "/sim_card_group_actions",
				URNKind:          "telnyx_sim_card_group_action",
				IDKeys:           []string{"id", "created_at", "group_id", "group_email", "email"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"group_id": "sim_card_group_id", "group_name": "type|sim_card_group_id", "id": "id", "name": "type|created_at", "observed_at": "updated_at|created_at", "provider_id": "id", "resource_id": "id", "resource_name": "type|sim_card_group_id", "resource_type": "record_type|type", "source_event_id": "id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "sim_card_group_action", "source_system": "telnyx"},
			},
		}),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func applyTelnyxDefaults(families []jsonapi.Family) []jsonapi.Family {
	for idx := range families {
		if strings.TrimSpace(families[idx].Config.ResourceURNKind) == "" {
			families[idx].Config.ResourceURNKind = families[idx].URNKind
		}
		if families[idx].Config.ConfigAttributes == nil {
			families[idx].Config.ConfigAttributes = map[string]string{}
		}
		families[idx].Config.ConfigAttributes["tenant_id"] = "tenant_id"
		if len(families[idx].PageSizeParams) == 0 {
			families[idx].PageSizeParams = []string{"page[size]"}
		}
		if strings.TrimSpace(families[idx].CursorParam) == "" {
			families[idx].CursorParam = "page[number]"
		}
		if strings.TrimSpace(families[idx].PageFirstCursor) == "" {
			families[idx].PageFirstCursor = "1"
		}
	}
	return families
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
