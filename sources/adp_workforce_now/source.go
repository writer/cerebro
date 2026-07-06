package adp_workforce_now

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
	sourceID                 = "adp_workforce_now"
	defaultFamily            = familyUsers
	defaultHealthPath        = "/hr/v2/workers/meta"
	defaultBaseURLTemplate   = "https://api.adp.com"
	tokenHeader              = ""
	tokenScheme              = "Bearer"
	familyUsers              = "users"
	familyEventNotifications = "event_notifications"
)

var templateKeys = []string{"base_url", "token"}

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
		Families: []jsonapi.Family{
			{
				Name:             familyUsers,
				Path:             "/hr/v2/workers",
				URNKind:          "adp_workforce_now_users",
				IDKeys:           []string{"associateOID", "workerID.idValue", "person.legalName.formattedName", "person.communication.emails.0.emailUri"},
				CursorParam:      "$skip",
				PageFirstCursor:  "0",
				PageSizeParams:   []string{"$top"},
				ListKeys:         []string{"workers"},
				Config:           jsonapi.FamilyConfig{OffsetCursor: true},
				TimestampKeys:    []string{"workerDates.originalHireDate", "workerDates.terminationDate", "observed_at"},
				Attributes:       map[string]string{"created_at": "workerDates.originalHireDate", "department": "workAssignments.0.homeOrganizationalUnits.0.nameCode.shortName|workAssignments.0.assignedOrganizationalUnits.0.nameCode.shortName", "display_name": "person.legalName.formattedName", "domain": "businessCommunication.emails.0.emailUri|person.communication.emails.0.emailUri", "email": "businessCommunication.emails.0.emailUri|person.communication.emails.0.emailUri", "job_title": "workAssignments.0.jobTitle", "last_login_at": "", "login": "businessCommunication.emails.0.emailUri|person.communication.emails.0.emailUri|associateOID", "manager": "workAssignments.0.reportsTo.0.workerID.idValue|workAssignments.0.reportsTo.0.associateOID", "observed_at": "workerDates.originalHireDate|workerDates.terminationDate", "primary_email": "businessCommunication.emails.0.emailUri|person.communication.emails.0.emailUri", "resource_id": "associateOID", "resource_name": "person.legalName.formattedName", "resource_type": "worker", "source_event_id": "associateOID", "status": "workerStatus.statusCode.codeValue|workerStatus.statusCode.shortName", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "associateOID"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "adp_workforce_now"},
			},
			{
				Name:          familyEventNotifications,
				Path:          "/core/v1/event-notification-messages",
				URNKind:       "adp_workforce_now_event_notifications",
				IDKeys:        []string{"eventID", "eventNameCode.codeValue", "data.eventContext.worker.associateOID"},
				ListKeys:      []string{"events"},
				TimestampKeys: []string{"eventStatusCode.effectiveDateTime", "data.eventContext.effectiveDateTime", "eventDateTime", "observed_at"},
				Attributes:    map[string]string{"actor_id": "originator.associateOID|actor.associateOID", "event_type": "eventNameCode.codeValue", "id": "eventID|eventNameCode.codeValue", "observed_at": "eventStatusCode.effectiveDateTime|eventDateTime", "resource_id": "data.eventContext.worker.associateOID", "resource_type": "worker", "source_event_id": "eventID|eventNameCode.codeValue", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{
					"record_class":  "audit_event",
					"schema":        "event_notifications",
					"source_system": "adp_workforce_now",
				},
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
