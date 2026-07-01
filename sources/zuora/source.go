package zuora

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
	sourceID                     = "zuora"
	defaultFamily                = familyEventTrigger
	defaultHealthPath            = "/events/event-triggers"
	defaultBaseURLTemplate       = "https://rest.zuora.com"
	tokenHeader                  = ""
	tokenScheme                  = "Bearer"
	familyEventTrigger           = "event_trigger"
	familyAccountingCode         = "accounting_code"
	familyCallout                = "callout"
	familyHostedpage             = "hostedpage"
	familyProduct                = "product"
	familyAccountingPeriod       = "accounting_period"
	familyEmail                  = "email"
	familyEmailTemplate          = "email_template"
	familyNotificationDefinition = "notification_definition"
	familyRevenueEvent           = "revenue_event"
	familyRevenueSchedule        = "revenue_schedule"
	familyAccount                = "account"
)

var templateKeys = []string{"account_key", "event_number", "rs_number", "token"}

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
				Name:             familyEventTrigger,
				Path:             "/events/event-triggers",
				URNKind:          "zuora_event_trigger",
				IDKeys:           []string{"id", "description", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"updatedOn", "createdOn", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|createdBy|updatedBy|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "eventType.name|eventType.displayName|event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "description|eventType.displayName|eventType.name", "observed_at": "observed_at|updatedOn|createdOn|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|description|eventType.displayName|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|baseObject|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "event_trigger", "source_system": "zuora"},
			},
			{
				Name:             familyAccountingCode,
				Path:             "/v1/accounting-codes",
				URNKind:          "zuora_accounting_code",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"accountingCodes"},
				TimestampKeys:    []string{"updatedOn", "createdOn", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "createdOn|created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "name", "observed_at": "observed_at|updatedOn|createdOn|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "accounting_code", "source_system": "zuora"},
			},
			{
				Name:             familyCallout,
				Path:             "/v1/notification-history/callout",
				URNKind:          "zuora_callout",
				IDKeys:           []string{"attemptedNum", "alert_id", "id", "sid", "incident_id", "uuid"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"calloutHistories"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"alert_description": "description|summary|message|body|notification", "alert_fired_at": "fired_at|triggered_at|createTime|created_at|occurred_at|timestamp", "alert_id": "attemptedNum", "alert_name": "notification|requestUrl|attemptedNum", "alert_resolved_at": "resolved_at|closed_at|acknowledged_at", "alert_severity": "severity|alert_severity|risk_level", "alert_source": "requestUrl|source|alert_source|monitor|check", "alert_status": "responseCode|status|result|attemptedNum", "alert_type": "eventCategory|alert_type|type|category|kind", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "attemptedNum", "name": "notification|requestUrl|attemptedNum", "observed_at": "observed_at|createTime|updated_at|last_seen_at", "provider_id": "attemptedNum", "resource_id": "attemptedNum", "resource_name": "notification|requestUrl|attemptedNum", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|attemptedNum|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "alert", "resource_type": "callout_history", "schema": "callout", "source_system": "zuora"},
			},
			{
				Name:             familyHostedpage,
				Path:             "/v1/hostedpages",
				URNKind:          "zuora_hostedpage",
				IDKeys:           []string{"pageId", "id", "urn", "resource_urn", "name"},
				DisablePageSize:  true,
				ListKeys:         []string{"hostedpages"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "pageId", "name": "pageId", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "pageId", "resource_name": "pageId", "resource_type": "hostedpage", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "hostedpage", "schema": "hostedpage", "source_system": "zuora"},
			},
			{
				Name:             familyProduct,
				Path:             "/v1/catalog/products",
				URNKind:          "zuora_product",
				IDKeys:           []string{"id", "name", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"products"},
				TimestampKeys:    []string{"updatedDate", "createdDate", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|updatedBy|createdBy|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updatedDate|createdDate|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|id|productNumber|sku|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "product", "schema": "product", "source_system": "zuora"},
			},
			{
				Name:             familyAccountingPeriod,
				Path:             "/v1/accounting-periods",
				URNKind:          "zuora_accounting_period",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"accountingPeriods"},
				TimestampKeys:    []string{"updatedOn", "createdOn", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "createdOn|created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "name", "observed_at": "observed_at|updatedOn|createdOn|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "accounting_period", "source_system": "zuora"},
			},
			{
				Name:             familyEmail,
				Path:             "/v1/notification-history/email",
				URNKind:          "zuora_email",
				IDKeys:           []string{"bcc", "subject", "user_id", "id", "email", "primary_email", "login"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"emailHistories"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "sendTime|created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|subject|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "bcc|toEmail|email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "bcc", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "subject", "observed_at": "observed_at|sendTime|updated_at|last_seen_at", "primary_email": "toEmail|primary_email|email|profile.email", "provider_id": "bcc", "resource_id": "resource_id|bcc|id|metadata.resource_id", "resource_name": "subject|notification|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|bcc|id|metadata.event_id", "status": "result|status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "bcc|user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "email", "source_system": "zuora"},
			},
			{
				Name:             familyEmailTemplate,
				Path:             "/notifications/email-templates",
				URNKind:          "zuora_email_template",
				IDKeys:           []string{"id", "name", "user_id", "email", "primary_email", "login"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "last_login_at|last_login|last_seen_at", "login": "login|username|email|profile.login", "manager": "manager|profile.manager", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "primary_email": "primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "email_template", "source_system": "zuora"},
			},
			{
				Name:             familyNotificationDefinition,
				Path:             "/notifications/notification-definitions",
				URNKind:          "zuora_notification_definition",
				IDKeys:           []string{"id", "name", "alert_id", "sid", "incident_id", "uuid"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"alert_description": "description|summary|message|body", "alert_fired_at": "fired_at|triggered_at|created_at|occurred_at|timestamp", "alert_id": "id", "alert_name": "name", "alert_resolved_at": "resolved_at|closed_at|acknowledged_at", "alert_severity": "severity|alert_severity|risk_level", "alert_source": "source|alert_source|monitor|check", "alert_status": "active", "alert_type": "alert_type|type|category|kind", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "alert", "schema": "notification_definition", "source_system": "zuora"},
			},
			{
				Name:             familyRevenueEvent,
				Path:             "/v1/revenue-items/revenue-events/${config.event_number}",
				URNKind:          "zuora_revenue_event",
				IDKeys:           []string{"eventNumber", "accountingPeriodEndDate", "event_id", "id", "uuid", "request_id"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"revenueItems"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "eventType|event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "eventNumber|accountingPeriodEndDate", "name": "eventNumber|accountingPeriodEndDate", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "eventNumber|accountingPeriodEndDate", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|eventNumber|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|eventNumber|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|eventNumber|accountingPeriodEndDate|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "revenue_event", "schema": "revenue_event", "source_system": "zuora"},
			},
			{
				Name:             familyRevenueSchedule,
				Path:             "/v1/revenue-events/revenue-schedules/${config.rs_number}",
				URNKind:          "zuora_revenue_schedule",
				IDKeys:           []string{"revenueScheduleNumber", "accountId", "event_id", "id", "uuid", "request_id"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"revenueEventDetails"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "eventType|event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "revenueScheduleNumber|accountId", "name": "revenueScheduleNumber|accountId", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "revenueScheduleNumber|accountId", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|revenueScheduleNumber|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|revenueScheduleNumber|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|revenueScheduleNumber|accountId|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "resource_type": "revenue_schedule", "schema": "revenue_schedule", "source_system": "zuora"},
			},
			{
				Name:             familyAccount,
				Path:             "/v1/accounts/${config.account_key}/payment-methods",
				URNKind:          "zuora_account",
				IDKeys:           []string{"id", "accountHolderInfo.accountHolderName", "accountKey", "email", "primary_email", "login"},
				DisablePageSize:  true,
				ListKeys:         []string{"creditcard"},
				TimestampKeys:    []string{"updatedDate", "createdDate", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"created_at": "createdDate|createdOn|created_at|created|profile.created_at", "department": "department|profile.department", "display_name": "display_name|accountHolderInfo.accountHolderName|name|profile.display_name|profile.name", "domain": "domain|tenant_domain|organization_domain", "email": "accountHolderInfo.email|email|primary_email|profile.email", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "job_title": "job_title|title|profile.title", "last_login_at": "lastTransactionDateTime|lastTransactionTime|last_login_at|last_login|last_seen_at", "login": "login|username|accountHolderInfo.email|email|profile.login", "manager": "manager|profile.manager", "name": "accountHolderInfo.accountHolderName|cardHolderInfo|id", "observed_at": "observed_at|updatedDate|createdDate|updated_at|last_seen_at", "primary_email": "accountHolderInfo.email|primary_email|email|profile.email", "provider_id": "id", "resource_id": "resource_id|id|metadata.resource_id", "resource_name": "accountHolderInfo.accountHolderName|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "status": "status|state|lifecycle_state", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "user_id|id|uid"},
				StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "account", "source_system": "zuora"},
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
