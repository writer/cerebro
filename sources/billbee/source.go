package billbee

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
	sourceID                = "billbee"
	defaultFamily           = familyWebhook
	defaultHealthPath       = "/api/v1/webhooks"
	defaultBaseURLTemplate  = "https://app.billbee.io"
	tokenHeader             = ""
	tokenScheme             = "Token"
	familyWebhook           = "webhook"
	familyCloudstorage      = "cloudstorage"
	familyCustomField       = "custom_field"
	familyCustomer          = "customer"
	familyCustomerAddresses = "customer_addresses"
	familyLayout            = "layout"
	familyOrder             = "order"
	familyProduct           = "product"
	familyShipment          = "shipment"
	familyStock             = "stock"
	familyAddresses         = "addresses"
	familyImage             = "image"
)

var templateKeys = []string{"id", "productid", "api_key"}

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
				Name:             familyWebhook,
				Path:             "/api/v1/webhooks",
				URNKind:          "billbee_webhook",
				IDKeys:           []string{"Id", "Description", "id", "urn", "resource_urn", "name"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Description", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Description", "resource_type": "webhook", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "webhook", "source_system": "billbee"},
			},
			{
				Name:             familyCloudstorage,
				Path:             "/api/v1/cloudstorages",
				URNKind:          "billbee_cloudstorage",
				IDKeys:           []string{"Id", "Name", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Name", "resource_type": "cloudstorage", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "cloudstorage", "source_system": "billbee"},
			},
			{
				Name:             familyCustomField,
				Path:             "/api/v1/products/custom-fields",
				URNKind:          "billbee_custom_field",
				IDKeys:           []string{"Id", "Name", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Name", "resource_type": "custom_field", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "custom_field", "source_system": "billbee"},
			},
			{
				Name:             familyCustomer,
				Path:             "/api/v1/customers",
				URNKind:          "billbee_customer",
				IDKeys:           []string{"Id", "Name", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Name", "resource_type": "customer", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "customer", "source_system": "billbee"},
			},
			{
				Name:             familyCustomerAddresses,
				Path:             "/api/v1/customer-addresses",
				URNKind:          "billbee_customer_addresses",
				IDKeys:           []string{"Id", "Email", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Email", "resource_type": "customer_addresses", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "customer_addresses", "source_system": "billbee"},
			},
			{
				Name:             familyLayout,
				Path:             "/api/v1/layouts",
				URNKind:          "billbee_layout",
				IDKeys:           []string{"Id", "Name", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Name", "resource_type": "layout", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "layout", "source_system": "billbee"},
			},
			{
				Name:             familyOrder,
				Path:             "/api/v1/orders",
				URNKind:          "billbee_order",
				IDKeys:           []string{"Id", "AcceptLossOfReturnRight", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "AcceptLossOfReturnRight", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "AcceptLossOfReturnRight", "resource_type": "order", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "order", "source_system": "billbee"},
			},
			{
				Name:             familyProduct,
				Path:             "/api/v1/products",
				URNKind:          "billbee_product",
				IDKeys:           []string{"Id", "Title", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Title", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Title", "resource_type": "product", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "product", "source_system": "billbee"},
			},
			{
				Name:             familyShipment,
				Path:             "/api/v1/shipment/shipments",
				URNKind:          "billbee_shipment",
				IDKeys:           []string{"BillbeeId", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "BillbeeId", "name": "BillbeeId", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "BillbeeId", "resource_name": "BillbeeId", "resource_type": "shipment", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "shipment", "source_system": "billbee"},
			},
			{
				Name:             familyStock,
				Path:             "/api/v1/products/stocks",
				URNKind:          "billbee_stock",
				IDKeys:           []string{"Id", "Name", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Name", "resource_type": "stock", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "stock", "source_system": "billbee"},
			},
			{
				Name:             familyAddresses,
				Path:             "/api/v1/customers/${config.id}/addresses",
				URNKind:          "billbee_addresses",
				IDKeys:           []string{"Id", "Email", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Email", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Email", "resource_type": "addresses", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "addresses", "source_system": "billbee"},
			},
			{
				Name:             familyImage,
				Path:             "/api/v1/products/${config.productid}/images",
				URNKind:          "billbee_image",
				IDKeys:           []string{"Id", "Url", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"Data"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "Id", "name": "Url", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "Id", "resource_name": "Url", "resource_type": "image", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "image", "source_system": "billbee"},
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
