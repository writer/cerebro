package evidencecas

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID      = "evidence_cas"
	defaultFamily = familyObject
	defaultBucket = "cases"

	familyObject = "object"
)

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
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{
				Name:    familyObject,
				Path:    "/v1/b/cases/refs",
				URNKind: "runtime_evidence",
				IDKeys:  []string{"uri", "digest"},
				TimestampKeys: []string{
					"updated_at",
				},
				Attributes: map[string]string{
					"evidence_id":                   "metadata.evidence_id|uri|key",
					"resource_urn":                  "metadata.resource_urn|metadata.case_urn",
					"observed_at":                   "updated_at",
					"case_id":                       "metadata.case_id",
					"evidence_cas_uri":              "uri",
					"evidence_cas_digest":           "digest",
					"evidence_cas_manifest_version": "manifest_version",
					"evidence_cas_merkle_root":      "merkle_root",
					"evidence_cas_commit_id":        "commit_id",
					"evidence_cas_content_type":     "content_type",
					"evidence_cas_size_bytes":       "size",
					"evidence_cas_blocks_count":     "blocks_count",
					"evidence_cas_ref_type":         "ref_type",
				},
				StaticAttributes: map[string]string{
					"source_product": "evidence_cas",
					"evidence_type":  "evidence_cas.artifact",
				},
				ConfigQuery: map[string]string{
					"prefix": "prefix",
					"tag":    "tag",
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
	cfg, err := s.configForInner(cfg)
	if err != nil {
		return err
	}
	if err := s.checkReadiness(ctx, cfg); err != nil {
		return err
	}
	if err := s.checkContract(ctx, cfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	cfg, err := s.configForInner(cfg)
	if err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	cfg, err := s.configForInner(cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, cfg, cursor)
}

func (s *Source) configForInner(cfg sourcecdk.Config) (sourcecdk.Config, error) {
	values := cfg.Values()
	if strings.TrimSpace(values["path"]) == "" && strings.TrimSpace(values[familyObject+"_path"]) == "" {
		bucket := strings.TrimSpace(values["bucket"])
		if bucket == "" {
			bucket = defaultBucket
		}
		if err := validateBucket(bucket); err != nil {
			return sourcecdk.Config{}, err
		}
		values["path"] = "/v1/b/" + bucket + "/refs"
	}
	return sourcecdk.NewConfig(values), nil
}

func validateBucket(bucket string) error {
	if bucket == "" {
		return fmt.Errorf("%s bucket is required", sourceID)
	}
	if len(bucket) > 128 {
		return fmt.Errorf("%s bucket is too long", sourceID)
	}
	for index, char := range bucket {
		if index == 0 && !isASCIIAlnum(char) {
			return fmt.Errorf("%s bucket must start with an ASCII letter or digit", sourceID)
		}
		if isASCIIAlnum(char) || char == '-' || char == '_' || char == '.' {
			continue
		}
		return fmt.Errorf("%s bucket contains unsupported character %q", sourceID, char)
	}
	return nil
}

func isASCIIAlnum(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')
}

func (s *Source) checkReadiness(ctx context.Context, cfg sourcecdk.Config) error {
	var body struct {
		OK bool `json:"ok"`
	}
	if err := s.getControlJSON(ctx, cfg, "/readyz", &body); err != nil {
		return err
	}
	if !body.OK {
		return fmt.Errorf("%s readiness check failed", sourceID)
	}
	return nil
}

func (s *Source) checkContract(ctx context.Context, cfg sourcecdk.Config) error {
	var body struct {
		Service              string `json:"service"`
		RouteContractVersion int    `json:"route_contract_version"`
	}
	if err := s.getControlJSON(ctx, cfg, "/v1/contract", &body); err != nil {
		return err
	}
	if body.Service != "evidence-cas" {
		return fmt.Errorf("%s contract service = %q, want evidence-cas", sourceID, body.Service)
	}
	if body.RouteContractVersion < 1 {
		return fmt.Errorf("%s contract route_contract_version is required", sourceID)
	}
	return nil
}

func (s *Source) getControlJSON(ctx context.Context, cfg sourcecdk.Config, path string, target any) error {
	baseURL := strings.TrimSpace(configValue(cfg, "base_url"))
	normalizedBaseURL, _, err := sourcehttp.NormalizeBaseURL(sourceID, baseURL, s != nil && s.allowLoopback)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedBaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build %s control request: %w", sourceID, err)
	}
	req.Header.Set("Accept", "application/json")
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      sourceID,
		AllowLoopback: s != nil && s.allowLoopback,
		Timeout:       10 * time.Second,
	})
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s control route %s returned HTTP %d", sourceID, path, resp.StatusCode)
	}
	if err := json.Unmarshal(resp.Body, target); err != nil {
		return fmt.Errorf("decode %s control response: %w", sourceID, err)
	}
	return nil
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
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

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
