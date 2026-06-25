package writer

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "writer"

type Source struct{ inner *jsonapi.Source }

type familyOption func(*jsonapi.Family)

var staticAttributes = map[string]string{"source_product": "writer"}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.writer.com",
		DefaultFamily:   "application",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families:        writerFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func writerFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		writerListFamily("model", "/v1/models", "writer_model", []string{"id"}, nil, map[string]string{
			"model_id": "id",
			"name":     "name",
		}, withListKeys("models"), withoutPagination()),
		writerListFamily("graph", "/v1/graphs", "writer_graph", []string{"id"}, []string{"created_at"}, map[string]string{
			"graph_id":                "id",
			"name":                    "name",
			"description":             "description",
			"type":                    "type",
			"created_at":              "created_at",
			"file_status_in_progress": "file_status.in_progress",
			"file_status_completed":   "file_status.completed",
			"file_status_failed":      "file_status.failed",
			"file_status_total":       "file_status.total",
			"urls":                    "urls",
		}, withQuery(map[string]string{"order": "order"})),
		writerListFamily("file", "/v1/files", "writer_file", []string{"id"}, []string{"created_at"}, map[string]string{
			"file_id":    "id",
			"name":       "name",
			"created_at": "created_at",
			"graph_ids":  "graph_ids",
			"status":     "status",
		}, withQuery(map[string]string{"file_types": "file_types", "graph_id": "graph_id", "order": "order", "status": "status"})),
		writerListFamily("application", "/v1/applications", "writer_application", []string{"id"}, []string{"updated_at", "created_at"}, map[string]string{
			"application_id":   "id",
			"name":             "name",
			"type":             "type",
			"status":           "status",
			"inputs":           "inputs",
			"created_at":       "created_at",
			"updated_at":       "updated_at",
			"last_deployed_at": "last_deployed_at",
		}, withDetailPath("/v1/applications/{id}"), withQuery(map[string]string{"order": "order", "type": "type"})),
		writerListFamily("application_graph", "/v1/applications/{application_id}/graphs", "writer_application_graph", []string{"application_id", "id"}, nil, map[string]string{
			"application_id": "application_id",
			"graph_ids":      "graph_ids",
		}, withPathParams("application_id"), asSingleton(), withoutPagination()),
		writerListFamily("application_job", "/v1/applications/{application_id}/jobs", "writer_application_job", []string{"id"}, []string{"updated_at", "created_at"}, map[string]string{
			"job_id":         "id",
			"application_id": "application_id",
			"status":         "status",
			"created_at":     "created_at",
			"updated_at":     "updated_at",
			"completed_at":   "completed_at",
			"error":          "error",
		}, withPathParams("application_id"), withListKeys("result"), withQuery(map[string]string{"offset": "offset", "status": "status"}), withOffsetPagination()),
	}
}

func writerListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	family := jsonapi.Family{
		Name:             name,
		Path:             path,
		CursorParam:      "after",
		NextCursorKeys:   []string{"last_id"},
		HasMoreKey:       "has_more",
		URNKind:          urnKind,
		IDKeys:           idKeys,
		TimestampKeys:    timestampKeys,
		Attributes:       attrs,
		StaticAttributes: staticAttributes,
		PageSizeParams:   []string{"limit"},
	}
	for _, opt := range opts {
		opt(&family)
	}
	return family
}

func withPathParams(params ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.PathParams = append([]string{}, params...)
	}
}

func withDetailPath(path string) familyOption {
	return func(f *jsonapi.Family) {
		f.DetailPath = path
		f.AllowBareDetailRecord = true
	}
}

func withListKeys(keys ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.ListKeys = append([]string{}, keys...)
	}
}

func withQuery(query map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		f.Config.ConfigQuery = query
	}
}

func asSingleton() familyOption {
	return func(f *jsonapi.Family) {
		f.Singleton = true
	}
}

func withoutPagination() familyOption {
	return func(f *jsonapi.Family) {
		f.DisablePageSize = true
		f.CursorParam = ""
		f.NextCursorKeys = nil
		f.HasMoreKey = "has_more"
	}
}

func withOffsetPagination() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = "offset"
		f.NextCursorKeys = nil
	}
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
