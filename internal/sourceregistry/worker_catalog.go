package sourceregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	sourcecatalogs "github.com/writer/cerebro/sources"
)

var errWorkerCatalogExecutionRequired = errors.New("source execution requires the configured worker")

// workerCatalogSource keeps portable source metadata in the Go registry while
// its collection path is owned exclusively by the credential-free worker.
// Direct calls fail closed so they cannot restore a retired Go provider path.
type workerCatalogSource struct {
	spec *cerebrov1.SourceSpec
}

func newWorkerCatalogSource(sourceID string) (*workerCatalogSource, error) {
	sourceID = strings.TrimSpace(sourceID)
	payload, err := sourcecatalogs.BuiltinCatalog(sourceID)
	if err != nil {
		return nil, err
	}
	catalog, err := sourcecdk.LoadSourceCatalog(payload)
	if err != nil {
		return nil, fmt.Errorf("load %s worker source catalog: %w", sourceID, err)
	}
	if catalog.Spec == nil || catalog.Spec.GetId() != sourceID {
		return nil, fmt.Errorf("worker source catalog id does not match %q", sourceID)
	}
	return &workerCatalogSource{spec: catalog.Spec}, nil
}

func (s *workerCatalogSource) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return s.spec
}

func (s *workerCatalogSource) Check(context.Context, sourcecdk.Config) error {
	return s.executionError("")
}

func (s *workerCatalogSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, s.executionError("")
}

func (s *workerCatalogSource) Read(_ context.Context, cfg sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, s.executionError(sourcecdk.ConfigValue(cfg, "family"))
}

func (s *workerCatalogSource) executionError(family string) error {
	sourceID := ""
	if s != nil && s.spec != nil {
		sourceID = s.spec.GetId()
	}
	return sourcecdk.WrapSourceError(sourcecdk.ErrorKindProvider, sourceID, family, errWorkerCatalogExecutionRequired)
}
