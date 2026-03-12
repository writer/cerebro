package functionscan

import (
	"context"
	"fmt"
	"io"
	"strings"

	functions "cloud.google.com/go/functions/apiv2"
	"cloud.google.com/go/functions/apiv2/functionspb"
	"cloud.google.com/go/storage"
	gax "github.com/googleapis/gax-go/v2"
)

type gcpFunctionsAPI interface {
	GetFunction(ctx context.Context, req *functionspb.GetFunctionRequest, opts ...gax.CallOption) (*functionspb.Function, error)
	Close() error
}

type gcpStorageOpener interface {
	OpenObject(ctx context.Context, bucket, object string, generation int64) (io.ReadCloser, error)
	Close() error
}

type realGCPStorage struct{ client *storage.Client }

func (s *realGCPStorage) OpenObject(ctx context.Context, bucket, object string, generation int64) (io.ReadCloser, error) {
	handle := s.client.Bucket(strings.TrimSpace(bucket)).Object(strings.TrimSpace(object))
	if generation > 0 {
		handle = handle.Generation(generation)
	}
	return handle.NewReader(ctx)
}

func (s *realGCPStorage) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

type gcpFunctionClient struct{ client *functions.FunctionClient }

func (c *gcpFunctionClient) GetFunction(ctx context.Context, req *functionspb.GetFunctionRequest, opts ...gax.CallOption) (*functionspb.Function, error) {
	return c.client.GetFunction(ctx, req, opts...)
}
func (c *gcpFunctionClient) Close() error { return c.client.Close() }

type GCPProvider struct {
	functions gcpFunctionsAPI
	storage   gcpStorageOpener
}

func NewGCPProvider(ctx context.Context) (*GCPProvider, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	functionsClient, err := functions.NewFunctionClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create functions client: %w", err)
	}
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		_ = functionsClient.Close()
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	return &GCPProvider{functions: &gcpFunctionClient{client: functionsClient}, storage: &realGCPStorage{client: storageClient}}, nil
}

func NewGCPProviderWithClients(functionsClient gcpFunctionsAPI, storageClient gcpStorageOpener) *GCPProvider {
	return &GCPProvider{functions: functionsClient, storage: storageClient}
}

func (p *GCPProvider) Close() error {
	if p == nil {
		return nil
	}
	if p.functions != nil {
		_ = p.functions.Close()
	}
	if p.storage != nil {
		_ = p.storage.Close()
	}
	return nil
}

func (p *GCPProvider) Kind() ProviderKind { return ProviderGCP }

func (p *GCPProvider) DescribeFunction(ctx context.Context, target FunctionTarget) (*FunctionDescriptor, error) {
	if p == nil || p.functions == nil {
		return nil, fmt.Errorf("gcp function scan provider is not configured")
	}
	name := target.Identity()
	if name == "" {
		return nil, fmt.Errorf("gcp function name is required")
	}
	fn, err := p.functions.GetFunction(ctx, &functionspb.GetFunctionRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("get cloud function %s: %w", name, err)
	}
	descriptor := &FunctionDescriptor{
		ID:                 strings.TrimSpace(fn.GetName()),
		Name:               strings.TrimSpace(fn.GetName()),
		Runtime:            strings.TrimSpace(fn.GetBuildConfig().GetRuntime()),
		EntryPoint:         strings.TrimSpace(fn.GetBuildConfig().GetEntryPoint()),
		ServiceAccount:     firstNonEmpty(fn.GetServiceConfig().GetServiceAccountEmail(), fn.GetBuildConfig().GetServiceAccount()),
		RuntimeEnvironment: fn.GetEnvironment().String(),
		Environment:        cloneStringMap(fn.GetServiceConfig().GetEnvironmentVariables()),
		BuildEnvironment:   cloneStringMap(fn.GetBuildConfig().GetEnvironmentVariables()),
		Metadata: map[string]any{
			"service":             strings.TrimSpace(fn.GetServiceConfig().GetService()),
			"ingress":             fn.GetServiceConfig().GetIngressSettings().String(),
			"vpc_connector":       strings.TrimSpace(fn.GetServiceConfig().GetVpcConnector()),
			"max_instance_count":  fn.GetServiceConfig().GetMaxInstanceCount(),
			"min_instance_count":  fn.GetServiceConfig().GetMinInstanceCount(),
			"all_traffic_latest":  fn.GetServiceConfig().GetAllTrafficOnLatestRevision(),
			"docker_repository":   strings.TrimSpace(fn.GetBuildConfig().GetDockerRepository()),
			"binary_authz_policy": strings.TrimSpace(fn.GetServiceConfig().GetBinaryAuthorizationPolicy()),
		},
	}
	if descriptor.Environment == nil {
		descriptor.Environment = map[string]string{}
	}
	for key, value := range fn.GetBuildConfig().GetEnvironmentVariables() {
		if _, exists := descriptor.Environment[key]; !exists {
			descriptor.Environment[key] = value
		}
	}
	if fn.GetUpdateTime() != nil {
		updated := fn.GetUpdateTime().AsTime().UTC()
		descriptor.UpdatedAt = &updated
	}
	if source := fn.GetBuildConfig().GetSource(); source != nil && source.GetStorageSource() != nil {
		storageSource := source.GetStorageSource()
		artifactID := fmt.Sprintf("%s/%s#%d", storageSource.GetBucket(), storageSource.GetObject(), storageSource.GetGeneration())
		descriptor.SourceRevision = strings.TrimSpace(fn.GetBuildConfig().GetBuild())
		descriptor.Artifacts = append(descriptor.Artifacts, ArtifactRef{
			ID:     artifactID,
			Kind:   ArtifactFunctionCode,
			Format: ArchiveFormatZIP,
			Name:   filepathBase(storageSource.GetObject()),
			Metadata: map[string]any{
				"bucket":     strings.TrimSpace(storageSource.GetBucket()),
				"object":     strings.TrimSpace(storageSource.GetObject()),
				"generation": storageSource.GetGeneration(),
			},
		})
	}
	if descriptor.ID == "" {
		descriptor.ID = name
	}
	if descriptor.Name == "" {
		descriptor.Name = name
	}
	descriptor.EventSources = eventSourcesForGCP(fn)
	if len(descriptor.Artifacts) == 0 {
		descriptor.ImageURI = strings.TrimSpace(fn.GetBuildConfig().GetDockerRepository())
	}
	return descriptor, nil
}

func (p *GCPProvider) OpenArtifact(ctx context.Context, _ FunctionTarget, artifact ArtifactRef) (io.ReadCloser, error) {
	if p == nil || p.storage == nil {
		return nil, fmt.Errorf("gcp function scan provider storage is not configured")
	}
	bucket, _ := artifact.Metadata["bucket"].(string)
	object, _ := artifact.Metadata["object"].(string)
	generation, _ := artifact.Metadata["generation"].(int64)
	if generation == 0 {
		switch value := artifact.Metadata["generation"].(type) {
		case int:
			generation = int64(value)
		case float64:
			generation = int64(value)
		}
	}
	if strings.TrimSpace(bucket) == "" || strings.TrimSpace(object) == "" {
		return nil, fmt.Errorf("gcp function artifact %s is missing storage coordinates", artifact.ID)
	}
	reader, err := p.storage.OpenObject(ctx, bucket, object, generation)
	if err != nil {
		return nil, fmt.Errorf("open cloud function source %s/%s: %w", bucket, object, err)
	}
	return reader, nil
}

func eventSourcesForGCP(fn *functionspb.Function) []string {
	if fn == nil || fn.GetEventTrigger() == nil {
		return nil
	}
	sources := []string{}
	if eventType := strings.TrimSpace(fn.GetEventTrigger().GetEventType()); eventType != "" {
		sources = append(sources, eventType)
	}
	if topic := strings.TrimSpace(fn.GetEventTrigger().GetPubsubTopic()); topic != "" {
		sources = append(sources, topic)
	}
	if trigger := strings.TrimSpace(fn.GetEventTrigger().GetTrigger()); trigger != "" {
		sources = append(sources, trigger)
	}
	return sources
}

func filepathBase(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}
