package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type BlobFetcher interface {
	DownloadBlob(ctx context.Context, repo, digest string) (io.ReadCloser, error)
}

type manifestFetchFunc func(ctx context.Context, reference string) ([]byte, http.Header, error)
type blobFetchFunc func(ctx context.Context, digest string) ([]byte, error)

type registryManifestIndex struct {
	MediaType string `json:"mediaType"`
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Platform  struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
}

type registryConfigBlob struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Created      string `json:"created"`
	Config       struct {
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Env        []string          `json:"Env"`
		User       string            `json:"User"`
		WorkingDir string            `json:"WorkingDir"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
	History []struct {
		CreatedBy string `json:"created_by"`
		Empty     bool   `json:"empty_layer"`
	} `json:"history"`
}

func resolveRegistryManifest(ctx context.Context, reference string, fetchManifest manifestFetchFunc, fetchBlob blobFetchFunc) (*ImageManifest, error) {
	ref := strings.TrimSpace(reference)
	if ref == "" {
		return nil, fmt.Errorf("image reference is required")
	}
	for depth := 0; depth < 4; depth++ {
		body, headers, err := fetchManifest(ctx, ref)
		if err != nil {
			return nil, err
		}
		mediaType := normalizeContentType(headers.Get("Content-Type"))
		index, isIndex, err := decodeManifestIndex(body, mediaType)
		if err != nil {
			return nil, err
		}
		if isIndex {
			nextRef, err := selectPreferredManifest(index)
			if err != nil {
				return nil, err
			}
			ref = nextRef
			continue
		}

		manifest := &ImageManifest{}
		if err := parseManifest(body, manifest); err != nil {
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
		if mediaType != "" && manifest.MediaType == "" {
			manifest.MediaType = mediaType
		}
		if digest := strings.TrimSpace(headers.Get("Docker-Content-Digest")); digest != "" && manifest.Digest == "" {
			manifest.Digest = digest
		}
		if fetchBlob != nil && strings.TrimSpace(manifest.ConfigDigest) != "" {
			configBlob, err := fetchBlob(ctx, manifest.ConfigDigest)
			if err != nil {
				return nil, fmt.Errorf("load config blob %s: %w", manifest.ConfigDigest, err)
			}
			if err := populateManifestConfig(configBlob, manifest); err != nil {
				return nil, fmt.Errorf("decode config blob %s: %w", manifest.ConfigDigest, err)
			}
		}
		if manifest.Labels == nil && len(manifest.Config.Labels) > 0 {
			manifest.Labels = cloneStringMap(manifest.Config.Labels)
		}
		return manifest, nil
	}
	return nil, fmt.Errorf("manifest resolution exceeded max depth for %s", reference)
}

func manifestAcceptMediaTypes() []string {
	return []string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v1+json",
	}
}

func manifestAcceptHeader() string {
	return strings.Join(manifestAcceptMediaTypes(), ", ")
}

func imageIdentifierForReference(reference string) ecrtypes.ImageIdentifier {
	reference = strings.TrimSpace(reference)
	if strings.HasPrefix(reference, "sha256:") {
		return ecrtypes.ImageIdentifier{ImageDigest: &reference}
	}
	return ecrtypes.ImageIdentifier{ImageTag: &reference}
}

func decodeManifestIndex(data []byte, contentType string) (registryManifestIndex, bool, error) {
	var index registryManifestIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return registryManifestIndex{}, false, nil
	}
	mediaType := normalizeContentType(index.MediaType)
	if len(index.Manifests) == 0 {
		return registryManifestIndex{}, false, nil
	}
	if isManifestIndexMediaType(contentType) || isManifestIndexMediaType(mediaType) {
		return index, true, nil
	}
	return registryManifestIndex{}, false, nil
}

func selectPreferredManifest(index registryManifestIndex) (string, error) {
	type preference struct {
		os   string
		arch string
	}
	preferences := []preference{
		{os: "linux", arch: "amd64"},
		{os: "linux", arch: "arm64"},
	}
	for _, preferred := range preferences {
		for _, descriptor := range index.Manifests {
			if strings.EqualFold(strings.TrimSpace(descriptor.Platform.OS), preferred.os) &&
				strings.EqualFold(strings.TrimSpace(descriptor.Platform.Architecture), preferred.arch) {
				return strings.TrimSpace(descriptor.Digest), nil
			}
		}
	}
	for _, descriptor := range index.Manifests {
		if digest := strings.TrimSpace(descriptor.Digest); digest != "" {
			return digest, nil
		}
	}
	return "", fmt.Errorf("manifest index does not contain a resolvable platform manifest")
}

func populateManifestConfig(data []byte, manifest *ImageManifest) error {
	var decoded registryConfigBlob
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	manifest.Config = ImageConfig{
		OS:           strings.TrimSpace(decoded.OS),
		Architecture: strings.TrimSpace(decoded.Architecture),
		Entrypoint:   append([]string(nil), decoded.Config.Entrypoint...),
		Cmd:          append([]string(nil), decoded.Config.Cmd...),
		Env:          append([]string(nil), decoded.Config.Env...),
		User:         strings.TrimSpace(decoded.Config.User),
		WorkDir:      strings.TrimSpace(decoded.Config.WorkingDir),
		Labels:       cloneStringMap(decoded.Config.Labels),
	}
	manifest.Labels = cloneStringMap(decoded.Config.Labels)
	manifest.History = manifest.History[:0]
	for _, history := range decoded.History {
		command := strings.TrimSpace(history.CreatedBy)
		if command != "" {
			manifest.History = append(manifest.History, command)
		}
	}
	if created, err := parseOCIImageTime(decoded.Created); err == nil {
		manifest.Created = created
	}
	manifest.BaseImageRef = firstNonEmptyLabel(manifest.Labels,
		"org.opencontainers.image.base.name",
		"io.buildpacks.base-image",
		"io.buildpacks.stack.id",
	)
	manifest.BaseImageDigest = firstNonEmptyLabel(manifest.Labels,
		"org.opencontainers.image.base.digest",
	)
	if manifest.BaseImageRef == "" {
		manifest.BaseImageRef = inferBaseImageFromHistory(manifest.History)
	}
	return nil
}

func downloadBlobBytes(ctx context.Context, fetcher BlobFetcher, repo, digest string) ([]byte, error) {
	reader, err := fetcher.DownloadBlob(ctx, repo, digest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

func normalizeContentType(contentType string) string {
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = contentType[:idx]
	}
	return strings.TrimSpace(contentType)
}

func isManifestIndexMediaType(mediaType string) bool {
	mediaType = normalizeContentType(mediaType)
	return strings.Contains(mediaType, "manifest.list") || strings.Contains(mediaType, "image.index")
}

func parseOCIImageTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty image time")
	}
	return time.Parse(time.RFC3339Nano, raw)
}

func inferBaseImageFromHistory(history []string) string {
	for _, step := range history {
		normalized := strings.TrimSpace(step)
		if normalized == "" {
			continue
		}
		if idx := strings.Index(strings.ToUpper(normalized), " FROM "); idx >= 0 {
			return strings.TrimSpace(normalized[idx+6:])
		}
		if strings.HasPrefix(strings.ToUpper(normalized), "FROM ") {
			return strings.TrimSpace(normalized[5:])
		}
	}
	return ""
}

func firstNonEmptyLabel(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
