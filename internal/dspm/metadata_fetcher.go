package dspm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// MetadataFetcher provides a lightweight DSPM fetcher that classifies resource
// metadata when deep object inspection is not configured.
type MetadataFetcher struct{}

func NewMetadataFetcher() *MetadataFetcher {
	return &MetadataFetcher{}
}

func (f *MetadataFetcher) FetchSample(_ context.Context, target *ScanTarget, maxBytes int64) ([]DataSample, error) {
	if target == nil {
		return nil, fmt.Errorf("scan target is required")
	}

	payload := map[string]any{
		"id":           target.ID,
		"type":         target.Type,
		"provider":     target.Provider,
		"account":      target.Account,
		"region":       target.Region,
		"name":         target.Name,
		"arn":          target.ARN,
		"is_public":    target.IsPublic,
		"is_encrypted": target.IsEncrypted,
		"properties":   target.Properties,
		"tags":         target.Tags,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata sample: %w", err)
	}

	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		raw = raw[:maxBytes]
	}

	lastModified := target.LastModified
	if lastModified.IsZero() {
		lastModified = time.Now().UTC()
	}

	return []DataSample{{
		ObjectKey:    target.Name,
		Path:         target.ARN,
		ContentType:  "application/json",
		Size:         int64(len(raw)),
		Data:         raw,
		LastModified: lastModified,
	}}, nil
}

func (f *MetadataFetcher) ListObjects(_ context.Context, target *ScanTarget, _ int) ([]ObjectInfo, error) {
	if target == nil {
		return nil, fmt.Errorf("scan target is required")
	}
	lastModified := target.LastModified
	if lastModified.IsZero() {
		lastModified = time.Now().UTC()
	}
	return []ObjectInfo{{
		Key:          target.Name,
		ContentType:  "application/json",
		LastModified: lastModified,
	}}, nil
}
