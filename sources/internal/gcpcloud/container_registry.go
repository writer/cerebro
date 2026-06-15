package gcpcloud

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type JSONFetcher func(path string, query url.Values, target any) error

type ContainerRegistryRecord struct {
	Host             string              `json:"host"`
	Bucket           string              `json:"bucket"`
	Location         string              `json:"location"`
	StorageClass     string              `json:"storageClass"`
	Labels           map[string]string   `json:"labels"`
	Encryption       GCSEncryption       `json:"encryption"`
	Versioning       GCSVersioning       `json:"versioning"`
	IAMConfiguration GCSIAMConfiguration `json:"iamConfiguration"`
	IAMPolicy        IAMPolicy           `json:"iamPolicy"`
	Raw              json.RawMessage     `json:"-"`
}

type containerRegistryBucket struct {
	host     string
	bucket   string
	location string
}

func ListContainerRegistries(projectID string, fetch JSONFetcher) ([]ContainerRegistryRecord, error) {
	records := make([]ContainerRegistryRecord, 0, 4)
	for _, candidate := range containerRegistryBuckets(projectID) {
		var raw json.RawMessage
		path := "/storage/v1/b/" + url.PathEscape(candidate.bucket)
		if err := fetch(path, nil, &raw); err != nil {
			if gcpAPIStatus(err, "404") {
				continue
			}
			return nil, fmt.Errorf("lookup gcp container registry bucket %s: %w", candidate.bucket, err)
		}
		var bucket GCSBucketRecord
		if err := json.Unmarshal(raw, &bucket); err != nil {
			return nil, fmt.Errorf("decode gcp container registry bucket %s: %w", candidate.bucket, err)
		}
		record := ContainerRegistryRecord{
			Host:             candidate.host,
			Bucket:           candidate.bucket,
			Location:         firstNonEmpty(bucket.Location, candidate.location),
			StorageClass:     bucket.StorageClass,
			Labels:           bucket.Labels,
			Encryption:       bucket.Encryption,
			Versioning:       bucket.Versioning,
			IAMConfiguration: bucket.IAMConfiguration,
			Raw:              raw,
		}
		query := url.Values{"optionsRequestedPolicyVersion": {"3"}}
		if err := fetch(path+"/iam", query, &record.IAMPolicy); err != nil && !optionalContainerRegistryEnrichmentErr(err) {
			return nil, fmt.Errorf("lookup gcp container registry IAM policy %s: %w", candidate.bucket, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func containerRegistryBuckets(projectID string) []containerRegistryBucket {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil
	}
	return []containerRegistryBucket{
		{host: "gcr.io", bucket: "artifacts." + projectID + ".appspot.com", location: "us"},
		{host: "us.gcr.io", bucket: "us.artifacts." + projectID + ".appspot.com", location: "us"},
		{host: "eu.gcr.io", bucket: "eu.artifacts." + projectID + ".appspot.com", location: "eu"},
		{host: "asia.gcr.io", bucket: "asia.artifacts." + projectID + ".appspot.com", location: "asia"},
	}
}

func optionalContainerRegistryEnrichmentErr(err error) bool {
	if err == nil {
		return false
	}
	return gcpAPIStatus(err, "403") || gcpAPIStatus(err, "404") ||
		strings.Contains(fmt.Sprint(err), "PERMISSION_DENIED") ||
		strings.Contains(fmt.Sprint(err), "IAM_PERMISSION_DENIED")
}

func gcpAPIStatus(err error, status string) bool {
	return err != nil && strings.Contains(fmt.Sprint(err), "gcp API returned "+status)
}
