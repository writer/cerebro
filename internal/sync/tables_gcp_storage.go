package sync

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpStorageBucketTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_storage_buckets",
		Columns: []string{"project_id", "name", "location", "location_type", "storage_class", "time_created", "updated", "versioning_enabled", "logging_log_bucket", "logging_log_object_prefix", "lifecycle_rules", "labels", "retention_policy_retention_period", "retention_policy_effective_time", "retention_policy_is_locked", "public_access_prevention", "uniform_bucket_level_access", "default_event_based_hold", "cors", "website_main_page_suffix", "website_not_found_page", "encryption_default_kms_key", "iam_policy", "acl", "self_link"},
		Fetch:   e.fetchGCPStorageBuckets,
	}
}

func (e *GCPSyncEngine) gcpStorageObjectTable() GCPTableSpec {
	return GCPTableSpec{
		Name: "gcp_storage_objects",
		Columns: []string{
			"project_id", "bucket", "name", "size", "storage_class", "created", "updated",
			"etag", "kms_key_name", "content_type", "content_language", "crc32c", "md5",
			"custom_time", "event_based_hold", "temporary_hold", "metadata", "owner", "self_link",
		},
		Fetch: e.fetchGCPStorageObjects,
	}
}

func (e *GCPSyncEngine) fetchGCPStorageBuckets(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := storage.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	it := client.Buckets(ctx, projectID)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}

		selfLink := fmt.Sprintf("https://storage.googleapis.com/b/%s", attrs.Name)

		row := map[string]interface{}{
			"_cq_id":                   selfLink,
			"project_id":               projectID,
			"name":                     attrs.Name,
			"location":                 attrs.Location,
			"location_type":            attrs.LocationType,
			"storage_class":            attrs.StorageClass,
			"time_created":             attrs.Created,
			"updated":                  attrs.Updated,
			"versioning_enabled":       attrs.VersioningEnabled,
			"default_event_based_hold": attrs.DefaultEventBasedHold,
			"labels":                   attrs.Labels,
			"self_link":                selfLink,
		}

		// Logging
		if attrs.Logging != nil {
			row["logging_log_bucket"] = attrs.Logging.LogBucket
			row["logging_log_object_prefix"] = attrs.Logging.LogObjectPrefix
		}

		// Lifecycle rules
		if len(attrs.Lifecycle.Rules) > 0 {
			var rules []map[string]interface{}
			for _, rule := range attrs.Lifecycle.Rules {
				ruleInfo := map[string]interface{}{
					"action_type":          rule.Action.Type,
					"action_storage_class": rule.Action.StorageClass,
				}
				if rule.Condition.AgeInDays > 0 {
					ruleInfo["condition_age_days"] = rule.Condition.AgeInDays
				}
				if !rule.Condition.CreatedBefore.IsZero() {
					ruleInfo["condition_created_before"] = rule.Condition.CreatedBefore
				}
				if rule.Condition.NumNewerVersions > 0 {
					ruleInfo["condition_num_newer_versions"] = rule.Condition.NumNewerVersions
				}
				rules = append(rules, ruleInfo)
			}
			row["lifecycle_rules"] = rules
		}

		// Retention policy
		if attrs.RetentionPolicy != nil {
			row["retention_policy_retention_period"] = attrs.RetentionPolicy.RetentionPeriod.Seconds()
			row["retention_policy_effective_time"] = attrs.RetentionPolicy.EffectiveTime
			row["retention_policy_is_locked"] = attrs.RetentionPolicy.IsLocked
		}

		// Public access prevention
		row["public_access_prevention"] = attrs.PublicAccessPrevention.String()

		// Uniform bucket-level access
		row["uniform_bucket_level_access"] = attrs.UniformBucketLevelAccess.Enabled

		// CORS
		if len(attrs.CORS) > 0 {
			var cors []map[string]interface{}
			for _, c := range attrs.CORS {
				cors = append(cors, map[string]interface{}{
					"origins":          c.Origins,
					"methods":          c.Methods,
					"response_headers": c.ResponseHeaders,
					"max_age_seconds":  c.MaxAge.Seconds(),
				})
			}
			row["cors"] = cors
		}

		// Website
		if attrs.Website != nil {
			row["website_main_page_suffix"] = attrs.Website.MainPageSuffix
			row["website_not_found_page"] = attrs.Website.NotFoundPage
		}

		// Encryption
		if attrs.Encryption != nil {
			row["encryption_default_kms_key"] = attrs.Encryption.DefaultKMSKeyName
		}

		// Get IAM policy
		bucket := client.Bucket(attrs.Name)
		policy, err := bucket.IAM().V3().Policy(ctx)
		if err == nil && policy != nil {
			var bindings []map[string]interface{}
			for _, b := range policy.Bindings {
				bindings = append(bindings, map[string]interface{}{
					"role":    b.Role,
					"members": b.Members,
				})
			}
			row["iam_policy"] = map[string]interface{}{
				"bindings": bindings,
			}
		}

		// Get ACL
		acl, err := bucket.ACL().List(ctx)
		if err == nil {
			var aclEntries []map[string]interface{}
			for _, entry := range acl {
				aclEntries = append(aclEntries, map[string]interface{}{
					"entity":       string(entry.Entity),
					"role":         string(entry.Role),
					"entity_id":    entry.EntityID,
					"domain":       entry.Domain,
					"email":        entry.Email,
					"project_team": serializeProjectTeam(entry.ProjectTeam),
				})
			}
			row["acl"] = aclEntries
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPStorageObjects(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := storage.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 200)
	bucketIt := client.Buckets(ctx, projectID)
	for {
		bucketAttrs, err := bucketIt.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}

		objIt := client.Bucket(bucketAttrs.Name).Objects(ctx, nil)
		for {
			obj, err := objIt.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("list objects for bucket %s: %w", bucketAttrs.Name, err)
			}

			selfLink := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s", bucketAttrs.Name, obj.Name)
			row := map[string]interface{}{
				"_cq_id":           selfLink,
				"project_id":       projectID,
				"bucket":           bucketAttrs.Name,
				"name":             obj.Name,
				"size":             obj.Size,
				"storage_class":    obj.StorageClass,
				"created":          obj.Created,
				"updated":          obj.Updated,
				"etag":             obj.Etag,
				"kms_key_name":     obj.KMSKeyName,
				"content_type":     obj.ContentType,
				"content_language": obj.ContentLanguage,
				"crc32c":           obj.CRC32C,
				"md5":              obj.MD5,
				"custom_time":      obj.CustomTime,
				"event_based_hold": obj.EventBasedHold,
				"temporary_hold":   obj.TemporaryHold,
				"metadata":         obj.Metadata,
				"self_link":        selfLink,
			}

			if obj.Owner != "" {
				row["owner"] = obj.Owner
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func serializeProjectTeam(pt *storage.ProjectTeam) map[string]interface{} {
	if pt == nil {
		return nil
	}
	return map[string]interface{}{
		"project_number": pt.ProjectNumber,
		"team":           pt.Team,
	}
}
