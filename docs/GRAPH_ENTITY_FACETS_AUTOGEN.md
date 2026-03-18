# Graph Entity Facet Contract Catalog

Generated from the built-in entity facet registry via `go run ./scripts/generate_entity_facet_docs/main.go`.

- Catalog API version: **cerebro.entity-facets/v1alpha1**
- Catalog kind: **EntityFacetContractCatalog**
- Facets: **8**

| ID | Version | Schema Name | Schema URL | Applicable Kinds | Claim Predicates | Source Keys |
|---|---|---|---|---|---|---|
| `bucket_encryption` | `1.0.0` | `PlatformBucketEncryptionFacet` | `urn:cerebro:entity-facet:bucket-encryption:v1` | `bucket` | `encrypted`, `default_encryption_enabled` | `encrypted`, `default_encryption`, `default_encryption_enabled`, `kms_encrypted`, `encryption_algorithm`, `encryption_key_id`, `bucket_key_enabled` |
| `bucket_logging` | `1.0.0` | `PlatformBucketLoggingFacet` | `urn:cerebro:entity-facet:bucket-logging:v1` | `bucket` | `access_logging_enabled` | `logging_enabled`, `access_logging_enabled`, `logging_target_bucket` |
| `bucket_public_access` | `1.0.0` | `PlatformBucketPublicAccessFacet` | `urn:cerebro:entity-facet:bucket-public-access:v1` | `bucket` | `public_access`, `internet_exposed` | `public`, `public_access`, `block_public_acls`, `block_public_policy`, `restrict_public_buckets`, `public_access_prevention`, `all_users_access`, `all_authenticated_users_access`, `anonymous_access` |
| `bucket_versioning` | `1.0.0` | `PlatformBucketVersioningFacet` | `urn:cerebro:entity-facet:bucket-versioning:v1` | `bucket` | `versioning_enabled` | `versioning`, `versioning_status`, `mfa_delete` |
| `data_sensitivity` | `1.0.0` | `PlatformEntityDataSensitivityFacet` | `urn:cerebro:entity-facet:data-sensitivity:v1` | `bucket`, `database`, `secret`, `service` | `contains_sensitive_data`, `data_classification` | `contains_pii`, `contains_phi`, `contains_pci`, `contains_secrets`, `data_classification` |
| `exposure` | `1.0.0` | `PlatformEntityExposureFacet` | `urn:cerebro:entity-facet:exposure:v1` | `bucket`, `database`, `function`, `instance`, `network`, `service` | `public_access`, `internet_exposed` | `public`, `public_access`, `internet_accessible`, `publicly_accessible` |
| `ownership` | `1.0.0` | `PlatformEntityOwnershipFacet` | `urn:cerebro:entity-facet:ownership:v1` | - | `owner`, `managed_by` | - |
| `workload_security` | `1.1.0` | `PlatformWorkloadSecurityFacet` | `urn:cerebro:entity-facet:workload-security:v1` | `instance`, `function`, `workload` | - | - |

## Fields

### `bucket_encryption`

Bucket encryption posture and key configuration.

| Field | Value Type | Description |
|---|---|---|
| `encrypted` | `boolean` | - |
| `encryption_algorithm` | `string` | - |
| `encryption_key_id` | `string` | - |
| `bucket_key_enabled` | `boolean` | - |

### `bucket_logging`

Bucket access logging configuration and target.

| Field | Value Type | Description |
|---|---|---|
| `logging_enabled` | `boolean` | - |
| `logging_target_bucket` | `string` | - |

### `bucket_public_access`

Bucket public exposure and public-access-block configuration.

| Field | Value Type | Description |
|---|---|---|
| `public_access` | `boolean` | - |
| `block_public_acls` | `boolean` | - |
| `block_public_policy` | `boolean` | - |
| `restrict_public_buckets` | `boolean` | - |
| `all_users_access` | `boolean` | - |
| `all_authenticated_users_access` | `boolean` | - |

### `bucket_versioning`

Bucket versioning and MFA delete posture.

| Field | Value Type | Description |
|---|---|---|
| `versioning_status` | `string` | - |
| `mfa_delete` | `boolean` | - |

### `data_sensitivity`

Sensitivity signals derived from tags, raw properties, and normalized sensitivity claims.

| Field | Value Type | Description |
|---|---|---|
| `contains_pii` | `boolean` | - |
| `contains_phi` | `boolean` | - |
| `contains_pci` | `boolean` | - |
| `contains_secrets` | `boolean` | - |
| `classification` | `string` | - |

### `exposure`

Internet/public-access posture derived from graph edges, raw properties, and exposure claims.

| Field | Value Type | Description |
|---|---|---|
| `internet_exposed` | `boolean` | - |
| `public_access` | `boolean` | - |

### `ownership`

Typed owner and manager context derived from relations and ownership claims.

| Field | Value Type | Description |
|---|---|---|
| `owner_ids` | `array[string]` | - |
| `manager_ids` | `array[string]` | - |

### `workload_security`

Latest workload scan posture with vulnerability depth and attack-path context.

| Field | Value Type | Description |
|---|---|---|
| `last_scan_id` | `string` | - |
| `last_scanned_at` | `string` | - |
| `stale` | `boolean` | - |
| `os_name` | `string` | - |
| `os_version` | `string` | - |
| `os_architecture` | `string` | - |
| `package_count` | `integer` | - |
| `vulnerability_count` | `integer` | - |
| `reachable_vulnerability_count` | `integer` | - |
| `critical_vulnerability_count` | `integer` | - |
| `reachable_critical_vulnerability_count` | `integer` | - |
| `high_vulnerability_count` | `integer` | - |
| `reachable_high_vulnerability_count` | `integer` | - |
| `known_exploited_count` | `integer` | - |
| `reachable_known_exploited_count` | `integer` | - |
| `direct_reachable_vulnerability_count` | `integer` | - |
| `fixable_vulnerability_count` | `integer` | - |
| `internet_exposed` | `boolean` | - |
| `admin_reachable_count` | `integer` | - |
| `sensitive_data_path_count` | `integer` | - |
| `cross_account_risk` | `boolean` | - |
| `prioritized_risk` | `string` | - |

## Notes

- `docs/GRAPH_ENTITY_FACETS.json` is the machine-readable facet catalog for compatibility checks and generated tooling.
- Facet contract changes must bump the facet version when the semantic surface changes.
- Entity detail and entity-summary should bind to facet IDs and schema URLs rather than provider-specific property names.
