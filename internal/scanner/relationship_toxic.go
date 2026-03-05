package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

type RelationshipToxicFinding struct {
	Severity       string
	PolicyID       string
	Title          string
	ResourceID     string
	ResourceName   string
	URL            string
	ServiceAccount string
	ContainerImage string
	Description    string
	Risks          string
}

// ToxicDetectionResult holds toxic findings plus a data-derived cursor.
type ToxicDetectionResult struct {
	Findings    []RelationshipToxicFinding
	MaxSyncTime time.Time // max _cq_sync_time across all processed source rows
	MaxCursorID string    // deterministic tiebreak: max resource_id at MaxSyncTime
}

// ToxicScanCursor holds the incremental cursor for toxic relationship scans.
type ToxicScanCursor struct {
	SinceTime time.Time
	SinceID   string // keyset tiebreak: last resource_id at SinceTime
}

func DetectRelationshipToxicCombinations(ctx context.Context, sf *snowflake.Client, cursor *ToxicScanCursor) (*ToxicDetectionResult, error) {
	if sf == nil {
		return &ToxicDetectionResult{}, nil
	}
	svcFilter := toxicSinceFilter("s", cursor)
	bucketFilter := toxicSinceFilter("b", cursor)
	iamFilter := toxicSinceFilter("r", cursor)
	relFilter := toxicSinceFilterColumn("", "sync_time", cursor)
	keysetWhere := toxicKeysetWhere(cursor)
	query := fmt.Sprintf(`
WITH changed_rel_sources AS (
    SELECT DISTINCT SOURCE_ID
    FROM RAW.RESOURCE_RELATIONSHIPS
    WHERE 1=1%s
),
toxic_cloudrun_with_vuln AS (
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        r_sa.TARGET_ID as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        CASE 
            WHEN TEMPLATE:containers[0]:image::VARCHAR LIKE '%%:latest%%' 
                 OR (TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%%@sha256:%%' 
                     AND TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%%:%%') 
            THEN TRUE ELSE FALSE 
        END as unpinned_image,
        GREATEST(s._cq_sync_time, r_sa.sync_time) as _row_sync_time
    FROM GCP_CLOUDRUN_SERVICES s
    JOIN RAW.RESOURCE_RELATIONSHIPS r_sa 
        ON REPLACE(s.NAME, '"', '') = r_sa.SOURCE_ID 
        AND r_sa.REL_TYPE = 'USES_DEFAULT_SA'
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
      AND (1=1%s OR REPLACE(s.NAME, '"', '') IN (SELECT SOURCE_ID FROM changed_rel_sources))
),
toxic_buckets AS (
    SELECT 
        b.NAME as resource_id,
        REPLACE(b.NAME, '"', '') as clean_name,
        REPLACE(b.SELF_LINK, '"', '') as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image,
        b._cq_sync_time as _row_sync_time
    FROM GCP_STORAGE_BUCKETS b
    WHERE (b.IAM_POLICY LIKE '%%allUsers%%' OR b.IAM_POLICY LIKE '%%allAuthenticatedUsers%%')%s
),
high_iam_confused_deputy AS (
    SELECT 
        r.ARN as resource_id,
        REPLACE(r.ARN, '"', '') as clean_name,
        NULL as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image,
        r._cq_sync_time as _row_sync_time
    FROM AWS_IAM_ROLES r
    WHERE r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%%aws:SourceArn%%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%%aws:SourceAccount%%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%%sts:AssumeRole%%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%%Service%%'%s
),
high_cloudrun_no_auth AS (
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        NULL as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        FALSE as unpinned_image,
        s._cq_sync_time as _row_sync_time
    FROM GCP_CLOUDRUN_SERVICES s
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
      AND (1=1%s OR REPLACE(s.NAME, '"', '') IN (SELECT SOURCE_ID FROM changed_rel_sources))
      AND NOT EXISTS (
          SELECT 1 FROM RAW.RESOURCE_RELATIONSHIPS r 
          WHERE REPLACE(s.NAME, '"', '') = r.SOURCE_ID AND r.REL_TYPE = 'USES_DEFAULT_SA'
      )
),
all_toxic AS (
SELECT 'CRITICAL' as severity, 'toxic-cloudrun-vuln-default-sa' as policy_id,
    'Internet-facing Cloud Run with vulnerabilities and data access' as title,
    clean_name as resource_name, resource_id, url, service_account, container_image,
    'Cloud Run is public, uses default SA with data access, and runs unpinned image susceptible to supply chain attacks' as description,
    'EXTERNAL_EXPOSURE, VULNERABILITY, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA' as risks,
    _row_sync_time
FROM toxic_cloudrun_with_vuln WHERE unpinned_image = TRUE
UNION ALL
SELECT 'CRITICAL', 'toxic-cloudrun-external-default-sa',
    'Internet-facing Cloud Run with default SA and data access',
    clean_name, resource_id, url, service_account, container_image,
    'Cloud Run service is publicly accessible, uses default compute service account with broad permissions',
    'EXTERNAL_EXPOSURE, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA',
    _row_sync_time
FROM toxic_cloudrun_with_vuln WHERE unpinned_image = FALSE
UNION ALL
SELECT 'CRITICAL', 'toxic-bucket-public-data',
    'Publicly readable bucket contains sensitive data',
    clean_name, resource_id, url, service_account, container_image,
    'Storage bucket is publicly accessible and may contain sensitive data',
    'EXTERNAL_EXPOSURE, UNPROTECTED_DATA',
    _row_sync_time
FROM toxic_buckets
UNION ALL
SELECT 'HIGH', 'iam-confused-deputy-risk',
    'IAM role vulnerable to confused deputy attack',
    clean_name, resource_id, url, service_account, container_image,
    'IAM role trust policy allows AWS services to assume it without SourceArn/SourceAccount conditions',
    'CONFUSED_DEPUTY, PRIVILEGE_ESCALATION',
    _row_sync_time
FROM high_iam_confused_deputy
UNION ALL
SELECT 'HIGH', 'cloudrun-public-no-auth',
    'Cloud Run service publicly accessible',
    clean_name, resource_id, url, service_account, container_image,
    'Cloud Run service is exposed to internet without IAM authentication',
    'EXTERNAL_EXPOSURE, NO_AUTHENTICATION',
    _row_sync_time
FROM high_cloudrun_no_auth
),
toxic_cursor AS (
    SELECT MAX(_row_sync_time) as _max_sync_time FROM all_toxic
)
SELECT t.severity, t.policy_id, t.title, t.resource_name, t.resource_id, t.url,
       t.service_account, t.container_image, t.description, t.risks,
       c._max_sync_time,
       (SELECT MAX(resource_id) FROM all_toxic WHERE _row_sync_time = c._max_sync_time) as _max_cursor_id
FROM all_toxic t
CROSS JOIN toxic_cursor c%s
`, relFilter, svcFilter, bucketFilter, iamFilter, svcFilter, keysetWhere)

	result, err := sf.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("toxic combination query failed: %w", err)
	}

	findings := MapRelationshipToxicRows(result.Rows)
	maxSync, maxID := extractToxicCursor(result.Rows)
	return &ToxicDetectionResult{Findings: findings, MaxSyncTime: maxSync, MaxCursorID: maxID}, nil
}

// toxicSinceFilter returns a SQL AND clause filtering by _cq_sync_time with
// optional table alias qualification. Empty alias uses unqualified column name
// (for single-table CTEs like changed_rel_sources).
//
// When the cursor carries a SinceID the operator is >= so that boundary rows
// at exactly SinceTime survive into all_toxic where toxicKeysetWhere applies
// the precise keyset predicate. When SinceID is empty the operator is strict >.
func toxicSinceFilter(alias string, cursor *ToxicScanCursor) string {
	return toxicSinceFilterColumn(alias, "_cq_sync_time", cursor)
}

func toxicSinceFilterColumn(alias, column string, cursor *ToxicScanCursor) string {
	if cursor == nil || cursor.SinceTime.IsZero() {
		return ""
	}
	if strings.TrimSpace(column) == "" {
		column = "_cq_sync_time"
	}
	col := column
	if alias != "" {
		col = alias + "." + column
	}
	ts := cursor.SinceTime.UTC().Format(time.RFC3339Nano)
	op := ">"
	if cursor.SinceID != "" {
		op = ">="
	}
	return fmt.Sprintf(" AND %s %s '%s'", col, op, ts)
}

// toxicKeysetWhere returns a WHERE clause for the final SELECT over all_toxic
// that implements keyset pagination: rows strictly after the cursor position.
// When SinceID is empty, falls back to time-only filtering on _row_sync_time.
// When both are set, uses: (_row_sync_time > T) OR (_row_sync_time = T AND resource_id > ID).
func toxicKeysetWhere(cursor *ToxicScanCursor) string {
	if cursor == nil || cursor.SinceTime.IsZero() {
		return ""
	}
	ts := cursor.SinceTime.UTC().Format(time.RFC3339Nano)
	if cursor.SinceID == "" {
		return fmt.Sprintf("\nWHERE t._row_sync_time > '%s'", ts)
	}
	escapedID := strings.ReplaceAll(cursor.SinceID, "'", "''")
	return fmt.Sprintf(
		"\nWHERE (t._row_sync_time > '%s' OR (t._row_sync_time = '%s' AND t.resource_id > '%s'))",
		ts, ts, escapedID,
	)
}

func extractToxicCursor(rows []map[string]interface{}) (time.Time, string) {
	var maxTime time.Time
	var maxID string
	for _, row := range rows {
		if v, ok := row["_max_sync_time"]; ok {
			if t := toTime(v); !t.IsZero() && t.After(maxTime) {
				maxTime = t
			}
		}
		if v, ok := row["_max_cursor_id"]; ok {
			if s := toString(v); s != "" && s > maxID {
				maxID = s
			}
		}
	}
	return maxTime, maxID
}

func toTime(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, typed); err == nil {
				return parsed
			}
		}
	case []byte:
		return toTime(string(typed))
	}
	return time.Time{}
}

// MapRelationshipToxicRows converts Snowflake result rows into toxic findings.
func MapRelationshipToxicRows(rows []map[string]interface{}) []RelationshipToxicFinding {
	findings := make([]RelationshipToxicFinding, 0, len(rows))
	for _, row := range rows {
		finding := RelationshipToxicFinding{
			Severity:       toString(row["severity"]),
			PolicyID:       toString(row["policy_id"]),
			Title:          toString(row["title"]),
			ResourceID:     toString(row["resource_id"]),
			ResourceName:   toString(row["resource_name"]),
			URL:            toString(row["url"]),
			ServiceAccount: toString(row["service_account"]),
			ContainerImage: toString(row["container_image"]),
			Description:    toString(row["description"]),
			Risks:          toString(row["risks"]),
		}
		if finding.PolicyID == "" && finding.Severity == "" {
			continue
		}
		findings = append(findings, finding)
	}
	return findings
}

func (f RelationshipToxicFinding) ToPolicyFinding() policy.Finding {
	resource := map[string]interface{}{
		"id": f.ResourceID,
	}
	if f.ResourceName != "" {
		resource["name"] = f.ResourceName
	}
	if f.URL != "" {
		resource["url"] = f.URL
	}
	if f.ServiceAccount != "" {
		resource["service_account"] = f.ServiceAccount
	}
	if f.ContainerImage != "" {
		resource["container_image"] = f.ContainerImage
	}

	return policy.Finding{
		ID:             fmt.Sprintf("%s:%s", f.PolicyID, f.ResourceID),
		PolicyID:       f.PolicyID,
		PolicyName:     f.Title,
		Title:          f.Title,
		Severity:       strings.ToLower(f.Severity),
		Description:    f.Description,
		Resource:       resource,
		ResourceID:     f.ResourceID,
		ResourceName:   f.ResourceName,
		RiskCategories: ParseRiskCategories(f.Risks),
	}
}

func toString(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}
