package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/snowflake"
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

func DetectRelationshipToxicCombinations(ctx context.Context, sf *snowflake.Client) ([]RelationshipToxicFinding, error) {
	if sf == nil {
		return nil, nil
	}
	query := `
WITH toxic_cloudrun_with_vuln AS (
    -- CRITICAL: Cloud Run with default SA + public exposure + unpinned image (vulnerability risk)
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        r_sa.TARGET_ID as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        CASE 
            WHEN TEMPLATE:containers[0]:image::VARCHAR LIKE '%:latest%' 
                 OR (TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%@sha256:%' 
                     AND TEMPLATE:containers[0]:image::VARCHAR NOT LIKE '%:%') 
            THEN TRUE ELSE FALSE 
        END as unpinned_image
    FROM GCP_CLOUDRUN_SERVICES s
    JOIN RAW.RESOURCE_RELATIONSHIPS r_sa 
        ON REPLACE(s.NAME, '"', '') = r_sa.SOURCE_ID 
        AND r_sa.REL_TYPE = 'USES_DEFAULT_SA'
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
),
toxic_buckets AS (
    -- CRITICAL: Public buckets
    SELECT 
        b.NAME as resource_id,
        REPLACE(b.NAME, '"', '') as clean_name,
        REPLACE(b.SELF_LINK, '"', '') as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image
    FROM GCP_STORAGE_BUCKETS b
    WHERE b.IAM_POLICY LIKE '%allUsers%' OR b.IAM_POLICY LIKE '%allAuthenticatedUsers%'
),
high_iam_confused_deputy AS (
    -- HIGH: IAM roles without confused deputy protection that trust AWS services
    SELECT 
        r.ARN as resource_id,
        REPLACE(r.ARN, '"', '') as clean_name,
        NULL as url,
        NULL as service_account,
        NULL as container_image,
        FALSE as unpinned_image
    FROM AWS_IAM_ROLES r
    WHERE r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%aws:SourceArn%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT NOT LIKE '%aws:SourceAccount%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%sts:AssumeRole%'
      AND r.ASSUME_ROLE_POLICY_DOCUMENT LIKE '%Service%'
),
high_cloudrun_no_auth AS (
    -- HIGH: Cloud Run services with no authentication (not using default SA)
    SELECT 
        s.NAME as resource_id,
        REPLACE(s.NAME, '"', '') as clean_name,
        REPLACE(s.URI, '"', '') as url,
        NULL as service_account,
        TEMPLATE:containers[0]:image::VARCHAR as container_image,
        FALSE as unpinned_image
    FROM GCP_CLOUDRUN_SERVICES s
    WHERE s.INGRESS = 'INGRESS_TRAFFIC_ALL'
      AND NOT EXISTS (
          SELECT 1 FROM RAW.RESOURCE_RELATIONSHIPS r 
          WHERE REPLACE(s.NAME, '"', '') = r.SOURCE_ID AND r.REL_TYPE = 'USES_DEFAULT_SA'
      )
)
-- CRITICAL: Cloud Run with default SA + public + unpinned image = vulnerability risk
SELECT 
    'CRITICAL' as severity,
    'toxic-cloudrun-vuln-default-sa' as policy_id,
    'Internet-facing Cloud Run with vulnerabilities and data access' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run is public, uses default SA with data access, and runs unpinned image susceptible to supply chain attacks' as description,
    'EXTERNAL_EXPOSURE, VULNERABILITY, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA' as risks
FROM toxic_cloudrun_with_vuln
WHERE unpinned_image = TRUE

UNION ALL

-- CRITICAL: Cloud Run with default SA + public (no unpinned image)
SELECT 
    'CRITICAL' as severity,
    'toxic-cloudrun-external-default-sa' as policy_id,
    'Internet-facing Cloud Run with default SA and data access' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run service is publicly accessible, uses default compute service account with broad permissions' as description,
    'EXTERNAL_EXPOSURE, UNPROTECTED_PRINCIPAL, UNPROTECTED_DATA' as risks
FROM toxic_cloudrun_with_vuln
WHERE unpinned_image = FALSE

UNION ALL

SELECT 
    'CRITICAL' as severity,
    'toxic-bucket-public-data' as policy_id,
    'Publicly readable bucket contains sensitive data' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Storage bucket is publicly accessible and may contain sensitive data' as description,
    'EXTERNAL_EXPOSURE, UNPROTECTED_DATA' as risks
FROM toxic_buckets

UNION ALL

SELECT 
    'HIGH' as severity,
    'iam-confused-deputy-risk' as policy_id,
    'IAM role vulnerable to confused deputy attack' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'IAM role trust policy allows AWS services to assume it without SourceArn/SourceAccount conditions' as description,
    'CONFUSED_DEPUTY, PRIVILEGE_ESCALATION' as risks
FROM high_iam_confused_deputy

UNION ALL

SELECT 
    'HIGH' as severity,
    'cloudrun-public-no-auth' as policy_id,
    'Cloud Run service publicly accessible' as title,
    clean_name as resource_name,
    resource_id,
    url,
    service_account,
    container_image,
    'Cloud Run service is exposed to internet without IAM authentication' as description,
    'EXTERNAL_EXPOSURE, NO_AUTHENTICATION' as risks
FROM high_cloudrun_no_auth
`

	result, err := sf.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("toxic combination query failed: %w", err)
	}

	return MapRelationshipToxicRows(result.Rows), nil
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
