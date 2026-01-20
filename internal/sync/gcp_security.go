package sync

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/writerinternal/cerebro/internal/snowflake"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

// GCPSecuritySync handles syncing security-related GCP data
type GCPSecuritySync struct {
	sf        *snowflake.Client
	logger    *slog.Logger
	projectID string
	orgID     string
}

// NewGCPSecuritySync creates a new GCP security sync instance
func NewGCPSecuritySync(sf *snowflake.Client, logger *slog.Logger, projectID, orgID string) *GCPSecuritySync {
	return &GCPSecuritySync{
		sf:        sf,
		logger:    logger,
		projectID: projectID,
		orgID:     orgID,
	}
}

// SyncAll syncs all GCP security data
func (s *GCPSecuritySync) SyncAll(ctx context.Context) error {
	s.logger.Info("starting GCP security sync", "project", s.projectID)

	// Sync vulnerability occurrences from Container Analysis
	if err := s.syncVulnerabilityOccurrences(ctx); err != nil {
		s.logger.Warn("failed to sync vulnerability occurrences", "error", err)
	}

	// Sync Artifact Registry docker images
	if err := s.syncArtifactRegistryImages(ctx); err != nil {
		s.logger.Warn("failed to sync artifact registry images", "error", err)
	}

	// Sync Security Command Center findings (if org ID provided)
	if s.orgID != "" {
		if err := s.syncSCCFindings(ctx); err != nil {
			s.logger.Warn("failed to sync SCC findings", "error", err)
		}
	}

	return nil
}

// syncVulnerabilityOccurrences syncs vulnerability data from Container Analysis API
func (s *GCPSecuritySync) syncVulnerabilityOccurrences(ctx context.Context) error {
	client, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create container analysis client: %w", err)
	}
	defer client.Close()

	grafeasClient := client.GetGrafeasClient()

	parent := fmt.Sprintf("projects/%s", s.projectID)
	filter := `kind="VULNERABILITY"`

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: parent,
		Filter: filter,
	}

	var vulns []map[string]interface{}
	it := grafeasClient.ListOccurrences(ctx, req)
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate occurrences: %w", err)
		}

		vuln := occ.GetVulnerability()
		if vuln == nil {
			continue
		}

		// Extract resource URI (container image)
		resourceURI := occ.GetResourceUri()

		vulns = append(vulns, map[string]interface{}{
			"_cq_id":            occ.GetName(),
			"project_id":        s.projectID,
			"name":              occ.GetName(),
			"resource_uri":      resourceURI,
			"note_name":         occ.GetNoteName(),
			"kind":              "VULNERABILITY",
			"create_time":       occ.GetCreateTime().AsTime().Format(time.RFC3339),
			"update_time":       occ.GetUpdateTime().AsTime().Format(time.RFC3339),
			"severity":          vuln.GetSeverity().String(),
			"cvss_score":        vuln.GetCvssScore(),
			"cvss_v3_score":     vuln.GetCvssv3().GetBaseScore(),
			"effective_severity": vuln.GetEffectiveSeverity().String(),
			"fix_available":     vuln.GetFixAvailable(),
			"long_description":  vuln.GetLongDescription(),
			"short_description": vuln.GetShortDescription(),
			"cve_id":            extractCVEFromNote(occ.GetNoteName()),
			"package_issue":     formatPackageIssues(vuln.GetPackageIssue()),
		})
	}

	s.logger.Info("synced vulnerability occurrences", "count", len(vulns))

	if len(vulns) > 0 {
		return s.upsertVulnerabilities(ctx, vulns)
	}

	return nil
}

// syncArtifactRegistryImages syncs docker images from Artifact Registry
func (s *GCPSecuritySync) syncArtifactRegistryImages(ctx context.Context) error {
	client, err := artifactregistry.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry client: %w", err)
	}
	defer client.Close()

	// List all repositories across common locations
	locations := []string{"us", "us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"}
	
	var images []map[string]interface{}
	for _, loc := range locations {
		repoReq := &artifactregistrypb.ListRepositoriesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", s.projectID, loc),
		}

		repoIt := client.ListRepositories(ctx, repoReq)
		for {
			repo, err := repoIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				// Skip locations that don't exist or have no repos
				break
			}

			// Only process Docker repositories
			if repo.GetFormat() != artifactregistrypb.Repository_DOCKER {
				continue
			}

			// List docker images in this repository
			imgReq := &artifactregistrypb.ListDockerImagesRequest{
				Parent: repo.GetName(),
			}

			imgIt := client.ListDockerImages(ctx, imgReq)
			for {
				img, err := imgIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					s.logger.Warn("failed to list docker images", "error", err, "repo", repo.GetName())
					break
				}

				images = append(images, map[string]interface{}{
					"_cq_id":         img.GetUri(),
					"project_id":     s.projectID,
					"name":           img.GetName(),
					"uri":            img.GetUri(),
					"tags":           strings.Join(img.GetTags(), ","),
					"image_size":     img.GetImageSizeBytes(),
					"upload_time":    img.GetUploadTime().AsTime().Format(time.RFC3339),
					"media_type":     img.GetMediaType(),
					"build_time":     img.GetBuildTime().AsTime().Format(time.RFC3339),
					"update_time":    img.GetUpdateTime().AsTime().Format(time.RFC3339),
					"repository":     repo.GetName(),
				})
			}
		}
	}

	s.logger.Info("synced artifact registry images", "count", len(images))

	if len(images) > 0 {
		return s.upsertDockerImages(ctx, images)
	}

	return nil
}

// syncSCCFindings syncs findings from Security Command Center
func (s *GCPSecuritySync) syncSCCFindings(ctx context.Context) error {
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create security center client: %w", err)
	}
	defer client.Close()

	parent := fmt.Sprintf("organizations/%s/sources/-", s.orgID)
	
	// Filter for active, high severity findings
	filter := `state="ACTIVE" AND (severity="CRITICAL" OR severity="HIGH")`

	req := &securitycenterpb.ListFindingsRequest{
		Parent: parent,
		Filter: filter,
	}

	var findings []map[string]interface{}
	it := client.ListFindings(ctx, req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate findings: %w", err)
		}

		finding := resp.GetFinding()
		findings = append(findings, map[string]interface{}{
			"_cq_id":           finding.GetName(),
			"project_id":       s.projectID,
			"name":             finding.GetName(),
			"parent":           finding.GetParent(),
			"resource_name":    finding.GetResourceName(),
			"state":            finding.GetState().String(),
			"category":         finding.GetCategory(),
			"external_uri":     finding.GetExternalUri(),
			"severity":         finding.GetSeverity().String(),
			"finding_class":    finding.GetFindingClass().String(),
			"mute":             finding.GetMute().String(),
			"create_time":      finding.GetCreateTime().AsTime().Format(time.RFC3339),
			"event_time":       finding.GetEventTime().AsTime().Format(time.RFC3339),
			"description":      finding.GetDescription(),
			"indicator":        formatIndicator(finding.GetIndicator()),
			"vulnerability":    formatVulnerability(finding.GetVulnerability()),
		})
	}

	s.logger.Info("synced SCC findings", "count", len(findings))

	if len(findings) > 0 {
		return s.upsertSCCFindings(ctx, findings)
	}

	return nil
}

// upsertVulnerabilities saves vulnerability data to Snowflake
func (s *GCPSecuritySync) upsertVulnerabilities(ctx context.Context, vulns []map[string]interface{}) error {
	// Create table if not exists
	createSQL := `
	CREATE TABLE IF NOT EXISTS GCP_CONTAINER_VULNERABILITIES (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		PROJECT_ID VARCHAR,
		NAME VARCHAR,
		RESOURCE_URI VARCHAR,
		NOTE_NAME VARCHAR,
		KIND VARCHAR,
		CREATE_TIME VARCHAR,
		UPDATE_TIME VARCHAR,
		SEVERITY VARCHAR,
		CVSS_SCORE FLOAT,
		CVSS_V3_SCORE FLOAT,
		EFFECTIVE_SEVERITY VARCHAR,
		FIX_AVAILABLE BOOLEAN,
		LONG_DESCRIPTION VARCHAR,
		SHORT_DESCRIPTION VARCHAR,
		CVE_ID VARCHAR,
		PACKAGE_ISSUE VARCHAR
	)`

	if _, err := s.sf.Query(ctx, createSQL); err != nil {
		return fmt.Errorf("failed to create vulnerabilities table: %w", err)
	}

	// Delete existing and insert new
	deleteSQL := fmt.Sprintf("DELETE FROM GCP_CONTAINER_VULNERABILITIES WHERE PROJECT_ID = '%s'", s.projectID)
	if _, err := s.sf.Query(ctx, deleteSQL); err != nil {
		s.logger.Warn("failed to delete existing vulnerabilities", "error", err)
	}

	// Insert records
	for _, v := range vulns {
		insertSQL := fmt.Sprintf(`
		INSERT INTO GCP_CONTAINER_VULNERABILITIES 
		(_CQ_ID, PROJECT_ID, NAME, RESOURCE_URI, NOTE_NAME, KIND, CREATE_TIME, UPDATE_TIME, 
		 SEVERITY, CVSS_SCORE, CVSS_V3_SCORE, EFFECTIVE_SEVERITY, FIX_AVAILABLE, 
		 LONG_DESCRIPTION, SHORT_DESCRIPTION, CVE_ID, PACKAGE_ISSUE)
		VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %v, %v, '%s', %v, '%s', '%s', '%s', '%s')`,
			escapeSQL(toStr(v["_cq_id"])),
			escapeSQL(toStr(v["project_id"])),
			escapeSQL(toStr(v["name"])),
			escapeSQL(toStr(v["resource_uri"])),
			escapeSQL(toStr(v["note_name"])),
			escapeSQL(toStr(v["kind"])),
			escapeSQL(toStr(v["create_time"])),
			escapeSQL(toStr(v["update_time"])),
			escapeSQL(toStr(v["severity"])),
			v["cvss_score"],
			v["cvss_v3_score"],
			escapeSQL(toStr(v["effective_severity"])),
			v["fix_available"],
			escapeSQL(toStr(v["long_description"])),
			escapeSQL(toStr(v["short_description"])),
			escapeSQL(toStr(v["cve_id"])),
			escapeSQL(toStr(v["package_issue"])),
		)
		if _, err := s.sf.Query(ctx, insertSQL); err != nil {
			s.logger.Warn("failed to insert vulnerability", "error", err, "cve", v["cve_id"])
		}
	}
	return nil
}

// upsertDockerImages saves docker image data to Snowflake
func (s *GCPSecuritySync) upsertDockerImages(ctx context.Context, images []map[string]interface{}) error {
	createSQL := `
	CREATE TABLE IF NOT EXISTS GCP_ARTIFACT_REGISTRY_IMAGES (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		PROJECT_ID VARCHAR,
		NAME VARCHAR,
		URI VARCHAR,
		TAGS VARCHAR,
		IMAGE_SIZE NUMBER,
		UPLOAD_TIME VARCHAR,
		MEDIA_TYPE VARCHAR,
		BUILD_TIME VARCHAR,
		UPDATE_TIME VARCHAR,
		REPOSITORY VARCHAR
	)`

	if _, err := s.sf.Query(ctx, createSQL); err != nil {
		return fmt.Errorf("failed to create images table: %w", err)
	}

	deleteSQL := fmt.Sprintf("DELETE FROM GCP_ARTIFACT_REGISTRY_IMAGES WHERE PROJECT_ID = '%s'", s.projectID)
	if _, err := s.sf.Query(ctx, deleteSQL); err != nil {
		s.logger.Warn("failed to delete existing images", "error", err)
	}

	for _, img := range images {
		insertSQL := fmt.Sprintf(`
		INSERT INTO GCP_ARTIFACT_REGISTRY_IMAGES 
		(_CQ_ID, PROJECT_ID, NAME, URI, TAGS, IMAGE_SIZE, UPLOAD_TIME, MEDIA_TYPE, BUILD_TIME, UPDATE_TIME, REPOSITORY)
		VALUES ('%s', '%s', '%s', '%s', '%s', %v, '%s', '%s', '%s', '%s', '%s')`,
			escapeSQL(toStr(img["_cq_id"])),
			escapeSQL(toStr(img["project_id"])),
			escapeSQL(toStr(img["name"])),
			escapeSQL(toStr(img["uri"])),
			escapeSQL(toStr(img["tags"])),
			img["image_size"],
			escapeSQL(toStr(img["upload_time"])),
			escapeSQL(toStr(img["media_type"])),
			escapeSQL(toStr(img["build_time"])),
			escapeSQL(toStr(img["update_time"])),
			escapeSQL(toStr(img["repository"])),
		)
		if _, err := s.sf.Query(ctx, insertSQL); err != nil {
			s.logger.Warn("failed to insert image", "error", err, "uri", img["uri"])
		}
	}
	return nil
}

// upsertSCCFindings saves SCC findings to Snowflake
func (s *GCPSecuritySync) upsertSCCFindings(ctx context.Context, findings []map[string]interface{}) error {
	createSQL := `
	CREATE TABLE IF NOT EXISTS GCP_SCC_FINDINGS (
		_CQ_ID VARCHAR PRIMARY KEY,
		_CQ_SYNC_TIME TIMESTAMP_TZ DEFAULT CURRENT_TIMESTAMP(),
		PROJECT_ID VARCHAR,
		NAME VARCHAR,
		PARENT VARCHAR,
		RESOURCE_NAME VARCHAR,
		STATE VARCHAR,
		CATEGORY VARCHAR,
		EXTERNAL_URI VARCHAR,
		SEVERITY VARCHAR,
		FINDING_CLASS VARCHAR,
		MUTE VARCHAR,
		CREATE_TIME VARCHAR,
		EVENT_TIME VARCHAR,
		DESCRIPTION VARCHAR,
		INDICATOR VARCHAR,
		VULNERABILITY VARCHAR
	)`

	if _, err := s.sf.Query(ctx, createSQL); err != nil {
		return fmt.Errorf("failed to create SCC findings table: %w", err)
	}

	deleteSQL := fmt.Sprintf("DELETE FROM GCP_SCC_FINDINGS WHERE PROJECT_ID = '%s'", s.projectID)
	if _, err := s.sf.Query(ctx, deleteSQL); err != nil {
		s.logger.Warn("failed to delete existing SCC findings", "error", err)
	}

	for _, f := range findings {
		insertSQL := fmt.Sprintf(`
		INSERT INTO GCP_SCC_FINDINGS 
		(_CQ_ID, PROJECT_ID, NAME, PARENT, RESOURCE_NAME, STATE, CATEGORY, EXTERNAL_URI, 
		 SEVERITY, FINDING_CLASS, MUTE, CREATE_TIME, EVENT_TIME, DESCRIPTION, INDICATOR, VULNERABILITY)
		VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`,
			escapeSQL(toStr(f["_cq_id"])),
			escapeSQL(toStr(f["project_id"])),
			escapeSQL(toStr(f["name"])),
			escapeSQL(toStr(f["parent"])),
			escapeSQL(toStr(f["resource_name"])),
			escapeSQL(toStr(f["state"])),
			escapeSQL(toStr(f["category"])),
			escapeSQL(toStr(f["external_uri"])),
			escapeSQL(toStr(f["severity"])),
			escapeSQL(toStr(f["finding_class"])),
			escapeSQL(toStr(f["mute"])),
			escapeSQL(toStr(f["create_time"])),
			escapeSQL(toStr(f["event_time"])),
			escapeSQL(toStr(f["description"])),
			escapeSQL(toStr(f["indicator"])),
			escapeSQL(toStr(f["vulnerability"])),
		)
		if _, err := s.sf.Query(ctx, insertSQL); err != nil {
			s.logger.Warn("failed to insert SCC finding", "error", err, "name", f["name"])
		}
	}
	return nil
}

// Helper functions
func extractCVEFromNote(noteName string) string {
	// Note name format: projects/goog-vulnz/notes/CVE-2024-1234
	parts := strings.Split(noteName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func formatPackageIssues(issues []*grafeaspb.VulnerabilityOccurrence_PackageIssue) string {
	if len(issues) == 0 {
		return ""
	}
	var parts []string
	for _, issue := range issues {
		pkg := issue.GetAffectedPackage()
		version := issue.GetAffectedVersion().GetFullName()
		fixed := issue.GetFixedVersion().GetFullName()
		parts = append(parts, fmt.Sprintf("%s@%s (fix: %s)", pkg, version, fixed))
	}
	return strings.Join(parts, "; ")
}

func formatIndicator(ind *securitycenterpb.Indicator) string {
	if ind == nil {
		return ""
	}
	var parts []string
	for _, ip := range ind.GetIpAddresses() {
		parts = append(parts, "ip:"+ip)
	}
	for _, domain := range ind.GetDomains() {
		parts = append(parts, "domain:"+domain)
	}
	return strings.Join(parts, ",")
}

func formatVulnerability(vuln *securitycenterpb.Vulnerability) string {
	if vuln == nil {
		return ""
	}
	cve := vuln.GetCve()
	if cve == nil {
		return ""
	}
	// Get CVSS score from Cvssv3 if available
	cvssScore := 0.0
	if cvss := cve.GetCvssv3(); cvss != nil {
		cvssScore = cvss.GetBaseScore()
	}
	return fmt.Sprintf("%s (CVSS: %.1f)", cve.GetId(), cvssScore)
}

// toStr safely converts interface{} to string for SQL escaping
func toStr(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
