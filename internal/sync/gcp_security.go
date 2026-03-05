package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/writer/cerebro/internal/snowflake"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

// GCPSecuritySync handles syncing security-related GCP data
type GCPSecuritySync struct {
	sf        *snowflake.Client
	logger    *slog.Logger
	projectID string
	orgID     string
	filter    map[string]struct{}
}

// GCPSecurityOption configures the GCP security sync
type GCPSecurityOption func(*GCPSecuritySync)

func WithGCPSecurityTableFilter(tables []string) GCPSecurityOption {
	return func(s *GCPSecuritySync) { s.filter = normalizeTableFilter(tables) }
}

// NewGCPSecuritySync creates a new GCP security sync instance
func NewGCPSecuritySync(sf *snowflake.Client, logger *slog.Logger, projectID, orgID string, opts ...GCPSecurityOption) *GCPSecuritySync {
	syncer := &GCPSecuritySync{
		sf:        sf,
		logger:    logger,
		projectID: projectID,
		orgID:     orgID,
	}
	for _, opt := range opts {
		opt(syncer)
	}
	return syncer
}

// SyncAll syncs all GCP security data
func (s *GCPSecuritySync) SyncAll(ctx context.Context) error {
	if len(s.filter) > 0 {
		s.logger.Info("filtering GCP security tables", "tables", strings.Join(filterNames(s.filter), ", "))
	}

	s.logger.Info("starting GCP security sync", "project", s.projectID)

	matched := false

	// Sync vulnerability occurrences from Container Analysis
	if matchesFilter(s.filter, "gcp_container_vulnerabilities", "container_vulnerabilities", "vulnerabilities") {
		matched = true
		if err := s.syncVulnerabilityOccurrences(ctx); err != nil {
			s.logger.Warn("failed to sync vulnerability occurrences", "error", err)
		}
	}

	// Sync Artifact Registry docker images
	if matchesFilter(s.filter, "gcp_artifact_registry_images", "artifact_registry_images", "artifact_images") {
		matched = true
		if err := s.syncArtifactRegistryImages(ctx); err != nil {
			s.logger.Warn("failed to sync artifact registry images", "error", err)
		}
	}

	// Sync Security Command Center findings (if org ID provided)
	if matchesFilter(s.filter, "gcp_scc_findings", "scc_findings", "security_command_center_findings") {
		matched = true
		if s.orgID == "" {
			s.logger.Warn("skipping SCC findings; org ID not set")
		} else if err := s.syncSCCFindings(ctx); err != nil {
			s.logger.Warn("failed to sync SCC findings", "error", err)
		}
	}

	if len(s.filter) > 0 && !matched {
		return fmt.Errorf("no GCP security tables matched filter: %s", strings.Join(filterNames(s.filter), ", "))
	}

	return nil
}

// syncVulnerabilityOccurrences syncs vulnerability data from Container Analysis API
func (s *GCPSecuritySync) syncVulnerabilityOccurrences(ctx context.Context) error {
	client, err := containeranalysis.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return fmt.Errorf("failed to create container analysis client: %w", err)
	}
	defer func() { _ = client.Close() }()

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
		if errors.Is(err, iterator.Done) {
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
			"_cq_id":             occ.GetName(),
			"project_id":         s.projectID,
			"name":               occ.GetName(),
			"resource_uri":       resourceURI,
			"note_name":          occ.GetNoteName(),
			"kind":               "VULNERABILITY",
			"create_time":        occ.GetCreateTime().AsTime().Format(time.RFC3339),
			"update_time":        occ.GetUpdateTime().AsTime().Format(time.RFC3339),
			"severity":           vuln.GetSeverity().String(),
			"cvss_score":         vuln.GetCvssScore(),
			"cvss_v3_score":      vuln.GetCvssv3().GetBaseScore(),
			"effective_severity": vuln.GetEffectiveSeverity().String(),
			"fix_available":      vuln.GetFixAvailable(),
			"long_description":   vuln.GetLongDescription(),
			"short_description":  vuln.GetShortDescription(),
			"cve_id":             extractCVEFromNote(occ.GetNoteName()),
			"package_issue":      formatPackageIssues(vuln.GetPackageIssue()),
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
	client, err := artifactregistry.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry client: %w", err)
	}
	defer func() { _ = client.Close() }()

	secretSignals, err := s.fetchArtifactRegistryImageSecretSignals(ctx)
	if err != nil {
		s.logger.Warn("failed to fetch artifact registry secret signals", "error", err)
		secretSignals = map[string]artifactImageSecretSignal{}
	}

	scanSignals, err := s.fetchArtifactRegistryImageScanSignals(ctx)
	if err != nil {
		s.logger.Warn("failed to fetch artifact registry image scan signals", "error", err)
		scanSignals = map[string]artifactImageScanSignal{}
	}

	vulnerabilitySignals, err := s.fetchArtifactRegistryImageVulnerabilitySignals(ctx)
	if err != nil {
		s.logger.Warn("failed to fetch artifact registry image vulnerability signals", "error", err)
		vulnerabilitySignals = map[string]artifactImageVulnerabilitySignal{}
	}

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
			if errors.Is(err, iterator.Done) {
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
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					s.logger.Warn("failed to list docker images", "error", err, "repo", repo.GetName())
					break
				}

				normalizedURI := normalizeArtifactImageURI(img.GetUri())
				signal := secretSignals[normalizedURI]
				scanSignal := scanSignals[normalizedURI]
				vulnSignal := vulnerabilitySignals[normalizedURI]
				scanStatus := strings.TrimSpace(scanSignal.ScanStatus)
				if scanStatus == "" {
					scanStatus = "UNSCANNED"
				}

				vulnerabilitiesJSON := "[]"
				if len(vulnSignal.CVEIDs) > 0 {
					vulnerabilitiesJSON = marshalJSON(vulnSignal.CVEIDs)
				}

				secretsJSON := "[]"
				if len(signal.Secrets) > 0 {
					secretsJSON = marshalJSON(signal.Secrets)
				}

				images = append(images, map[string]interface{}{
					"_cq_id":                        img.GetUri(),
					"project_id":                    s.projectID,
					"name":                          img.GetName(),
					"uri":                           img.GetUri(),
					"tags":                          strings.Join(img.GetTags(), ","),
					"image_size":                    img.GetImageSizeBytes(),
					"upload_time":                   img.GetUploadTime().AsTime().Format(time.RFC3339),
					"media_type":                    img.GetMediaType(),
					"build_time":                    img.GetBuildTime().AsTime().Format(time.RFC3339),
					"update_time":                   img.GetUpdateTime().AsTime().Format(time.RFC3339),
					"repository":                    repo.GetName(),
					"registry_type":                 detectContainerRegistryType(img.GetUri()),
					"scanned":                       scanSignal.Scanned,
					"scan_status":                   scanStatus,
					"vulnerabilities":               vulnerabilitiesJSON,
					"has_vulnerabilities":           vulnSignal.HasVulnerabilities,
					"has_openssl_vulnerability":     vulnSignal.HasOpenSSLVulnerability,
					"secrets":                       secretsJSON,
					"has_cloud_keys":                signal.HasCloudKeys,
					"has_high_privilege_cloud_keys": signal.HasHighPrivilegeCloudKeys,
					"has_cross_account_cloud_keys":  signal.HasCrossAccountCloudKeys,
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

type artifactImageSecretSignal struct {
	Secrets                   []map[string]interface{}
	HasCloudKeys              bool
	HasHighPrivilegeCloudKeys bool
	HasCrossAccountCloudKeys  bool
}

type artifactImageScanSignal struct {
	Scanned    bool
	ScanStatus string
	UpdatedAt  time.Time
}

type artifactImageVulnerabilitySignal struct {
	CVEIDs                  []string
	HasVulnerabilities      bool
	HasOpenSSLVulnerability bool
}

func (s *GCPSecuritySync) fetchArtifactRegistryImageSecretSignals(ctx context.Context) (map[string]artifactImageSecretSignal, error) {
	client, err := containeranalysis.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create container analysis client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", s.projectID),
		Filter: `kind="SECRET"`,
	}

	grafeasClient := client.GetGrafeasClient()
	it := grafeasClient.ListOccurrences(ctx, req)
	results := make(map[string]artifactImageSecretSignal)

	for {
		occ, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list secret occurrences: %w", err)
		}

		secret := occ.GetSecret()
		if secret == nil {
			continue
		}

		resourceURI := normalizeArtifactImageURI(occ.GetResourceUri())
		if resourceURI == "" || !looksLikeContainerImageURI(resourceURI) {
			continue
		}

		isCloudKey, highPrivilege, crossAccount := classifyCloudKeySignals(secret)
		entry := map[string]interface{}{
			"kind":                  secret.GetKind().String(),
			"type":                  "other",
			"cleartext":             true,
			"grants_high_privilege": false,
			"cross_account_access":  false,
		}
		if isCloudKey {
			entry["type"] = "cloud_key"
			entry["grants_high_privilege"] = highPrivilege
			entry["cross_account_access"] = crossAccount
		}

		statusRows := serializeSecretStatuses(secret.GetStatuses())
		if len(statusRows) > 0 {
			entry["statuses"] = statusRows
		}
		if data := secret.GetData(); data != nil && strings.TrimSpace(data.GetTypeUrl()) != "" {
			entry["data_type_url"] = strings.TrimSpace(data.GetTypeUrl())
		}

		signal := results[resourceURI]
		signal.Secrets = append(signal.Secrets, entry)
		signal.HasCloudKeys = signal.HasCloudKeys || isCloudKey
		signal.HasHighPrivilegeCloudKeys = signal.HasHighPrivilegeCloudKeys || (isCloudKey && highPrivilege)
		signal.HasCrossAccountCloudKeys = signal.HasCrossAccountCloudKeys || (isCloudKey && crossAccount)
		results[resourceURI] = signal
	}

	return results, nil
}

func (s *GCPSecuritySync) fetchArtifactRegistryImageScanSignals(ctx context.Context) (map[string]artifactImageScanSignal, error) {
	client, err := containeranalysis.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create container analysis client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", s.projectID),
		Filter: `kind="DISCOVERY"`,
	}

	grafeasClient := client.GetGrafeasClient()
	it := grafeasClient.ListOccurrences(ctx, req)
	results := make(map[string]artifactImageScanSignal)

	for {
		occ, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list discovery occurrences: %w", err)
		}

		discovery := occ.GetDiscovery()
		if discovery == nil {
			continue
		}

		resourceURI := normalizeArtifactImageURI(occ.GetResourceUri())
		if resourceURI == "" || !looksLikeContainerImageURI(resourceURI) {
			continue
		}

		scanned, scanStatus := classifyImageScanStatus(discovery.GetAnalysisStatus())
		candidate := artifactImageScanSignal{
			Scanned:    scanned,
			ScanStatus: scanStatus,
		}
		if updateTime := occ.GetUpdateTime(); updateTime != nil {
			candidate.UpdatedAt = updateTime.AsTime()
		}

		existing, ok := results[resourceURI]
		if !ok || shouldReplaceScanSignal(existing, candidate) {
			results[resourceURI] = candidate
		}
	}

	return results, nil
}

func (s *GCPSecuritySync) fetchArtifactRegistryImageVulnerabilitySignals(ctx context.Context) (map[string]artifactImageVulnerabilitySignal, error) {
	client, err := containeranalysis.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("failed to create container analysis client: %w", err)
	}
	defer func() { _ = client.Close() }()

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", s.projectID),
		Filter: `kind="VULNERABILITY"`,
	}

	grafeasClient := client.GetGrafeasClient()
	it := grafeasClient.ListOccurrences(ctx, req)
	results := make(map[string]artifactImageVulnerabilitySignal)

	for {
		occ, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list vulnerability occurrences: %w", err)
		}

		vulnerability := occ.GetVulnerability()
		if vulnerability == nil {
			continue
		}

		resourceURI := normalizeArtifactImageURI(occ.GetResourceUri())
		if resourceURI == "" || !looksLikeContainerImageURI(resourceURI) {
			continue
		}

		signal := results[resourceURI]
		signal.HasVulnerabilities = true

		cveID := strings.ToUpper(strings.TrimSpace(extractCVEFromNote(occ.GetNoteName())))
		if cveID != "" {
			signal.CVEIDs = appendUniqueString(signal.CVEIDs, cveID)
			if isOpenSSLCVE(cveID) {
				signal.HasOpenSSLVulnerability = true
			}
		}

		results[resourceURI] = signal
	}

	for resourceURI, signal := range results {
		sort.Strings(signal.CVEIDs)
		results[resourceURI] = signal
	}

	return results, nil
}

func classifyImageScanStatus(status grafeaspb.DiscoveryOccurrence_AnalysisStatus) (scanned bool, scanStatus string) {
	if status == grafeaspb.DiscoveryOccurrence_ANALYSIS_STATUS_UNSPECIFIED {
		return false, "UNSCANNED"
	}

	return status == grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS || status == grafeaspb.DiscoveryOccurrence_COMPLETE,
		status.String()
}

func shouldReplaceScanSignal(existing artifactImageScanSignal, candidate artifactImageScanSignal) bool {
	if candidate.Scanned && !existing.Scanned {
		return true
	}
	if !candidate.UpdatedAt.IsZero() && (existing.UpdatedAt.IsZero() || candidate.UpdatedAt.After(existing.UpdatedAt)) {
		return true
	}
	if strings.TrimSpace(existing.ScanStatus) == "" && strings.TrimSpace(candidate.ScanStatus) != "" {
		return true
	}
	return false
}

func classifyCloudKeySignals(secret *grafeaspb.SecretOccurrence) (isCloudKey bool, highPrivilege bool, crossAccount bool) {
	if secret == nil || !isCloudSecretKind(secret.GetKind()) {
		return false, false, false
	}

	validStatus, highFromStatus, crossFromStatus := classifySecretStatuses(secret.GetStatuses())
	highPrivilege = highFromStatus || validStatus
	return true, highPrivilege, crossFromStatus
}

func classifySecretStatuses(statuses []*grafeaspb.SecretStatus) (valid bool, highPrivilege bool, crossAccount bool) {
	for _, status := range statuses {
		if status == nil {
			continue
		}

		if status.GetStatus() == grafeaspb.SecretStatus_VALID {
			valid = true
		}

		high, cross := classifySecretStatusMessage(status.GetMessage())
		highPrivilege = highPrivilege || high
		crossAccount = crossAccount || cross
	}

	return valid, highPrivilege, crossAccount
}

func classifySecretStatusMessage(message string) (highPrivilege bool, crossAccount bool) {
	message = strings.ToLower(strings.TrimSpace(message))
	if message == "" {
		return false, false
	}

	highIndicators := []string{"admin", "owner", "high privilege", "privileged", "full access", "write access", "elevated"}
	for _, indicator := range highIndicators {
		if strings.Contains(message, indicator) {
			highPrivilege = true
			break
		}
	}

	crossIndicators := []string{"cross-account", "cross account", "cross-project", "cross project", "other project", "other subscription", "external account", "external project"}
	for _, indicator := range crossIndicators {
		if strings.Contains(message, indicator) {
			crossAccount = true
			break
		}
	}

	return highPrivilege, crossAccount
}

func serializeSecretStatuses(statuses []*grafeaspb.SecretStatus) []map[string]interface{} {
	rows := make([]map[string]interface{}, 0, len(statuses))
	for _, status := range statuses {
		if status == nil {
			continue
		}
		row := map[string]interface{}{
			"status": status.GetStatus().String(),
		}
		if message := strings.TrimSpace(status.GetMessage()); message != "" {
			row["message"] = message
		}
		if updateTime := status.GetUpdateTime(); updateTime != nil {
			row["update_time"] = updateTime.AsTime().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}
	return rows
}

func isCloudSecretKind(kind grafeaspb.SecretKind) bool {
	switch kind {
	case grafeaspb.SecretKind_SECRET_KIND_GCP_SERVICE_ACCOUNT_KEY,
		grafeaspb.SecretKind_SECRET_KIND_GCP_API_KEY,
		grafeaspb.SecretKind_SECRET_KIND_GCP_OAUTH2_CLIENT_CREDENTIALS,
		grafeaspb.SecretKind_SECRET_KIND_GCP_OAUTH2_ACCESS_TOKEN,
		grafeaspb.SecretKind_SECRET_KIND_AZURE_ACCESS_TOKEN,
		grafeaspb.SecretKind_SECRET_KIND_AZURE_IDENTITY_TOKEN:
		return true
	default:
		return false
	}
}

func looksLikeContainerImageURI(uri string) bool {
	uri = strings.ToLower(strings.TrimSpace(uri))
	if uri == "" {
		return false
	}
	return strings.Contains(uri, "pkg.dev/") || strings.Contains(uri, "gcr.io/")
}

func detectContainerRegistryType(uri string) string {
	uri = strings.ToLower(normalizeArtifactImageURI(uri))
	if uri == "" {
		return "unknown"
	}
	if strings.Contains(uri, "gcr.io/") {
		return "gcr"
	}
	if strings.Contains(uri, "pkg.dev/") {
		return "artifact_registry"
	}
	return "unknown"
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func isOpenSSLCVE(cveID string) bool {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	return cveID == "CVE-2022-3602" || cveID == "CVE-2022-3786"
}

func normalizeArtifactImageURI(uri string) string {
	uri = strings.TrimSpace(uri)
	uri = strings.TrimPrefix(uri, "https://")
	uri = strings.TrimPrefix(uri, "http://")
	uri = strings.TrimSuffix(uri, "/")
	return uri
}

func marshalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// syncSCCFindings syncs findings from Security Command Center
func (s *GCPSecuritySync) syncSCCFindings(ctx context.Context) error {
	client, err := securitycenter.NewClient(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return fmt.Errorf("failed to create security center client: %w", err)
	}
	defer func() { _ = client.Close() }()

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
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate findings: %w", err)
		}

		finding := resp.GetFinding()
		findings = append(findings, map[string]interface{}{
			"_cq_id":        finding.GetName(),
			"project_id":    s.projectID,
			"name":          finding.GetName(),
			"parent":        finding.GetParent(),
			"resource_name": finding.GetResourceName(),
			"state":         finding.GetState().String(),
			"category":      finding.GetCategory(),
			"external_uri":  finding.GetExternalUri(),
			"severity":      finding.GetSeverity().String(),
			"finding_class": finding.GetFindingClass().String(),
			"mute":          finding.GetMute().String(),
			"create_time":   finding.GetCreateTime().AsTime().Format(time.RFC3339),
			"event_time":    finding.GetEventTime().AsTime().Format(time.RFC3339),
			"description":   finding.GetDescription(),
			"indicator":     formatIndicator(finding.GetIndicator()),
			"vulnerability": formatVulnerability(finding.GetVulnerability()),
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
	deleteSQL := "DELETE FROM GCP_CONTAINER_VULNERABILITIES WHERE PROJECT_ID = ?"
	if _, err := s.sf.Exec(ctx, deleteSQL, s.projectID); err != nil {
		s.logger.Warn("failed to delete existing vulnerabilities", "error", err)
	}

	// Insert records
	insertSQL := `
		INSERT INTO GCP_CONTAINER_VULNERABILITIES
		(_CQ_ID, PROJECT_ID, NAME, RESOURCE_URI, NOTE_NAME, KIND, CREATE_TIME, UPDATE_TIME,
		 SEVERITY, CVSS_SCORE, CVSS_V3_SCORE, EFFECTIVE_SEVERITY, FIX_AVAILABLE,
		 LONG_DESCRIPTION, SHORT_DESCRIPTION, CVE_ID, PACKAGE_ISSUE)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, v := range vulns {
		if _, err := s.sf.Exec(ctx, insertSQL,
			toStr(v["_cq_id"]),
			toStr(v["project_id"]),
			toStr(v["name"]),
			toStr(v["resource_uri"]),
			toStr(v["note_name"]),
			toStr(v["kind"]),
			toStr(v["create_time"]),
			toStr(v["update_time"]),
			toStr(v["severity"]),
			v["cvss_score"],
			v["cvss_v3_score"],
			toStr(v["effective_severity"]),
			v["fix_available"],
			toStr(v["long_description"]),
			toStr(v["short_description"]),
			toStr(v["cve_id"]),
			toStr(v["package_issue"]),
		); err != nil {
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
		REPOSITORY VARCHAR,
		REGISTRY_TYPE VARCHAR,
		SCANNED BOOLEAN,
		SCAN_STATUS VARCHAR,
		VULNERABILITIES VARCHAR,
		HAS_VULNERABILITIES BOOLEAN,
		HAS_OPENSSL_VULNERABILITY BOOLEAN,
		SECRETS VARCHAR,
		HAS_CLOUD_KEYS BOOLEAN,
		HAS_HIGH_PRIVILEGE_CLOUD_KEYS BOOLEAN,
		HAS_CROSS_ACCOUNT_CLOUD_KEYS BOOLEAN
	)`

	if _, err := s.sf.Query(ctx, createSQL); err != nil {
		return fmt.Errorf("failed to create images table: %w", err)
	}

	for _, stmt := range []string{
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS REGISTRY_TYPE VARCHAR",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS SCANNED BOOLEAN",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS SCAN_STATUS VARCHAR",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS VULNERABILITIES VARCHAR",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS HAS_VULNERABILITIES BOOLEAN",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS HAS_OPENSSL_VULNERABILITY BOOLEAN",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS SECRETS VARCHAR",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS HAS_CLOUD_KEYS BOOLEAN",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS HAS_HIGH_PRIVILEGE_CLOUD_KEYS BOOLEAN",
		"ALTER TABLE GCP_ARTIFACT_REGISTRY_IMAGES ADD COLUMN IF NOT EXISTS HAS_CROSS_ACCOUNT_CLOUD_KEYS BOOLEAN",
	} {
		if _, err := s.sf.Exec(ctx, stmt); err != nil {
			s.logger.Warn("failed to alter images table", "statement", stmt, "error", err)
		}
	}

	deleteSQL := "DELETE FROM GCP_ARTIFACT_REGISTRY_IMAGES WHERE PROJECT_ID = ?"
	if _, err := s.sf.Exec(ctx, deleteSQL, s.projectID); err != nil {
		s.logger.Warn("failed to delete existing images", "error", err)
	}

	insertSQL := `
		INSERT INTO GCP_ARTIFACT_REGISTRY_IMAGES
		(_CQ_ID, PROJECT_ID, NAME, URI, TAGS, IMAGE_SIZE, UPLOAD_TIME, MEDIA_TYPE, BUILD_TIME, UPDATE_TIME, REPOSITORY, REGISTRY_TYPE, SCANNED, SCAN_STATUS, VULNERABILITIES, HAS_VULNERABILITIES, HAS_OPENSSL_VULNERABILITY, SECRETS, HAS_CLOUD_KEYS, HAS_HIGH_PRIVILEGE_CLOUD_KEYS, HAS_CROSS_ACCOUNT_CLOUD_KEYS)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, img := range images {
		if _, err := s.sf.Exec(ctx, insertSQL,
			toStr(img["_cq_id"]),
			toStr(img["project_id"]),
			toStr(img["name"]),
			toStr(img["uri"]),
			toStr(img["tags"]),
			img["image_size"],
			toStr(img["upload_time"]),
			toStr(img["media_type"]),
			toStr(img["build_time"]),
			toStr(img["update_time"]),
			toStr(img["repository"]),
			toStr(img["registry_type"]),
			img["scanned"],
			toStr(img["scan_status"]),
			toStr(img["vulnerabilities"]),
			img["has_vulnerabilities"],
			img["has_openssl_vulnerability"],
			toStr(img["secrets"]),
			img["has_cloud_keys"],
			img["has_high_privilege_cloud_keys"],
			img["has_cross_account_cloud_keys"],
		); err != nil {
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

	deleteSQL := "DELETE FROM GCP_SCC_FINDINGS WHERE PROJECT_ID = ?"
	if _, err := s.sf.Exec(ctx, deleteSQL, s.projectID); err != nil {
		s.logger.Warn("failed to delete existing SCC findings", "error", err)
	}

	insertSQL := `
		INSERT INTO GCP_SCC_FINDINGS
		(_CQ_ID, PROJECT_ID, NAME, PARENT, RESOURCE_NAME, STATE, CATEGORY, EXTERNAL_URI,
		 SEVERITY, FINDING_CLASS, MUTE, CREATE_TIME, EVENT_TIME, DESCRIPTION, INDICATOR, VULNERABILITY)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for _, f := range findings {
		if _, err := s.sf.Exec(ctx, insertSQL,
			toStr(f["_cq_id"]),
			toStr(f["project_id"]),
			toStr(f["name"]),
			toStr(f["parent"]),
			toStr(f["resource_name"]),
			toStr(f["state"]),
			toStr(f["category"]),
			toStr(f["external_uri"]),
			toStr(f["severity"]),
			toStr(f["finding_class"]),
			toStr(f["mute"]),
			toStr(f["create_time"]),
			toStr(f["event_time"]),
			toStr(f["description"]),
			toStr(f["indicator"]),
			toStr(f["vulnerability"]),
		); err != nil {
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
