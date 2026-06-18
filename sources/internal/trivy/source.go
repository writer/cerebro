package trivyinternal

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	packageurl "github.com/package-url/packageurl-go"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

//go:embed catalog.internal.yaml
var catalogFS embed.FS

const (
	sourceID                 = "trivy"
	familyImageScan          = "image_scan"
	familyImagePackage       = "image_package"
	familyImageVulnerability = "image_vulnerability"
	familyFix                = "fix"
	defaultFamily            = familyImageVulnerability
)

type settings struct {
	tenantID string
	family   string
	path     string
}

type Source struct {
	spec     *cerebrov1.SourceSpec
	families *sourcecdk.FamilyEngine[settings]
	readFile func(string) ([]byte, error)
	now      func() time.Time
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{
		spec:     spec,
		readFile: os.ReadFile,
		now:      func() time.Time { return time.Now().UTC() },
	}
	families, err := sourcecdk.NewFamilyEngine(source.parseSettings, func(st settings) string { return st.family },
		source.family(familyImageScan),
		source.family(familyImagePackage),
		source.family(familyImageVulnerability),
		source.family(familyFix),
	)
	if err != nil {
		return nil, err
	}
	source.families = families
	return source, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) family(name string) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: name,
		Check: func(_ context.Context, st settings) error {
			_, err := s.loadReport(st)
			return err
		},
		Discover: func(_ context.Context, st settings) ([]sourcecdk.URN, error) {
			report, err := s.loadReport(st)
			if err != nil {
				return nil, err
			}
			urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:trivy_report:%s", url.PathEscape(st.tenantID), url.PathEscape(firstNonEmpty(report.Metadata.ImageID, report.ArtifactName, stableID(st.path)))))
			if err != nil {
				return nil, err
			}
			return []sourcecdk.URN{urn}, nil
		},
		Read: func(_ context.Context, st settings, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			report, err := s.loadReport(st)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events, err := s.events(st, report)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			return sourcecdk.Pull{Events: events}, nil
		},
	}
}

func (s *Source) parseSettings(cfg sourcecdk.Config) (settings, error) {
	st := settings{
		tenantID: firstNonEmpty(configValue(cfg, "tenant_id"), configValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:   strings.TrimSpace(configValue(cfg, "family")),
		path:     strings.TrimSpace(firstNonEmpty(configValue(cfg, "path"), configValue(cfg, "report_path"))),
	}
	if st.family == "" {
		st.family = defaultFamily
	}
	switch st.family {
	case familyImageScan, familyImagePackage, familyImageVulnerability, familyFix:
	default:
		return st, fmt.Errorf("trivy family must be one of image_scan, image_package, image_vulnerability, or fix")
	}
	if st.tenantID == "" {
		return st, fmt.Errorf("trivy tenant_id is required")
	}
	if st.path == "" {
		return st, fmt.Errorf("trivy report path is required")
	}
	return st, nil
}

type report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      metadata `json:"Metadata"`
	Results       []result `json:"Results"`
}

type metadata struct {
	ImageID     string   `json:"ImageID"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

type result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
	Packages        []pkg           `json:"Packages"`
}

type vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Status           string            `json:"Status"`
	Severity         string            `json:"Severity"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	PrimaryURL       string            `json:"PrimaryURL"`
	PkgIdentifier    packageIdentifier `json:"PkgIdentifier"`
	CVSS             map[string]any    `json:"CVSS"`
}

type pkg struct {
	ID         string            `json:"ID"`
	Name       string            `json:"Name"`
	Version    string            `json:"Version"`
	Identifier packageIdentifier `json:"Identifier"`
}

type packageIdentifier struct {
	PURL string `json:"PURL"`
}

func (s *Source) loadReport(st settings) (report, error) {
	raw, err := s.readFile(st.path)
	if err != nil {
		return report{}, fmt.Errorf("read trivy report: %w", err)
	}
	var out report
	if err := json.Unmarshal(raw, &out); err != nil {
		return report{}, fmt.Errorf("decode trivy report: %w", err)
	}
	if imageDigest(out) == "" {
		return report{}, fmt.Errorf("trivy report must include Metadata.RepoDigests or an image digest")
	}
	return out, nil
}

func (s *Source) events(st settings, report report) ([]*primitives.Event, error) {
	switch st.family {
	case familyImageScan:
		return s.scanEvents(st, report)
	case familyImagePackage:
		return s.packageEvents(st, report)
	case familyImageVulnerability:
		return s.vulnerabilityEvents(st, report)
	case familyFix:
		return s.fixEvents(st, report)
	default:
		return nil, fmt.Errorf("unsupported trivy family %q", st.family)
	}
}

func (s *Source) scanEvents(st settings, report report) ([]*primitives.Event, error) {
	payload := map[string]any{"image_digest": imageDigest(report), "artifact_name": report.ArtifactName, "artifact_type": report.ArtifactType, "repo_tags": report.Metadata.RepoTags, "repo_digests": report.Metadata.RepoDigests}
	event, err := s.event(st, "trivy-image-scan-"+stableID(imageDigest(report)), "trivy.image_scan", "trivy/image_scan/v1", payload, map[string]string{"image_digest": imageDigest(report), "image_uri": firstNonEmpty(report.ArtifactName, firstRepoDigest(report)), "scanner": "trivy"}, s.now())
	if err != nil {
		return nil, err
	}
	return []*primitives.Event{event}, nil
}

func (s *Source) vulnerabilityEvents(st settings, report report) ([]*primitives.Event, error) {
	events := []*primitives.Event{}
	for _, scan := range report.Results {
		for _, vuln := range scan.Vulnerabilities {
			attrs := vulnerabilityAttrs(report, scan, vuln)
			event, err := s.event(st, "trivy-image-vulnerability-"+stableID(imageDigest(report)+"|"+vuln.VulnerabilityID+"|"+vuln.PkgName+"|"+vuln.InstalledVersion), "trivy.image_vulnerability", "trivy/image_vulnerability/v1", attrs, attrs, s.now())
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

func (s *Source) packageEvents(st settings, report report) ([]*primitives.Event, error) {
	seen := map[string]struct{}{}
	events := []*primitives.Event{}
	addPackage := func(scan result, name, version, purl string) error {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
			return nil
		}
		key := scan.Type + "|" + name + "|" + version
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		attrs := packageAttrs(report, scan, name, version, purl)
		event, err := s.event(st, "trivy-image-package-"+stableID(imageDigest(report)+"|"+key), "trivy.image_package", "trivy/image_package/v1", attrs, attrs, s.now())
		if err != nil {
			return err
		}
		events = append(events, event)
		return nil
	}
	for _, scan := range report.Results {
		for _, vuln := range scan.Vulnerabilities {
			if err := addPackage(scan, vuln.PkgName, vuln.InstalledVersion, vuln.PkgIdentifier.PURL); err != nil {
				return nil, err
			}
		}
		for _, pkg := range scan.Packages {
			if err := addPackage(scan, pkg.Name, pkg.Version, pkg.Identifier.PURL); err != nil {
				return nil, err
			}
		}
	}
	return events, nil
}

func (s *Source) fixEvents(st settings, report report) ([]*primitives.Event, error) {
	events := []*primitives.Event{}
	for _, scan := range report.Results {
		for _, vuln := range scan.Vulnerabilities {
			if strings.TrimSpace(vuln.FixedVersion) == "" {
				continue
			}
			attrs := vulnerabilityAttrs(report, scan, vuln)
			attrs["fixed_version"] = vuln.FixedVersion
			event, err := s.event(st, "trivy-fix-"+stableID(imageDigest(report)+"|"+vuln.VulnerabilityID+"|"+vuln.PkgName+"|"+vuln.FixedVersion), "trivy.fix", "trivy/fix/v1", attrs, attrs, s.now())
			if err != nil {
				return nil, err
			}
			events = append(events, event)
		}
	}
	return events, nil
}

func (s *Source) event(st settings, id string, kind string, schemaRef string, payload any, attrs map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	event := &cerebrov1.EventEnvelope{Id: id, TenantId: st.tenantID, SourceId: sourceID, Kind: kind, SchemaRef: schemaRef, Payload: raw, Attributes: compact(attrs), OccurredAt: timestamppb.New(occurredAt.UTC())}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, err
	}
	return event, nil
}

func vulnerabilityAttrs(report report, scan result, vuln vulnerability) map[string]string {
	attrs := packageAttrs(report, scan, vuln.PkgName, vuln.InstalledVersion, vuln.PkgIdentifier.PURL)
	attrs["vulnerability_id"] = vuln.VulnerabilityID
	attrs["cve_id"] = vuln.VulnerabilityID
	attrs["severity"] = vuln.Severity
	attrs["title"] = vuln.Title
	attrs["description"] = vuln.Description
	attrs["primary_url"] = vuln.PrimaryURL
	attrs["fixed_version"] = vuln.FixedVersion
	attrs["status"] = normalizeVulnerabilityStatus(vuln.Status)
	if strings.TrimSpace(vuln.FixedVersion) != "" {
		attrs["fix_available"] = "true"
	}
	return attrs
}

// normalizeVulnerabilityStatus lowercases the Trivy DetectedVulnerability
// Status (including VEX-derived statuses such as not_affected) so downstream
// projection and findings can reason about current vulnerability state. An
// unset status is reported as "affected" because Trivy only lists a finding
// when the vulnerable package is present in the scanned image.
func normalizeVulnerabilityStatus(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" {
		return "affected"
	}
	return normalized
}

func packageAttrs(report report, scan result, name string, version string, purl string) map[string]string {
	attrs := map[string]string{"image_digest": imageDigest(report), "image_uri": firstNonEmpty(report.ArtifactName, firstRepoDigest(report)), "package": name, "package_name": name, "installed_version": version, "version": version, "class": scan.Class, "ecosystem": scan.Type, "type": scan.Type, "purl": purl}
	if normalized := normalizedPackageID(purl, scan.Type, name, version); normalized != "" {
		attrs["normalized_id"] = normalized
	}
	return attrs
}

func imageDigest(report report) string {
	for _, digest := range report.Metadata.RepoDigests {
		if idx := strings.LastIndex(digest, "@sha256:"); idx >= 0 {
			return digest[idx+1:]
		}
	}
	if idx := strings.LastIndex(report.ArtifactName, "@sha256:"); idx >= 0 {
		return report.ArtifactName[idx+1:]
	}
	return ""
}

func firstRepoDigest(report report) string {
	if len(report.Metadata.RepoDigests) > 0 {
		return report.Metadata.RepoDigests[0]
	}
	return ""
}

func normalizedPackageID(purl string, ecosystem string, name string, version string) string {
	if parsed, err := packageurl.FromString(purl); err == nil && parsed.Name != "" {
		packageName := parsed.Name
		if parsed.Namespace != "" {
			packageName = parsed.Namespace + "/" + packageName
		}
		return strings.ToLower(parsed.Type + "|" + packageName + "|" + firstNonEmpty(parsed.Version, version))
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
		return ""
	}
	return strings.ToLower(firstNonEmpty(ecosystem, "unknown") + "|" + name + "|" + version)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.internal.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func compact(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range attrs {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			out[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
