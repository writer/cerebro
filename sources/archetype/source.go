package archetype

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "archetype"

type Source struct {
	spec                 *cerebrov1.SourceSpec
	allowLoopbackBaseURL bool
}

type settings struct {
	tenantID                 string
	family                   string
	baseURL                  string
	token                    string
	apiPrefix                string
	privateEndpointAllowlist []string
}
type scanRecord struct {
	ID           int    `json:"id"`
	RepositoryID int    `json:"repository_id"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at"`
	CreatedAt    string `json:"created_at"`
}
type vulnerabilityRecord struct {
	ID            int     `json:"id"`
	ScanID        int     `json:"scan_id"`
	LineNumber    int     `json:"line_number"`
	FilePath      string  `json:"file_path"`
	Category      string  `json:"category"`
	Severity      string  `json:"severity"`
	Description   string  `json:"description"`
	AnalyzerScore float64 `json:"analyzer_score"`
	AnalyzerLabel string  `json:"analyzer_label"`
	CreatedAt     string  `json:"created_at"`
}
type repositoryRecord struct {
	ID    int    `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func New() (*Source, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return &Source{spec: spec}, nil
}
func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	st, err := parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
	if err != nil {
		return err
	}
	var scans []scanRecord
	return s.get(ctx, st, "/scans", nil, &scans)
}
func (s *Source) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.ReadWithCheckpoint(ctx, cfg, cursor, nil)
}
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	st, err := parseSettings(cfg, s != nil && s.allowLoopbackBaseURL)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	var scans []scanRecord
	if err := s.get(ctx, st, "/scans", nil, &scans); err != nil {
		return sourcecdk.Pull{}, err
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].ID < scans[j].ID })
	last := lastScanID(cursor, checkpoint)
	repos := map[int]repositoryRecord{}
	events := []*primitives.Event{}
	for _, scan := range scans {
		if scan.ID <= last {
			continue
		}
		if len(repos) == 0 {
			repos = s.repositories(ctx, st)
		}
		events = append(events, scanEvent(st, scan, repos[scan.RepositoryID]))
		if st.family == "scan" {
			continue
		}
		var vulns []vulnerabilityRecord
		if err := s.get(ctx, st, fmt.Sprintf("/scans/%d/vulnerabilities", scan.ID), nil, &vulns); err != nil {
			return sourcecdk.Pull{}, err
		}
		for _, vuln := range vulns {
			events = append(events, vulnerabilityEvent(st, scan, vuln, repos[scan.RepositoryID]))
		}
	}
	if len(events) == 0 {
		return sourcecdk.NotModifiedPull(checkpoint), nil
	}
	next := strconv.Itoa(maxScanID(scans))
	return sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: next, Watermark: events[len(events)-1].OccurredAt}}, nil
}
func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	st := settings{
		tenantID:  first(configValue(cfg, "tenant_id"), configValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:    first(configValue(cfg, "family"), "vulnerability"),
		baseURL:   strings.TrimRight(configValue(cfg, "base_url"), "/"),
		token:     first(configValue(cfg, "token"), configValue(cfg, "api_token")),
		apiPrefix: first(configValue(cfg, "api_prefix"), "/api/v1"),
	}
	if st.tenantID == "" || st.baseURL == "" {
		return st, fmt.Errorf("%w: archetype tenant_id and base_url are required", sourcecdk.ErrInvalidConfig)
	}
	if st.family != "scan" && st.family != "vulnerability" {
		return st, fmt.Errorf("%w: archetype family must be scan or vulnerability", sourcecdk.ErrInvalidConfig)
	}
	privateEndpointAllowlist, err := sourcehttp.ParsePrivateEndpointAllowlist(sourceID, configValue(cfg, "private_endpoint_allowlist"))
	if err != nil {
		return st, err
	}
	baseURL, _, err := sourcehttp.NormalizeBaseURLWithOptions(sourceID, st.baseURL, sourcehttp.URLValidationOptions{
		AllowLoopback:            allowLoopback,
		PrivateEndpointAllowlist: privateEndpointAllowlist,
	})
	if err != nil {
		return st, err
	}
	apiPrefix, err := sourcehttp.NormalizeRequestPath(sourceID, st.apiPrefix)
	if err != nil {
		return st, err
	}
	st.baseURL = baseURL
	st.apiPrefix = strings.TrimRight(apiPrefix, "/")
	st.privateEndpointAllowlist = privateEndpointAllowlist
	return st, nil
}
func (s *Source) get(ctx context.Context, st settings, path string, query url.Values, out any) error {
	requestPath, err := sourcehttp.NormalizeRequestPath(sourceID, st.apiPrefix+path)
	if err != nil {
		return err
	}
	endpoint := st.baseURL + requestPath
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if st.token != "" {
		req.Header.Set("Authorization", "Bearer "+st.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := sourcehttp.DoWithRetry(ctx, sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:                 sourceID,
		AllowLoopback:            s != nil && s.allowLoopbackBaseURL,
		PrivateEndpointAllowlist: st.privateEndpointAllowlist,
	}), req, sourcehttp.RetryOptions{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("archetype GET %s failed with status %d", path, resp.StatusCode)
	}
	return json.Unmarshal(resp.Body, out)
}
func (s *Source) repositories(ctx context.Context, st settings) map[int]repositoryRecord {
	var repos []repositoryRecord
	if err := s.get(ctx, st, "/repositories", nil, &repos); err != nil {
		return nil
	}
	out := map[int]repositoryRecord{}
	for _, repo := range repos {
		out[repo.ID] = repo
	}
	return out
}
func scanEvent(st settings, scan scanRecord, repo repositoryRecord) *primitives.Event {
	attrs := map[string]string{"scan_id": itoa(scan.ID), "repository_id": itoa(scan.RepositoryID), "status": scan.Status, "owner": repo.Owner, "repo": repo.Name, "source_product": sourceID}
	return event(st, "archetype.scan", "archetype-scan-"+itoa(scan.ID), "archetype/scan/v1", scanTime(scan), attrs, scan)
}
func vulnerabilityEvent(st settings, scan scanRecord, vuln vulnerabilityRecord, repo repositoryRecord) *primitives.Event {
	attrs := map[string]string{"vulnerability_id": itoa(vuln.ID), "scan_id": itoa(vuln.ScanID), "repository_id": itoa(scan.RepositoryID), "severity": vuln.Severity, "category": vuln.Category, "file_path": vuln.FilePath, "line_number": itoa(vuln.LineNumber), "owner": repo.Owner, "repo": repo.Name, "source_product": sourceID}
	return event(st, "archetype.vulnerability", "archetype-vulnerability-"+itoa(vuln.ID), "archetype/vulnerability/v1", parseTime(vuln.CreatedAt, scanTime(scan)), attrs, vuln)
}
func event(st settings, kind, id, schema string, at time.Time, attrs map[string]string, payload any) *primitives.Event {
	body, _ := json.Marshal(payload)
	return &cerebrov1.EventEnvelope{Id: id, TenantId: st.tenantID, SourceId: sourceID, Kind: kind, SchemaRef: schema, OccurredAt: timestamppb.New(at), Payload: body, Attributes: compact(attrs)}
}
func lastScanID(cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) int {
	value := first(sourcecdk.CursorToken(cursor), checkpoint.GetCursorOpaque())
	id, _ := strconv.Atoi(value)
	return id
}
func maxScanID(scans []scanRecord) int {
	max := 0
	for _, scan := range scans {
		if scan.ID > max {
			max = scan.ID
		}
	}
	return max
}
func scanTime(scan scanRecord) time.Time {
	return parseTime(first(scan.CompletedAt, scan.StartedAt, scan.CreatedAt), time.Now().UTC())
}
func parseTime(value string, fallback time.Time) time.Time {
	if at, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
		return at.UTC()
	}
	return fallback.UTC()
}
func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}
func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func compact(attrs map[string]string) map[string]string {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
		}
	}
	return attrs
}
func itoa(value int) string { return strconv.Itoa(value) }
