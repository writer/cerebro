package archetype

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
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
	"github.com/writer/cerebro/sources/internal/archetypeclient"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "archetype"

const (
	defaultFanoutConcurrency = 4
	maxFanoutConcurrency     = 16
)

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
	fanoutConcurrency        int
}

type scanRecord = archetypeclient.Scan
type vulnerabilityRecord = archetypeclient.Vulnerability
type knowledgeEntryRecord = archetypeclient.KnowledgeEntry
type repositoryRecord = archetypeclient.Repository

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
	return archetypeclient.Get(ctx, s.clientSettings(st), "/scans", new([]scanRecord))
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
	clientSettings := s.clientSettings(st)
	if err := archetypeclient.Get(ctx, clientSettings, "/scans", &scans); err != nil {
		return sourcecdk.Pull{}, err
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].ID < scans[j].ID })
	last := lastScanID(cursor, checkpoint)
	newScans := make([]scanRecord, 0, len(scans))
	for _, scan := range scans {
		if scan.ID > last {
			newScans = append(newScans, scan)
		}
	}
	if len(newScans) == 0 {
		return sourcecdk.NotModifiedPull(checkpoint), nil
	}
	repos := archetypeclient.Repositories(ctx, clientSettings)
	vulnerabilities := make([][]vulnerabilityRecord, len(newScans))
	if st.family != "scan" {
		var err error
		vulnerabilities, err = archetypeclient.VulnerabilitiesForScans(ctx, clientSettings, newScans)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
	}
	knowledgeRepos := map[int]bool{}
	events := []*primitives.Event{}
	for i, scan := range newScans {
		events = append(events, scanEvent(st, scan, repos[scan.RepositoryID]))
		if st.family == "scan" {
			continue
		}
		for _, vuln := range vulnerabilities[i] {
			events = append(events, vulnerabilityEvent(st, scan, vuln, repos[scan.RepositoryID]))
		}
		if !knowledgeRepos[scan.RepositoryID] {
			entries, cacheable := archetypeclient.RepositoryKnowledge(ctx, clientSettings, scan.RepositoryID)
			knowledgeRepos[scan.RepositoryID] = cacheable
			for _, entry := range entries {
				if event := libraryNoteEvent(st, scan, entry, repos[scan.RepositoryID]); event != nil {
					events = append(events, event)
				}
			}
			if err := ctx.Err(); err != nil {
				return sourcecdk.Pull{}, err
			}
		}
	}
	if len(events) == 0 {
		return sourcecdk.NotModifiedPull(checkpoint), nil
	}
	next := strconv.Itoa(scans[len(scans)-1].ID)
	return sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{CursorOpaque: next, Watermark: events[len(events)-1].OccurredAt}}, nil
}
func parseSettings(cfg sourcecdk.Config, allowLoopback bool) (settings, error) {
	st := settings{
		tenantID:  first(sourcecdk.ConfigValue(cfg, "tenant_id"), sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey)),
		family:    first(sourcecdk.ConfigValue(cfg, "family"), "vulnerability"),
		baseURL:   strings.TrimRight(sourcecdk.ConfigValue(cfg, "base_url"), "/"),
		token:     first(sourcecdk.ConfigValue(cfg, "token"), sourcecdk.ConfigValue(cfg, "api_token")),
		apiPrefix: first(sourcecdk.ConfigValue(cfg, "api_prefix"), "/api/v1"),
	}
	var err error
	if st.fanoutConcurrency, err = parseFanoutConcurrency(sourcecdk.ConfigValue(cfg, "request_concurrency")); err != nil {
		return st, err
	}
	if st.tenantID == "" || st.baseURL == "" {
		return st, fmt.Errorf("%w: archetype tenant_id and base_url are required", sourcecdk.ErrInvalidConfig)
	}
	if st.family != "scan" && st.family != "vulnerability" {
		return st, fmt.Errorf("%w: archetype family must be scan or vulnerability", sourcecdk.ErrInvalidConfig)
	}
	privateEndpointAllowlist, err := sourcehttp.ParsePrivateEndpointAllowlist(sourceID, sourcecdk.ConfigValue(cfg, "private_endpoint_allowlist"))
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
	st.baseURL, st.apiPrefix = baseURL, strings.TrimRight(apiPrefix, "/")
	st.privateEndpointAllowlist = privateEndpointAllowlist
	return st, nil
}
func (s *Source) clientSettings(st settings) archetypeclient.Settings {
	return archetypeclient.Settings{
		SourceID:                 sourceID,
		BaseURL:                  st.baseURL,
		Token:                    st.token,
		APIPrefix:                st.apiPrefix,
		PrivateEndpointAllowlist: st.privateEndpointAllowlist,
		AllowLoopback:            s != nil && s.allowLoopbackBaseURL,
		FanoutConcurrency:        st.fanoutConcurrency,
	}
}
func parseFanoutConcurrency(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultFanoutConcurrency, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("%w: archetype request_concurrency must be an integer", sourcecdk.ErrInvalidConfig)
	}
	if value <= 0 || value > maxFanoutConcurrency {
		return 0, fmt.Errorf("%w: archetype request_concurrency must be between 1 and %d", sourcecdk.ErrInvalidConfig, maxFanoutConcurrency)
	}
	return value, nil
}
func scanEvent(st settings, scan scanRecord, repo repositoryRecord) *primitives.Event {
	attrs := map[string]string{"scan_id": strconv.Itoa(scan.ID), "repository_id": strconv.Itoa(scan.RepositoryID), "status": scan.Status, "owner": repo.Owner, "repo": repo.Name, "source_product": sourceID}
	return event(st, "archetype.scan", "archetype-scan-"+strconv.Itoa(scan.ID), "archetype/scan/v1", scanTime(scan), attrs, scan)
}
func vulnerabilityEvent(st settings, scan scanRecord, vuln vulnerabilityRecord, repo repositoryRecord) *primitives.Event {
	attrs := map[string]string{"vulnerability_id": strconv.Itoa(vuln.ID), "scan_id": strconv.Itoa(vuln.ScanID), "repository_id": strconv.Itoa(scan.RepositoryID), "severity": vuln.Severity, "category": vuln.Category, "file_path": vuln.FilePath, "line_number": strconv.Itoa(vuln.LineNumber), "owner": repo.Owner, "repo": repo.Name, "source_product": sourceID}
	return event(st, "archetype.vulnerability", "archetype-vulnerability-"+strconv.Itoa(vuln.ID), "archetype/vulnerability/v1", parseTime(vuln.CreatedAt, scanTime(scan)), attrs, vuln)
}
func libraryNoteEvent(st settings, scan scanRecord, entry knowledgeEntryRecord, repo repositoryRecord) *primitives.Event {
	entry.Slug = first(entry.Slug)
	entry.Owner, entry.RepositoryName = first(entry.Owner, repo.Owner), first(entry.RepositoryName, repo.Name)
	if entry.RepositoryID == 0 {
		entry.RepositoryID = scan.RepositoryID
	}
	if entry.Owner == "" || entry.RepositoryName == "" || entry.Slug == "" {
		return nil
	}
	attrs := map[string]string{
		"knowledge_slug":    entry.Slug,
		"scan_id":           strconv.Itoa(scan.ID),
		"repository_id":     strconv.Itoa(entry.RepositoryID),
		"dominant_severity": entry.DominantSeverity,
		"owner":             entry.Owner,
		"repo":              entry.RepositoryName,
	}
	eventID := "archetype-library-" + strconv.Itoa(entry.RepositoryID) + "-" + url.QueryEscape(entry.Slug)
	return event(st, "archetype.library_note", eventID, "archetype/library-note/v1", scanTime(scan), attrs, entry)
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
func scanTime(scan scanRecord) time.Time {
	return parseTime(first(scan.CompletedAt, scan.StartedAt, scan.CreatedAt), time.Now().UTC())
}
func parseTime(value string, fallback time.Time) time.Time {
	if at, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
		return at.UTC()
	}
	return fallback.UTC()
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
