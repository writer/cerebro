package vulnpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/internal/sourcehttp/vulnfetch"
)

// Pull kinds.
const (
	PullKindHTTP  = "http_json"
	PullKindStrix = "strix"
	PullKindS3    = "s3"
)

const (
	pullSourceID          = "vulnerability-pull"
	defaultStrixBaseURL   = "https://app.strix.ai/api/v1"
	strixPageLimit        = 100
	maxStrixPagesPerType  = 500
	defaultHTTPMaxPages   = 20
	pullRequestTimeout    = 60 * time.Second
	defaultHTTPAuthHeader = "Authorization"
	defaultHTTPAuthScheme = "Bearer"
)

// DefaultStrixHosts are the API hosts a Strix profile may send its token to
// when StrixPuller.AllowedHosts is empty.
var DefaultStrixHosts = []string{"app.strix.ai"}

// HTTPOptions configures outbound HTTP for API pullers. Tests use them to
// reach local servers; production leaves them empty so only public HTTPS
// endpoints are reachable.
type HTTPOptions struct {
	AllowLoopback bool
}

func (o HTTPOptions) fetcher() *vulnfetch.Fetcher {
	return vulnfetch.New(vulnfetch.Options{SourceID: pullSourceID, Timeout: pullRequestTimeout, MaxBodyBytes: MaxPayloadBytes, AllowLoopback: o.AllowLoopback})
}

// validatePullURL accepts an HTTPS URL with an optional query and returns the
// normalized URL.
func (o HTTPOptions) validatePullURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	query := parsed.RawQuery
	parsed.RawQuery, parsed.ForceQuery = "", false
	normalized, _, err := sourcehttp.NormalizeBaseURL(pullSourceID, parsed.String(), o.AllowLoopback)
	if err != nil {
		return "", err
	}
	if query != "" {
		normalized += "?" + query
	}
	return normalized, nil
}

// credentialQueryParam returns the first query parameter of raw whose name
// looks like a credential. Such values would be stored in plain profile config
// and could surface in errors, so they must go through token instead.
func credentialQueryParam(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(parsed.Query()))
	for name := range parsed.Query() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		lower := strings.ToLower(name)
		// Pagination tokens (page_token, nextToken, continuation_token) are not credentials.
		if strings.Contains(lower, "page") || strings.Contains(lower, "next") || strings.Contains(lower, "cursor") || strings.Contains(lower, "continuation") {
			continue
		}
		if sourceconfig.SensitiveKey(name) || lower == "access_token" || lower == "sig" || lower == "signature" {
			return name
		}
	}
	return ""
}

// HTTPPuller fetches JSON or NDJSON from any HTTPS API, following an optional
// next-URL or cursor pagination scheme.
type HTTPPuller struct {
	Options HTTPOptions
}

func (HTTPPuller) Kind() string { return PullKindHTTP }

func (HTTPPuller) SecretKeys() []string { return []string{"token"} }

var httpPullKeys = []string{"url", "token", "auth_header", "auth_scheme", "format", "full_snapshot", "next_url_path", "cursor_path", "cursor_param", "max_pages"}

func (p HTTPPuller) ValidateConfig(config map[string]string) error {
	if err := rejectUnknownKeys(config, httpPullKeys...); err != nil {
		return err
	}
	if strings.TrimSpace(config["url"]) == "" {
		return errors.New("url is required")
	}
	if _, err := p.Options.validatePullURL(config["url"]); err != nil {
		return err
	}
	if name := credentialQueryParam(config["url"]); name != "" {
		return fmt.Errorf("url query parameter %q looks like a credential; send it with token and auth_header instead", name)
	}
	if format := config["format"]; format != "" && (!validFormat(format) || format == FormatAuto) {
		return fmt.Errorf("unknown format %q", format)
	}
	if header := config["auth_header"]; header != "" && !validHeaderName(header) {
		return errors.New("auth_header must be a valid HTTP header name")
	}
	if _, err := configBool(config, "full_snapshot"); err != nil {
		return err
	}
	if _, err := configPositiveInt(config, "max_pages", defaultHTTPMaxPages); err != nil {
		return err
	}
	for _, key := range []string{"next_url_path", "cursor_path"} {
		if value := config[key]; value != "" {
			if _, err := parsePath(value); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	if config["next_url_path"] != "" && config["cursor_path"] != "" {
		return errors.New("set next_url_path or cursor_path, not both")
	}
	if (config["cursor_path"] == "") != (config["cursor_param"] == "") {
		return errors.New("cursor_path and cursor_param must be set together")
	}
	return nil
}

func (p HTTPPuller) Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error) {
	config := request.Config
	endpoint, err := p.Options.validatePullURL(config["url"])
	if err != nil {
		return PullOutcome{}, err
	}
	maxPages, _ := configPositiveInt(config, "max_pages", defaultHTTPMaxPages)
	snapshot, _ := configBool(config, "full_snapshot")
	header := configValue(config, "auth_header", defaultHTTPAuthHeader)
	authValue := ""
	if token := strings.TrimSpace(config["token"]); token != "" {
		scheme := configValue(config, "auth_scheme", defaultHTTPAuthScheme)
		authValue = token
		if !strings.EqualFold(scheme, "none") {
			authValue = scheme + " " + token
		}
	}
	client := p.Options.fetcher()
	seen := map[string]bool{}
	for page := 1; ; page++ {
		if seen[endpoint] {
			return PullOutcome{}, errors.New("pagination returned a page that was already fetched")
		}
		seen[endpoint] = true
		body, contentType, err := client.Get(ctx, endpoint, header, authValue)
		if err != nil {
			return PullOutcome{}, err
		}
		if err := emit(PullPage{Payload: body, ContentType: contentType, Format: config["format"]}); err != nil {
			return PullOutcome{}, err
		}
		next, complete, err := p.nextEndpoint(config, endpoint, body, contentType)
		if err != nil {
			return PullOutcome{}, err
		}
		if next == "" {
			// A page without its pagination field may be one of many, so
			// the listing is not known to be complete.
			return PullOutcome{Snapshot: snapshot && complete}, nil
		}
		if page >= maxPages {
			// A truncated listing is not a complete snapshot.
			return PullOutcome{}, nil
		}
		endpoint = next
	}
}

// nextEndpoint returns the next page URL. When there is none, complete reports
// whether the page positively said so (the pagination field was present but
// empty or null) rather than omitting the field.
func (p HTTPPuller) nextEndpoint(config map[string]string, current string, body []byte, contentType string) (next string, complete bool, err error) {
	nextURLPath, cursorPath := config["next_url_path"], config["cursor_path"]
	if nextURLPath == "" && cursorPath == "" {
		return "", true, nil
	}
	document, err := decodeDocument(body, contentType)
	if err != nil {
		return "", false, fmt.Errorf("decode page for pagination: %w", err)
	}
	if nextURLPath != "" {
		value := strings.TrimSpace(resolveFirstString(document, nextURLPath))
		if value == "" {
			return "", pathPresent(document, nextURLPath), nil
		}
		base, _ := url.Parse(current)
		reference, err := url.Parse(value)
		if err != nil {
			return "", false, fmt.Errorf("parse next page url: %w", err)
		}
		resolved := base.ResolveReference(reference).String()
		sameOrigin, err := sourcehttp.SameOriginAbsoluteURL(pullSourceID, current, resolved)
		if err != nil {
			return "", false, fmt.Errorf("%w: %w", ErrUnsafePageURL, err)
		}
		return sameOrigin, false, nil
	}
	cursor := strings.TrimSpace(resolveFirstString(document, cursorPath))
	if cursor == "" {
		return "", pathPresent(document, cursorPath), nil
	}
	parsed, _ := url.Parse(current)
	query := parsed.Query()
	query.Set(config["cursor_param"], cursor)
	parsed.RawQuery = query.Encode()
	return parsed.String(), false, nil
}

func pathPresent(document any, raw string) bool {
	segments, err := parsePath(raw)
	if err != nil {
		return false
	}
	return len(resolvePath(document, segments)) > 0
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return !strings.EqualFold(value, "host") && !strings.EqualFold(value, "content-length")
}

// StrixPuller syncs the full vulnerability list from the Strix API. The API
// token is only ever sent to AllowedHosts (DefaultStrixHosts when empty).
type StrixPuller struct {
	Options      HTTPOptions
	AllowedHosts []string
}

func (StrixPuller) Kind() string { return PullKindStrix }

func (StrixPuller) SecretKeys() []string { return []string{"api_token"} }

var strixFindingTypes = map[string]bool{"live_pentest": true, "code": true, "dependency": true}

func (p StrixPuller) ValidateConfig(config map[string]string) error {
	if err := rejectUnknownKeys(config, "base_url", "api_token", "finding_types"); err != nil {
		return err
	}
	if strings.TrimSpace(config["api_token"]) == "" {
		return errors.New("api_token is required")
	}
	if _, err := p.baseURL(config); err != nil {
		return err
	}
	_, err := strixTypes(config)
	return err
}

func (p StrixPuller) baseURL(config map[string]string) (string, error) {
	normalized, _, err := sourcehttp.NormalizeBaseURL(pullSourceID, configValue(config, "base_url", defaultStrixBaseURL), p.Options.AllowLoopback)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("parse base_url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	if p.Options.AllowLoopback && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return normalized, nil
	}
	allowed := p.AllowedHosts
	if len(allowed) == 0 {
		allowed = DefaultStrixHosts
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), host) {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("base_url host %q is not an allowed Strix API host", host)
}

func strixTypes(config map[string]string) ([]string, error) {
	raw := configValue(config, "finding_types", "live_pentest,code")
	types := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		if !strixFindingTypes[part] {
			return nil, fmt.Errorf("finding_types entry %q must be live_pentest, code, or dependency", part)
		}
		seen[part] = true
		types = append(types, part)
	}
	if len(types) == 0 {
		return nil, errors.New("finding_types must list at least one type")
	}
	return types, nil
}

func (p StrixPuller) Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error) {
	baseURL, err := p.baseURL(request.Config)
	if err != nil {
		return PullOutcome{}, err
	}
	types, err := strixTypes(request.Config)
	if err != nil {
		return PullOutcome{}, err
	}
	token := strings.TrimSpace(request.Config["api_token"])
	if token == "" {
		return PullOutcome{}, errors.New("api_token is required")
	}
	client := p.Options.fetcher()
	snapshot := true
	for _, findingType := range types {
		for page := 1; ; page++ {
			if page > maxStrixPagesPerType {
				return PullOutcome{}, fmt.Errorf("strix %s listing exceeded %d pages", findingType, maxStrixPagesPerType)
			}
			query := url.Values{}
			query.Set("page", strconv.Itoa(page))
			query.Set("limit", strconv.Itoa(strixPageLimit))
			query.Set("finding_type", findingType)
			body, contentType, err := client.Get(ctx, baseURL+"/vulnerabilities?"+query.Encode(), "Authorization", "Bearer "+token)
			if err != nil {
				return PullOutcome{}, err
			}
			if err := emit(PullPage{Payload: body, ContentType: contentType, Format: FormatStrix}); err != nil {
				return PullOutcome{}, err
			}
			hasNext, known := strixPageInfo(body, page)
			if !known {
				// Without page info the listing may continue, so absent
				// records must not be resolved.
				snapshot = false
				break
			}
			if !hasNext {
				break
			}
		}
	}
	return PullOutcome{Snapshot: snapshot}, nil
}

// strixPageInfo reads the pagination meta of a Strix page. known is false when
// the page carries no usable has_next or total_pages.
func strixPageInfo(body []byte, page int) (hasNext bool, known bool) {
	document, err := decodeDocument(body, "application/json")
	if err != nil {
		return false, false
	}
	root, _ := document.(map[string]any)
	meta, _ := root["meta"].(map[string]any)
	if meta == nil {
		return false, false
	}
	if value, ok := meta["has_next"].(bool); ok {
		return value, true
	}
	if total, ok := wholeNumber(meta["total_pages"]); ok {
		return int64(page) < total, true
	}
	return false, false
}

func wholeNumber(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil && number >= 0
	case float64:
		if typed < 0 || typed != math.Trunc(typed) || typed > math.MaxInt32 {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}
