package vulnpipeline

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

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
		next, err := p.nextEndpoint(config, endpoint, body, contentType)
		if err != nil {
			return PullOutcome{}, err
		}
		if next == "" {
			return PullOutcome{Snapshot: snapshot}, nil
		}
		if page >= maxPages {
			// A truncated listing is not a complete snapshot.
			return PullOutcome{}, nil
		}
		endpoint = next
	}
}

func (p HTTPPuller) nextEndpoint(config map[string]string, current string, body []byte, contentType string) (string, error) {
	nextURLPath, cursorPath := config["next_url_path"], config["cursor_path"]
	if nextURLPath == "" && cursorPath == "" {
		return "", nil
	}
	document, err := decodeDocument(body, contentType)
	if err != nil {
		return "", fmt.Errorf("decode page for pagination: %w", err)
	}
	if nextURLPath != "" {
		next := strings.TrimSpace(resolveFirstString(document, nextURLPath))
		if next == "" {
			return "", nil
		}
		base, _ := url.Parse(current)
		reference, err := url.Parse(next)
		if err != nil {
			return "", fmt.Errorf("parse next page url: %w", err)
		}
		resolved := base.ResolveReference(reference).String()
		sameOrigin, err := sourcehttp.SameOriginAbsoluteURL(pullSourceID, current, resolved)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrUnsafePageURL, err)
		}
		return sameOrigin, nil
	}
	cursor := strings.TrimSpace(resolveFirstString(document, cursorPath))
	if cursor == "" {
		return "", nil
	}
	parsed, _ := url.Parse(current)
	query := parsed.Query()
	query.Set(config["cursor_param"], cursor)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
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

// StrixPuller syncs the full vulnerability list from the Strix API.
type StrixPuller struct {
	Options HTTPOptions
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
	if _, _, err := sourcehttp.NormalizeBaseURL(pullSourceID, configValue(config, "base_url", defaultStrixBaseURL), p.Options.AllowLoopback); err != nil {
		return err
	}
	_, err := strixTypes(config)
	return err
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
	baseURL, _, err := sourcehttp.NormalizeBaseURL(pullSourceID, configValue(request.Config, "base_url", defaultStrixBaseURL), p.Options.AllowLoopback)
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
			if !strixHasNext(body, page) {
				break
			}
		}
	}
	return PullOutcome{Snapshot: true}, nil
}

func strixHasNext(body []byte, page int) bool {
	document, err := decodeDocument(body, "application/json")
	if err != nil {
		return false
	}
	root, _ := document.(map[string]any)
	meta, _ := root["meta"].(map[string]any)
	if meta == nil {
		return false
	}
	if hasNext, ok := meta["has_next"].(bool); ok {
		return hasNext
	}
	if total := number(meta["total_pages"]); total != nil {
		return float64(page) < *total
	}
	return false
}
