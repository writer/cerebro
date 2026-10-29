package cloudidentitysource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	gcpSourceID                      = "cloud_identity_gcp"
	gcpDefaultCloudAssetBaseURL      = "https://cloudasset.googleapis.com"
	gcpDefaultIAMBaseURL             = "https://iam.googleapis.com"
	gcpDefaultResourceManagerBaseURL = "https://cloudresourcemanager.googleapis.com"
	gcpDefaultTimeout                = 30 * time.Second
	gcpDefaultPageSize               = 200
	gcpMaxPageSize                   = 500
	gcpDefaultMaxPages               = 50
	gcpDefaultRetryAttempts          = 3
	gcpDefaultRetryBackoff           = 250 * time.Millisecond
	gcpQuotaProjectHeader            = "X-Goog-User-Project"
	gcpSearchAllIAMPoliciesReference = "cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies"
	gcpGetServiceAccountReference    = "iam.googleapis.com/v1/{name}"
	gcpGetServiceAccountIAMReference = "iam.googleapis.com/v1/{resource}:getIamPolicy"
	gcpGetRoleReference              = "iam.googleapis.com/v1/{name}"
	gcpGetProjectReference           = "cloudresourcemanager.googleapis.com/v3/projects/{projectId}"
	gcpGetAncestryReference          = "cloudresourcemanager.googleapis.com/v1/projects/{projectId}:getAncestry"
	// gcpRequestedPolicyVersion is always requested on getIamPolicy calls so
	// conditional bindings are returned intact instead of being collapsed
	// into synthetic "_withcond_" role names (IAM's behavior for version 1,
	// its default when unspecified).
	gcpRequestedPolicyVersion = 3
)

// gcpClient issues bounded, read-only REST calls against Cloud Asset, IAM, and
// Resource Manager. It never writes, never execs a provider SDK, and never
// logs or returns the bearer token itself.
type gcpClient struct {
	httpClient      *http.Client
	cloudAssetBase  string
	iamBase         string
	resourceMgrBase string
	quotaProject    string
	pageSize        int
	maxPages        int
}

func newGCPClient(options GCPOptions) (*gcpClient, error) {
	cloudAssetBase := firstNonEmptyGCP(options.CloudAssetBaseURL, gcpDefaultCloudAssetBaseURL)
	iamBase := firstNonEmptyGCP(options.IAMBaseURL, gcpDefaultIAMBaseURL)
	resourceMgrBase := firstNonEmptyGCP(options.ResourceManagerBaseURL, gcpDefaultResourceManagerBaseURL)
	for _, base := range []string{cloudAssetBase, iamBase, resourceMgrBase} {
		if _, err := url.Parse(base); err != nil {
			return nil, fmt.Errorf("cloudidentitysource: invalid GCP base URL %q: %w", base, err)
		}
	}
	timeout := options.RequestTimeout
	if timeout <= 0 {
		timeout = gcpDefaultTimeout
	}
	allowLoopback := gcpAllowLoopback(cloudAssetBase, iamBase, resourceMgrBase)
	hardenOptions := sourcehttp.ClientOptions{SourceID: gcpSourceID, Timeout: timeout, AllowLoopback: allowLoopback}
	hardened := sourcehttp.HardenClient(options.HTTPClient, hardenOptions)
	hardened.Transport = &oauth2.Transport{
		Source: options.TokenSource,
		Base:   hardened.Transport,
	}
	pageSize := options.PageSize
	if pageSize <= 0 {
		pageSize = gcpDefaultPageSize
	}
	if pageSize > gcpMaxPageSize {
		pageSize = gcpMaxPageSize
	}
	maxPages := options.MaxPages
	if maxPages <= 0 {
		maxPages = gcpDefaultMaxPages
	}
	return &gcpClient{
		httpClient:      hardened,
		cloudAssetBase:  cloudAssetBase,
		iamBase:         iamBase,
		resourceMgrBase: resourceMgrBase,
		quotaProject:    strings.TrimSpace(options.QuotaProject),
		pageSize:        pageSize,
		maxPages:        maxPages,
	}, nil
}

func gcpAllowLoopback(bases ...string) bool {
	for _, raw := range bases {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if parsed.Scheme == "http" && sourcehttp.IsLoopbackHost(parsed.Hostname()) {
			return true
		}
	}
	return false
}

func firstNonEmptyGCP(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// gcpAPIResult carries one decoded REST call outcome. A non-nil Gap means the
// call completed (possibly with a non-2xx status) and evidence collection
// should continue in a degraded, explicitly-marked-incomplete state rather
// than fail outright. Err is reserved for transport-level failures that make
// the whole request unusable (context cancellation, DNS failure, etc.).
type gcpAPIResult struct {
	StatusCode int
	Body       []byte
	Gap        *gcpGap
}

type gcpGap struct {
	Code    string
	Message string
}

type gcpErrorEnvelope struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (c *gcpClient) get(ctx context.Context, rawURL string, query url.Values, apiReference string) (gcpAPIResult, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: parse gcp request url: %w", err)
	}
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: build gcp request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.quotaProject != "" {
		req.Header.Set(gcpQuotaProjectHeader, c.quotaProject)
	}
	response, err := sourcehttp.DoWithRetry(ctx, c.httpClient, req, sourcehttp.RetryOptions{
		MaxAttempts:  gcpDefaultRetryAttempts,
		Backoff:      gcpDefaultRetryBackoff,
		MaxBodyBytes: sourcehttp.MaxBodyBytes,
	})
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: gcp request to %s failed: %w", apiReference, err)
	}
	result := gcpAPIResult{StatusCode: response.StatusCode, Body: response.Body}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return result, nil
	}
	result.Gap = &gcpGap{Code: gcpGapCodeForStatus(response.StatusCode), Message: gcpErrorMessage(apiReference, response)}
	return result, nil
}

// post issues a bounded, read-only POST request (for GCP REST methods that
// are POST-shaped but still read-only, e.g. projects.serviceAccounts.
// getIamPolicy and projects.getAncestry). A nil body sends a genuinely
// empty request body (http.NoBody), not "{}": some of these methods (e.g.
// getIamPolicy, whose GetPolicyOptions travel as the "options" QUERY
// parameter, not the body) are documented to require an empty body.
func (c *gcpClient) post(ctx context.Context, rawURL string, query url.Values, body any, apiReference string) (gcpAPIResult, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: parse gcp request url: %w", err)
	}
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: encode gcp request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), reader)
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: build gcp request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.quotaProject != "" {
		req.Header.Set(gcpQuotaProjectHeader, c.quotaProject)
	}
	response, err := sourcehttp.DoWithRetry(ctx, c.httpClient, req, sourcehttp.RetryOptions{
		MaxAttempts:  gcpDefaultRetryAttempts,
		Backoff:      gcpDefaultRetryBackoff,
		MaxBodyBytes: sourcehttp.MaxBodyBytes,
	})
	if err != nil {
		return gcpAPIResult{}, fmt.Errorf("cloudidentitysource: gcp request to %s failed: %w", apiReference, err)
	}
	result := gcpAPIResult{StatusCode: response.StatusCode, Body: response.Body}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return result, nil
	}
	result.Gap = &gcpGap{Code: gcpGapCodeForStatus(response.StatusCode), Message: gcpErrorMessage(apiReference, response)}
	return result, nil
}

func gcpGapCodeForStatus(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "gcp_auth_denied"
	case status == http.StatusForbidden:
		return "gcp_permission_denied"
	case status == http.StatusNotFound:
		return "gcp_resource_not_found"
	case status == http.StatusTooManyRequests:
		return "gcp_quota_exceeded"
	case status >= 500:
		return "gcp_provider_unavailable"
	default:
		return "gcp_request_failed"
	}
}

func gcpErrorMessage(apiReference string, response sourcehttp.ResponseBody) string {
	var envelope gcpErrorEnvelope
	message := ""
	if err := json.Unmarshal(response.Body, &envelope); err == nil && envelope.Error.Message != "" {
		message = envelope.Error.Message
	}
	retryAfter := strings.TrimSpace(response.Header.Get("Retry-After"))
	parts := []string{fmt.Sprintf("%s returned HTTP %d", apiReference, response.StatusCode)}
	if message != "" {
		parts = append(parts, message)
	}
	if retryAfter != "" {
		parts = append(parts, "retry-after="+retryAfter)
	}
	return strings.Join(parts, ": ")
}

// searchAllIamPolicies performs one bounded, fully-paginated org-wide IAM
// policy search. It stops once a page has no next token, once maxPages is
// reached (reported as a gap, not silent truncation), or once a request fails.
func (c *gcpClient) searchAllIamPolicies(ctx context.Context, scope string, query string) ([]gcpIamPolicySearchResult, []gcpGap, bool) {
	var results []gcpIamPolicySearchResult
	var gaps []gcpGap
	pageToken := ""
	for range c.maxPages {
		values := url.Values{}
		if query != "" {
			values.Set("query", query)
		}
		values.Set("pageSize", strconv.Itoa(c.pageSize))
		if pageToken != "" {
			values.Set("pageToken", pageToken)
		}
		endpoint := c.cloudAssetBase + "/v1/" + scope + ":searchAllIamPolicies"
		outcome, err := c.get(ctx, endpoint, values, gcpSearchAllIAMPoliciesReference)
		if err != nil {
			gaps = append(gaps, gcpGap{Code: "gcp_search_iam_policies_failed", Message: err.Error()})
			return results, gaps, false
		}
		if outcome.Gap != nil {
			gaps = append(gaps, *outcome.Gap)
			return results, gaps, false
		}
		var decoded struct {
			Results       []gcpIamPolicySearchResult `json:"results"`
			NextPageToken string                     `json:"nextPageToken"`
		}
		if err := json.Unmarshal(outcome.Body, &decoded); err != nil {
			gaps = append(gaps, gcpGap{Code: "gcp_search_iam_policies_decode_failed", Message: err.Error()})
			return results, gaps, false
		}
		results = append(results, decoded.Results...)
		if strings.TrimSpace(decoded.NextPageToken) == "" {
			return results, gaps, true
		}
		pageToken = decoded.NextPageToken
	}
	gaps = append(gaps, gcpGap{Code: "gcp_search_iam_policies_pagination_truncated", Message: fmt.Sprintf("searchAllIamPolicies exceeded the %d page budget for scope %s", c.maxPages, scope)})
	return results, gaps, false
}

func (c *gcpClient) getServiceAccount(ctx context.Context, project string, email string) (gcpServiceAccount, []gcpGap) {
	name := fmt.Sprintf("projects/%s/serviceAccounts/%s", project, email)
	outcome, err := c.get(ctx, c.iamBase+"/v1/"+name, nil, gcpGetServiceAccountReference)
	if err != nil {
		return gcpServiceAccount{}, []gcpGap{{Code: "gcp_service_account_lookup_failed", Message: err.Error()}}
	}
	if outcome.Gap != nil {
		return gcpServiceAccount{}, []gcpGap{*outcome.Gap}
	}
	var account gcpServiceAccount
	if err := json.Unmarshal(outcome.Body, &account); err != nil {
		return gcpServiceAccount{}, []gcpGap{{Code: "gcp_service_account_decode_failed", Message: err.Error()}}
	}
	return account, nil
}

// getServiceAccountIAMPolicy fetches a service account's own IAM policy.
// projects.serviceAccounts.getIamPolicy is documented as a POST method (a
// GET is rejected by the real endpoint) and must request policy version 3;
// without it IAM silently returns version 1, which strips conditional
// bindings' CEL expressions and rewrites their role names with a
// "_withcond_" suffix instead.
func (c *gcpClient) getServiceAccountIAMPolicy(ctx context.Context, project string, email string) (gcpPolicy, []gcpGap) {
	resource := fmt.Sprintf("projects/%s/serviceAccounts/%s", project, email)
	query := url.Values{"options.requestedPolicyVersion": {strconv.Itoa(gcpRequestedPolicyVersion)}}
	outcome, err := c.post(ctx, c.iamBase+"/v1/"+resource+":getIamPolicy", query, nil, gcpGetServiceAccountIAMReference)
	if err != nil {
		return gcpPolicy{}, []gcpGap{{Code: "gcp_service_account_policy_failed", Message: err.Error()}}
	}
	if outcome.Gap != nil {
		return gcpPolicy{}, []gcpGap{*outcome.Gap}
	}
	var policy gcpPolicy
	if err := json.Unmarshal(outcome.Body, &policy); err != nil {
		return gcpPolicy{}, []gcpGap{{Code: "gcp_service_account_policy_decode_failed", Message: err.Error()}}
	}
	return policy, nil
}

// getProjectAncestry resolves a project's Resource Manager ancestry (the
// project itself, then each enclosing folder, then the organization), read
// via the v1 getAncestry method with resourcemanager.projects.get only (no
// separate folder/organization read permission is required). The result is
// ordered innermost-first, matching the live API's documented response.
func (c *gcpClient) getProjectAncestry(ctx context.Context, projectID string) ([]gcpAncestor, []gcpGap) {
	outcome, err := c.post(ctx, c.resourceMgrBase+"/v1/projects/"+projectID+":getAncestry", nil, nil, gcpGetAncestryReference)
	if err != nil {
		return nil, []gcpGap{{Code: "gcp_project_ancestry_failed", Message: err.Error()}}
	}
	if outcome.Gap != nil {
		return nil, []gcpGap{*outcome.Gap}
	}
	var decoded struct {
		Ancestor []gcpAncestor `json:"ancestor"`
	}
	if err := json.Unmarshal(outcome.Body, &decoded); err != nil {
		return nil, []gcpGap{{Code: "gcp_project_ancestry_decode_failed", Message: err.Error()}}
	}
	return decoded.Ancestor, nil
}

// getRole resolves a predefined ("roles/x") or custom ("projects/p/roles/x",
// "organizations/o/roles/x") role by its exact resource name.
func (c *gcpClient) getRole(ctx context.Context, name string) (gcpRole, []gcpGap) {
	outcome, err := c.get(ctx, c.iamBase+"/v1/"+name, nil, gcpGetRoleReference)
	if err != nil {
		return gcpRole{}, []gcpGap{{Code: "gcp_role_lookup_failed", Message: err.Error()}}
	}
	if outcome.Gap != nil {
		return gcpRole{}, []gcpGap{*outcome.Gap}
	}
	var role gcpRole
	if err := json.Unmarshal(outcome.Body, &role); err != nil {
		return gcpRole{}, []gcpGap{{Code: "gcp_role_decode_failed", Message: err.Error()}}
	}
	return role, nil
}

func (c *gcpClient) getProject(ctx context.Context, projectID string) (gcpProject, []gcpGap) {
	outcome, err := c.get(ctx, c.resourceMgrBase+"/v3/projects/"+projectID, nil, gcpGetProjectReference)
	if err != nil {
		return gcpProject{}, []gcpGap{{Code: "gcp_project_lookup_failed", Message: err.Error()}}
	}
	if outcome.Gap != nil {
		return gcpProject{}, []gcpGap{*outcome.Gap}
	}
	var project gcpProject
	if err := json.Unmarshal(outcome.Body, &project); err != nil {
		return gcpProject{}, []gcpGap{{Code: "gcp_project_decode_failed", Message: err.Error()}}
	}
	return project, nil
}

type gcpIamPolicySearchResult struct {
	Resource     string     `json:"resource"`
	AssetType    string     `json:"assetType"`
	Project      string     `json:"project"`
	Folders      []string   `json:"folders"`
	Organization string     `json:"organization"`
	Policy       *gcpPolicy `json:"policy"`
}

type gcpPolicy struct {
	Version  int          `json:"version"`
	Bindings []gcpBinding `json:"bindings"`
	Etag     string       `json:"etag"`
}

type gcpBinding struct {
	Role      string        `json:"role"`
	Members   []string      `json:"members"`
	Condition *gcpCondition `json:"condition"`
}

type gcpCondition struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
}

type gcpServiceAccount struct {
	Name        string `json:"name"`
	ProjectID   string `json:"projectId"`
	UniqueID    string `json:"uniqueId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`
}

type gcpRole struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`
	Deleted             bool     `json:"deleted"`
	Etag                string   `json:"etag"`
}

type gcpProject struct {
	Name      string `json:"name"`
	ProjectID string `json:"projectId"`
	State     string `json:"state"`
}

// gcpAncestor is one entry in a v1 getAncestry response: ResourceID.Type is
// "project", "folder", or "organization"; ResourceID.Id is that resource's
// bare numeric/alphanumeric id (never a fully-qualified resource name).
type gcpAncestor struct {
	ResourceID struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"resourceId"`
}
