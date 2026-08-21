package sourcefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion                = "cerebro.source-api-fixture.v1"
	SanitizerName                = "sourcefixture"
	SanitizerVersion             = 1
	langSmithRunsQueryBodySHA256 = "c58c62a9a6c15cfcc152d632eaeab82a875f779d5caa6474337365a3586fe327"
)

var (
	ErrCredentialField = errors.New("provider response contains credential field")
	ErrCredentialQuery = errors.New("request URL contains credential query parameter")
	ErrMalformedQuery  = errors.New("request query is malformed")
	ErrPersonalEmail   = errors.New("provider response contains non-example email")
	ErrProviderID      = errors.New("provider response contains unsanitized provider identifier")
	ErrReplayBinding   = errors.New("replay test does not bind the fixture contract")
	ErrReplayQuery     = errors.New("replay query is malformed")
	ErrSanitizedURL    = errors.New("request URL sanitization contract is invalid")
	ErrURLFragment     = errors.New("request URL contains a fragment")

	emailPattern             = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	credentialFieldKey       = regexp.MustCompile(`(?i)^(?:authorization|credentials?|tokens?|secrets?|passwords?|access[_-]?tokens?|refresh[_-]?tokens?|api[_-]?keys?|client[_-]?secrets?|private[_-]?keys?)$|(?:^|[_-])(?:access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|password|private[_-]?key|secret|token)$`)
	allowedEmailHost         = regexp.MustCompile(`(?i)@(example\.(?:com|net|org|test)|users\.noreply\.github\.com)$`)
	zendeskTenantHost        = regexp.MustCompile(`(?i)(^|[^%a-z0-9.-])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.zendesk\.com\b`)
	escapedZendeskTenantHost = regexp.MustCompile(`(?i)(%2f%2f)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.zendesk\.com\b`)
	auth0FixtureHost         = regexp.MustCompile(`(?i)(^|[^%a-z0-9.-])(?:[a-z0-9-]+\.)*terraform-provider-auth0\.com\b`)
	escapedAuth0FixtureHost  = regexp.MustCompile(`(?i)(%2f%2f)(?:[a-z0-9-]+\.)*terraform-provider-auth0\.com\b`)
	auth0TenantHost          = regexp.MustCompile(`(?i)(^|[^%a-z0-9.-])(?:[a-z0-9-]+\.)+auth0\.com\b`)
	escapedAuth0TenantHost   = regexp.MustCompile(`(?i)(%2f%2f)(?:[a-z0-9-]+\.)+auth0\.com\b`)
	auth0FixtureTenant       = regexp.MustCompile(`(?i)\bterraform-provider-auth0(?:-[a-z0-9-]+)?\b`)
	mailchimpListPath        = regexp.MustCompile(`(?i)^(https://[a-z0-9-]+\.api\.mailchimp\.com/3\.0/lists/)([0-9a-f]{10})\b`)
	contentfulAssetURL       = regexp.MustCompile(`(?i)^((?:https:)?//images\.ctfassets\.net/)([^/?#]+)/([^/?#]+)/([^/?#]+)(/[^?#]*)(\?[^#]*)?(#.*)?$`)
	contentfulSpaceURL       = regexp.MustCompile(`(?i)^(https://(?:cdn|preview)\.contentful\.com/spaces/)([^/?#]+)(/[^?#]*)(\?[^#]*)?(#.*)?$`)
	ipv4Pattern              = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	providerIDPattern        = regexp.MustCompile(`(?i)\b(?:(?:00[tuoga]|0oa)[0-9a-z]{17}|aut[0-9a-z][0-9][0-9a-z]{15}|(?:org|rol|con|cgr)_[0-9a-z]{8,}|user_[0-9a-f]{32}|auth0(?:\||%7c)[0-9a-z]{8,}|[0-9a-f]{24})\b`)
	objectID                 = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	fullCommit               = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Digest             = regexp.MustCompile(`^[0-9a-f]{64}$`)
	replayTestName           = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
)

type Manifest struct {
	SchemaVersion string       `yaml:"schema_version"`
	SourceID      string       `yaml:"source_id"`
	Family        string       `yaml:"family"`
	Case          string       `yaml:"case"`
	ReplayTest    string       `yaml:"replay_test"`
	Request       Request      `yaml:"request"`
	Response      Response     `yaml:"response"`
	Sanitization  Sanitization `yaml:"sanitization"`
	Origin        Origin       `yaml:"origin"`
}

type Request struct {
	Method     string `yaml:"method"`
	URL        string `yaml:"url"`
	Semantics  string `yaml:"semantics,omitempty"`
	BodySHA256 string `yaml:"body_sha256,omitempty"`
}

// ReplayContract binds a production decoder replay to the exact sanitized
// provenance contract carried by one provider response bundle.
type ReplayContract struct {
	SourceID string
	Family   string
	Case     string
	Method   string
	Host     string
	Path     string
	RawQuery string
}

// ReplayTestReporter is the subset of testing.T used by replay assertions.
type ReplayTestReporter interface {
	Helper()
	Fatalf(format string, args ...any)
}

type Response struct {
	Status      int               `yaml:"status"`
	ContentType string            `yaml:"content_type"`
	CapturedAt  string            `yaml:"captured_at"`
	SHA256      string            `yaml:"sha256"`
	Headers     map[string]string `yaml:"headers,omitempty"`
}

type Sanitization struct {
	Tool          string   `yaml:"tool"`
	Version       int      `yaml:"version"`
	ChangedFields []string `yaml:"changed_fields,omitempty"`
	RemovedFields []string `yaml:"removed_fields,omitempty"`
}

type Origin struct {
	Type                string   `yaml:"type"`
	Repository          string   `yaml:"repository,omitempty"`
	Commit              string   `yaml:"commit,omitempty"`
	Path                string   `yaml:"path,omitempty"`
	ArtifactSHA256      string   `yaml:"artifact_sha256,omitempty"`
	License             string   `yaml:"license,omitempty"`
	RecordingTool       string   `yaml:"recording_tool,omitempty"`
	HarnessPath         string   `yaml:"harness_path,omitempty"`
	InteractionIndex    int      `yaml:"interaction_index,omitempty"`
	Freshness           string   `yaml:"freshness,omitempty"`
	CaptureTimeBasis    string   `yaml:"capture_time_basis,omitempty"`
	Locator             string   `yaml:"locator,omitempty"`
	RedistributionBasis string   `yaml:"redistribution_basis,omitempty"`
	Release             string   `yaml:"release,omitempty"`
	ImageDigest         string   `yaml:"image_digest,omitempty"`
	SeedCommands        []string `yaml:"seed_commands,omitempty"`
}

type Bundle struct {
	Directory    string
	ResponsePath string
	ManifestPath string
	Manifest     Manifest
	Payload      []byte
}

type Catalog struct {
	ID              string   `yaml:"id"`
	RuntimeFamilies []string `yaml:"runtime_families"`
	Families        []struct {
		ID string `yaml:"id"`
	} `yaml:"families"`
}

type RepositoryReport struct {
	Bundles  int
	Sources  int
	Families int
}

func CanonicalJSON(payload []byte) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("decode JSON response: multiple values")
		}
		return nil, fmt.Errorf("decode JSON response trailing data: %w", err)
	}
	if emptyJSONValue(value) {
		return nil, errors.New("provider response is empty")
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("format JSON response: %w", err)
	}
	return append(formatted, '\n'), nil
}

func Digest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// CanonicalRequestBodySHA256 returns the digest of a canonical JSON request
// body without writing or echoing the request body. It is used to bind an
// explicitly read-only POST query to its provenance manifest.
func CanonicalRequestBodySHA256(payload []byte) (string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("decode JSON request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("decode JSON request body: multiple values")
		}
		return "", fmt.Errorf("decode JSON request body trailing data: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode canonical JSON request body: %w", err)
	}
	return Digest(canonical), nil
}

// ValidateReplayContract rejects a bundle unless its identity and sanitized
// provider request provenance match the contract exercised by the replay test.
func ValidateReplayContract(bundle Bundle, expected ReplayContract) error {
	actual := bundle.Manifest
	for name, values := range map[string][2]string{
		"source_id": {actual.SourceID, strings.TrimSpace(expected.SourceID)},
		"family":    {actual.Family, strings.TrimSpace(expected.Family)},
		"case":      {actual.Case, strings.TrimSpace(expected.Case)},
		"method":    {strings.ToUpper(strings.TrimSpace(actual.Request.Method)), strings.ToUpper(strings.TrimSpace(expected.Method))},
	} {
		if values[0] == "" || values[0] != values[1] {
			return fmt.Errorf("replay provenance %s = %q, want %q", name, values[0], values[1])
		}
	}
	rawRequestURL := strings.TrimSpace(actual.Request.URL)
	if strings.Contains(rawRequestURL, "#") {
		return fmt.Errorf("%w: replay provenance request URL must not contain a fragment", ErrURLFragment)
	}
	requestURL, err := url.ParseRequestURI(rawRequestURL)
	if err != nil || requestURL.Scheme != "https" || requestURL.User != nil {
		return errors.New("replay provenance request URL must be sanitized HTTPS")
	}
	if requestURL.Fragment != "" {
		return fmt.Errorf("%w: replay provenance request URL must not contain a fragment", ErrURLFragment)
	}
	if requestURL.Port() != "" || !strings.EqualFold(requestURL.Hostname(), strings.TrimSpace(expected.Host)) {
		return fmt.Errorf("replay provenance host = %q, want %q", requestURL.Host, expected.Host)
	}
	if requestURL.EscapedPath() != strings.TrimSpace(expected.Path) {
		return fmt.Errorf("replay provenance path = %q, want %q", requestURL.EscapedPath(), expected.Path)
	}
	actualQuery, err := canonicalRawQuery(requestURL.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: replay provenance query is invalid: %w", ErrReplayQuery, err)
	}
	expectedQuery, err := canonicalRawQuery(strings.TrimSpace(expected.RawQuery))
	if err != nil {
		return fmt.Errorf("%w: expected replay query is invalid: %w", ErrReplayQuery, err)
	}
	if actualQuery != expectedQuery {
		return fmt.Errorf("replay provenance query = %q, want %q", actualQuery, expectedQuery)
	}
	return nil
}

// RequireReplayContract makes provenance validation non-ignorable in replay
// tests. Repository verification accepts only direct calls to this helper with
// an exact literal ReplayContract bound to the matching fixture variable.
func RequireReplayContract(t ReplayTestReporter, bundle Bundle, expected ReplayContract) {
	t.Helper()
	if err := ValidateReplayContract(bundle, expected); err != nil {
		t.Fatalf("ValidateReplayContract() error = %v", err)
	}
}

func canonicalRawQuery(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	return values.Encode(), nil
}

func WriteBundle(root string, manifest Manifest, payload []byte) (Bundle, error) {
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return Bundle{}, err
	}
	manifest.SchemaVersion = SchemaVersion
	manifest.SourceID = cleanSegment(manifest.SourceID)
	manifest.Family = cleanSegment(manifest.Family)
	manifest.Case = cleanSegment(manifest.Case)
	if manifest.Case == "" {
		manifest.Case = "response"
	}
	manifest.Request.Method = strings.ToUpper(strings.TrimSpace(manifest.Request.Method))
	manifest.Request.URL = strings.TrimSpace(manifest.Request.URL)
	manifest.Request.Semantics = strings.TrimSpace(manifest.Request.Semantics)
	manifest.Request.BodySHA256 = strings.ToLower(strings.TrimSpace(manifest.Request.BodySHA256))
	manifest.Response.SHA256 = Digest(canonical)
	manifest.Sanitization.Tool = SanitizerName
	manifest.Sanitization.Version = SanitizerVersion
	manifest.Sanitization.ChangedFields = normalizedList(manifest.Sanitization.ChangedFields)
	manifest.Sanitization.RemovedFields = normalizedList(manifest.Sanitization.RemovedFields)
	manifest.Origin = normalizedOrigin(manifest.Origin)
	if err := ValidateManifest(manifest, canonical); err != nil {
		return Bundle{}, err
	}
	directory := filepath.Join(root, "sources", manifest.SourceID, "testdata", "api", manifest.Family, manifest.Case)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return Bundle{}, fmt.Errorf("create bundle directory: %w", err)
	}
	responsePath := filepath.Join(directory, "response.json")
	manifestPath := filepath.Join(directory, "provenance.yaml")
	manifestPayload, err := yaml.Marshal(manifest)
	if err != nil {
		return Bundle{}, fmt.Errorf("encode provenance: %w", err)
	}
	if err := os.WriteFile(responsePath, canonical, 0o644); err != nil { // #nosec G306 -- validated repository fixtures use normal source-file permissions.
		return Bundle{}, fmt.Errorf("write response: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifestPayload, 0o644); err != nil { // #nosec G306 -- provenance is a checked-in repository document.
		return Bundle{}, fmt.Errorf("write provenance: %w", err)
	}
	return Bundle{Directory: directory, ResponsePath: responsePath, ManifestPath: manifestPath, Manifest: manifest, Payload: canonical}, nil
}

func LoadBundle(manifestPath string) (Bundle, error) {
	manifestPayload, err := os.ReadFile(manifestPath) // #nosec G304 -- operator-selected local repository fixture path.
	if err != nil {
		return Bundle{}, fmt.Errorf("read provenance %s: %w", manifestPath, err)
	}
	var manifest Manifest
	if err := yaml.Unmarshal(manifestPayload, &manifest); err != nil {
		return Bundle{}, fmt.Errorf("decode provenance %s: %w", manifestPath, err)
	}
	responsePath := filepath.Join(filepath.Dir(manifestPath), "response.json")
	payload, err := os.ReadFile(responsePath) // #nosec G304 -- response is fixed beside the selected provenance file.
	if err != nil {
		return Bundle{}, fmt.Errorf("read response %s: %w", responsePath, err)
	}
	if err := ValidateManifest(manifest, payload); err != nil {
		return Bundle{}, fmt.Errorf("verify %s: %w", manifestPath, err)
	}
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return Bundle{}, fmt.Errorf("verify %s: %w", responsePath, err)
	}
	if !bytes.Equal(payload, canonical) {
		return Bundle{}, fmt.Errorf("verify %s: response must use canonical indented JSON with a trailing newline", responsePath)
	}
	return Bundle{Directory: filepath.Dir(manifestPath), ResponsePath: responsePath, ManifestPath: manifestPath, Manifest: manifest, Payload: payload}, nil
}

func ValidateManifest(manifest Manifest, payload []byte) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version = %q, want %q", manifest.SchemaVersion, SchemaVersion)
	}
	if cleanSegment(manifest.SourceID) == "" || cleanSegment(manifest.Family) == "" || cleanSegment(manifest.Case) == "" {
		return errors.New("source_id, family, and case are required safe path segments")
	}
	if _, _, err := parseReplayTest(manifest.ReplayTest); err != nil {
		return err
	}
	method := strings.ToUpper(strings.TrimSpace(manifest.Request.Method))
	switch method {
	case "GET":
		if strings.TrimSpace(manifest.Request.Semantics) != "" || strings.TrimSpace(manifest.Request.BodySHA256) != "" {
			return errors.New("GET captures must not declare POST query semantics or a request body digest")
		}
	case "POST":
		if strings.TrimSpace(manifest.Request.Semantics) != "read_only_query" {
			return errors.New("POST captures require request.semantics = read_only_query")
		}
		if !sha256Digest.MatchString(strings.ToLower(strings.TrimSpace(manifest.Request.BodySHA256))) {
			return errors.New("read-only POST captures require a canonical request body SHA-256")
		}
	default:
		return fmt.Errorf("request.method = %q, want GET or explicitly read-only POST query", method)
	}
	rawRequestURL := strings.TrimSpace(manifest.Request.URL)
	if strings.Contains(rawRequestURL, "#") {
		return fmt.Errorf("%w: request.url must not contain a fragment", ErrURLFragment)
	}
	requestURL, err := url.ParseRequestURI(rawRequestURL)
	if err != nil || requestURL.Scheme != "https" || requestURL.Host == "" || requestURL.User != nil {
		return errors.New("request.url must be an HTTPS URL without user information")
	}
	if requestURL.Fragment != "" {
		return fmt.Errorf("%w: request.url must not contain a fragment", ErrURLFragment)
	}
	requestQuery, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return fmt.Errorf("%w: request.url query is invalid: %w", ErrMalformedQuery, err)
	}
	if manifest.SourceID == "langfuse" && strings.HasSuffix(strings.ToLower(requestURL.Hostname()), ".writer.com") {
		return fmt.Errorf("%w: langfuse capture provenance must not publish an environment-specific Writer host", ErrSanitizedURL)
	}
	if manifest.SourceID == "langfuse" && strings.EqualFold(requestURL.Hostname(), "langfuse.example.com") {
		markedSanitized := false
		for _, field := range manifest.Sanitization.ChangedFields {
			if strings.TrimSpace(field) == "$request.url" {
				markedSanitized = true
				break
			}
		}
		if !markedSanitized {
			return fmt.Errorf("%w: langfuse example-host provenance must mark $request.url as sanitized", ErrSanitizedURL)
		}
	}
	allowedReadOnlyQuery := manifest.SourceID == "langchain" &&
		strings.EqualFold(requestURL.Hostname(), "api.smith.langchain.com") &&
		requestURL.Port() == "" &&
		requestURL.EscapedPath() == "/api/v1/runs/query" &&
		requestURL.RawQuery == "" &&
		requestURL.Fragment == ""
	if method == "POST" && !allowedReadOnlyQuery {
		return errors.New("read-only POST captures are limited to langchain https://api.smith.langchain.com/api/v1/runs/query")
	}
	if method == "POST" && strings.ToLower(strings.TrimSpace(manifest.Request.BodySHA256)) != langSmithRunsQueryBodySHA256 {
		return errors.New("read-only POST capture body digest does not match the approved LangSmith runs query")
	}
	for key := range requestQuery {
		if isCredentialQueryKey(key) {
			return fmt.Errorf("%w %q", ErrCredentialQuery, key)
		}
	}
	if containsUnsanitizedProviderText(manifest.Request.URL) {
		return fmt.Errorf("%w in request.url", ErrProviderID)
	}
	if manifest.Response.Status < 200 || manifest.Response.Status > 299 {
		return fmt.Errorf("response.status = %d, want 2xx", manifest.Response.Status)
	}
	for name, value := range manifest.Response.Headers {
		if containsUnsanitizedProviderText(value) {
			return fmt.Errorf("%w in response.headers.%s", ErrProviderID, name)
		}
	}
	if !strings.Contains(strings.ToLower(manifest.Response.ContentType), "json") {
		return fmt.Errorf("response.content_type = %q, want JSON", manifest.Response.ContentType)
	}
	if _, err := time.Parse(time.RFC3339, manifest.Response.CapturedAt); err != nil {
		return fmt.Errorf("response.captured_at must be RFC3339: %w", err)
	}
	if manifest.Sanitization.Tool != SanitizerName || manifest.Sanitization.Version != SanitizerVersion {
		return fmt.Errorf("sanitization tool/version = %s/%d, want %s/%d", manifest.Sanitization.Tool, manifest.Sanitization.Version, SanitizerName, SanitizerVersion)
	}
	if err := validateOrigin(manifest.Origin); err != nil {
		return err
	}
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return err
	}
	if manifest.Response.SHA256 != Digest(canonical) {
		return fmt.Errorf("response.sha256 = %q, want %q", manifest.Response.SHA256, Digest(canonical))
	}
	if err := scanPayload(canonical); err != nil {
		return err
	}
	return nil
}

func VerifyRepository(root string) (RepositoryReport, error) {
	pattern := filepath.Join(root, "sources", "*", "testdata", "api", "*", "*", "provenance.yaml")
	manifestPaths, err := filepath.Glob(pattern)
	if err != nil {
		return RepositoryReport{}, err
	}
	sort.Strings(manifestPaths)
	report := RepositoryReport{}
	sources := map[string]struct{}{}
	families := map[string]struct{}{}
	for _, manifestPath := range manifestPaths {
		bundle, err := LoadBundle(manifestPath)
		if err != nil {
			return report, err
		}
		catalogPath := filepath.Join(root, "sources", bundle.Manifest.SourceID, "catalog.yaml")
		catalogPayload, err := os.ReadFile(catalogPath) // #nosec G304 -- path uses the validated source ID under the operator-selected repository root.
		if err != nil {
			return report, fmt.Errorf("read catalog for %s: %w", manifestPath, err)
		}
		var catalog Catalog
		if err := yaml.Unmarshal(catalogPayload, &catalog); err != nil {
			return report, fmt.Errorf("decode catalog %s: %w", catalogPath, err)
		}
		if catalog.ID != bundle.Manifest.SourceID {
			return report, fmt.Errorf("%s source_id %q does not match catalog id %q", manifestPath, bundle.Manifest.SourceID, catalog.ID)
		}
		if !catalogHasFamily(catalog, bundle.Manifest.Family) {
			return report, fmt.Errorf("%s family %q is not declared by %s", manifestPath, bundle.Manifest.Family, catalogPath)
		}
		if err := verifyReplayTest(root, bundle); err != nil {
			return report, err
		}
		relative, err := filepath.Rel(filepath.Join(root, "sources", bundle.Manifest.SourceID, "testdata", "api"), bundle.Directory)
		if err != nil {
			return report, err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if len(parts) != 2 || parts[0] != bundle.Manifest.Family || parts[1] != bundle.Manifest.Case {
			return report, fmt.Errorf("%s path does not match family/case %s/%s", manifestPath, bundle.Manifest.Family, bundle.Manifest.Case)
		}
		report.Bundles++
		sources[bundle.Manifest.SourceID] = struct{}{}
		families[bundle.Manifest.SourceID+"/"+bundle.Manifest.Family] = struct{}{}
	}
	report.Sources = len(sources)
	report.Families = len(families)
	return report, nil
}

func PackagesWithBundles(root string) ([]string, error) {
	sources := map[string]struct{}{}
	if err := WalkBundles(root, func(bundle Bundle) error {
		sources[bundle.Manifest.SourceID] = struct{}{}
		return nil
	}); err != nil {
		return nil, err
	}
	packages := make([]string, 0, len(sources))
	for sourceID := range sources {
		packages = append(packages, "./sources/"+sourceID)
	}
	sort.Strings(packages)
	return packages, nil
}

func FindBundle(root, sourceID, family, fixtureCase string) (Bundle, error) {
	manifestPath := filepath.Join(root, "sources", cleanSegment(sourceID), "testdata", "api", cleanSegment(family), cleanSegment(fixtureCase), "provenance.yaml")
	return LoadBundle(manifestPath)
}

// CompareOrUpdateGenerated verifies a generated fixture or rewrites it when an
// explicit update run is requested.
func CompareOrUpdateGenerated(path string, payload []byte, update bool) error {
	if update {
		if err := os.WriteFile(path, payload, 0o644); err != nil { // #nosec G306 -- generated repository fixtures use normal source-file permissions.
			return fmt.Errorf("write generated fixture %s: %w", path, err)
		}
		return nil
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- caller supplies a local generated repository fixture path.
	if err != nil {
		return fmt.Errorf("read generated fixture %s: %w", path, err)
	}
	if !bytes.Equal(existing, payload) {
		return fmt.Errorf("generated fixture %s is stale; run the package test with CEREBRO_UPDATE_SOURCE_FIXTURES=1", path)
	}
	return nil
}

func WalkBundles(root string, visit func(Bundle) error) error {
	apiRoot := filepath.Join(root, "sources")
	return filepath.WalkDir(apiRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "provenance.yaml" || !strings.Contains(filepath.ToSlash(path), "/testdata/api/") {
			return nil
		}
		bundle, err := LoadBundle(path)
		if err != nil {
			return err
		}
		return visit(bundle)
	})
}

func catalogHasFamily(catalog Catalog, family string) bool {
	for _, candidate := range catalog.RuntimeFamilies {
		if candidate == family {
			return true
		}
	}
	for _, candidate := range catalog.Families {
		if candidate.ID == family {
			return true
		}
	}
	return false
}

func scanPayload(payload []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return walkJSON(value, "$")
}

func parseReplayTest(reference string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(reference), "#")
	if len(parts) != 2 || filepath.Base(parts[0]) != parts[0] || !strings.HasSuffix(parts[0], "_test.go") || !replayTestName.MatchString(parts[1]) {
		return "", "", errors.New("replay_test must use source_test.go#TestName format")
	}
	return parts[0], parts[1], nil
}

func verifyReplayTest(root string, bundle Bundle) error {
	fileName, testName, err := parseReplayTest(bundle.Manifest.ReplayTest)
	if err != nil {
		return fmt.Errorf("%s: %w", bundle.ManifestPath, err)
	}
	testPath := filepath.Join(root, "sources", bundle.Manifest.SourceID, fileName)
	payload, err := os.ReadFile(testPath) // #nosec G304 -- path uses validated fixture source and test-file segments under the repository root.
	if err != nil {
		return fmt.Errorf("read replay test for %s: %w", bundle.ManifestPath, err)
	}
	foundFunction, foundBundle, foundContract, err := replayTestBindings(payload, testName, bundle.Manifest)
	if err != nil {
		return fmt.Errorf("parse replay test for %s: %w", bundle.ManifestPath, err)
	}
	requiresBoundReplay := bundle.Manifest.SourceID == "langchain" || bundle.Manifest.SourceID == "langfuse" || bundle.Manifest.SourceID == "writer"
	if !foundFunction {
		return fmt.Errorf("%s replay_test %s must name a real Go test function", bundle.ManifestPath, bundle.Manifest.ReplayTest)
	}
	if requiresBoundReplay && !foundBundle {
		return fmt.Errorf("%s replay_test %s must load fixture case %q with sourcefixture.FindBundle", bundle.ManifestPath, bundle.Manifest.ReplayTest, bundle.Manifest.Case)
	}
	if requiresBoundReplay && !foundContract {
		return fmt.Errorf("%w: %s replay_test %s must directly bind fixture case %q with sourcefixture.RequireReplayContract and an exact literal contract", ErrReplayBinding, bundle.ManifestPath, bundle.Manifest.ReplayTest, bundle.Manifest.Case)
	}
	if !requiresBoundReplay && (!strings.Contains(string(payload), "sourcefixture.FindBundle") || !strings.Contains(string(payload), `"`+bundle.Manifest.Case+`"`)) {
		return fmt.Errorf("%s replay_test %s must load fixture case %q with sourcefixture.FindBundle", bundle.ManifestPath, bundle.Manifest.ReplayTest, bundle.Manifest.Case)
	}
	return nil
}

func replayTestBindings(payload []byte, testName string, manifest Manifest) (bool, bool, bool, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "source_test.go", payload, 0)
	if err != nil {
		return false, false, false, err
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name == nil || function.Name.Name != testName || function.Body == nil {
			continue
		}
		foundBundle := false
		foundContract := false
		bundleVariables := map[string]struct{}{}
		testReporter := testReporterName(function)
		for _, statement := range function.Body.List {
			if assignment, ok := statement.(*ast.AssignStmt); ok {
				for _, expression := range assignment.Rhs {
					call, ok := expression.(*ast.CallExpr)
					if !ok || !matchingFindBundleCall(call, manifest.SourceID, manifest.Family, manifest.Case) {
						continue
					}
					foundBundle = true
					if len(assignment.Lhs) > 0 {
						if identifier, ok := assignment.Lhs[0].(*ast.Ident); ok && identifier.Name != "_" {
							bundleVariables[identifier.Name] = struct{}{}
						}
					}
				}
			}
			expression, ok := statement.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := expression.X.(*ast.CallExpr)
			if ok && matchingRequiredReplayContractCall(call, testReporter, bundleVariables, manifest) {
				foundContract = true
			}
		}
		return true, foundBundle, foundContract, nil
	}
	return false, false, false, nil
}

func testReporterName(function *ast.FuncDecl) string {
	if function == nil || function.Type == nil || function.Type.Params == nil {
		return ""
	}
	for _, field := range function.Type.Params.List {
		for _, name := range field.Names {
			if name.Name == "t" {
				return name.Name
			}
		}
	}
	return ""
}

func matchingRequiredReplayContractCall(call *ast.CallExpr, testReporter string, bundleVariables map[string]struct{}, manifest Manifest) bool {
	if call == nil || selectorName(call.Fun) != "sourcefixture.RequireReplayContract" || len(call.Args) != 3 || testReporter == "" {
		return false
	}
	reporter, ok := call.Args[0].(*ast.Ident)
	if !ok || reporter.Name != testReporter {
		return false
	}
	bundle, ok := call.Args[1].(*ast.Ident)
	if !ok {
		return false
	}
	if _, ok := bundleVariables[bundle.Name]; !ok {
		return false
	}
	contract, ok := literalReplayContract(call.Args[2])
	if !ok {
		return false
	}
	expected, err := manifestReplayContract(manifest)
	return err == nil && contract == expected
}

func literalReplayContract(expression ast.Expr) (ReplayContract, bool) {
	literal, ok := expression.(*ast.CompositeLit)
	if !ok || selectorName(literal.Type) != "sourcefixture.ReplayContract" {
		return ReplayContract{}, false
	}
	values := map[string]string{}
	for _, element := range literal.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return ReplayContract{}, false
		}
		key, ok := field.Key.(*ast.Ident)
		if !ok {
			return ReplayContract{}, false
		}
		value := stringLiteral(field.Value)
		if key.Name == "Method" && value == "" {
			value = httpMethodConstant(field.Value)
		}
		if _, duplicate := values[key.Name]; duplicate {
			return ReplayContract{}, false
		}
		values[key.Name] = value
	}
	for _, required := range []string{"SourceID", "Family", "Case", "Method", "Host", "Path", "RawQuery"} {
		if _, ok := values[required]; !ok {
			return ReplayContract{}, false
		}
	}
	if len(values) != 7 || values["SourceID"] == "" || values["Family"] == "" || values["Case"] == "" || values["Method"] == "" || values["Host"] == "" || values["Path"] == "" {
		return ReplayContract{}, false
	}
	return ReplayContract{
		SourceID: values["SourceID"],
		Family:   values["Family"],
		Case:     values["Case"],
		Method:   values["Method"],
		Host:     values["Host"],
		Path:     values["Path"],
		RawQuery: values["RawQuery"],
	}, true
}

func httpMethodConstant(expression ast.Expr) string {
	switch selectorName(expression) {
	case "http.MethodGet":
		return "GET"
	case "http.MethodPost":
		return "POST"
	default:
		return ""
	}
}

func manifestReplayContract(manifest Manifest) (ReplayContract, error) {
	requestURL, err := url.ParseRequestURI(strings.TrimSpace(manifest.Request.URL))
	if err != nil {
		return ReplayContract{}, err
	}
	rawQuery, err := canonicalRawQuery(requestURL.RawQuery)
	if err != nil {
		return ReplayContract{}, err
	}
	return ReplayContract{
		SourceID: manifest.SourceID,
		Family:   manifest.Family,
		Case:     manifest.Case,
		Method:   strings.ToUpper(strings.TrimSpace(manifest.Request.Method)),
		Host:     requestURL.Hostname(),
		Path:     requestURL.EscapedPath(),
		RawQuery: rawQuery,
	}, nil
}

func matchingFindBundleCall(call *ast.CallExpr, sourceID, family, fixtureCase string) bool {
	return call != nil && selectorName(call.Fun) == "sourcefixture.FindBundle" && len(call.Args) >= 4 &&
		stringLiteral(call.Args[1]) == sourceID && stringLiteral(call.Args[2]) == family && stringLiteral(call.Args[3]) == fixtureCase
}

func selectorName(expression ast.Expr) string {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel == nil {
		return ""
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name + "." + selector.Sel.Name
}

func stringLiteral(expression ast.Expr) string {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return ""
	}
	return value
}

func walkJSON(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if isCredentialFieldKey(key) {
				if err := validateCredentialJSONValue(child, childPath); err != nil {
					return err
				}
				continue
			}
			if err := walkJSON(child, childPath); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := walkJSON(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case string:
		if containsUnsanitizedProviderText(typed) {
			return fmt.Errorf("%w %s", ErrProviderID, path)
		}
		for _, email := range emailPattern.FindAllString(typed, -1) {
			if strings.HasPrefix(typed, email+":") && (strings.HasPrefix(typed, "git@") || strings.HasPrefix(typed, "hg@")) {
				continue
			}
			if !allowedEmailHost.MatchString(email) {
				return fmt.Errorf("%w at %s", ErrPersonalEmail, path)
			}
		}
	}
	return nil
}

func validateCredentialJSONValue(value any, path string) error {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		for key, child := range typed {
			if err := validateCredentialJSONValue(child, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for index, child := range typed {
			if err := validateCredentialJSONValue(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		return nil
	case string:
		if typed == "" {
			return nil
		}
	case json.Number:
		if typed == "0" {
			return nil
		}
	case bool:
		if !typed {
			return nil
		}
	}
	return fmt.Errorf("%w %s", ErrCredentialField, path)
}

func isCredentialFieldKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "continuation_token", "cursor_token", "delta_token", "next_page_token", "next_token", "page_token", "pagination_token", "sync_token":
		return false
	default:
		return credentialFieldKey.MatchString(key)
	}
}

func isCredentialQueryKey(key string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch normalized {
	case "continuation_token", "cursor_token", "delta_token", "next_page_token", "next_token", "page_token", "pagination_token", "sync_token":
		return false
	case "auth", "authorization", "token", "secret", "key", "sig", "signature", "pat", "password",
		"access_token", "accesstoken", "refresh_token", "refreshtoken", "api_key", "apikey",
		"client_secret", "clientsecret", "private_key", "privatekey", "private_token", "privatetoken":
		return true
	}
	for _, suffix := range []string{
		"_access_token", "_refresh_token", "_api_key", "_client_secret", "_private_key", "_private_token",
		"_token", "_secret", "_password", "_signature", "_sig", "_pat",
	} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func emptyJSONValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(typed) == ""
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

func cleanSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
		return ""
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return ""
	}
	return value
}

func normalizedList(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizedOrigin(origin Origin) Origin {
	origin.Type = strings.TrimSpace(origin.Type)
	origin.Repository = strings.TrimSpace(origin.Repository)
	origin.Commit = strings.ToLower(strings.TrimSpace(origin.Commit))
	origin.Path = strings.TrimSpace(origin.Path)
	origin.ArtifactSHA256 = strings.ToLower(strings.TrimSpace(origin.ArtifactSHA256))
	origin.License = strings.TrimSpace(origin.License)
	origin.RecordingTool = strings.TrimSpace(origin.RecordingTool)
	origin.HarnessPath = strings.TrimSpace(origin.HarnessPath)
	origin.Freshness = strings.TrimSpace(origin.Freshness)
	origin.CaptureTimeBasis = strings.TrimSpace(origin.CaptureTimeBasis)
	origin.Locator = strings.TrimSpace(origin.Locator)
	origin.RedistributionBasis = strings.TrimSpace(origin.RedistributionBasis)
	origin.Release = strings.TrimSpace(origin.Release)
	origin.ImageDigest = strings.TrimSpace(origin.ImageDigest)
	origin.SeedCommands = normalizedList(origin.SeedCommands)
	return origin
}

func validateOrigin(origin Origin) error {
	origin = normalizedOrigin(origin)
	switch origin.Type {
	case "operator_request":
		if origin.Repository != "" || origin.Commit != "" || origin.Path != "" || origin.ArtifactSHA256 != "" || origin.License != "" || origin.RecordingTool != "" || origin.HarnessPath != "" || origin.InteractionIndex != 0 || origin.Freshness != "" || origin.CaptureTimeBasis != "" || origin.Locator != "" || origin.RedistributionBasis != "" || origin.Release != "" || origin.ImageDigest != "" || len(origin.SeedCommands) != 0 {
			return errors.New("operator_request origin must not declare upstream import or artifact fields")
		}
		return nil
	case "upstream_recording":
		if err := validateHTTPSURL("origin.repository", origin.Repository); err != nil {
			return err
		}
		if !fullCommit.MatchString(origin.Commit) {
			return errors.New("origin.commit must be a full lowercase Git commit")
		}
		if err := validateRelativeArtifactPath("origin.path", origin.Path); err != nil {
			return err
		}
		if err := validateRelativeArtifactPath("origin.harness_path", origin.HarnessPath); err != nil {
			return err
		}
		if !sha256Digest.MatchString(origin.ArtifactSHA256) {
			return errors.New("origin.artifact_sha256 must be a lowercase SHA-256 digest")
		}
		if origin.License == "" || strings.EqualFold(origin.License, "NOASSERTION") || strings.EqualFold(origin.License, "UNKNOWN") {
			return errors.New("origin.license must declare redistribution terms")
		}
		if origin.RecordingTool == "" {
			return errors.New("origin.recording_tool is required for an upstream recording")
		}
		return validateFreshnessAndCaptureBasis(origin)
	case "public_archive":
		if err := validateHTTPSURL("origin.locator", origin.Locator); err != nil {
			return err
		}
		if !sha256Digest.MatchString(origin.ArtifactSHA256) {
			return errors.New("origin.artifact_sha256 must be a lowercase SHA-256 digest")
		}
		if origin.RedistributionBasis == "" {
			return errors.New("origin.redistribution_basis is required for a public archive")
		}
		return validateFreshnessAndCaptureBasis(origin)
	case "official_implementation":
		if origin.Release == "" && origin.ImageDigest == "" {
			return errors.New("origin.release or origin.image_digest is required for an official implementation")
		}
		if len(origin.SeedCommands) == 0 {
			return errors.New("origin.seed_commands are required for an official implementation")
		}
		return validateFreshnessAndCaptureBasis(origin)
	default:
		return errors.New("origin.type must be operator_request, upstream_recording, public_archive, or official_implementation")
	}
}

func validateFreshnessAndCaptureBasis(origin Origin) error {
	if origin.Freshness != "current" && origin.Freshness != "historical" {
		return errors.New("origin.freshness must be current or historical")
	}
	switch origin.CaptureTimeBasis {
	case "response_header", "recorded_at", "artifact_commit":
		return nil
	default:
		return errors.New("origin.capture_time_basis must be response_header, recorded_at, or artifact_commit")
	}
}

func validateHTTPSURL(field, value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("%s must be an HTTPS URL without user information", field)
	}
	return nil
}

func validateRelativeArtifactPath(field, value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("%s must be a clean repository-relative path", field)
	}
	return nil
}
