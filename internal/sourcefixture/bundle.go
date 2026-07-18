package sourcefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion    = "cerebro.source-api-fixture.v1"
	SanitizerName    = "sourcefixture"
	SanitizerVersion = 1
)

var (
	ErrCredentialField = errors.New("provider response contains credential field")
	ErrPersonalEmail   = errors.New("provider response contains non-example email")

	emailPattern     = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	credentialKey    = regexp.MustCompile(`(?i)(authorization|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|password|private[_-]?key|credential)`)
	allowedEmailHost = regexp.MustCompile(`(?i)@(example\.(?:com|net|org|test)|users\.noreply\.github\.com)$`)
	replayTestName   = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
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
}

type Request struct {
	Method string `yaml:"method"`
	URL    string `yaml:"url"`
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
	manifest.Response.SHA256 = Digest(canonical)
	manifest.Sanitization.Tool = SanitizerName
	manifest.Sanitization.Version = SanitizerVersion
	manifest.Sanitization.ChangedFields = normalizedList(manifest.Sanitization.ChangedFields)
	manifest.Sanitization.RemovedFields = normalizedList(manifest.Sanitization.RemovedFields)
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
	if strings.ToUpper(strings.TrimSpace(manifest.Request.Method)) != "GET" {
		return errors.New("only read-only GET captures are accepted")
	}
	requestURL, err := url.ParseRequestURI(strings.TrimSpace(manifest.Request.URL))
	if err != nil || requestURL.Scheme != "https" || requestURL.Host == "" || requestURL.User != nil {
		return errors.New("request.url must be an HTTPS URL without user information")
	}
	for key := range requestURL.Query() {
		if credentialKey.MatchString(key) {
			return fmt.Errorf("request.url contains credential query parameter %q", key)
		}
	}
	if manifest.Response.Status < 200 || manifest.Response.Status > 299 {
		return fmt.Errorf("response.status = %d, want 2xx", manifest.Response.Status)
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
	text := string(payload)
	if !strings.Contains(text, "func "+testName+"(") || !strings.Contains(text, "sourcefixture.FindBundle") || !strings.Contains(text, `"`+bundle.Manifest.Case+`"`) {
		return fmt.Errorf("%s replay_test %s must load fixture case %q with sourcefixture.FindBundle", bundle.ManifestPath, bundle.Manifest.ReplayTest, bundle.Manifest.Case)
	}
	return nil
}

func walkJSON(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if credentialKey.MatchString(key) && !emptyJSONValue(child) {
				return fmt.Errorf("%w %s", ErrCredentialField, childPath)
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
		for _, email := range emailPattern.FindAllString(typed, -1) {
			if strings.Contains(typed, email+":") && (strings.HasPrefix(typed, "git@") || strings.HasPrefix(typed, "hg@")) {
				continue
			}
			if !allowedEmailHost.MatchString(email) {
				return fmt.Errorf("%w at %s", ErrPersonalEmail, path)
			}
		}
	}
	return nil
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
