package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/internal/sourcehttp"
	"gopkg.in/yaml.v3"
)

const maxResponseBytes = 4 << 20
const maxArtifactBytes = 32 << 20

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: sourcefixture <capture|import|resanitize|verify|packages>"))
	}
	switch os.Args[1] {
	case "capture":
		capture(os.Args[2:])
	case "import":
		importRecording(os.Args[2:])
	case "resanitize":
		resanitize(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "packages":
		packages(os.Args[2:])
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func resanitize(arguments []string) {
	flags := flag.NewFlagSet("resanitize", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil {
		fail(err)
	}
	manifestPaths, err := filepath.Glob(filepath.Join(*root, "sources", "*", "testdata", "api", "*", "*", "provenance.yaml"))
	if err != nil {
		fail(err)
	}
	sort.Strings(manifestPaths)
	changedBundles := 0
	for _, manifestPath := range manifestPaths {
		manifestPayload, readErr := os.ReadFile(manifestPath) // #nosec G304 -- paths come from a fixed repository fixture glob.
		if readErr != nil {
			fail(readErr)
		}
		var manifest sourcefixture.Manifest
		if decodeErr := yaml.Unmarshal(manifestPayload, &manifest); decodeErr != nil {
			fail(fmt.Errorf("decode provenance %s: %w", manifestPath, decodeErr))
		}
		responsePath := filepath.Join(filepath.Dir(manifestPath), "response.json")
		payload, readErr := os.ReadFile(responsePath) // #nosec G304 -- response is fixed beside the globbed provenance file.
		if readErr != nil {
			fail(readErr)
		}
		sanitized, changedFields, sanitizeErr := sourcefixture.SanitizeImportedCredentials(payload)
		if sanitizeErr != nil {
			fail(fmt.Errorf("sanitize %s: %w", responsePath, sanitizeErr))
		}
		if len(changedFields) == 0 {
			continue
		}
		manifest.Sanitization.ChangedFields = append(manifest.Sanitization.ChangedFields, changedFields...)
		if _, writeErr := sourcefixture.WriteBundle(*root, manifest, sanitized); writeErr != nil {
			fail(fmt.Errorf("rewrite %s: %w", manifestPath, writeErr))
		}
		changedBundles++
	}
	fmt.Printf("sourcefixture: resanitized bundles=%d\n", changedBundles)
}

func capture(arguments []string) {
	flags := flag.NewFlagSet("capture", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	sourceID := flags.String("source", "", "source id")
	family := flags.String("family", "", "runtime family")
	fixtureCase := flags.String("case", "response", "fixture case")
	replayTest := flags.String("replay-test", "", "source test reference in source_test.go#TestName format")
	requestURL := flags.String("url", "", "public HTTPS GET URL")
	stdin := flags.Bool("stdin", false, "read a response captured by an authenticated provider CLI from stdin")
	status := flags.Int("status", 200, "HTTP status for a stdin capture")
	contentType := flags.String("content-type", "application/json", "content type for a stdin capture")
	var changedFields stringList
	var removedFields stringList
	flags.Var(&changedFields, "changed-field", "sanitized JSON field path (repeatable)")
	flags.Var(&removedFields, "removed-field", "removed JSON field path (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		fail(err)
	}
	parsedURL, err := url.ParseRequestURI(strings.TrimSpace(*requestURL))
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		fail(fmt.Errorf("-url must be an HTTPS URL without user information"))
	}
	responseStatus := *status
	responseContentType := strings.TrimSpace(*contentType)
	responseHeaders := map[string]string(nil)
	var payload []byte
	if *stdin {
		payload, err = io.ReadAll(io.LimitReader(os.Stdin, maxResponseBytes+1))
		if err != nil {
			fail(fmt.Errorf("read provider CLI response: %w", err))
		}
	} else {
		response, fetchErr := fetchPublicResponse(parsedURL)
		if fetchErr != nil {
			fail(fetchErr)
		}
		payload = response.Body
		responseStatus = response.StatusCode
		responseContentType = response.Header.Get("Content-Type")
		responseHeaders = captureHeaders(response.Header)
	}
	if len(payload) > maxResponseBytes {
		fail(fmt.Errorf("provider response exceeds %d bytes", maxResponseBytes))
	}
	manifest := sourcefixture.Manifest{
		SourceID:   *sourceID,
		Family:     *family,
		Case:       *fixtureCase,
		ReplayTest: *replayTest,
		Request:    sourcefixture.Request{Method: "GET", URL: parsedURL.String()},
		Response: sourcefixture.Response{
			Status:      responseStatus,
			ContentType: responseContentType,
			CapturedAt:  time.Now().UTC().Format(time.RFC3339),
			Headers:     responseHeaders,
		},
		Sanitization: sourcefixture.Sanitization{ChangedFields: changedFields, RemovedFields: removedFields},
		Origin:       sourcefixture.Origin{Type: "operator_request"},
	}
	bundle, err := sourcefixture.WriteBundle(*root, manifest, payload)
	if err != nil {
		fail(err)
	}
	fmt.Printf("sourcefixture: captured source=%s family=%s case=%s status=%d digest=%s path=%s\n", bundle.Manifest.SourceID, bundle.Manifest.Family, bundle.Manifest.Case, bundle.Manifest.Response.Status, bundle.Manifest.Response.SHA256, bundle.ResponsePath)
}

func importRecording(arguments []string) {
	flags := flag.NewFlagSet("import", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	sourceID := flags.String("source", "", "source id")
	family := flags.String("family", "", "runtime family")
	fixtureCase := flags.String("case", "response", "fixture case")
	replayTest := flags.String("replay-test", "", "source test reference in source_test.go#TestName format")
	input := flags.String("input", "", "local upstream recording artifact")
	format := flags.String("format", "", "recording format: vcr or pygithub")
	interactionIndex := flags.Int("interaction", 0, "zero-based interaction index")
	requestURL := flags.String("url", "", "sanitized request URL override")
	capturedAt := flags.String("captured-at", "", "RFC3339 capture time when the recording omits one")
	captureTimeBasis := flags.String("capture-time-basis", "", "response_header, recorded_at, or artifact_commit")
	repository := flags.String("repository", "", "upstream repository HTTPS URL")
	commit := flags.String("commit", "", "upstream full Git commit")
	artifactPath := flags.String("artifact-path", "", "upstream repository-relative artifact path")
	license := flags.String("license", "", "upstream SPDX license identifier")
	recordingTool := flags.String("recording-tool", "", "upstream recording tool")
	harnessPath := flags.String("harness-path", "", "upstream repository-relative recording harness path")
	freshness := flags.String("freshness", "current", "current or historical provider-contract compatibility")
	var declaredChangedFields stringList
	var removedFields stringList
	var sanitizeKeys stringList
	flags.Var(&declaredChangedFields, "changed-field", "manually sanitized request or JSON field path (repeatable)")
	flags.Var(&removedFields, "removed-field", "removed JSON field path (repeatable)")
	flags.Var(&sanitizeKeys, "sanitize-key", "replace every string field with this exact key (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		fail(err)
	}
	artifact, err := readBoundedFile(*input, maxArtifactBytes)
	if err != nil {
		fail(err)
	}
	interaction, err := sourcefixture.ExtractRecording(artifact, *format, *interactionIndex)
	if err != nil {
		fail(err)
	}
	if strings.TrimSpace(*requestURL) != "" {
		if err := validateSanitizedRequestURL(interaction.Request.URL, strings.TrimSpace(*requestURL)); err != nil {
			fail(err)
		}
		interaction.Request.URL = strings.TrimSpace(*requestURL)
	}
	if strings.TrimSpace(*capturedAt) != "" {
		interaction.CapturedAt = strings.TrimSpace(*capturedAt)
	}
	if strings.TrimSpace(*captureTimeBasis) != "" {
		interaction.CaptureTimeBasis = strings.TrimSpace(*captureTimeBasis)
	}
	if interaction.CapturedAt == "" {
		fail(fmt.Errorf("recording has no capture time; provide -captured-at and -capture-time-basis artifact_commit"))
	}
	if interaction.ContentType == "" {
		fail(fmt.Errorf("recording response has no Content-Type header"))
	}
	originalRequestURL := interaction.Request.URL
	interaction.Request.URL = sourcefixture.SanitizeImportedText(interaction.Request.URL)
	if interaction.Request.URL != originalRequestURL {
		declaredChangedFields = append(declaredChangedFields, "$request.url")
	}
	payload, changedFields, err := sourcefixture.SanitizeImportedJSONWithKeys(interaction.Payload, sanitizeKeys)
	if err != nil {
		fail(err)
	}
	changedFields = append(changedFields, declaredChangedFields...)
	responseHeaders, headerChanges := recordingResponseHeaders(interaction.Headers)
	changedFields = append(changedFields, headerChanges...)
	manifest := sourcefixture.Manifest{
		SourceID:   *sourceID,
		Family:     *family,
		Case:       *fixtureCase,
		ReplayTest: *replayTest,
		Request:    interaction.Request,
		Response: sourcefixture.Response{
			Status:      interaction.Status,
			ContentType: interaction.ContentType,
			CapturedAt:  interaction.CapturedAt,
			Headers:     responseHeaders,
		},
		Sanitization: sourcefixture.Sanitization{ChangedFields: changedFields, RemovedFields: removedFields},
		Origin: sourcefixture.Origin{
			Type:             "upstream_recording",
			Repository:       *repository,
			Commit:           *commit,
			Path:             *artifactPath,
			ArtifactSHA256:   sourcefixture.Digest(artifact),
			License:          *license,
			RecordingTool:    *recordingTool,
			HarnessPath:      *harnessPath,
			InteractionIndex: *interactionIndex,
			Freshness:        *freshness,
			CaptureTimeBasis: interaction.CaptureTimeBasis,
		},
	}
	bundle, err := sourcefixture.WriteBundle(*root, manifest, payload)
	if err != nil {
		fail(err)
	}
	fmt.Printf("sourcefixture: imported source=%s family=%s case=%s interaction=%d digest=%s path=%s\n", bundle.Manifest.SourceID, bundle.Manifest.Family, bundle.Manifest.Case, *interactionIndex, bundle.Manifest.Response.SHA256, bundle.ResponsePath)
}

func validateSanitizedRequestURL(recorded, sanitized string) error {
	recordedURL, recordedErr := url.ParseRequestURI(recorded)
	sanitizedURL, sanitizedErr := url.ParseRequestURI(sanitized)
	if recordedErr != nil || sanitizedErr != nil || recordedURL.Scheme != sanitizedURL.Scheme || !strings.EqualFold(recordedURL.Host, sanitizedURL.Host) || recordedURL.EscapedPath() != sanitizedURL.EscapedPath() {
		return errors.New("-url may sanitize query values but must preserve the recorded scheme, host, and path")
	}
	return nil
}

func readBoundedFile(fileName string, limit int64) ([]byte, error) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return nil, errors.New("-input is required")
	}
	file, err := os.Open(fileName) // #nosec G304 -- operator selects the local upstream artifact.
	if err != nil {
		return nil, fmt.Errorf("open recording artifact: %w", err)
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read recording artifact: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close recording artifact: %w", closeErr)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("recording artifact exceeds %d bytes", limit)
	}
	return payload, nil
}

func recordingResponseHeaders(headers map[string]string) (map[string]string, []string) {
	result := map[string]string{}
	changed := []string{}
	for name, value := range headers {
		switch strings.ToLower(name) {
		case "link", "x-next-page", "x-page", "x-per-page", "x-total", "x-total-pages":
			if strings.TrimSpace(value) != "" {
				sanitized := sourcefixture.SanitizeImportedText(strings.TrimSpace(value))
				result[name] = sanitized
				if sanitized != strings.TrimSpace(value) {
					changed = append(changed, "$response.headers."+name)
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, changed
	}
	return result, changed
}

func packages(arguments []string) {
	flags := flag.NewFlagSet("packages", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil {
		fail(err)
	}
	packages, err := sourcefixture.PackagesWithBundles(*root)
	if err != nil {
		fail(err)
	}
	fmt.Println(strings.Join(packages, " "))
}

func verify(arguments []string) {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil {
		fail(err)
	}
	report, err := sourcefixture.VerifyRepository(*root)
	if err != nil {
		fail(err)
	}
	fmt.Printf("sourcefixture: bundles=%d sources=%d families=%d\n", report.Bundles, report.Sources, report.Families)
}

func fetchPublicResponse(initialURL *url.URL) (sourcehttp.ResponseBody, error) {
	const maxRedirects = 3
	currentURL := initialURL
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: "sourcefixture", Timeout: 30 * time.Second})
	for redirect := 0; ; redirect++ {
		requestPath := currentURL.EscapedPath()
		if requestPath == "" {
			requestPath = "/"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		request, err := sourcehttp.NewRequest(ctx, "sourcefixture", currentURL.Scheme+"://"+currentURL.Host, false, "GET", requestPath, currentURL.Query(), nil)
		if err != nil {
			cancel()
			return sourcehttp.ResponseBody{}, fmt.Errorf("build provider request: %w", err)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "cerebro-sourcefixture/1")
		response, err := sourcehttp.DoWithRetry(ctx, client, request, sourcehttp.RetryOptions{MaxAttempts: 1, MaxBodyBytes: maxResponseBytes})
		cancel()
		if err != nil {
			return sourcehttp.ResponseBody{}, fmt.Errorf("capture provider response: %w", err)
		}
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			return response, nil
		}
		if redirect >= maxRedirects {
			return sourcehttp.ResponseBody{}, fmt.Errorf("capture provider response: too many redirects")
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return sourcehttp.ResponseBody{}, fmt.Errorf("capture provider response: redirect without location")
		}
		nextURL, err := currentURL.Parse(location)
		if err != nil {
			return sourcehttp.ResponseBody{}, fmt.Errorf("resolve provider redirect: %w", err)
		}
		if nextURL.Scheme != "https" || nextURL.User != nil || !strings.EqualFold(nextURL.Host, initialURL.Host) {
			return sourcehttp.ResponseBody{}, fmt.Errorf("capture provider response: redirect must stay on %s over HTTPS", initialURL.Host)
		}
		currentURL = nextURL
	}
}

type headerGetter interface {
	Get(string) string
}

func captureHeaders(headers headerGetter) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"Link", "X-Next-Page", "X-Page", "X-Per-Page", "X-Total", "X-Total-Pages"} {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			result[name] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sourcefixture:", err)
	os.Exit(2)
}
