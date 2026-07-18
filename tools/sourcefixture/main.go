package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const maxResponseBytes = 4 << 20

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: sourcefixture <capture|verify|packages>"))
	}
	switch os.Args[1] {
	case "capture":
		capture(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "packages":
		packages(os.Args[2:])
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
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
	}
	bundle, err := sourcefixture.WriteBundle(*root, manifest, payload)
	if err != nil {
		fail(err)
	}
	fmt.Printf("sourcefixture: captured source=%s family=%s case=%s status=%d digest=%s path=%s\n", bundle.Manifest.SourceID, bundle.Manifest.Family, bundle.Manifest.Case, bundle.Manifest.Response.Status, bundle.Manifest.Response.SHA256, bundle.ResponsePath)
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
