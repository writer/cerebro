package sourcefixture

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RecordingFormatVCR      = "vcr"
	RecordingFormatPyGitHub = "pygithub"
	maxRecordedResponseSize = 4 << 20
)

var pythonHeaderPair = regexp.MustCompile(`\('([^']+)', '([^']*)'\)`)

type RecordedInteraction struct {
	Request          Request
	Status           int
	ContentType      string
	CapturedAt       string
	CaptureTimeBasis string
	Headers          map[string]string
	Payload          []byte
}

type vcrDocument struct {
	Interactions     []vcrInteraction `yaml:"interactions"`
	HTTPInteractions []vcrInteraction `yaml:"http_interactions"`
}

type vcrInteraction struct {
	Request struct {
		Method string `yaml:"method"`
		URL    string `yaml:"url"`
		URI    string `yaml:"uri"`
	} `yaml:"request"`
	Response struct {
		Code       int            `yaml:"code"`
		StatusCode int            `yaml:"status_code"`
		Status     vcrStatus      `yaml:"status"`
		Headers    map[string]any `yaml:"headers"`
		Body       vcrBody        `yaml:"body"`
		Content    vcrBody        `yaml:"content"`
		RecordedAt string         `yaml:"recorded_at"`
	} `yaml:"response"`
	RecordedAt string `yaml:"recorded_at"`
}

type vcrStatus struct {
	Code int
}

func (status *vcrStatus) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		fields := strings.Fields(node.Value)
		if len(fields) == 0 {
			return nil
		}
		code, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("decode VCR response status: %w", err)
		}
		status.Code = code
		return nil
	case yaml.MappingNode:
		var value struct {
			Code int `yaml:"code"`
		}
		if err := node.Decode(&value); err != nil {
			return err
		}
		status.Code = value.Code
		return nil
	default:
		return errors.New("decode VCR response status: unsupported value")
	}
}

type vcrBody struct {
	Payload []byte
}

func (body *vcrBody) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!binary" || node.Tag == "!binary" {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(node.Value))
			if err != nil {
				return fmt.Errorf("decode VCR binary response body: %w", err)
			}
			body.Payload = decoded
			return nil
		}
		body.Payload = []byte(node.Value)
		return nil
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value != "string" || node.Content[index+1].Tag != "!binary" {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(node.Content[index+1].Value))
			if err != nil {
				return fmt.Errorf("decode VCR binary response body: %w", err)
			}
			body.Payload = decoded
			return nil
		}
		var value struct {
			String       string `yaml:"string"`
			Base64String string `yaml:"base64_string"`
		}
		if err := node.Decode(&value); err != nil {
			return err
		}
		if value.Base64String != "" {
			decoded, err := base64.StdEncoding.DecodeString(value.Base64String)
			if err != nil {
				return fmt.Errorf("decode VCR base64 response body: %w", err)
			}
			body.Payload = decoded
			return nil
		}
		body.Payload = []byte(value.String)
		return nil
	default:
		return errors.New("decode VCR response body: unsupported value")
	}
}

func ExtractRecording(artifact []byte, format string, interactionIndex int) (RecordedInteraction, error) {
	if interactionIndex < 0 {
		return RecordedInteraction{}, errors.New("interaction index must be zero or greater")
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case RecordingFormatVCR:
		return extractVCRRecording(artifact, interactionIndex)
	case RecordingFormatPyGitHub:
		return extractPyGitHubRecording(artifact, interactionIndex)
	default:
		return RecordedInteraction{}, fmt.Errorf("recording format %q is not supported", format)
	}
}

func extractVCRRecording(artifact []byte, interactionIndex int) (RecordedInteraction, error) {
	var document vcrDocument
	if err := yaml.Unmarshal(artifact, &document); err != nil {
		var interactions []vcrInteraction
		if sequenceErr := yaml.Unmarshal(artifact, &interactions); sequenceErr != nil {
			return RecordedInteraction{}, fmt.Errorf("decode VCR artifact: %w", err)
		}
		document.Interactions = interactions
	}
	interactions := document.Interactions
	if len(interactions) == 0 {
		interactions = document.HTTPInteractions
	}
	if interactionIndex >= len(interactions) {
		return RecordedInteraction{}, fmt.Errorf("interaction index %d is outside artifact interaction count %d", interactionIndex, len(interactions))
	}
	selected := interactions[interactionIndex]
	requestURL := strings.TrimSpace(selected.Request.URL)
	if requestURL == "" {
		requestURL = strings.TrimSpace(selected.Request.URI)
	}
	status := selected.Response.Code
	if status == 0 {
		status = selected.Response.Status.Code
	}
	if status == 0 {
		status = selected.Response.StatusCode
	}
	headers := flattenHeaders(selected.Response.Headers)
	recordedPayload := selected.Response.Body.Payload
	if len(recordedPayload) == 0 {
		recordedPayload = selected.Response.Content.Payload
	}
	payload, err := decodeRecordedBody(recordedPayload, headerValue(headers, "Content-Encoding"))
	if err != nil {
		return RecordedInteraction{}, err
	}
	recordedTimestamp := strings.TrimSpace(selected.RecordedAt)
	if recordedTimestamp == "" {
		recordedTimestamp = strings.TrimSpace(selected.Response.RecordedAt)
	}
	capturedAt, basis := recordedAt(recordedTimestamp, headers)
	return RecordedInteraction{
		Request:          Request{Method: strings.ToUpper(strings.TrimSpace(selected.Request.Method)), URL: requestURL},
		Status:           status,
		ContentType:      headerValue(headers, "Content-Type"),
		CapturedAt:       capturedAt,
		CaptureTimeBasis: basis,
		Headers:          headers,
		Payload:          payload,
	}, nil
}

func extractPyGitHubRecording(artifact []byte, interactionIndex int) (RecordedInteraction, error) {
	lines := strings.Split(strings.ReplaceAll(string(artifact), "\r\n", "\n"), "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	blocks := make([][]string, 0)
	for len(lines) > 0 {
		for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
			lines = lines[1:]
		}
		if len(lines) == 0 {
			break
		}
		if len(lines) < 10 {
			return RecordedInteraction{}, fmt.Errorf("decode PyGitHub replay: incomplete %d-line interaction", len(lines))
		}
		blocks = append(blocks, lines[:10])
		lines = lines[10:]
	}
	if interactionIndex >= len(blocks) {
		return RecordedInteraction{}, fmt.Errorf("interaction index %d is outside artifact interaction count %d", interactionIndex, len(blocks))
	}
	selected := blocks[interactionIndex]
	requestURL, err := pyGitHubRequestURL(selected[0], selected[2], selected[3], selected[4])
	if err != nil {
		return RecordedInteraction{}, err
	}
	status, err := strconv.Atoi(strings.TrimSpace(selected[7]))
	if err != nil {
		return RecordedInteraction{}, fmt.Errorf("decode PyGitHub response status: %w", err)
	}
	headers := pyGitHubHeaders(selected[8])
	capturedAt, basis := recordedAt("", headers)
	return RecordedInteraction{
		Request:          Request{Method: strings.ToUpper(strings.TrimSpace(selected[1])), URL: requestURL},
		Status:           status,
		ContentType:      headerValue(headers, "Content-Type"),
		CapturedAt:       capturedAt,
		CaptureTimeBasis: basis,
		Headers:          headers,
		Payload:          []byte(selected[9]),
	}, nil
}

func pyGitHubRequestURL(scheme, host, port, requestPath string) (string, error) {
	scheme = strings.TrimSpace(scheme)
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if port != "" && port != "None" {
		host += ":" + port
	}
	parsed := &url.URL{Scheme: scheme, Host: host, Path: requestPath}
	if strings.Contains(requestPath, "?") {
		parts := strings.SplitN(requestPath, "?", 2)
		parsed.Path, parsed.RawQuery = parts[0], parts[1]
	}
	if _, err := url.ParseRequestURI(parsed.String()); err != nil {
		return "", fmt.Errorf("decode PyGitHub request URL: %w", err)
	}
	return parsed.String(), nil
}

func pyGitHubHeaders(value string) map[string]string {
	headers := map[string]string{}
	for _, match := range pythonHeaderPair.FindAllStringSubmatch(value, -1) {
		if len(match) == 3 {
			headers[match[1]] = match[2]
		}
	}
	return headers
}

func flattenHeaders(values map[string]any) map[string]string {
	headers := map[string]string{}
	for name, raw := range values {
		switch typed := raw.(type) {
		case string:
			headers[name] = typed
		case []any:
			parts := make([]string, 0, len(typed))
			for _, value := range typed {
				parts = append(parts, fmt.Sprint(value))
			}
			headers[name] = strings.Join(parts, ", ")
		default:
			headers[name] = fmt.Sprint(typed)
		}
	}
	return headers
}

func headerValue(headers map[string]string, name string) string {
	for candidate, value := range headers {
		if strings.EqualFold(candidate, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func recordedAt(explicit string, headers map[string]string) (string, string) {
	for _, candidate := range []struct {
		value string
		basis string
	}{{explicit, "recorded_at"}, {headerValue(headers, "Date"), "response_header"}} {
		if strings.TrimSpace(candidate.value) == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC} {
			if parsed, err := time.Parse(layout, candidate.value); err == nil {
				return parsed.UTC().Format(time.RFC3339), candidate.basis
			}
		}
	}
	return "", ""
}

func decodeRecordedBody(payload []byte, contentEncoding string) ([]byte, error) {
	if !strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") || len(payload) < 2 || payload[0] != 0x1f || payload[1] != 0x8b {
		return payload, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("open gzip response body: %w", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxRecordedResponseSize+1))
	closeErr := reader.Close()
	if err != nil {
		return nil, fmt.Errorf("decompress response body: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close gzip response body: %w", closeErr)
	}
	if len(decompressed) > maxRecordedResponseSize {
		return nil, fmt.Errorf("decompressed response body exceeds %d bytes", maxRecordedResponseSize)
	}
	return decompressed, nil
}
