package repohistoryscan

import (
	"net/url"
	"regexp"
	"strings"
)

const redactedPathValue = "<redacted-path>"

var (
	embeddedURLPattern  = regexp.MustCompile(`(?:https?|ssh)://[^\s"'<>]+`)
	absolutePathPattern = regexp.MustCompile(`(^|[\s=(\["'])(/[^\s)\]"']+)`)
	scpStyleRepoPattern = regexp.MustCompile(`^[^@\s]+@[^:/\s]+:[^\s]+$`)
)

func sanitizeRunForPersistence(run *RunRecord) {
	if run == nil {
		return
	}
	run.Target = sanitizeScanTarget(run.Target)
	run.Error = sanitizeMessage(run.Error)
	if run.Descriptor != nil {
		run.Descriptor.RepoURL = sanitizeRepositoryURL(run.Descriptor.RepoURL)
	}
	if run.Checkout != nil && len(run.Checkout.Metadata) > 0 {
		if raw, ok := run.Checkout.Metadata["repo_url"].(string); ok {
			run.Checkout.Metadata["repo_url"] = sanitizeRepositoryURL(raw)
		}
	}
}

func sanitizeEventForPersistence(event *RunEvent) {
	if event == nil {
		return
	}
	event.Message = sanitizeMessage(event.Message)
}

func sanitizeScanTarget(target ScanTarget) ScanTarget {
	target.RepoURL = sanitizeRepositoryURL(target.RepoURL)
	target.Repository = strings.TrimSpace(target.Repository)
	target.Ref = strings.TrimSpace(target.Ref)
	target.SinceCommit = strings.TrimSpace(target.SinceCommit)
	return target
}

func operatorSafeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := sanitizeMessage(err.Error())
	if message == "" {
		return "repository history scan failed"
	}
	return message
}

func sanitizeMessage(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	sanitized := embeddedURLPattern.ReplaceAllStringFunc(trimmed, sanitizeEmbeddedURL)
	return absolutePathPattern.ReplaceAllString(sanitized, `${1}`+redactedPathValue)
}

func sanitizeRepositoryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil {
			parsed.User = nil
			parsed.RawQuery = ""
			parsed.Fragment = ""
			return parsed.String()
		}
	}
	if scpStyleRepoPattern.MatchString(raw) {
		if idx := strings.Index(raw, "@"); idx > 0 {
			return raw[idx+1:]
		}
	}
	return raw
}

func sanitizeEmbeddedURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if parsed, err := url.Parse(raw); err == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
		return raw[:idx]
	}
	return sanitizeRepositoryURL(raw)
}
