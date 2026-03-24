package scm

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var commitPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

func ValidateGitRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("git ref must not start with '-'")
	}
	if IsCommitSHA(ref) {
		return nil
	}
	if err := validateRefName(ref); err != nil {
		return fmt.Errorf("git ref %q is invalid: %w", ref, err)
	}
	return nil
}

func ValidateSinceCommit(commit string) error {
	commit = strings.TrimSpace(commit)
	if commit == "" {
		return nil
	}
	if !IsCommitSHA(commit) {
		return fmt.Errorf("sinceCommit must match %s", commitPattern.String())
	}
	return nil
}

func IsCommitSHA(value string) bool {
	return commitPattern.MatchString(strings.TrimSpace(value))
}

func validateRefName(ref string) error {
	if ref == "@" {
		return fmt.Errorf("reserved ref name")
	}
	if strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") || strings.Contains(ref, "//") {
		return fmt.Errorf("ref path must not start or end with '/' or contain '//'")
	}
	if strings.HasSuffix(ref, ".") {
		return fmt.Errorf("ref must not end with '.'")
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("ref must not contain '..'")
	}
	if strings.Contains(ref, "@{") {
		return fmt.Errorf("ref must not contain '@{'")
	}
	for _, r := range ref {
		switch {
		case unicode.IsControl(r):
			return fmt.Errorf("ref contains control characters")
		case r == ' ':
			return fmt.Errorf("ref must not contain spaces")
		case strings.ContainsRune(`~^:?*[\`, r):
			return fmt.Errorf("ref contains invalid character %q", r)
		}
	}
	for _, component := range strings.Split(ref, "/") {
		if component == "" {
			return fmt.Errorf("ref contains an empty path component")
		}
		if strings.HasPrefix(component, ".") {
			return fmt.Errorf("ref component %q must not start with '.'", component)
		}
		if strings.HasSuffix(component, ".lock") {
			return fmt.Errorf("ref component %q must not end with '.lock'", component)
		}
	}
	return nil
}
