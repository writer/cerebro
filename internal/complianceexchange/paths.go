package complianceexchange

import (
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

var reservedPackagePaths = map[string]struct{}{
	"manifest.json": {},
	"manifest.jws":  {},
}

func validatePackagePath(value string, maxBytes int) error {
	if value == "" {
		return errorsPath("path is required")
	}
	if !utf8.ValidString(value) {
		return errorsPath("path must be valid UTF-8")
	}
	if len(value) > maxBytes {
		return errorsPath(fmt.Sprintf("path exceeds %d bytes", maxBytes))
	}
	if strings.ContainsAny(value, "\\\x00\r\n") {
		return errorsPath("path contains a forbidden character")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errorsPath("path contains a control character")
		}
	}
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return errorsPath("path must be a relative file path")
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return errorsPath("path is not normalized or escapes the package root")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errorsPath("path contains an unsafe segment")
		}
	}
	if strings.Contains(strings.SplitN(value, "/", 2)[0], ":") {
		return errorsPath("path starts with a volume-like segment")
	}
	if _, reserved := reservedPackagePaths[strings.ToLower(value)]; reserved {
		return errorsPath("path is reserved for package metadata")
	}
	return nil
}

type pathError string

func (e pathError) Error() string { return string(e) }

func errorsPath(message string) error { return pathError(message) }

func collisionKey(value string) string {
	return strings.ToLower(value)
}

func safeIssuePath(value string) string {
	const maxRunes = 160
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || character == utf8.RuneError {
			return '\uFFFD'
		}
		return character
	}, value)
	characters := []rune(value)
	if len(characters) > maxRunes {
		return string(characters[:maxRunes]) + "..."
	}
	if value == "" {
		return "files"
	}
	return value
}
