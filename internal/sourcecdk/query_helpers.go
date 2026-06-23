package sourcecdk

import (
	"net/url"
	"strings"
)

// AddQueryParam sets a URL query parameter only when the trimmed value is
// non-empty. This replaces the per-source addQuery helper that gates on
// whitespace-only values.
func AddQueryParam(query url.Values, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	query.Set(key, value)
}
