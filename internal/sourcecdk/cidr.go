package sourcecdk

import "strings"

const (
	openIPv4AnyCIDR = "0.0.0.0/0"
	openIPv6AnyCIDR = "::/0"
)

// FirstOpenCIDR returns the first value that opens access to the entire
// internet ("0.0.0.0/0" or "::/0"), trimmed of surrounding whitespace, or ""
// when none of the values are an unrestricted range. It lets sources detect
// public network exposure without re-implementing the any-address check.
func FirstOpenCIDR(values []string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == openIPv4AnyCIDR || trimmed == openIPv6AnyCIDR {
			return trimmed
		}
	}
	return ""
}
