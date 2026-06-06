package sourcehttp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrUnsafeGitHubBaseURLHost = errors.New("github base_url must not target loopback, private, or link-local hosts")

func NormalizeGitHubBaseURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse github base_url: %w", err)
	}
	host := parsed.Hostname()
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && isGitHubLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("github base_url must use https")
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("github base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", fmt.Errorf("github base_url must not include user info, query, or fragment")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if (path != "" && path != "/api/v3") || parsed.RawPath != "" {
		return "", fmt.Errorf("github base_url must be an origin URL")
	}
	if isUnsafeGitHubHost(host) && (!allowLoopback || !isGitHubLoopbackHost(host)) {
		return "", ErrUnsafeGitHubBaseURLHost
	}
	if path == "/api/v3" && IsGitHubAPIHost(host) {
		parsed.Path = "/api/v3"
	} else {
		parsed.Path = ""
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func IsGitHubAPIHost(host string) bool {
	normalized := strings.ToLower(strings.TrimSpace(host))
	return strings.HasPrefix(normalized, "api.") || strings.Contains(normalized, ".api.")
}

func isUnsafeGitHubHost(host string) bool {
	value := normalizedGitHubIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericGitHubIPv4Host(value)
	}
	if ip == nil {
		return false
	}
	return isUnsafeGitHubIP(ip)
}

func isGitHubLoopbackHost(host string) bool {
	value := normalizedGitHubIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericGitHubIPv4Host(value)
	}
	return ip != nil && ip.IsLoopback()
}

func isUnsafeGitHubIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

func normalizedGitHubIPHost(host string) string {
	value := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	value = strings.Trim(value, "[]")
	if address, _, ok := strings.Cut(value, "%"); ok {
		value = address
	}
	return value
}

func parseNumericGitHubIPv4Host(host string) net.IP {
	if strings.Contains(host, ":") {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return nil
		}
		values[i] = value
	}
	var ipv4 uint32
	switch len(values) {
	case 1:
		ipv4 = uint32FromUint64(values[0])
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		ipv4 = uint32FromUint64(values[0]<<24 | values[1])
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		ipv4 = uint32FromUint64(values[0]<<24 | values[1]<<16 | values[2])
	case 4:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xff || values[3] > 0xff {
			return nil
		}
		ipv4 = uint32FromUint64(values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3])
	}
	return net.IPv4(byte(ipv4>>24), byte(ipv4>>16), byte(ipv4>>8), byte(ipv4))
}

func uint32FromUint64(value uint64) uint32 {
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}
