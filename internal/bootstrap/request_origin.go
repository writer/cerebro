package bootstrap

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/config"
)

type requestOrigin struct {
	RemoteIP     string
	ClientIP     string
	Scheme       string
	Host         string
	PublicURL    string
	TrustedProxy bool
}

func resolveRequestOrigin(r *http.Request, cfg config.RequestOriginConfig) requestOrigin {
	origin := requestOrigin{
		RemoteIP: accessAuditRemoteIP(""),
		Scheme:   "https",
		Host:     "cerebro",
	}
	if r == nil {
		return origin
	}
	origin.RemoteIP = accessAuditRemoteIP(r.RemoteAddr)
	if r.TLS == nil {
		origin.Scheme = "http"
	}
	if host := strings.TrimSpace(r.Host); host != "" {
		origin.Host = host
	}
	if publicOrigin := normalizedPublicOrigin(cfg.PublicOrigin); publicOrigin != nil {
		origin.Scheme = publicOrigin.Scheme
		origin.Host = publicOrigin.Host
	}
	remoteIP := net.ParseIP(origin.RemoteIP)
	origin.TrustedProxy = requestOriginTrustsProxy(remoteIP, cfg)
	if origin.TrustedProxy {
		if publicOrigin := normalizedPublicOrigin(cfg.PublicOrigin); publicOrigin == nil {
			forwardedProto, malformedProto := trustedForwardedProto(r.Header.Get("X-Forwarded-Proto"))
			forwardedHost, malformedHost := trustedForwardedHost(r.Header.Get("X-Forwarded-Host"))
			if !malformedProto && !malformedHost && forwardedProto != "" {
				origin.Scheme = forwardedProto
			}
			if !malformedProto && !malformedHost && forwardedHost != "" {
				origin.Host = forwardedHost
			}
		}
		origin.ClientIP = forwardedClientIP(r.Header.Get("X-Forwarded-For"), cfg)
	}
	if origin.ClientIP == "" {
		origin.ClientIP = origin.RemoteIP
	}
	origin.PublicURL = origin.Scheme + "://" + origin.Host + r.URL.RequestURI()
	return origin
}

func requestOriginTrustsProxy(remoteIP net.IP, cfg config.RequestOriginConfig) bool {
	if remoteIP == nil {
		return false
	}
	for _, rawCIDR := range cfg.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err == nil && network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func normalizedPublicOrigin(raw string) *url.URL {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return nil
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil
	}
	return parsed
}

func trustedForwardedProto(header string) (string, bool) {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "https":
			return "https", false
		case "http":
			return "http", false
		case "":
			continue
		}
		return "", true
	}
	return "", false
}

func trustedForwardedHost(header string) (string, bool) {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		host := strings.TrimSpace(parts[i])
		if host == "" {
			continue
		}
		parsed, err := url.Parse("//" + host)
		if err == nil && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Path == "" {
			return parsed.Host, false
		}
		return "", true
	}
	return "", false
}

func forwardedClientIP(header string, cfg config.RequestOriginConfig) string {
	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return ""
	}
	trustedProxyCount := cfg.TrustedProxyCount
	if trustedProxyCount <= 0 {
		trustedProxyCount = trailingTrustedForwardedHops(parts, cfg)
	}
	for i := len(parts) - 1 - trustedProxyCount; i >= 0; i-- {
		if ip := net.ParseIP(strings.TrimSpace(parts[i])); ip != nil {
			return ip.String()
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip != nil && !forwardedHopTrusted(ip, cfg) {
			return ip.String()
		}
	}
	return ""
}

func trailingTrustedForwardedHops(parts []string, cfg config.RequestOriginConfig) int {
	count := 0
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil || !forwardedHopTrusted(ip, cfg) {
			break
		}
		count++
	}
	return count
}

func forwardedHopTrusted(ip net.IP, cfg config.RequestOriginConfig) bool {
	if ip == nil {
		return false
	}
	for _, rawCIDR := range cfg.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
