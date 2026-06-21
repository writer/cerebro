package sourcecdk

import (
	"math"
	"net"
	"strconv"
	"strings"
)

// HostIsUnsafe reports whether a configured source host targets a loopback,
// private, link-local, unspecified, or multicast address. It additionally
// rejects obfuscated numeric IPv4 hosts (decimal, octal, or hexadecimal forms)
// that net.ParseIP alone does not normalize, closing an SSRF bypass that bare
// net.ParseIP-based checks leave open.
func HostIsUnsafe(host string) bool {
	value := normalizedIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericIPv4Host(value)
	}
	if ip == nil {
		return false
	}
	return ipIsUnsafe(ip)
}

// HostIsLoopback reports whether a host refers to a loopback address, including
// the localhost names and obfuscated numeric IPv4 loopback hosts.
func HostIsLoopback(host string) bool {
	value := normalizedIPHost(host)
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		ip = parseNumericIPv4Host(value)
	}
	return ip != nil && ip.IsLoopback()
}

func ipIsUnsafe(ip net.IP) bool {
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

func normalizedIPHost(host string) string {
	value := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	value = strings.Trim(value, "[]")
	if address, _, ok := strings.Cut(value, "%"); ok {
		value = address
	}
	return value
}

func parseNumericIPv4Host(host string) net.IP {
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
