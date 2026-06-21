package sourcecdk

import (
	"math"
	"net"
	"strconv"
	"strings"
)

// IsUnsafeHost reports whether host targets a loopback, private, link-local,
// unspecified, or multicast address. It also rejects IPv4 literals written in
// decimal, octal, or hexadecimal form so encoded loopback/private addresses
// cannot bypass the check.
func IsUnsafeHost(host string) bool {
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
	return isUnsafeIP(ip)
}

func isUnsafeIP(ip net.IP) bool {
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

// IsLoopbackHost reports whether host refers to a loopback address, including
// loopback IPv4 literals written in decimal, octal, or hexadecimal form.
func IsLoopbackHost(host string) bool {
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
