package emaildns

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

func evaluateDKIM(ctx context.Context, resolver Resolver, domain string, dkimSelectors []string, result *Health) int {
	found := 0
	for _, selector := range dkimSelectors {
		recordName := selector + "._domainkey." + domain
		values, err := resolver.LookupTXT(ctx, recordName)
		if err != nil {
			continue
		}
		dkimRecords := filterTXTPrefix(values, "v=dkim1")
		if len(dkimRecords) == 0 {
			continue
		}
		found++
		record := dkimRecords[0]
		tags := parseTagRecord(record)
		keyValue := strings.TrimSpace(tags["p"])
		algorithm := dkimKeyAlgorithm(tags["k"])
		keyBits, keyValid := dkimKeyBits(keyValue, algorithm)
		status := StatusHealthy
		switch {
		case keyValue == "":
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_missing_key", "DKIM public key missing", fmt.Sprintf("Selector %s is missing p= key material.", selector), "Publish valid DKIM public key material in p=."))
		case !keyValid:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_invalid_key", "DKIM public key is not valid base64", fmt.Sprintf("Selector %s p= value did not decode as base64 key material.", selector), "Republish the DKIM selector with valid base64-encoded key material."))
		case algorithm == "ed25519" && keyBits != 256:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityHigh, "dkim_invalid_ed25519_key", "DKIM Ed25519 key length is invalid", fmt.Sprintf("Selector %s Ed25519 key size is %d bits; expected 256 bits.", selector, keyBits), "Republish the Ed25519 selector with a 32-byte public key."))
		case algorithm == "rsa" && keyBits < 1024:
			status = StatusFailing
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityCrit, "dkim_weak_key", "DKIM RSA key is too weak", fmt.Sprintf("Selector %s RSA key size is %d bits.", selector, keyBits), "Rotate selector to at least 2048-bit RSA key material."))
		case algorithm == "rsa" && keyBits < 2048:
			status = StatusWarning
			result.Issues = append(result.Issues, makeIssue("DKIM", SeverityMedium, "dkim_key_short", "DKIM RSA key length below recommended", fmt.Sprintf("Selector %s RSA key size is %d bits.", selector, keyBits), "Rotate selector to a 2048-bit RSA key."))
		}
		result.DKIMSelectors = append(result.DKIMSelectors, DKIMSelector{Selector: selector, Status: status, KeyBits: keyBits, Record: record})
	}
	return found
}

func dkimKeyAlgorithm(raw string) string {
	algorithm := strings.ToLower(strings.TrimSpace(raw))
	if algorithm == "" {
		return "rsa"
	}
	return algorithm
}

// dkimKeyBits decodes the DKIM p= public-key payload and returns the key
// length in bits along with a flag indicating whether the payload was valid
// base64. Empty payloads return (0, true) so callers can distinguish a
// missing key from a malformed one. RSA keys use parsed modulus size when the
// payload is DER-encoded, falling back to byte length for legacy fixtures.
func dkimKeyBits(publicKey string, algorithm string) (int, bool) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(publicKey), " ", "")
	if cleaned == "" {
		return 0, true
	}
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return 0, false
	}
	if algorithm == "rsa" {
		if bits := rsaPublicKeyBits(decoded); bits > 0 {
			return bits, true
		}
	}
	return len(decoded) * 8, true
}

func rsaPublicKeyBits(der []byte) int {
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok && rsaKey.N != nil {
			return rsaKey.N.BitLen()
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil && key.N != nil {
		return key.N.BitLen()
	}
	return 0
}
