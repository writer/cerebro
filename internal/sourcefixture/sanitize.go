package sourcefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

var documentationIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

var base64TextEncodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// SanitizeImportedJSON clears string credential values and replaces personal
// email addresses while preserving the provider response schema.
func SanitizeImportedJSON(payload []byte) ([]byte, []string, error) {
	return SanitizeImportedJSONWithKeys(payload, nil)
}

// SanitizeImportedCredentials reapplies only credential-field sanitization to
// an existing bundle when the sanitizer's credential matching becomes stricter.
func SanitizeImportedCredentials(payload []byte) ([]byte, []string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("decode imported JSON response: %w", err)
	}
	changed := []string{}
	sanitized, err := sanitizeCredentialFields(value, "$", &changed)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return nil, nil, fmt.Errorf("encode sanitized JSON response: %w", err)
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		return nil, nil, err
	}
	return canonical, normalizedList(changed), nil
}

// SanitizeImportedTextValues reapplies idempotent provider identifier, tenant
// host, and public IP replacements without re-hashing personal-field values.
func SanitizeImportedTextValues(payload []byte) ([]byte, []string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("decode imported JSON response: %w", err)
	}
	changed := []string{}
	sanitized := sanitizeTextValues(value, "$", &changed)
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return nil, nil, fmt.Errorf("encode sanitized JSON response: %w", err)
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		return nil, nil, err
	}
	return canonical, normalizedList(changed), nil
}

func sanitizeTextValues(value any, valuePath string, changed *[]string) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = sanitizeTextValues(child, valuePath+"."+key, changed)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = sanitizeTextValues(child, fmt.Sprintf("%s[%d]", valuePath, index), changed)
		}
		return typed
	case string:
		sanitized := SanitizeImportedText(typed)
		if sanitized != typed {
			*changed = append(*changed, valuePath)
		}
		return sanitized
	default:
		return value
	}
}

// SanitizeImportedJSONWithKeys also replaces values for explicitly declared
// field keys while preserving their JSON types and response shape.
func SanitizeImportedJSONWithKeys(payload []byte, fieldKeys []string) ([]byte, []string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("decode imported JSON response: %w", err)
	}
	changed := []string{}
	explicitKeys := map[string]struct{}{}
	for _, key := range fieldKeys {
		if normalized := normalizedJSONKey(key); normalized != "" {
			explicitKeys[normalized] = struct{}{}
		}
	}
	sanitized, err := sanitizeJSONValue(value, "$", explicitKeys, &changed)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return nil, nil, fmt.Errorf("encode sanitized JSON response: %w", err)
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		return nil, nil, err
	}
	return canonical, normalizedList(changed), nil
}

func sanitizeJSONValue(value any, valuePath string, explicitKeys map[string]struct{}, changed *[]string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := valuePath + "." + key
			if _, ok := explicitKeys[normalizedJSONKey(key)]; ok {
				sanitized, err := sanitizeExplicitJSONValue(child, childPath, changed)
				if err != nil {
					return nil, err
				}
				typed[key] = sanitized
				continue
			}
			if credentialFieldKey.MatchString(key) {
				sanitized, err := sanitizeCredentialJSONValue(child, childPath, changed)
				if err != nil {
					return nil, err
				}
				typed[key] = sanitized
				continue
			}
			if text, ok := child.(string); ok && text != "" && shouldSanitizePersonalField(key, explicitKeys) {
				typed[key] = SanitizeImportedText(sanitizedPersonalString(key, text))
				*changed = append(*changed, childPath)
				continue
			}
			sanitized, err := sanitizeJSONValue(child, childPath, explicitKeys, changed)
			if err != nil {
				return nil, err
			}
			typed[key] = sanitized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			sanitized, err := sanitizeJSONValue(child, fmt.Sprintf("%s[%d]", valuePath, index), explicitKeys, changed)
			if err != nil {
				return nil, err
			}
			typed[index] = sanitized
		}
		return typed, nil
	case string:
		replaced := emailPattern.ReplaceAllStringFunc(typed, exampleEmail)
		replaced = SanitizeImportedText(replaced)
		if replaced != typed {
			*changed = append(*changed, valuePath)
		}
		return replaced, nil
	default:
		return value, nil
	}
}

func sanitizeExplicitJSONValue(value any, valuePath string, changed *[]string) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		for key, child := range typed {
			sanitized, err := sanitizeExplicitJSONValue(child, valuePath+"."+key, changed)
			if err != nil {
				return nil, err
			}
			typed[key] = sanitized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			sanitized, err := sanitizeExplicitJSONValue(child, fmt.Sprintf("%s[%d]", valuePath, index), changed)
			if err != nil {
				return nil, err
			}
			typed[index] = sanitized
		}
		return typed, nil
	case string:
		if typed == "" {
			return typed, nil
		}
		*changed = append(*changed, valuePath)
		return SanitizeImportedText(sanitizedPersonalString(valuePath, typed)), nil
	case json.Number:
		if typed == "0" {
			return typed, nil
		}
		*changed = append(*changed, valuePath)
		return json.Number("0"), nil
	case bool:
		if !typed {
			return typed, nil
		}
		*changed = append(*changed, valuePath)
		return false, nil
	default:
		return nil, fmt.Errorf("explicit field %s has unsupported JSON value type %T", valuePath, value)
	}
}

func sanitizeCredentialJSONValue(value any, valuePath string, changed *[]string) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		for key, child := range typed {
			sanitized, err := sanitizeCredentialJSONValue(child, valuePath+"."+key, changed)
			if err != nil {
				return nil, err
			}
			typed[key] = sanitized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			sanitized, err := sanitizeCredentialJSONValue(child, fmt.Sprintf("%s[%d]", valuePath, index), changed)
			if err != nil {
				return nil, err
			}
			typed[index] = sanitized
		}
		return typed, nil
	case string:
		if typed == "" {
			return typed, nil
		}
		*changed = append(*changed, valuePath)
		return "", nil
	case json.Number:
		if typed == "0" {
			return typed, nil
		}
		return nil, fmt.Errorf("credential field %s must be sanitized manually without changing its JSON type", valuePath)
	case bool:
		if !typed {
			return typed, nil
		}
		return nil, fmt.Errorf("credential field %s must be sanitized manually without changing its JSON type", valuePath)
	default:
		return nil, fmt.Errorf("credential field %s must be sanitized manually without changing its JSON type", valuePath)
	}
}

func sanitizeCredentialFields(value any, valuePath string, changed *[]string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := valuePath + "." + key
			var (
				sanitized any
				err       error
			)
			if credentialFieldKey.MatchString(key) {
				sanitized, err = sanitizeCredentialJSONValue(child, childPath, changed)
			} else {
				sanitized, err = sanitizeCredentialFields(child, childPath, changed)
			}
			if err != nil {
				return nil, err
			}
			typed[key] = sanitized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			sanitized, err := sanitizeCredentialFields(child, fmt.Sprintf("%s[%d]", valuePath, index), changed)
			if err != nil {
				return nil, err
			}
			typed[index] = sanitized
		}
		return typed, nil
	default:
		return value, nil
	}
}

// SanitizeImportedText replaces provider identifier shapes that can carry
// tenant data or resemble credentials with stable example values so references
// remain consistent across response fields.
func SanitizeImportedText(value string) string {
	sanitized := sanitizePlainImportedText(value)
	return sanitizeEncodedImportedText(sanitized)
}

func sanitizePlainImportedText(value string) string {
	value = zendeskTenantHost.ReplaceAllString(value, "zendesk.example.test")
	value = auth0FixtureHost.ReplaceAllString(value, "auth0.example.test")
	value = auth0TenantHost.ReplaceAllString(value, "auth0.example.test")
	value = auth0FixtureTenant.ReplaceAllString(value, "auth0-example-tenant")
	value = ipv4Pattern.ReplaceAllStringFunc(value, sanitizePublicIPv4)
	return providerIDPattern.ReplaceAllStringFunc(value, func(identifier string) string {
		digest := sha256.Sum256([]byte(strings.ToLower(identifier)))
		length := 8
		normalized := strings.ToLower(identifier)
		if strings.HasPrefix(normalized, "auth0|") || strings.HasPrefix(normalized, "auth0%7c") {
			length = 4
		}
		return "example-" + hex.EncodeToString(digest[:length])
	})
}

func sanitizeEncodedImportedText(value string) string {
	for _, encoding := range base64TextEncodings {
		decoded, err := encoding.DecodeString(value)
		if err != nil || !isPrintableText(decoded) {
			continue
		}
		sanitized := sanitizePlainImportedText(string(decoded))
		if sanitized != string(decoded) {
			return encoding.EncodeToString([]byte(sanitized))
		}
	}
	return value
}

func containsUnsanitizedProviderText(value string) bool {
	if sanitizePlainImportedText(value) != value {
		return true
	}
	for _, encoding := range base64TextEncodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && isPrintableText(decoded) && sanitizePlainImportedText(string(decoded)) != string(decoded) {
			return true
		}
	}
	return false
}

func isPrintableText(value []byte) bool {
	if len(value) == 0 || !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func sanitizePublicIPv4(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
		return value
	}
	for _, prefix := range documentationIPv4Prefixes {
		if prefix.Contains(address) {
			return value
		}
	}
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("203.0.113.%d", int(digest[0])%254+1)
}

func shouldSanitizePersonalField(key string, explicitKeys map[string]struct{}) bool {
	normalized := normalizedJSONKey(key)
	if _, ok := explicitKeys[normalized]; ok {
		return true
	}
	switch normalized {
	case "firstname", "lastname", "middlename", "displayname", "nickname", "login", "email", "secondemail", "mobilephone", "primaryphone", "honorificprefix", "honorificsuffix", "username":
		return true
	default:
		return false
	}
}

func normalizedJSONKey(key string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(key)))
}

func sanitizedPersonalString(key, value string) string {
	replacedEmail := emailPattern.ReplaceAllStringFunc(value, exampleEmail)
	if replacedEmail != value {
		return replacedEmail
	}
	digest := sha256.Sum256([]byte(strings.ToLower(value)))
	if strings.Contains(normalizedJSONKey(key), "phone") {
		return "+1-555-" + hex.EncodeToString(digest[:2])
	}
	return "example-" + hex.EncodeToString(digest[:4])
}

func exampleEmail(value string) string {
	if allowedEmailHost.MatchString(value) {
		return value
	}
	digest := sha256.Sum256([]byte(strings.ToLower(value)))
	return "user-" + hex.EncodeToString(digest[:4]) + "@example.test"
}
