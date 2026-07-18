package sourcefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// SanitizeImportedJSON clears string credential values and replaces personal
// email addresses while preserving the provider response schema.
func SanitizeImportedJSON(payload []byte) ([]byte, []string, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("decode imported JSON response: %w", err)
	}
	changed := []string{}
	sanitized, err := sanitizeJSONValue(value, "$", &changed)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := CanonicalJSON(mustMarshalJSON(sanitized))
	if err != nil {
		return nil, nil, err
	}
	return canonical, normalizedList(changed), nil
}

func sanitizeJSONValue(value any, valuePath string, changed *[]string) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := valuePath + "." + key
			if credentialFieldKey.MatchString(key) && !emptyJSONValue(child) {
				if _, ok := child.(string); !ok {
					return nil, fmt.Errorf("credential field %s must be sanitized manually without changing its JSON type", childPath)
				}
				typed[key] = ""
				*changed = append(*changed, childPath)
				continue
			}
			sanitized, err := sanitizeJSONValue(child, childPath, changed)
			if err != nil {
				return nil, err
			}
			typed[key] = sanitized
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			sanitized, err := sanitizeJSONValue(child, fmt.Sprintf("%s[%d]", valuePath, index), changed)
			if err != nil {
				return nil, err
			}
			typed[index] = sanitized
		}
		return typed, nil
	case string:
		replaced := emailPattern.ReplaceAllStringFunc(typed, exampleEmail)
		if replaced != typed {
			*changed = append(*changed, valuePath)
		}
		return replaced, nil
	default:
		return value, nil
	}
}

func exampleEmail(value string) string {
	if allowedEmailHost.MatchString(value) {
		return value
	}
	digest := sha256.Sum256([]byte(strings.ToLower(value)))
	return "user-" + hex.EncodeToString(digest[:4]) + "@example.test"
}

func mustMarshalJSON(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}
