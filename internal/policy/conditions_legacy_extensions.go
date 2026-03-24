package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var relativeNowPattern = regexp.MustCompile(`(?i)^(now\(\)|current_timestamp(?:\(\))?)(?:\s*([+-])\s*interval\s*'([0-9]+)\s+([a-z]+)')?$`)

func valueContainsExpected(value interface{}, expected interface{}) bool {
	if value == nil || expected == nil {
		return false
	}

	switch typed := normalizeCELNative(expected).(type) {
	case map[string]interface{}:
		return valueContainsObject(value, typed)
	default:
		return valueContains(value, stringifyComparable(typed))
	}
}

func valueContainsObject(value interface{}, expected map[string]interface{}) bool {
	if value == nil {
		return false
	}

	switch typed := normalizeCELNative(value).(type) {
	case []interface{}:
		for _, item := range typed {
			if valueContainsObject(item, expected) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		return mapContainsSubset(typed, expected)
	case string:
		if parsed := tryParseJSON(typed); parsed != nil {
			return valueContainsObject(parsed, expected)
		}
		return false
	default:
		return false
	}
}

func mapContainsSubset(actual map[string]interface{}, expected map[string]interface{}) bool {
	for key, expectedValue := range expected {
		actualValue := getFieldCaseInsensitive(actual, key)
		if actualValue == nil && expectedValue != nil {
			return false
		}
		switch nested := normalizeCELNative(expectedValue).(type) {
		case map[string]interface{}:
			actualMap, ok := normalizeCELNative(actualValue).(map[string]interface{})
			if !ok || !mapContainsSubset(actualMap, nested) {
				return false
			}
		default:
			if !compareValues(actualValue, nested, "==") {
				return false
			}
		}
	}
	return true
}

func valueEndsWith(value interface{}, suffix string) bool {
	if value == nil || suffix == "" {
		return false
	}

	switch typed := normalizeCELNative(value).(type) {
	case []interface{}:
		for _, item := range typed {
			if valueEndsWith(item, suffix) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range typed {
			if strings.HasSuffix(item, suffix) {
				return true
			}
		}
		return false
	case string:
		return strings.HasSuffix(typed, suffix)
	default:
		return strings.HasSuffix(fmt.Sprintf("%v", typed), suffix)
	}
}

func referencesPublicBucket(root interface{}, field string) bool {
	bucket := extractS3BucketName(stringifyComparable(pathValue(root, field)))
	if bucket == "" {
		return false
	}
	return resourceContainsReferencedPublicBucket(root, bucket)
}

func resourceContainsReferencedPublicBucket(root interface{}, bucket string) bool {
	switch typed := normalizeCELNative(root).(type) {
	case []interface{}:
		for _, item := range typed {
			if resourceContainsReferencedPublicBucket(item, bucket) {
				return true
			}
		}
	case map[string]interface{}:
		if mapReferencesPublicBucket(typed, bucket) {
			return true
		}
		for _, item := range typed {
			if resourceContainsReferencedPublicBucket(item, bucket) {
				return true
			}
		}
	case string:
		if parsed := tryParseJSON(typed); parsed != nil {
			return resourceContainsReferencedPublicBucket(parsed, bucket)
		}
	}
	return false
}

func mapReferencesPublicBucket(actual map[string]interface{}, bucket string) bool {
	if !mapHasPublicSignal(actual) {
		return false
	}
	for _, candidate := range actual {
		if bucketReferenceMatches(candidate, bucket) {
			return true
		}
	}
	return false
}

func mapHasPublicSignal(actual map[string]interface{}) bool {
	for _, key := range []string{
		"public_access",
		"public",
		"all_users_access",
		"all_authenticated_users_access",
		"anonymous_access",
		"publicly_accessible",
		"internet_accessible",
	} {
		if value, ok := getFieldCaseInsensitive(actual, key).(bool); ok && value {
			return true
		}
		if value, ok := toBoolValue(getFieldCaseInsensitive(actual, key)); ok && value {
			return true
		}
	}
	return false
}

func bucketReferenceMatches(value interface{}, bucket string) bool {
	bucket = strings.ToLower(strings.TrimSpace(bucket))
	if bucket == "" {
		return false
	}

	switch typed := normalizeCELNative(value).(type) {
	case []interface{}:
		for _, item := range typed {
			if bucketReferenceMatches(item, bucket) {
				return true
			}
		}
		return false
	case map[string]interface{}:
		for _, item := range typed {
			if bucketReferenceMatches(item, bucket) {
				return true
			}
		}
		return false
	case string:
		if referenced := extractS3BucketName(typed); referenced != "" {
			return referenced == bucket
		}
		return strings.Contains(strings.ToLower(typed), bucket)
	default:
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", typed)), bucket)
	}
}

func extractS3BucketName(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, "\"'"))
	if raw == "" {
		return ""
	}

	if strings.HasPrefix(strings.ToLower(raw), "s3://") {
		remainder := strings.TrimPrefix(raw, "s3://")
		remainder = strings.TrimPrefix(remainder, "S3://")
		parts := strings.SplitN(remainder, "/", 2)
		return strings.ToLower(strings.TrimSpace(parts[0]))
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}

	host := strings.ToLower(parsed.Host)
	switch {
	case strings.HasSuffix(host, ".s3.amazonaws.com"):
		return strings.TrimSuffix(host, ".s3.amazonaws.com")
	case strings.Contains(host, ".s3."):
		return strings.SplitN(host, ".s3.", 2)[0]
	case strings.HasPrefix(host, "s3.") || host == "s3.amazonaws.com":
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) > 0 {
			return strings.ToLower(strings.TrimSpace(parts[0]))
		}
	}

	return ""
}

func stringifyComparable(value interface{}) string {
	switch typed := normalizeCELNative(value).(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(strings.Trim(typed, "\"'"))
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case map[string]interface{}, []interface{}:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(encoded)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func toBoolValue(value interface{}) (bool, bool) {
	switch typed := normalizeCELNative(value).(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(strings.Trim(typed, "\"'"))) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	}
	return false, false
}

func numericValue(value interface{}) (float64, bool) {
	switch typed := normalizeCELNative(value).(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float32:
		return float64(typed), true
	case float64:
		return typed, true
	case string:
		trimmed := strings.TrimSpace(strings.Trim(typed, "\"'"))
		if trimmed == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func toTimeValue(value interface{}) (time.Time, bool) {
	switch typed := normalizeCELNative(value).(type) {
	case time.Time:
		return typed, true
	case string:
		return parseTimeValueString(typed)
	default:
		return time.Time{}, false
	}
}

func parseTimeValueString(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if isQuoted(value) {
		value = trimQuotes(value)
	}
	if value == "" {
		return time.Time{}, false
	}
	if parsed, ok := parseRelativeTimeExpression(value); ok {
		return parsed, true
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func parseRelativeTimeExpression(value string) (time.Time, bool) {
	matches := relativeNowPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) == 0 {
		return time.Time{}, false
	}

	base := time.Now().UTC()
	if matches[2] == "" {
		return base, true
	}

	amount, err := strconv.Atoi(matches[3])
	if err != nil {
		return time.Time{}, false
	}
	return applyTimeInterval(base, matches[2], amount, matches[4])
}

func applyTimeInterval(base time.Time, sign string, amount int, unit string) (time.Time, bool) {
	if amount < 0 {
		return time.Time{}, false
	}
	if sign == "-" {
		amount = -amount
	}

	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "minute", "minutes":
		return base.Add(time.Duration(amount) * time.Minute), true
	case "hour", "hours":
		return base.Add(time.Duration(amount) * time.Hour), true
	case "day", "days":
		return base.AddDate(0, 0, amount), true
	case "week", "weeks":
		return base.AddDate(0, 0, amount*7), true
	case "month", "months":
		return base.AddDate(0, amount, 0), true
	case "year", "years":
		return base.AddDate(amount, 0, 0), true
	default:
		return time.Time{}, false
	}
}
