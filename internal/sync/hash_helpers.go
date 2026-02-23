package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"
)

func hashRowContentWithMode(row map[string]interface{}, short bool) string {
	keys := make([]string, 0, len(row))
	for key := range row {
		if key == "_cq_id" || key == "_cq_hash" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, key := range keys {
		h.Write([]byte(key))
		h.Write(stableMarshalForHash(row[key]))
	}

	digest := h.Sum(nil)
	if short {
		return hex.EncodeToString(digest[:8])
	}
	return hex.EncodeToString(digest)
}

func stableMarshalForHash(value interface{}) []byte {
	canonical := canonicalizeHashValue(value)
	encoded, err := json.Marshal(canonical)
	if err == nil {
		return encoded
	}
	return []byte(strconv.Quote(fmt.Sprint(canonical)))
}

func canonicalizeHashValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return ""
		}
		return typed.UTC().Format(time.RFC3339Nano)
	case *time.Time:
		if typed == nil || typed.IsZero() {
			return ""
		}
		return typed.UTC().Format(time.RFC3339Nano)
	case map[string]interface{}:
		normalized := make(map[string]interface{}, len(typed))
		for key, entry := range typed {
			normalized[key] = canonicalizeHashValue(entry)
		}
		return normalized
	}

	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Ptr:
		if rv.IsNil() {
			return nil
		}
		return canonicalizeHashValue(rv.Elem().Interface())
	case reflect.Map:
		normalized := make(map[string]interface{}, rv.Len())
		for _, key := range rv.MapKeys() {
			normalized[fmt.Sprint(key.Interface())] = canonicalizeHashValue(rv.MapIndex(key).Interface())
		}
		return normalized
	case reflect.Slice, reflect.Array:
		normalized := make([]interface{}, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			normalized = append(normalized, canonicalizeHashValue(rv.Index(i).Interface()))
		}
		return normalized
	}

	return value
}
