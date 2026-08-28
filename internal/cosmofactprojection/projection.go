// Package cosmofactprojection narrows arbitrary provider facts to the closed
// credential-free payload accepted by the Cosmo finding kernel.
package cosmofactprojection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const (
	maxBytes  = 64 << 10
	maxDepth  = 8
	maxFields = 64
	maxItems  = 64
	maxString = 8 << 10
)

// Receipt binds the provider bytes to their closed projection.
type Receipt struct {
	InputDigest   string
	OutputDigest  string
	DroppedFields int
}

// DecodedRecord carries provider values and the payload admitted for event emission.
type DecodedRecord struct {
	Values  map[string]any
	Payload json.RawMessage
}

var allowedFields = map[string]struct{}{
	"key": {}, "category": {}, "source": {}, "risk_state": {}, "state": {},
	"status": {}, "resolved": {}, "risk_reason": {}, "risk_severity": {},
	"severity": {}, "confidence": {}, "value": {}, "reason": {}, "summary": {},
}

var trustedFields = map[string]struct{}{
	"tenant_id": {}, "workspace_id": {}, "runtime_id": {}, "source_runtime_id": {},
	"occurred_at": {}, "observed_at": {},
}

// DecodeRecord decodes provider values and projects fact payloads when requested.
func DecodeRecord(project bool, raw json.RawMessage) (DecodedRecord, error) {
	var values map[string]any
	if err := json.Unmarshal(raw, &values); err != nil {
		return DecodedRecord{}, err
	}
	if !project {
		return DecodedRecord{Values: values, Payload: raw}, nil
	}
	projected, _, err := Project(raw)
	return DecodedRecord{Values: values, Payload: projected}, err
}

// Project validates bounded provider JSON and returns only the rule DTO fields.
func Project(raw json.RawMessage) (json.RawMessage, Receipt, error) {
	if len(raw) == 0 || len(raw) > maxBytes {
		return nil, Receipt{}, fmt.Errorf("cosmo fact payload size is outside the closed limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateValue(decoder, 1, true); err != nil {
		return nil, Receipt{}, err
	}
	if err := requireEOF(decoder); err != nil {
		return nil, Receipt{}, err
	}

	var input map[string]any
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&input); err != nil {
		return nil, Receipt{}, fmt.Errorf("decode cosmo fact projection: %w", err)
	}
	projected := make(map[string]any, len(allowedFields))
	dropped := 0
	for key, value := range input {
		if _, trusted := trustedFields[key]; trusted {
			return nil, Receipt{}, fmt.Errorf("cosmo fact payload contains trusted context field %q", key)
		}
		if _, allowed := allowedFields[key]; !allowed {
			dropped++
			continue
		}
		switch value.(type) {
		case string, bool, json.Number:
			projected[key] = value
		default:
			return nil, Receipt{}, fmt.Errorf("cosmo fact field %q must be a scalar", key)
		}
	}
	output, err := json.Marshal(projected)
	if err != nil {
		return nil, Receipt{}, fmt.Errorf("encode cosmo fact projection: %w", err)
	}
	return output, Receipt{InputDigest: digest(raw), OutputDigest: digest(output), DroppedFields: dropped}, nil
}

func validateValue(decoder *json.Decoder, depth int, root bool) error {
	if depth > maxDepth {
		return fmt.Errorf("cosmo fact payload nesting exceeds the closed limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode cosmo fact payload: %w", err)
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		if value, ok := token.(string); ok && len(value) > maxString {
			return fmt.Errorf("cosmo fact payload string exceeds the closed limit")
		}
		if root {
			return fmt.Errorf("cosmo fact payload must be an object")
		}
		return nil
	}
	if root && delimiter != '{' {
		return fmt.Errorf("cosmo fact payload must be an object")
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		fields := 0
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode cosmo fact payload field: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("cosmo fact payload field name is invalid")
			}
			fields++
			if fields > maxFields {
				return fmt.Errorf("cosmo fact payload object exceeds the field limit")
			}
			if len(key) > maxString {
				return fmt.Errorf("cosmo fact payload field name exceeds the string limit")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("cosmo fact payload contains duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := validateValue(decoder, depth+1, false); err != nil {
				return err
			}
		}
	case '[':
		items := 0
		for decoder.More() {
			items++
			if items > maxItems {
				return fmt.Errorf("cosmo fact payload array exceeds the item limit")
			}
			if err := validateValue(decoder, depth+1, false); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("cosmo fact payload delimiter is invalid")
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("decode cosmo fact payload delimiter: %w", err)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("cosmo fact payload contains a trailing value")
		}
		return fmt.Errorf("decode cosmo fact payload trailing value: %w", err)
	}
	return nil
}

func digest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
