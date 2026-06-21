package sourcecdk

import "encoding/json"

// PayloadOverlay accumulates provider-agnostic context fields that are merged
// onto a raw provider record before it is stored as an event payload. Sources
// decode the raw record into a JSON object and overlay a small number of
// caller-supplied scalar fields (such as tenant or scope identifiers); the
// merge-and-re-encode mechanism is identical across sources, so it lives here
// rather than in each source package.
type PayloadOverlay struct {
	fields map[string]string
}

// NewPayloadOverlay returns an empty overlay ready to accept fields via Set.
func NewPayloadOverlay() *PayloadOverlay {
	return &PayloadOverlay{fields: map[string]string{}}
}

// Set records a top-level field to overlay onto the raw payload and returns the
// overlay so calls can be chained.
func (o *PayloadOverlay) Set(key string, value string) *PayloadOverlay {
	o.fields[key] = value
	return o
}

// MergeRawJSON decodes raw (a JSON object, or empty for no base fields), overlays
// the accumulated fields, and returns the re-marshaled payload bytes.
func (o *PayloadOverlay) MergeRawJSON(raw json.RawMessage) ([]byte, error) {
	payload := map[string]any{}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, err
		}
	}
	for key, value := range o.fields {
		payload[key] = value
	}
	return json.Marshal(payload)
}
