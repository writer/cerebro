package sentinelone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/primitives"
)

// raw types are used to capture the raw response body alongside the decoded fields so that
// downstream projection can read details that we did not statically model.

type rawCarrier interface {
	setRaw(json.RawMessage)
	rawBytes() json.RawMessage
}

type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(raw []byte) error {
	if strings.TrimSpace(string(raw)) == "null" {
		*b = false
		return nil
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		*b = flexibleBool(value)
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "", "0", "false", "n", "no", "none", "null":
			*b = false
			return nil
		case "1", "true", "y", "yes":
			*b = true
			return nil
		default:
			*b = false
			return nil
		}
	}
	return fmt.Errorf("invalid bool value %s", string(raw))
}

type flexibleString string

func (s *flexibleString) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		*s = ""
		return nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		*s = flexibleString(text)
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil:
		*s = ""
	case bool:
		*s = flexibleString(fmt.Sprint(typed))
	case json.Number:
		*s = flexibleString(typed.String())
	default:
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return err
		}
		*s = flexibleString(compact.String())
	}
	return nil
}

// applicationRecord is the per-agent installed application inventory entry.
type applicationRecord struct {
	AgentID       string `json:"-"`
	Name          string `json:"name"`
	Publisher     string `json:"publisher"`
	Version       string `json:"version"`
	InstalledDate string `json:"installedDate"`
	Size          int64  `json:"size"`
	raw           json.RawMessage
}

func (r *applicationRecord) setRaw(raw json.RawMessage) { r.raw = raw }
func (r *applicationRecord) rawBytes() json.RawMessage  { return r.raw }

func applicationID(_ settings, app applicationRecord) string {
	parts := []string{app.Publisher, app.Name, app.Version}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, strings.ReplaceAll(v, " ", "_"))
	}
	if len(out) == 0 {
		return "unknown"
	}
	return strings.Join(out, "::")
}

type applicationPayload struct {
	AgentID       string         `json:"agent_id"`
	TenantHost    string         `json:"tenant_host"`
	Name          string         `json:"name,omitempty"`
	Publisher     string         `json:"publisher,omitempty"`
	Version       string         `json:"version,omitempty"`
	InstalledDate string         `json:"installed_date,omitempty"`
	SizeBytes     int64          `json:"size_bytes,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

func applicationEvent(s settings, record applicationRecord) (*primitives.Event, error) {
	agentID := applicationAgentID(s, record)
	occurredAt := eventOccurredAt(parseTimestamp(record.InstalledDate))
	raw, err := decodeRaw(record.raw, "sentinelone application")
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(applicationPayload{
		AgentID:       agentID,
		TenantHost:    s.host,
		Name:          record.Name,
		Publisher:     record.Publisher,
		Version:       record.Version,
		InstalledDate: record.InstalledDate,
		SizeBytes:     record.Size,
		Raw:           raw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sentinelone application payload: %w", err)
	}
	attrs := map[string]string{
		"family":      familyApplication,
		"agent_id":    agentID,
		"tenant_host": s.host,
	}
	addAttribute(attrs, "application_name", record.Name)
	addAttribute(attrs, "publisher", record.Publisher)
	addAttribute(attrs, "version", record.Version)
	addAttribute(attrs, "installed_date", record.InstalledDate)
	return &primitives.Event{
		Id:         eventID("sentinelone-application", s, agentID, applicationID(s, record)),
		TenantId:   s.host,
		SourceId:   "sentinelone",
		Kind:       "sentinelone.application_inventory",
		OccurredAt: toTimestamp(occurredAt),
		SchemaRef:  "sentinelone/application_inventory/v1",
		Payload:    payload,
		Attributes: attrs,
	}, nil
}

func applicationAgentID(s settings, record applicationRecord) string {
	return firstNonEmpty(record.AgentID, s.agentID)
}

func joinedEndpointIPs(values ...string) string {
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		ip := strings.TrimSpace(value)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		cleaned = append(cleaned, ip)
	}
	return strings.Join(cleaned, ",")
}
