package fivetranapi

import (
	"encoding/json"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type pathParamCursor struct {
	Param  string   `json:"param,omitempty"`
	Values []string `json:"values,omitempty"`
	Cursor string   `json:"cursor,omitempty"`
}

const pathParamCursorMode = "fivetran_path_param_fanout"

func DecodePathParamCursor(cursor *cerebrov1.SourceCursor, param string) ([]string, *cerebrov1.SourceCursor, bool) {
	if cursor == nil {
		return nil, nil, false
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(cursor.GetOpaque())
	if !ok || envelope.Source != SourceID || envelope.Mode != pathParamCursorMode {
		return nil, nil, false
	}
	var state pathParamCursor
	if err := json.Unmarshal([]byte(envelope.Token), &state); err != nil {
		return nil, nil, false
	}
	state.Param = strings.TrimSpace(state.Param)
	if state.Param != strings.TrimSpace(param) {
		return nil, nil, false
	}
	values := CompactStrings(state.Values)
	if len(values) == 0 {
		return nil, nil, false
	}
	return values, sourceCursor(state.Cursor), true
}

func EncodePathParamCursor(param string, values []string, cursor *cerebrov1.SourceCursor) *cerebrov1.SourceCursor {
	if cursor == nil {
		return nil
	}
	inner := strings.TrimSpace(cursor.GetOpaque())
	if inner == "" {
		return nil
	}
	values = CompactStrings(values)
	if len(values) == 0 {
		return cursor
	}
	token, err := json.Marshal(pathParamCursor{Param: strings.TrimSpace(param), Values: values, Cursor: inner})
	if err != nil {
		return cursor
	}
	opaque, err := sourcecdk.EncodeCursorEnvelope(sourcecdk.CursorEnvelope{
		Version: 1,
		Source:  SourceID,
		Mode:    pathParamCursorMode,
		Token:   string(token),
	})
	if err != nil {
		return cursor
	}
	return &cerebrov1.SourceCursor{Opaque: opaque}
}

func ConfiguredPathParamValues(cfg sourcecdk.Config, param string) []string {
	switch strings.TrimSpace(param) {
	case "user_id":
		return ConfigListValues(cfg, "user_ids", "user_id")
	case "team_id":
		return ConfigListValues(cfg, "team_ids", "team_id")
	case "group_id":
		return ConfigListValues(cfg, "group_ids", "group_id")
	case "connection_id":
		return ConfigListValues(cfg, "connection_ids", "connection_id")
	case "destination_id":
		return ConfigListValues(cfg, "destination_ids", "destination_id")
	case "external_secret_manager_id":
		return ConfigListValues(cfg, "external_secret_manager_ids", "external_secret_manager_id", "esm_ids", "esm_id")
	case "proxy_agent_id":
		return ConfigListValues(cfg, "proxy_agent_ids", "proxy_agent_id", "agent_ids", "agent_id")
	case "service":
		return ConfigListValues(cfg, "connector_services", "services", "service")
	case "package_definition_id":
		return ConfigListValues(cfg, "package_definition_ids", "package_definition_id")
	default:
		return nil
	}
}

func sourceCursor(raw string) *cerebrov1.SourceCursor {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return &cerebrov1.SourceCursor{Opaque: raw}
}
