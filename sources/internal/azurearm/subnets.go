package azurearm

import (
	"encoding/json"
	"fmt"
	"strings"
)

func SubnetRecords[T any](networks []T, networkID func(T) string, networkLocation func(T) string, subnets func(T) []any) ([]json.RawMessage, error) {
	records := make([]json.RawMessage, 0)
	for _, network := range networks {
		for _, value := range subnets(network) {
			subnetMap, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if strings.TrimSpace(subnetString(subnetMap["type"])) == "" {
				subnetMap["type"] = "Microsoft.Network/virtualNetworks/subnets"
			}
			if strings.TrimSpace(subnetString(subnetMap["location"])) == "" {
				subnetMap["location"] = networkLocation(network)
			}
			raw, err := json.Marshal(subnetMap)
			if err != nil {
				return nil, fmt.Errorf("encode subnet from virtual network %q: %w", networkID(network), err)
			}
			records = append(records, raw)
		}
	}
	return records, nil
}

func subnetString(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}
