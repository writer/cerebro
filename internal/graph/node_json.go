package graph

import (
	"bytes"
	"encoding/json"
)

type nodeJSON Node

func (n *Node) MarshalJSON() ([]byte, error) {
	if n == nil {
		return []byte("null"), nil
	}
	payload := nodeJSON(*n)
	payload.Properties = cloneNodeProperties(n)
	return json.Marshal(payload)
}

func (n *Node) UnmarshalJSON(data []byte) error {
	var payload nodeJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return err
	}
	decoded := normalizeGraphMutationNode((*Node)(&payload))
	hydrateNodeTypedProperties(decoded)
	*n = *decoded
	return nil
}
