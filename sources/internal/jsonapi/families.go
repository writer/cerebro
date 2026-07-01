package jsonapi

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// LoadFamiliesFromFS loads JSON API family metadata from an embedded JSON
// document so provider packages can keep runtime wiring data out of Go code.
func LoadFamiliesFromFS(fsys fs.FS, path string) ([]Family, error) {
	body, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read JSON API families %s: %w", path, err)
	}
	var document struct {
		Families []Family `json:"families"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("unmarshal JSON API families %s: %w", path, err)
	}
	for i, family := range document.Families {
		if strings.TrimSpace(family.Name) == "" {
			return nil, fmt.Errorf("JSON API families %s entry %d missing name", path, i)
		}
	}
	return document.Families, nil
}
