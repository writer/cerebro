package pack

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Loader reads artifact pack definitions from disk.
type Loader struct{}

// LoadDirectory parses all YAML packs under dir and returns aggregated packs.
func (Loader) LoadDirectory(dir string) ([]Pack, error) {
	if dir == "" {
		return nil, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat pack directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pack path is not a directory: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read pack directory: %w", err)
	}

	packs := make([]Pack, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		pack, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}

	return packs, nil
}

func loadFile(path string) (Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Pack{}, fmt.Errorf("read pack file %s: %w", path, err)
	}

	var pack Pack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return Pack{}, fmt.Errorf("parse pack file %s: %w", path, err)
	}
	return pack, nil
}
