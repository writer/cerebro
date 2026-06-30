// Manifest parsing for the connector import tool.
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/writer/cerebro/internal/connectorimport"
)

type manifest struct {
	Targets []manifestTarget `yaml:"targets"`
}

type manifestTarget struct {
	SourceID              string   `yaml:"source_id"`
	DisplayName           string   `yaml:"display_name"`
	Description           string   `yaml:"description"`
	Domain                string   `yaml:"domain"`
	Categories            []string `yaml:"categories"`
	BaseURL               string   `yaml:"base_url"`
	AuthModel             string   `yaml:"auth_model"`
	ProviderAPIReferences []string `yaml:"provider_api_references"`
	MaxFamilies           int      `yaml:"max_families"`
	AllFamilies           bool     `yaml:"all_families"`

	APIsGuru string `yaml:"apis_guru"`
	SpecURL  string `yaml:"spec_url"`
	SpecFile string `yaml:"spec_file"`
}

func (t manifestTarget) target() connectorimport.Target {
	return connectorimport.Target{
		SourceID:              t.SourceID,
		DisplayName:           t.DisplayName,
		Description:           t.Description,
		Domain:                t.Domain,
		Categories:            t.Categories,
		BaseURL:               t.BaseURL,
		AuthModel:             t.AuthModel,
		ProviderAPIReferences: t.ProviderAPIReferences,
		MaxFamilies:           t.MaxFamilies,
		AllFamilies:           t.AllFamilies,
	}
}

func readManifest(path string) (manifest, error) {
	payload, err := os.ReadFile(path) //nolint:gosec // operator-provided manifest path for a build-time tool.
	if err != nil {
		return manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var man manifest
	if err := yaml.Unmarshal(payload, &man); err != nil {
		return manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if len(man.Targets) == 0 {
		return manifest{}, fmt.Errorf("manifest %s has no targets", path)
	}
	return man, nil
}
