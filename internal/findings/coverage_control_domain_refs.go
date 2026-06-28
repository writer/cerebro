package findings

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	_ "embed"

	"gopkg.in/yaml.v3"

	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed coverage_control_domain_refs.yaml
var coverageControlDomainRefsYAML []byte

var coverageControlDomainRefSet coverageControlDomainRefs

func init() {
	refs, err := loadCoverageControlDomainRefs(coverageControlDomainRefsYAML)
	if err != nil {
		panic(fmt.Sprintf("build coverage control domain refs: %v", err))
	}
	coverageControlDomainRefSet = refs
}

type coverageControlDomainRef struct {
	FrameworkName string `yaml:"framework_name"`
	FrameworkID   string `yaml:"framework_id"`
	ControlID     string `yaml:"control_id"`
}

type coverageControlDomainRefs struct {
	Version        string                                `yaml:"version"`
	ControlDomains map[string][]coverageControlDomainRef `yaml:"control_domains"`
}

func loadCoverageControlDomainRefs(data []byte) (coverageControlDomainRefs, error) {
	var refs coverageControlDomainRefs
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&refs); err != nil {
		return coverageControlDomainRefs{}, fmt.Errorf("decode coverage control domain refs: %w", err)
	}
	if strings.TrimSpace(refs.Version) == "" {
		return coverageControlDomainRefs{}, fmt.Errorf("coverage control domain refs version is required")
	}
	for domain, controls := range refs.ControlDomains {
		if strings.TrimSpace(domain) == "" {
			return coverageControlDomainRefs{}, fmt.Errorf("coverage control domain refs contain an empty control domain")
		}
		for _, control := range controls {
			if strings.TrimSpace(control.ControlID) == "" {
				return coverageControlDomainRefs{}, fmt.Errorf("control domain %q has a ref with an empty control_id", domain)
			}
			if strings.TrimSpace(control.FrameworkName) == "" && strings.TrimSpace(control.FrameworkID) == "" {
				return coverageControlDomainRefs{}, fmt.Errorf("control domain %q control %q requires framework_name or framework_id", domain, control.ControlID)
			}
		}
	}
	return refs, nil
}

// controlRefsForControlDomains returns the framework control refs that the given
// declared control domains can supply evidence for. The result is deduplicated
// and stably ordered so generated coverage output is deterministic.
func (c coverageControlDomainRefs) controlRefsForControlDomains(domains []string) []sourcecdk.CoverageControlRef {
	if len(domains) == 0 || len(c.ControlDomains) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	refs := make([]sourcecdk.CoverageControlRef, 0)
	for _, domain := range domains {
		key := strings.TrimSpace(domain)
		if key == "" {
			continue
		}
		for _, control := range c.ControlDomains[key] {
			ref := sourcecdk.CoverageControlRef{
				FrameworkID:   strings.TrimSpace(control.FrameworkID),
				FrameworkName: strings.TrimSpace(control.FrameworkName),
				ControlID:     strings.TrimSpace(control.ControlID),
			}
			dedupe := ref.FrameworkName + "\x00" + ref.FrameworkID + "\x00" + ref.ControlID
			if _, ok := seen[dedupe]; ok {
				continue
			}
			seen[dedupe] = struct{}{}
			refs = append(refs, ref)
		}
	}
	sort.Slice(refs, func(i int, j int) bool {
		if refs[i].FrameworkName != refs[j].FrameworkName {
			return refs[i].FrameworkName < refs[j].FrameworkName
		}
		return refs[i].ControlID < refs[j].ControlID
	})
	return refs
}

func controlRefsForControlDomains(domains []string) []sourcecdk.CoverageControlRef {
	return coverageControlDomainRefSet.controlRefsForControlDomains(domains)
}
