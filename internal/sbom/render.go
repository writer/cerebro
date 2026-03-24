package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
)

const (
	FormatCycloneDXJSON = "cyclonedx-json"
	FormatSPDXJSON      = "spdx-json"
)

var ErrUnsupportedFormat = errors.New("unsupported sbom format")

type SourceDescriptor struct {
	Name        string
	Namespace   string
	RunID       string
	Target      string
	GeneratedAt time.Time
}

type cyclonedxDocument struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	SerialNumber string                `json:"serialNumber,omitempty"`
	Metadata     *cyclonedxMetadata    `json:"metadata,omitempty"`
	Components   []cyclonedxComponent  `json:"components,omitempty"`
	Dependencies []cyclonedxDependency `json:"dependencies,omitempty"`
}

type cyclonedxMetadata struct {
	Timestamp string              `json:"timestamp,omitempty"`
	Component *cyclonedxComponent `json:"component,omitempty"`
}

type cyclonedxComponent struct {
	BOMRef     string              `json:"bom-ref,omitempty"`
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	PURL       string              `json:"purl,omitempty"`
	Properties []cyclonedxProperty `json:"properties,omitempty"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages,omitempty"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	PrimaryPurpose   string            `json:"primaryPackagePurpose,omitempty"`
	Summary          string            `json:"summary,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func Render(format string, source SourceDescriptor, doc filesystemanalyzer.SBOMDocument) ([]byte, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	merged := Merge(doc)
	switch format {
	case FormatCycloneDXJSON:
		payload, err := json.MarshalIndent(toCycloneDX(source, merged), "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("marshal cyclonedx sbom: %w", err)
		}
		return append(payload, '\n'), "application/vnd.cyclonedx+json", nil
	case FormatSPDXJSON:
		payload, err := json.MarshalIndent(toSPDX(source, merged), "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("marshal spdx sbom: %w", err)
		}
		return append(payload, '\n'), "application/spdx+json", nil
	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
}

func Merge(documents ...filesystemanalyzer.SBOMDocument) filesystemanalyzer.SBOMDocument {
	out := filesystemanalyzer.SBOMDocument{
		Format:      FormatCycloneDXJSON,
		SpecVersion: "1.5",
	}
	componentByKey := make(map[string]filesystemanalyzer.SBOMComponent)
	depsByRef := make(map[string]map[string]struct{})

	for _, doc := range documents {
		if strings.TrimSpace(doc.Format) != "" {
			out.Format = strings.TrimSpace(doc.Format)
		}
		if strings.TrimSpace(doc.SpecVersion) != "" {
			out.SpecVersion = strings.TrimSpace(doc.SpecVersion)
		}
		if doc.GeneratedAt.After(out.GeneratedAt) {
			out.GeneratedAt = doc.GeneratedAt.UTC()
		}
		for _, component := range doc.Components {
			key := sbomComponentKey(component)
			if key == "" {
				continue
			}
			existing, ok := componentByKey[key]
			if ok {
				componentByKey[key] = mergeComponent(existing, component)
				continue
			}
			componentByKey[key] = component
		}
		for _, dep := range doc.Dependencies {
			ref := strings.TrimSpace(dep.Ref)
			if ref == "" {
				continue
			}
			if _, ok := depsByRef[ref]; !ok {
				depsByRef[ref] = make(map[string]struct{})
			}
			for _, child := range dep.DependsOn {
				child = strings.TrimSpace(child)
				if child == "" {
					continue
				}
				depsByRef[ref][child] = struct{}{}
			}
		}
	}

	out.Components = make([]filesystemanalyzer.SBOMComponent, 0, len(componentByKey))
	for _, component := range componentByKey {
		out.Components = append(out.Components, component)
	}
	sort.Slice(out.Components, func(i, j int) bool {
		left := sbomComponentKey(out.Components[i])
		right := sbomComponentKey(out.Components[j])
		return left < right
	})

	out.Dependencies = make([]filesystemanalyzer.SBOMDependency, 0, len(depsByRef))
	for ref, deps := range depsByRef {
		entry := filesystemanalyzer.SBOMDependency{Ref: ref}
		for dep := range deps {
			entry.DependsOn = append(entry.DependsOn, dep)
		}
		sort.Strings(entry.DependsOn)
		out.Dependencies = append(out.Dependencies, entry)
	}
	sort.Slice(out.Dependencies, func(i, j int) bool {
		return out.Dependencies[i].Ref < out.Dependencies[j].Ref
	})

	return out
}

func toCycloneDX(source SourceDescriptor, doc filesystemanalyzer.SBOMDocument) cyclonedxDocument {
	timestamp := sbomTimestamp(source, doc)
	rendered := cyclonedxDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  firstNonEmpty(doc.SpecVersion, "1.5"),
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.NewString(),
		Components:   make([]cyclonedxComponent, 0, len(doc.Components)),
		Dependencies: make([]cyclonedxDependency, 0, len(doc.Dependencies)),
	}
	if !timestamp.IsZero() {
		rendered.Metadata = &cyclonedxMetadata{Timestamp: timestamp.UTC().Format(time.RFC3339)}
	}
	for _, component := range doc.Components {
		rendered.Components = append(rendered.Components, cyclonedxComponent{
			BOMRef:     strings.TrimSpace(component.BOMRef),
			Type:       firstNonEmpty(strings.TrimSpace(component.Type), "library"),
			Name:       strings.TrimSpace(component.Name),
			Version:    strings.TrimSpace(component.Version),
			PURL:       strings.TrimSpace(component.PURL),
			Properties: cyclonedxProperties(component),
		})
	}
	for _, dep := range doc.Dependencies {
		rendered.Dependencies = append(rendered.Dependencies, cyclonedxDependency{
			Ref:       strings.TrimSpace(dep.Ref),
			DependsOn: append([]string(nil), dep.DependsOn...),
		})
	}
	return rendered
}

func toSPDX(source SourceDescriptor, doc filesystemanalyzer.SBOMDocument) spdxDocument {
	timestamp := sbomTimestamp(source, doc)
	documentName := documentName(source)
	rendered := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              documentName,
		DocumentNamespace: "https://cerebro.evalops.local/sbom/" + uuid.NewString(),
		CreationInfo: spdxCreationInfo{
			Created:  timestamp.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: cerebro"},
		},
		Packages:      make([]spdxPackage, 0, len(doc.Components)),
		Relationships: make([]spdxRelationship, 0, len(doc.Components)+len(doc.Dependencies)),
	}

	componentIDs := make(map[string]string, len(doc.Components))
	usedIDs := make(map[string]struct{}, len(doc.Components))
	for index, component := range doc.Components {
		id := spdxPackageID(component, index, usedIDs)
		componentIDs[sbomComponentKey(component)] = id
		if strings.TrimSpace(component.BOMRef) != "" {
			componentIDs[strings.TrimSpace(component.BOMRef)] = id
		}
		pkg := spdxPackage{
			SPDXID:           id,
			Name:             firstNonEmpty(strings.TrimSpace(component.Name), "component"),
			VersionInfo:      strings.TrimSpace(component.Version),
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			PrimaryPurpose:   spdxPrimaryPurpose(component.Type),
			Summary:          strings.TrimSpace(component.Location),
		}
		if purl := strings.TrimSpace(component.PURL); purl != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}
		rendered.Packages = append(rendered.Packages, pkg)
		rendered.Relationships = append(rendered.Relationships, spdxRelationship{
			SPDXElementID:      rendered.SPDXID,
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: id,
		})
	}
	for _, dep := range doc.Dependencies {
		parentID := firstNonEmpty(componentIDs[strings.TrimSpace(dep.Ref)], componentIDs[sanitizeSPDXRef(strings.TrimSpace(dep.Ref))])
		if parentID == "" {
			continue
		}
		for _, child := range dep.DependsOn {
			childID := firstNonEmpty(componentIDs[strings.TrimSpace(child)], componentIDs[sanitizeSPDXRef(strings.TrimSpace(child))])
			if childID == "" {
				continue
			}
			rendered.Relationships = append(rendered.Relationships, spdxRelationship{
				SPDXElementID:      parentID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: childID,
			})
		}
	}
	return rendered
}

func cyclonedxProperties(component filesystemanalyzer.SBOMComponent) []cyclonedxProperty {
	properties := make([]cyclonedxProperty, 0, 5)
	add := func(name, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		properties = append(properties, cyclonedxProperty{Name: name, Value: value})
	}
	add("cerebro:ecosystem", component.Ecosystem)
	add("cerebro:location", component.Location)
	if component.DirectDependency {
		add("cerebro:direct_dependency", "true")
	}
	if component.Reachable {
		add("cerebro:reachable", "true")
	}
	if component.DependencyDepth > 0 {
		add("cerebro:dependency_depth", fmt.Sprintf("%d", component.DependencyDepth))
	}
	if component.ImportFileCount > 0 {
		add("cerebro:import_file_count", fmt.Sprintf("%d", component.ImportFileCount))
	}
	return properties
}

func mergeComponent(existing, incoming filesystemanalyzer.SBOMComponent) filesystemanalyzer.SBOMComponent {
	merged := existing
	merged.BOMRef = firstNonEmpty(existing.BOMRef, incoming.BOMRef)
	merged.Type = firstNonEmpty(existing.Type, incoming.Type)
	merged.Name = firstNonEmpty(existing.Name, incoming.Name)
	merged.Version = firstNonEmpty(existing.Version, incoming.Version)
	merged.PURL = firstNonEmpty(existing.PURL, incoming.PURL)
	merged.Ecosystem = firstNonEmpty(existing.Ecosystem, incoming.Ecosystem)
	merged.Location = firstNonEmpty(existing.Location, incoming.Location)
	merged.DirectDependency = existing.DirectDependency || incoming.DirectDependency
	merged.Reachable = existing.Reachable || incoming.Reachable
	merged.ImportFileCount = max(existing.ImportFileCount, incoming.ImportFileCount)
	switch {
	case merged.DependencyDepth == 0:
		merged.DependencyDepth = incoming.DependencyDepth
	case incoming.DependencyDepth > 0 && incoming.DependencyDepth < merged.DependencyDepth:
		merged.DependencyDepth = incoming.DependencyDepth
	}
	return merged
}

func sbomTimestamp(source SourceDescriptor, doc filesystemanalyzer.SBOMDocument) time.Time {
	switch {
	case !source.GeneratedAt.IsZero():
		return source.GeneratedAt.UTC()
	case !doc.GeneratedAt.IsZero():
		return doc.GeneratedAt.UTC()
	default:
		return time.Unix(0, 0).UTC()
	}
}

func documentName(source SourceDescriptor) string {
	return firstNonEmpty(
		strings.TrimSpace(source.Name),
		strings.TrimSpace(source.Target),
		strings.TrimSpace(source.RunID),
		"cerebro-sbom",
	)
}

func spdxPackageID(component filesystemanalyzer.SBOMComponent, index int, used map[string]struct{}) string {
	base := sanitizeSPDXRef(firstNonEmpty(component.BOMRef, component.Name, fmt.Sprintf("component-%d", index+1)))
	if base == "" {
		base = fmt.Sprintf("SPDXRef-Component-%d", index+1)
	}
	id := base
	for suffix := 2; ; suffix++ {
		if _, ok := used[id]; !ok {
			used[id] = struct{}{}
			return id
		}
		id = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func spdxPrimaryPurpose(componentType string) string {
	switch strings.ToLower(strings.TrimSpace(componentType)) {
	case "application", "framework", "container":
		return "APPLICATION"
	default:
		return "LIBRARY"
	}
}

func sanitizeSPDXRef(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("SPDXRef-")
	lastDash := false
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '.', r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if lastDash {
				continue
			}
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func sbomComponentKey(component filesystemanalyzer.SBOMComponent) string {
	if ref := strings.TrimSpace(component.BOMRef); ref != "" {
		return ref
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(component.Type)),
		strings.ToLower(strings.TrimSpace(component.Name)),
		strings.ToLower(strings.TrimSpace(component.Version)),
		strings.ToLower(strings.TrimSpace(component.Location)),
	}
	key := strings.Join(parts, "|")
	if strings.Trim(key, "|") == "" {
		return ""
	}
	return key
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func max(left, right int) int {
	if right > left {
		return right
	}
	return left
}
