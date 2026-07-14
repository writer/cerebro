package contentpacks

import (
	"fmt"
	"path/filepath"
	"sort"
)

const maxExternalPacks = 32

type Rejection struct {
	Candidate string `json:"candidate"`
	Reason    string `json:"reason"`
}

type Resolution struct {
	Packs                 []VerifiedPack `json:"-"`
	Rejected              []Rejection    `json:"rejected,omitempty"`
	ExternalAttempted     int            `json:"external_attempted"`
	ExternalAccepted      int            `json:"external_accepted"`
	ExternalRejected      int            `json:"external_rejected"`
	UsingEmbeddedFallback bool           `json:"using_embedded_fallback"`
}

// Resolve keeps validated embedded packs available when an external candidate
// is invalid. Earlier load_order values win conflicts; embedded content always
// wins over external content at the same logical ID.
func Resolve(defaults []VerifiedPack, externalDirectories []string, kernelVersion, tenantID string, allowlist Allowlist) (Resolution, error) {
	result := Resolution{Packs: append([]VerifiedPack(nil), defaults...)}
	seenPackIDs := map[string]struct{}{}
	seenContent := map[string]string{}
	for _, pack := range defaults {
		if _, exists := seenPackIDs[pack.Manifest.PackID]; exists {
			return Resolution{}, fmt.Errorf("embedded pack %s is duplicated", pack.Manifest.PackID)
		}
		seenPackIDs[pack.Manifest.PackID] = struct{}{}
		for _, content := range pack.Manifest.Contents {
			key := pack.Manifest.Kind + ":" + content.ID
			if owner, exists := seenContent[key]; exists {
				return Resolution{}, fmt.Errorf("embedded content %s conflicts with %s", key, owner)
			}
			seenContent[key] = pack.Manifest.PackID
		}
	}

	directories := append([]string(nil), externalDirectories...)
	sort.Strings(directories)
	if len(directories) > maxExternalPacks {
		for _, directory := range directories[maxExternalPacks:] {
			result.Rejected = append(result.Rejected, Rejection{Candidate: filepath.Base(directory), Reason: "external pack limit exceeded"})
		}
		directories = directories[:maxExternalPacks]
	}
	result.ExternalAttempted = len(externalDirectories)
	verified := make([]VerifiedPack, 0, len(directories))
	for _, directory := range directories {
		pack, err := VerifyDirectory(directory, kernelVersion, tenantID, allowlist)
		if err != nil {
			result.Rejected = append(result.Rejected, Rejection{Candidate: filepath.Base(directory), Reason: err.Error()})
			continue
		}
		verified = append(verified, pack)
	}
	sort.Slice(verified, func(i, j int) bool {
		left := verified[i].Manifest
		right := verified[j].Manifest
		if left.LoadOrder != right.LoadOrder {
			return left.LoadOrder < right.LoadOrder
		}
		if left.PackID != right.PackID {
			return left.PackID < right.PackID
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.ManifestDigest < right.ManifestDigest
	})
	for _, pack := range verified {
		if _, exists := seenPackIDs[pack.Manifest.PackID]; exists {
			result.Rejected = append(result.Rejected, Rejection{Candidate: pack.Manifest.PackID, Reason: "pack_id conflicts with an earlier pack"})
			continue
		}
		conflict := ""
		for _, content := range pack.Manifest.Contents {
			key := pack.Manifest.Kind + ":" + content.ID
			if owner, exists := seenContent[key]; exists {
				conflict = fmt.Sprintf("content %s conflicts with pack %s", key, owner)
				break
			}
		}
		if conflict != "" {
			result.Rejected = append(result.Rejected, Rejection{Candidate: pack.Manifest.PackID, Reason: conflict})
			continue
		}
		seenPackIDs[pack.Manifest.PackID] = struct{}{}
		for _, content := range pack.Manifest.Contents {
			seenContent[pack.Manifest.Kind+":"+content.ID] = pack.Manifest.PackID
		}
		result.Packs = append(result.Packs, pack)
		result.ExternalAccepted++
	}
	result.ExternalRejected = len(result.Rejected)
	result.UsingEmbeddedFallback = result.ExternalRejected > 0 && len(defaults) > 0
	return result, nil
}
