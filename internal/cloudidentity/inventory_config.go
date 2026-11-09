package cloudidentity

import "strings"

// manifestInventorySplitImageDigest separates a "repo:tag@sha256:digest" or
// "repo@sha256:digest" image reference into its mutable reference and pinned
// digest, when a digest is present.
func manifestInventorySplitImageDigest(image string) (ref string, digest string) {
	if idx := strings.Index(image, "@sha256:"); idx >= 0 {
		return image[:idx], image[idx+1:]
	}
	return image, ""
}
