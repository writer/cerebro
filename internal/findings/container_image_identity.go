package findings

import (
	"fmt"
	"strings"
)

func normalizedContainerImageURN(tenantID string, imageDigest string) string {
	tenantID = strings.TrimSpace(tenantID)
	imageDigest = strings.TrimSpace(imageDigest)
	if tenantID == "" || imageDigest == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:container_image_digest:%s", tenantID, imageDigest)
}
