package gcpcloud

import (
	"fmt"
	"strings"
)

func OptionalServiceErr(err error) error {
	if err != nil && (strings.Contains(fmt.Sprint(err), "SERVICE_DISABLED") || strings.Contains(fmt.Sprint(err), "has not been used")) {
		return nil
	}
	return err
}

func OptionalEnrichmentErr(err error) error {
	if err == nil {
		return nil
	}
	message := fmt.Sprint(err)
	if strings.Contains(message, "SERVICE_DISABLED") ||
		strings.Contains(message, "has not been used") ||
		strings.Contains(message, "PERMISSION_DENIED") ||
		strings.Contains(message, "IAM_PERMISSION_DENIED") ||
		strings.Contains(message, "gcp API returned 403") {
		return nil
	}
	return err
}
