package grc

import (
	"strings"
)

func monitoredComputerComplianceStatus(attrs map[string]string) string {
	result := ""
	statuses := []string{attrs["screenlock_status"], attrs["disk_encryption_status"], attrs["password_manager_status"], attrs["antivirus_status"]}
	for _, status := range statuses {
		trimmed := strings.TrimSpace(status)
		if trimmed == "" {
			continue
		}
		if strings.EqualFold(trimmed, "FAIL") || strings.EqualFold(trimmed, "NEEDS_ATTENTION") {
			return "needs_attention"
		}
		if strings.EqualFold(trimmed, "OK") || strings.EqualFold(trimmed, "PASS") {
			result = "ok"
		}
		if result == "" {
			result = strings.ToLower(trimmed)
		}
	}
	return result
}
