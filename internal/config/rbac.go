package config

import (
	"fmt"
	"strings"
)

var knownRBACRoles = map[string]struct{}{
	"cerebro.admin":             {},
	"cerebro.viewer":            {},
	"cerebro.analyst":           {},
	"cerebro.finding_manager":   {},
	"cerebro.grc_reviewer":      {},
	"cerebro.connector_manager": {},
	"cerebro.responder":         {},
	"cerebro.source_manager":    {},
	"cerebro.job_manager":       {},
	"viewer":                    {},
	"reader":                    {},
	"read_only":                 {},
	"analyst":                   {},
	"editor":                    {},
	"admin":                     {},
	"owner":                     {},
}

func validateKnownRBACRoles(field string, roles []string) error {
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if _, ok := knownRBACRoles[role]; !ok {
			return fmt.Errorf("%s contains unknown role %q", field, role)
		}
	}
	return nil
}
