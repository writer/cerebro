package app

import (
	"fmt"
	"sort"
	"strings"
)

func runInitStep(name string, fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	fn()
	return nil
}

func runInitErrorStep(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s init panic: %v", name, r)
		}
	}()
	return fn()
}

func (a *App) validateRequiredServices() error {
	required := map[string]bool{
		"policy_engine":   a.Policy != nil,
		"findings_store":  a.Findings != nil,
		"scanner":         a.Scanner != nil,
		"cache":           a.Cache != nil,
		"agent_registry":  a.Agents != nil,
		"ticketing":       a.Ticketing != nil,
		"identity":        a.Identity != nil,
		"attackpath":      a.AttackPath != nil,
		"providers":       a.Providers != nil,
		"webhooks":        a.Webhooks != nil,
		"notifications":   a.Notifications != nil,
		"scheduler":       a.Scheduler != nil,
		"rbac":            a.RBAC != nil,
		"threatintel":     a.ThreatIntel != nil,
		"health":          a.Health != nil,
		"lineage":         a.Lineage != nil,
		"remediation":     a.Remediation != nil,
		"runtime_detect":  a.RuntimeDetect != nil,
		"runtime_respond": a.RuntimeRespond != nil,
	}

	var missing []string
	for service, initialized := range required {
		if initialized {
			continue
		}
		missing = append(missing, service)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("required services not initialized: %s", strings.Join(missing, ", "))
	}
	return nil
}
