package compliance

import (
	"strings"

	findinganalysis "github.com/writer/cerebro/internal/findings"
)

func BuiltinRuleControlMappings() []RuleControlMapping {
	mappings := []RuleControlMapping{}
	for _, metadata := range findinganalysis.BuiltinRuleMetadata() {
		ruleID := strings.TrimSpace(metadata.ID)
		if ruleID == "" {
			continue
		}
		refs := make([]ControlRef, 0, len(metadata.ControlRefs))
		for _, ref := range metadata.ControlRefs {
			refs = append(refs, ControlRef{
				FrameworkName: ref.FrameworkName,
				ControlID:     ref.ControlID,
			})
		}
		mappings = append(mappings, RuleControlMapping{
			RuleID:      ruleID,
			ControlRefs: refs,
		})
	}
	return mappings
}
