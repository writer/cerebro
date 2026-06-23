package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/oktaasset"
)

var policyRulePolicyTypes = []string{"OKTA_SIGN_ON", "ACCESS_POLICY", "PASSWORD", "MFA_ENROLL", "PROFILE_ENROLLMENT", "IDP_DISCOVERY"}

type policyRecord struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	System      *bool      `json:"system"`
	Created     *time.Time `json:"created"`
	LastUpdated *time.Time `json:"lastUpdated"`
	raw         json.RawMessage
}

type policyRuleRecord struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Priority    *int       `json:"priority"`
	System      *bool      `json:"system"`
	Created     *time.Time `json:"created"`
	LastUpdated *time.Time `json:"lastUpdated"`
	raw         json.RawMessage
}

type policyRuleEntry struct {
	Policy policyRecord
	Rule   policyRuleRecord
}

type policyRuleCursor struct {
	ResumableCheckpoint bool                    `json:"resumable_checkpoint,omitempty"`
	PolicyTypeIndex     int                     `json:"policy_type_index,omitempty"`
	PolicyAfter         string                  `json:"policy_after,omitempty"`
	Policy              *policyRuleCursorPolicy `json:"policy,omitempty"`
	RuleAfter           string                  `json:"rule_after,omitempty"`
}

type policyRuleCursorPolicy struct {
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	Type            string `json:"type"`
	Status          string `json:"status,omitempty"`
	NextPolicyAfter string `json:"next_policy_after,omitempty"`
}

func (s *Source) policyRuleFamily() sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: familyPolicyRule,
		Check: func(ctx context.Context, settings settings) error {
			return s.checkPolicyRules(ctx, settings)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			return s.discoverPolicyRuleURNs(ctx, settings)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			return s.readPolicyRules(ctx, settings, cursor)
		},
	}
}

func (s *Source) checkPolicyRules(ctx context.Context, settings settings) error {
	var notFoundErr error
	for _, policyType := range policyRulePolicyTypes {
		if _, _, err := s.listPolicies(ctx, settings, policyType, "", 1); err != nil {
			if isNotFound(err) {
				notFoundErr = err
				continue
			}
			return wrapLookupError(oktaLabel("okta policies", settings), err)
		}
		return nil
	}
	if notFoundErr != nil {
		return wrapLookupError(oktaLabel("okta policies", settings), notFoundErr)
	}
	return nil
}

func (s *Source) discoverPolicyRuleURNs(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
	urns := []sourcecdk.URN{}
	for _, policyType := range policyRulePolicyTypes {
		policyAfter := ""
		for {
			policies, nextPolicyAfter, err := s.listPolicies(ctx, settings, policyType, policyAfter, settings.perPage)
			if err != nil {
				if isNotFound(err) {
					break
				}
				return nil, wrapLookupError(oktaLabel("okta policies", settings), err)
			}
			for _, policy := range policies {
				policy.Type = firstNonEmpty(policy.Type, policyType)
				ruleAfter := ""
				for {
					rules, nextRuleAfter, err := s.listPolicyRules(ctx, settings, policy.ID, ruleAfter, settings.perPage)
					if err != nil {
						if isNotFound(err) {
							break
						}
						return nil, wrapLookupError(oktaLabel("okta policy rules", settings), err)
					}
					for _, rule := range rules {
						urn, err := sourcecdk.ParseURN(policyRuleURN(settings, policy, rule))
						if err != nil {
							return nil, err
						}
						urns = append(urns, urn)
					}
					if strings.TrimSpace(nextRuleAfter) == "" {
						break
					}
					if nextRuleAfter == ruleAfter {
						return nil, fmt.Errorf("okta policy rule pagination cursor did not advance for policy %q", policy.ID)
					}
					ruleAfter = nextRuleAfter
				}
			}
			if strings.TrimSpace(nextPolicyAfter) == "" {
				break
			}
			if nextPolicyAfter == policyAfter {
				return nil, fmt.Errorf("okta policy pagination cursor did not advance for type %q", policyType)
			}
			policyAfter = nextPolicyAfter
		}
	}
	return urns, nil
}

func (s *Source) readPolicyRules(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	state, err := parsePolicyRuleCursor(cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	events := make([]*primitives.Event, 0, settings.perPage)
	for len(events) < settings.perPage && state.PolicyTypeIndex < len(policyRulePolicyTypes) {
		if state.Policy == nil || strings.TrimSpace(state.Policy.ID) == "" {
			if err := s.advancePolicyRuleCursorToNextPolicy(ctx, settings, &state); err != nil {
				return sourcecdk.Pull{}, err
			}
			if state.Policy == nil {
				continue
			}
		}
		policy := policyRecord{
			ID:     strings.TrimSpace(state.Policy.ID),
			Name:   strings.TrimSpace(state.Policy.Name),
			Type:   firstNonEmpty(state.Policy.Type, policyRulePolicyTypes[state.PolicyTypeIndex]),
			Status: strings.TrimSpace(state.Policy.Status),
		}
		rules, nextRuleAfter, err := s.listPolicyRules(ctx, settings, policy.ID, state.RuleAfter, settings.perPage-len(events))
		if err != nil {
			if isNotFound(err) {
				finishPolicyRuleCursorPolicy(&state)
				continue
			}
			return sourcecdk.Pull{}, wrapLookupError(oktaLabel("okta policy rules", settings), err)
		}
		for _, rule := range rules {
			event, err := policyRuleEvent(settings, policyRuleEntry{Policy: policy, Rule: rule})
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
			if len(events) >= settings.perPage {
				break
			}
		}
		if strings.TrimSpace(nextRuleAfter) != "" {
			if nextRuleAfter == state.RuleAfter {
				return sourcecdk.Pull{}, fmt.Errorf("okta policy rule pagination cursor did not advance for policy %q", policy.ID)
			}
			state.RuleAfter = nextRuleAfter
			if len(events) >= settings.perPage {
				break
			}
			continue
		}
		finishPolicyRuleCursorPolicy(&state)
	}
	return policyRulePullFromEvents(events, state)
}

func (s *Source) advancePolicyRuleCursorToNextPolicy(ctx context.Context, settings settings, state *policyRuleCursor) error {
	for state.PolicyTypeIndex < len(policyRulePolicyTypes) {
		policyType := policyRulePolicyTypes[state.PolicyTypeIndex]
		policies, nextPolicyAfter, err := s.listPolicies(ctx, settings, policyType, state.PolicyAfter, 1)
		if err != nil {
			if isNotFound(err) {
				state.PolicyTypeIndex++
				state.PolicyAfter = ""
				continue
			}
			return wrapLookupError(oktaLabel("okta policies", settings), err)
		}
		if len(policies) == 0 {
			state.PolicyTypeIndex++
			state.PolicyAfter = ""
			continue
		}
		policy := policies[0]
		policy.Type = firstNonEmpty(policy.Type, policyType)
		state.Policy = &policyRuleCursorPolicy{
			ID:              policy.ID,
			Name:            policy.Name,
			Type:            policy.Type,
			Status:          policy.Status,
			NextPolicyAfter: nextPolicyAfter,
		}
		state.RuleAfter = ""
		return nil
	}
	return nil
}

func finishPolicyRuleCursorPolicy(state *policyRuleCursor) {
	if state == nil || state.Policy == nil {
		return
	}
	nextPolicyAfter := strings.TrimSpace(state.Policy.NextPolicyAfter)
	state.Policy = nil
	state.RuleAfter = ""
	if nextPolicyAfter != "" {
		state.PolicyAfter = nextPolicyAfter
		return
	}
	state.PolicyTypeIndex++
	state.PolicyAfter = ""
}

func parsePolicyRuleCursor(cursor *cerebrov1.SourceCursor) (policyRuleCursor, error) {
	raw := strings.TrimSpace(cursor.GetOpaque())
	if raw == "" {
		return policyRuleCursor{}, nil
	}
	var state policyRuleCursor
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return policyRuleCursor{}, fmt.Errorf("parse okta policy_rule cursor: %w", err)
	}
	if state.PolicyTypeIndex < 0 || state.PolicyTypeIndex > len(policyRulePolicyTypes) {
		return policyRuleCursor{}, fmt.Errorf("okta policy_rule cursor has invalid policy_type_index %d", state.PolicyTypeIndex)
	}
	return state, nil
}

func encodePolicyRuleCursor(state policyRuleCursor) (string, error) {
	state.ResumableCheckpoint = true
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal okta policy_rule cursor: %w", err)
	}
	return string(payload), nil
}

func policyRulePullFromEvents(events []*primitives.Event, state policyRuleCursor) (sourcecdk.Pull, error) {
	if len(events) == 0 {
		return sourcecdk.Pull{}, nil
	}
	last := events[len(events)-1]
	checkpointOpaque, err := encodePolicyRuleCursor(state)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	var nextOpaque string
	if policyRuleCursorHasMore(state) {
		nextOpaque = checkpointOpaque
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    last.OccurredAt,
			CursorOpaque: checkpointOpaque,
		},
	}
	if nextOpaque != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextOpaque}
	}
	return pull, nil
}

func policyRuleCursorHasMore(state policyRuleCursor) bool {
	return state.PolicyTypeIndex < len(policyRulePolicyTypes)
}

func (s *Source) listPolicies(ctx context.Context, settings settings, policyType string, after string, limit int) ([]policyRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)
	sourcecdk.AddQueryParam(query, "type", policyType)

	return listJSONRecords(ctx, s, settings, "/api/v1/policies", query, "okta policy", func(record *policyRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
		if strings.TrimSpace(record.Type) == "" {
			record.Type = policyType
		}
	})
}

func (s *Source) listPolicyRules(ctx context.Context, settings settings, policyID string, after string, limit int) ([]policyRuleRecord, string, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	sourcecdk.AddQueryParam(query, "after", after)

	return listJSONRecords(ctx, s, settings, "/api/v1/policies/"+url.PathEscape(policyID)+"/rules", query, "okta policy rule", func(record *policyRuleRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
}

func policyRuleEvent(settings settings, entry policyRuleEntry) (*primitives.Event, error) {
	record := entry.Rule
	occurredAt := firstRecordTime(record.LastUpdated, record.Created, entry.Policy.LastUpdated, entry.Policy.Created)
	raw, err := decodeRawPayload(record.raw, "okta policy rule")
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"domain":         settings.domain,
		"policy_id":      entry.Policy.ID,
		"policy_rule_id": record.ID,
		"policy_type":    firstNonEmpty(entry.Policy.Type, "UNKNOWN"),
		"name":           record.Name,
		"status":         record.Status,
		"raw":            raw,
	}
	if record.Priority != nil {
		payload["priority"] = *record.Priority
	}
	if record.System != nil {
		payload["system"] = *record.System
	}
	if record.System == nil && entry.Policy.System != nil {
		payload["system"] = *entry.Policy.System
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal okta policy rule payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("okta-policy-rule-%s-%s-%d", entry.Policy.ID, record.ID, occurredAt.UnixMilli()),
		TenantId:   settings.domain,
		SourceId:   "okta",
		Kind:       "okta.policy_rule",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/policy_rule/v1",
		Payload:    encoded,
		Attributes: policyRuleAttributes(settings, entry),
	}, nil
}

func policyRuleAttributes(settings settings, entry policyRuleEntry) map[string]string {
	attributes := map[string]string{
		"domain":             settings.domain,
		"family":             familyPolicyRule,
		"policy_id":          entry.Policy.ID,
		"policy_name":        entry.Policy.Name,
		"policy_status":      entry.Policy.Status,
		"policy_rule_id":     entry.Rule.ID,
		"policy_type":        firstNonEmpty(entry.Policy.Type, "UNKNOWN"),
		"name":               entry.Rule.Name,
		"resource_id":        entry.Rule.ID,
		"resource_type":      "PolicyRule",
		"status":             entry.Rule.Status,
		"policy_rule_status": entry.Rule.Status,
	}
	if entry.Rule.Priority != nil {
		attributes["priority"] = strconv.Itoa(*entry.Rule.Priority)
	}
	if entry.Rule.System != nil {
		attributes["system"] = boolString(*entry.Rule.System)
	} else if entry.Policy.System != nil {
		attributes["system"] = boolString(*entry.Policy.System)
	}
	policyRuleActionsAttributes(entry.Rule.raw, attributes)
	policyRuleConditionsAttributes(entry.Rule.raw, attributes)
	return attributes
}

func policyRuleActionsAttributes(raw json.RawMessage, attrs map[string]string) {
	var rule struct {
		Actions struct {
			Signon struct {
				Access        string `json:"access"`
				RequireFactor bool   `json:"requireFactor"`
				FactorPrompt  string `json:"factorPromptMode"`
				FactorLife    int    `json:"factorLifetime"`
				Session       struct {
					UsePersistent bool `json:"usePersistentCookie"`
					MaxLifetime   int  `json:"maxSessionLifetimeMinutes"`
					Idle          int  `json:"maxSessionIdleMinutes"`
				} `json:"session"`
			} `json:"signon"`
			AppSignOn struct {
				Access string `json:"access"`
			} `json:"appSignOn"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &rule); err != nil {
		return
	}
	a := rule.Actions
	if a.Signon.Access != "" {
		attrs["access"] = strings.ToUpper(a.Signon.Access)
		attrs["requires_mfa"] = boolString(a.Signon.RequireFactor)
		if a.Signon.FactorPrompt != "" {
			attrs["mfa_prompt"] = strings.ToUpper(a.Signon.FactorPrompt)
		}
		if a.Signon.FactorLife > 0 {
			attrs["mfa_lifetime_minutes"] = strconv.Itoa(a.Signon.FactorLife)
		}
		if a.Signon.Session.MaxLifetime > 0 {
			attrs["session_max_lifetime_minutes"] = strconv.Itoa(a.Signon.Session.MaxLifetime)
		}
		if a.Signon.Session.Idle > 0 {
			attrs["session_idle_minutes"] = strconv.Itoa(a.Signon.Session.Idle)
		}
		attrs["session_persistent"] = boolString(a.Signon.Session.UsePersistent)
	}
	if a.AppSignOn.Access != "" {
		attrs["access"] = strings.ToUpper(a.AppSignOn.Access)
	}
}

func policyRuleConditionsAttributes(raw json.RawMessage, attrs map[string]string) {
	oktaasset.AddPolicyRuleConditionAttributes(raw, attrs)
}

func policyRuleURN(settings settings, policy policyRecord, rule policyRuleRecord) string {
	return fmt.Sprintf("urn:cerebro:%s:policy_rule:%s:%s", settings.domain, policy.ID, rule.ID)
}
