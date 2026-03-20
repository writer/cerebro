package graph

import (
	"fmt"
	"strings"
	"time"
)

// OrganizationalPolicyTemplate captures a reusable starter policy mapped to
// one or more compliance frameworks.
type OrganizationalPolicyTemplate struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Summary           string   `json:"summary,omitempty"`
	Content           string   `json:"content,omitempty"`
	ReviewCycleDays   int      `json:"review_cycle_days,omitempty"`
	FrameworkMappings []string `json:"framework_mappings,omitempty"`
}

// OrganizationalPolicyTemplateWriteOptions supplies caller-owned fields needed
// to turn a template into a concrete policy write request.
type OrganizationalPolicyTemplateWriteOptions struct {
	ID                    string         `json:"id,omitempty"`
	PolicyVersion         string         `json:"policy_version"`
	OwnerID               string         `json:"owner_id,omitempty"`
	Summary               string         `json:"summary,omitempty"`
	Content               string         `json:"content,omitempty"`
	ReviewCycleDays       int            `json:"review_cycle_days,omitempty"`
	FrameworkMappings     []string       `json:"framework_mappings,omitempty"`
	RequiredDepartmentIDs []string       `json:"required_department_ids,omitempty"`
	RequiredPersonIDs     []string       `json:"required_person_ids,omitempty"`
	SourceSystem          string         `json:"source_system,omitempty"`
	SourceEventID         string         `json:"source_event_id,omitempty"`
	ObservedAt            time.Time      `json:"observed_at,omitempty"`
	ValidFrom             time.Time      `json:"valid_from,omitempty"`
	ValidTo               *time.Time     `json:"valid_to,omitempty"`
	RecordedAt            time.Time      `json:"recorded_at,omitempty"`
	TransactionFrom       time.Time      `json:"transaction_from,omitempty"`
	TransactionTo         *time.Time     `json:"transaction_to,omitempty"`
	Confidence            float64        `json:"confidence,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

var organizationalPolicyTemplateCatalog = []OrganizationalPolicyTemplate{
	{
		ID:              "information-security-policy",
		Title:           "Information Security Policy",
		Summary:         "Defines the baseline security responsibilities, governance model, and annual review cadence for the organization.",
		Content:         "Purpose: define the organization's security program and baseline responsibilities.\n\nPolicy statements:\n- Security roles and accountability are assigned and reviewed at least annually.\n- Security requirements apply to employees, contractors, and third parties handling company systems or data.\n- Exceptions require documented approval, an expiry date, and compensating controls.\n- The policy is reviewed after major business or regulatory change.",
		ReviewCycleDays: 365,
		FrameworkMappings: []string{
			"iso27001:a.5.1",
			"iso27001:a.5.2",
		},
	},
	{
		ID:              "acceptable-use-policy",
		Title:           "Acceptable Use Policy",
		Summary:         "Sets the rules for how workforce members use company systems, identities, devices, and data.",
		Content:         "Policy statements:\n- Company systems are used only for approved business purposes.\n- Credentials, tokens, and devices must not be shared.\n- Sensitive data must be handled only in approved systems and storage locations.\n- Security events, phishing, and policy violations must be reported immediately.",
		ReviewCycleDays: 365,
		FrameworkMappings: []string{
			"soc2:cc6.1",
			"soc2:cc6.2",
		},
	},
	{
		ID:              "incident-response-plan",
		Title:           "Incident Response Plan",
		Summary:         "Defines incident classification, response ownership, escalation, evidence handling, and post-incident review.",
		Content:         "Policy statements:\n- Incidents are triaged by severity with documented response owners.\n- Evidence is preserved with timestamps and chain-of-custody notes.\n- Customer, executive, legal, and regulator notifications follow defined escalation criteria.\n- Every material incident receives a post-incident review with tracked corrective actions.",
		ReviewCycleDays: 180,
		FrameworkMappings: []string{
			"hipaa:164.308(a)(6)(i)",
			"iso27001:a.5.24",
			"pci-dss:12.10.1",
			"soc2:cc7.4",
		},
	},
	{
		ID:              "data-classification-policy",
		Title:           "Data Classification Policy",
		Summary:         "Defines how data is classified, labeled, stored, and protected based on sensitivity.",
		Content:         "Policy statements:\n- Data is classified before broad distribution or new system onboarding.\n- Restricted data requires approved encryption, access control, and retention handling.\n- Data labels travel with exports, tickets, and evidence packages where feasible.\n- Storage and transmission controls must align to the highest sensitivity present.",
		ReviewCycleDays: 365,
		FrameworkMappings: []string{
			"hipaa:164.312(a)(2)(iv)",
			"pci-dss:3.2.1",
		},
	},
	{
		ID:              "access-control-policy",
		Title:           "Access Control Policy",
		Summary:         "Defines identity lifecycle, least-privilege access, privileged access approval, and periodic review.",
		Content:         "Policy statements:\n- Access is approved by a designated owner and tied to a business role.\n- Privileged access requires stronger authentication and time-bounded approval where feasible.\n- Access is reviewed on a scheduled cadence and promptly removed after role change or separation.\n- Shared accounts are prohibited unless a documented operational exception exists.",
		ReviewCycleDays: 180,
		FrameworkMappings: []string{
			"hipaa:164.312(a)(1)",
			"iso27001:a.5.15",
			"pci-dss:7.2.1",
			"soc2:cc6.1",
		},
	},
	{
		ID:              "change-management-policy",
		Title:           "Change Management Policy",
		Summary:         "Defines review, approval, testing, and rollback expectations for production changes.",
		Content:         "Policy statements:\n- Production changes require documented review and approval before release.\n- Emergency changes are allowed only with documented justification and follow-up review.\n- Changes are tested proportionally to risk, with rollback or remediation plans captured before deployment.\n- Segregation of duties is maintained for high-risk production changes where feasible.",
		ReviewCycleDays: 180,
		FrameworkMappings: []string{
			"soc2:cc8.1",
			"soc2:cc8.2",
		},
	},
}

// OrganizationalPolicyTemplates returns the shipped policy template catalog.
func OrganizationalPolicyTemplates() []OrganizationalPolicyTemplate {
	out := make([]OrganizationalPolicyTemplate, 0, len(organizationalPolicyTemplateCatalog))
	for _, template := range organizationalPolicyTemplateCatalog {
		out = append(out, cloneOrganizationalPolicyTemplate(template))
	}
	return out
}

// OrganizationalPolicyTemplatesForFramework returns templates relevant to one
// canonical framework ID such as soc2, iso27001, hipaa, or pci-dss.
func OrganizationalPolicyTemplatesForFramework(framework string) []OrganizationalPolicyTemplate {
	framework = canonicalOrganizationalPolicyFrameworkID(framework)
	if framework == "" {
		return nil
	}
	out := make([]OrganizationalPolicyTemplate, 0, len(organizationalPolicyTemplateCatalog))
	for _, template := range organizationalPolicyTemplateCatalog {
		if !organizationalPolicyTemplateMatchesFramework(template, framework) {
			continue
		}
		out = append(out, cloneOrganizationalPolicyTemplate(template))
	}
	return out
}

// OrganizationalPolicyTemplateByID returns one shipped policy template by ID.
func OrganizationalPolicyTemplateByID(templateID string) (OrganizationalPolicyTemplate, bool) {
	templateID = strings.TrimSpace(templateID)
	for _, template := range organizationalPolicyTemplateCatalog {
		if template.ID == templateID {
			return cloneOrganizationalPolicyTemplate(template), true
		}
	}
	return OrganizationalPolicyTemplate{}, false
}

// OrganizationalPolicyWriteRequestFromTemplate builds a concrete policy write
// request from a shipped template plus caller-provided version/ownership/scope.
func OrganizationalPolicyWriteRequestFromTemplate(templateID string, opts OrganizationalPolicyTemplateWriteOptions) (OrganizationalPolicyWriteRequest, error) {
	template, ok := OrganizationalPolicyTemplateByID(templateID)
	if !ok {
		return OrganizationalPolicyWriteRequest{}, fmt.Errorf("unknown policy template: %s", strings.TrimSpace(templateID))
	}
	policyVersion := strings.TrimSpace(opts.PolicyVersion)
	if policyVersion == "" {
		return OrganizationalPolicyWriteRequest{}, fmt.Errorf("policy_version is required")
	}

	summary := firstNonEmpty(strings.TrimSpace(opts.Summary), template.Summary)
	content := firstNonEmpty(strings.TrimSpace(opts.Content), template.Content)
	reviewCycleDays := template.ReviewCycleDays
	if opts.ReviewCycleDays > 0 {
		reviewCycleDays = opts.ReviewCycleDays
	}
	frameworkMappings := uniquePolicyStrings(opts.FrameworkMappings)
	if len(frameworkMappings) == 0 {
		frameworkMappings = uniquePolicyStrings(template.FrameworkMappings)
	}

	metadata := cloneAnyMap(opts.Metadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["policy_template_id"] = template.ID

	return OrganizationalPolicyWriteRequest{
		ID:                    strings.TrimSpace(opts.ID),
		Title:                 template.Title,
		Summary:               summary,
		PolicyVersion:         policyVersion,
		Content:               content,
		OwnerID:               strings.TrimSpace(opts.OwnerID),
		ReviewCycleDays:       reviewCycleDays,
		FrameworkMappings:     frameworkMappings,
		RequiredDepartmentIDs: append([]string(nil), opts.RequiredDepartmentIDs...),
		RequiredPersonIDs:     append([]string(nil), opts.RequiredPersonIDs...),
		SourceSystem:          strings.TrimSpace(opts.SourceSystem),
		SourceEventID:         strings.TrimSpace(opts.SourceEventID),
		ObservedAt:            opts.ObservedAt,
		ValidFrom:             opts.ValidFrom,
		ValidTo:               opts.ValidTo,
		RecordedAt:            opts.RecordedAt,
		TransactionFrom:       opts.TransactionFrom,
		TransactionTo:         opts.TransactionTo,
		Confidence:            opts.Confidence,
		Metadata:              metadata,
	}, nil
}

func cloneOrganizationalPolicyTemplate(template OrganizationalPolicyTemplate) OrganizationalPolicyTemplate {
	template.FrameworkMappings = append([]string(nil), template.FrameworkMappings...)
	return template
}

func organizationalPolicyTemplateMatchesFramework(template OrganizationalPolicyTemplate, framework string) bool {
	for _, mapping := range template.FrameworkMappings {
		current := strings.TrimSpace(mapping)
		if current == "" {
			continue
		}
		current = strings.SplitN(current, ":", 2)[0]
		if canonicalOrganizationalPolicyFrameworkID(current) == framework {
			return true
		}
	}
	return false
}

func canonicalOrganizationalPolicyFrameworkID(value string) string {
	value = normalizeOrgKey(value)
	switch strings.ReplaceAll(value, "-", "") {
	case "soc2":
		return "soc2"
	case "iso27001":
		return "iso27001"
	case "hipaa":
		return "hipaa"
	case "pcidss":
		return "pci-dss"
	}
	return value
}
