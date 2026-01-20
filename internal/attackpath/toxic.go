package attackpath

import (
	"context"
	"fmt"
	"strings"
)

// ToxicCombination represents a dangerous combination of risk factors on a resource
type ToxicCombination struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     RiskLevel    `json:"severity"`
	ResourceID   string       `json:"resource_id"`
	ResourceName string       `json:"resource_name"`
	ResourceType string       `json:"resource_type"`
	Provider     string       `json:"provider"`
	Region       string       `json:"region,omitempty"`
	RiskFactors  []RiskFactor `json:"risk_factors"`
	Remediation  string       `json:"remediation"`
	MitreAttack  []string     `json:"mitre_attack,omitempty"`
	ControlID    string       `json:"control_id,omitempty"`
}

// RiskFactor represents a single risk attribute
type RiskFactor struct {
	Type        RiskFactorType `json:"type"`
	Description string         `json:"description"`
	Evidence    string         `json:"evidence,omitempty"`
	Severity    RiskLevel      `json:"severity"`
}

type RiskFactorType string

const (
	RiskFactorNetworkExposed      RiskFactorType = "NETWORK_EXPOSED"
	RiskFactorPublicAccess        RiskFactorType = "PUBLIC_ACCESS"
	RiskFactorHighPrivilege       RiskFactorType = "HIGH_PRIVILEGE"
	RiskFactorDataAccess          RiskFactorType = "DATA_ACCESS"
	RiskFactorSensitiveData       RiskFactorType = "SENSITIVE_DATA"
	RiskFactorVulnerable          RiskFactorType = "VULNERABLE"
	RiskFactorSecretsExposed      RiskFactorType = "SECRETS_EXPOSED"
	RiskFactorNoAuth              RiskFactorType = "NO_AUTHENTICATION"
	RiskFactorNoEncryption        RiskFactorType = "NO_ENCRYPTION"
	RiskFactorNoLogging           RiskFactorType = "NO_LOGGING"
	RiskFactorPrivilegedContainer RiskFactorType = "PRIVILEGED_CONTAINER"
	RiskFactorRootUser            RiskFactorType = "ROOT_USER"
	RiskFactorInactive            RiskFactorType = "INACTIVE_PRINCIPAL"
	RiskFactorUnrotatedKeys       RiskFactorType = "UNROTATED_KEYS"
	RiskFactorExternalRegistry    RiskFactorType = "EXTERNAL_REGISTRY"
)

// ToxicPattern defines a pattern of risk factors that creates a toxic combination
type ToxicPattern struct {
	ID                 string            `json:"id"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	RequiredFactors    []RiskFactorType  `json:"required_factors"`
	OptionalFactors    []RiskFactorType  `json:"optional_factors,omitempty"`
	MinFactors         int               `json:"min_factors"` // minimum total factors needed
	BaseSeverity       RiskLevel         `json:"base_severity"`
	SeverityEscalation map[int]RiskLevel `json:"severity_escalation,omitempty"` // factor count -> severity
	Remediation        string            `json:"remediation"`
	MitreAttack        []string          `json:"mitre_attack,omitempty"`
	ControlID          string            `json:"control_id,omitempty"`
	AppliesTo          []string          `json:"applies_to,omitempty"` // resource types
}

// ToxicCombinationDetector detects toxic combinations of risk factors
type ToxicCombinationDetector struct {
	patterns []ToxicPattern
}

// NewToxicCombinationDetector creates a detector with default Wiz-like patterns
func NewToxicCombinationDetector() *ToxicCombinationDetector {
	return &ToxicCombinationDetector{
		patterns: DefaultToxicPatterns(),
	}
}

// DefaultToxicPatterns returns patterns based on Wiz's toxic combination detection
func DefaultToxicPatterns() []ToxicPattern {
	return []ToxicPattern{
		{
			ID:          "internet-facing-vuln-data-access",
			Title:       "Internet-facing %s with initial access vulnerabilities and data access to sensitive data",
			Description: "This %s is exposed to the public Internet with high exposure level, has a role with access to sensitive data, and has a critical/high severity initial access vulnerability.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorVulnerable,
				RiskFactorDataAccess,
			},
			BaseSeverity: RiskCritical,
			Remediation: `### Limit external exposure
* Restrict access to resources that do not need to be accessible from the internet.
* Ensure that exposed ports allow only encrypted communications.

### Patch vulnerabilities
* Update to the latest patched version of vulnerable software.
* If patching is not immediately possible, implement compensating controls.

### Restrict data access
* Review and minimize data access permissions using least privilege principle.`,
			MitreAttack: []string{"T1190", "T1530"},
			ControlID:   "wc-id-1211",
		},
		{
			ID:          "public-serverless-high-priv-no-auth",
			Title:       "Publicly exposed %s with high privileges can be invoked by unauthenticated users",
			Description: "This %s is exposed to the public internet, has high privileges and authentication disabled, meaning that any unauthenticated user can invoke it.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorHighPrivilege,
				RiskFactorNoAuth,
			},
			BaseSeverity: RiskHigh,
			Remediation: `### Limit external exposure
* Restrict access to resources that do not need to be accessible from the internet.

### Protect highly privileged principals
* Use the "least privilege" principle when assigning permissions.
* Remove unnecessary high-privilege access.

### Enable authentication
* Require authentication for all public-facing services.
* Use IAM or identity-aware proxy for access control.`,
			MitreAttack: []string{"T1190", "T1078"},
			ControlID:   "wc-id-1234",
		},
		{
			ID:          "container-cleartext-keys-high-priv",
			Title:       "Container image with cleartext cloud keys granting high privileges",
			Description: "This container image contains cloud keys in cleartext that permit a service account with high privileges. High permissions allow access to data or the ability to delete resources and disrupt workflows.",
			RequiredFactors: []RiskFactorType{
				RiskFactorSecretsExposed,
				RiskFactorHighPrivilege,
			},
			BaseSeverity: RiskMedium,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskHigh, // if 3+ factors
			},
			Remediation: `### Ensure secure use of secrets
* Manage all cloud keys using approved secret management solutions.
* Use AWS Secrets Manager, Parameter Store, or workload identity federation.
* Remove cleartext keys from container images.

### Restrict privileges
* Review and minimize permissions assigned to the cloud key.
* Use separate keys for different permission levels.`,
			MitreAttack: []string{"T1552.001", "T1078"},
			ControlID:   "wc-id-5678",
			AppliesTo:   []string{"container", "deployment", "task_definition"},
		},
		{
			ID:          "public-vm-high-priv-data",
			Title:       "Publicly exposed %s with data access to sensitive data",
			Description: "This %s is exposed to the public internet and has a role with access to sensitive data. An attacker who compromises this resource could access sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorDataAccess,
			},
			OptionalFactors: []RiskFactorType{
				RiskFactorHighPrivilege,
				RiskFactorVulnerable,
			},
			BaseSeverity: RiskMedium,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskHigh,
				4: RiskCritical,
			},
			Remediation: `### Limit external exposure
* Move resources behind a load balancer or bastion host.
* Use VPC private subnets where possible.

### Restrict data access
* Apply least privilege to data access permissions.
* Use separate service accounts for public-facing workloads.`,
			MitreAttack: []string{"T1190", "T1530"},
		},
		{
			ID:          "public-bucket-sensitive-data",
			Title:       "Publicly readable bucket contains sensitive data",
			Description: "This storage bucket allows public read access and contains sensitive data. Anyone on the internet can access the sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorPublicAccess,
				RiskFactorSensitiveData,
			},
			BaseSeverity: RiskCritical,
			Remediation: `### Remove public access
* Disable public access on the bucket immediately.
* Enable Block Public Access settings.

### Review bucket contents
* Identify and classify sensitive data.
* Consider encryption and access logging.`,
			MitreAttack: []string{"T1530"},
			AppliesTo:   []string{"bucket", "s3", "storage"},
		},
		{
			ID:          "data-resource-excessive-access",
			Title:       "Data resource with sensitive data has excessive access permissions",
			Description: "This data resource contains sensitive data and has excessive access permissions, allowing more principals than necessary to access sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorSensitiveData,
				RiskFactorHighPrivilege,
			},
			BaseSeverity: RiskMedium,
			Remediation: `### Restrict access permissions
* Review and remove excessive permissions.
* Implement least privilege access.
* Use resource-based policies to limit access.`,
			MitreAttack: []string{"T1530"},
		},
		{
			ID:          "privileged-inactive-keys",
			Title:       "Admin user/service account with active access keys unrotated in the past year",
			Description: "This admin account has active access keys that have not been rotated in over a year, increasing the risk of credential compromise.",
			RequiredFactors: []RiskFactorType{
				RiskFactorHighPrivilege,
				RiskFactorUnrotatedKeys,
			},
			OptionalFactors: []RiskFactorType{
				RiskFactorInactive,
			},
			BaseSeverity: RiskMedium,
			Remediation: `### Rotate access keys
* Rotate all access keys that are over 90 days old.
* Implement automated key rotation.

### Review account necessity
* Disable inactive admin accounts.
* Remove unnecessary admin privileges.`,
			MitreAttack: []string{"T1078.004"},
		},
		{
			ID:          "ecs-task-privileged-exposed",
			Title:       "ECS task with privileged container exposed to network",
			Description: "This ECS task runs a privileged container and is exposed to network access, enabling container escape and lateral movement.",
			RequiredFactors: []RiskFactorType{
				RiskFactorPrivilegedContainer,
				RiskFactorNetworkExposed,
			},
			BaseSeverity: RiskHigh,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskCritical,
			},
			Remediation: `### Remove privileged mode
* Remove the privileged flag from container definitions.
* Use specific Linux capabilities instead.

### Restrict network access
* Use security groups to limit inbound access.
* Place tasks in private subnets where possible.`,
			MitreAttack: []string{"T1611", "T1021"},
			AppliesTo:   []string{"task_definition", "ecs", "container"},
		},
	}
}

// ResourceRiskProfile contains the risk factors for a resource
type ResourceRiskProfile struct {
	ResourceID   string
	ResourceName string
	ResourceType string
	Provider     string
	Region       string
	RiskFactors  []RiskFactor
	Properties   map[string]interface{}
}

// Detect finds toxic combinations in the given resource profiles
func (d *ToxicCombinationDetector) Detect(ctx context.Context, profiles []ResourceRiskProfile) []ToxicCombination {
	var combinations []ToxicCombination

	for _, profile := range profiles {
		for _, pattern := range d.patterns {
			if combo := d.matchPattern(pattern, profile); combo != nil {
				combinations = append(combinations, *combo)
			}
		}
	}

	return combinations
}

func (d *ToxicCombinationDetector) matchPattern(pattern ToxicPattern, profile ResourceRiskProfile) *ToxicCombination {
	// Check if pattern applies to this resource type
	if len(pattern.AppliesTo) > 0 {
		applies := false
		for _, t := range pattern.AppliesTo {
			if strings.Contains(strings.ToLower(profile.ResourceType), strings.ToLower(t)) {
				applies = true
				break
			}
		}
		if !applies {
			return nil
		}
	}

	// Build a set of the profile's risk factor types
	profileFactors := make(map[RiskFactorType]RiskFactor)
	for _, f := range profile.RiskFactors {
		profileFactors[f.Type] = f
	}

	// Check required factors
	matchedFactors := make([]RiskFactor, 0)
	for _, required := range pattern.RequiredFactors {
		if f, ok := profileFactors[required]; ok {
			matchedFactors = append(matchedFactors, f)
		} else {
			return nil // missing required factor
		}
	}

	// Check optional factors
	for _, optional := range pattern.OptionalFactors {
		if f, ok := profileFactors[optional]; ok {
			matchedFactors = append(matchedFactors, f)
		}
	}

	// Check minimum factor count
	if pattern.MinFactors > 0 && len(matchedFactors) < pattern.MinFactors {
		return nil
	}

	// Determine severity with escalation
	severity := pattern.BaseSeverity
	if pattern.SeverityEscalation != nil {
		for count, sev := range pattern.SeverityEscalation {
			if len(matchedFactors) >= count {
				severity = sev
			}
		}
	}

	// Build title with resource type
	resourceTypeDisplay := formatResourceType(profile.ResourceType)
	title := pattern.Title
	if strings.Contains(title, "%s") {
		title = fmt.Sprintf(title, resourceTypeDisplay)
	}

	description := pattern.Description
	if strings.Contains(description, "%s") {
		description = fmt.Sprintf(description, resourceTypeDisplay)
	}

	return &ToxicCombination{
		ID:           fmt.Sprintf("%s-%s", pattern.ID, profile.ResourceID),
		Title:        title,
		Description:  description,
		Severity:     severity,
		ResourceID:   profile.ResourceID,
		ResourceName: profile.ResourceName,
		ResourceType: profile.ResourceType,
		Provider:     profile.Provider,
		Region:       profile.Region,
		RiskFactors:  matchedFactors,
		Remediation:  pattern.Remediation,
		MitreAttack:  pattern.MitreAttack,
		ControlID:    pattern.ControlID,
	}
}

func formatResourceType(rt string) string {
	// Convert resource types to human-readable format
	rt = strings.ReplaceAll(rt, "_", " ")
	rt = strings.ReplaceAll(rt, "::", " ")

	// Common mappings
	mappings := map[string]string{
		"run revision":    "serverless",
		"task definition": "container task",
		"ec2 instance":    "VM",
		"lambda function": "serverless function",
		"ecs service":     "container service",
	}

	lower := strings.ToLower(rt)
	for pattern, replacement := range mappings {
		if strings.Contains(lower, pattern) {
			return replacement
		}
	}

	return rt
}

// BuildRiskProfile builds a risk profile from resource properties
func BuildRiskProfile(resourceID, resourceName, resourceType, provider, region string, properties map[string]interface{}) ResourceRiskProfile {
	profile := ResourceRiskProfile{
		ResourceID:   resourceID,
		ResourceName: resourceName,
		ResourceType: resourceType,
		Provider:     provider,
		Region:       region,
		RiskFactors:  make([]RiskFactor, 0),
		Properties:   properties,
	}

	// Detect risk factors from properties

	// Network exposure
	if isPublic, ok := properties["public"].(bool); ok && isPublic {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorNetworkExposed,
			Description: "Resource is publicly accessible from the internet",
			Severity:    RiskMedium,
		})
	}
	if isInternetFacing, ok := properties["internet_facing"].(bool); ok && isInternetFacing {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorNetworkExposed,
			Description: "Resource is internet-facing",
			Severity:    RiskMedium,
		})
	}

	// Public access (for storage)
	if publicAccess, ok := properties["public_access"].(bool); ok && publicAccess {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorPublicAccess,
			Description: "Resource allows public access",
			Severity:    RiskHigh,
		})
	}

	// High privileges
	if isAdmin, ok := properties["admin"].(bool); ok && isAdmin {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorHighPrivilege,
			Description: "Resource has admin privileges",
			Severity:    RiskHigh,
		})
	}
	if highPriv, ok := properties["high_privilege"].(bool); ok && highPriv {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorHighPrivilege,
			Description: "Resource has high privilege access",
			Severity:    RiskHigh,
		})
	}

	// Data access
	if hasDataAccess, ok := properties["data_access"].(bool); ok && hasDataAccess {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorDataAccess,
			Description: "Resource has access to data stores",
			Severity:    RiskMedium,
		})
	}
	if sensitiveData, ok := properties["sensitive_data"].(bool); ok && sensitiveData {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorSensitiveData,
			Description: "Resource contains or accesses sensitive data",
			Severity:    RiskHigh,
		})
	}

	// Vulnerabilities
	if vulnCount, ok := properties["vulnerability_count"].(int); ok && vulnCount > 0 {
		sev := RiskLow
		if vulnCount > 10 {
			sev = RiskHigh
		} else if vulnCount > 5 {
			sev = RiskMedium
		}
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorVulnerable,
			Description: fmt.Sprintf("Resource has %d known vulnerabilities", vulnCount),
			Severity:    sev,
		})
	}
	if criticalVuln, ok := properties["critical_vulnerability"].(bool); ok && criticalVuln {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorVulnerable,
			Description: "Resource has critical severity vulnerability",
			Severity:    RiskCritical,
		})
	}

	// Secrets
	if secretsExposed, ok := properties["secrets_in_env"].(bool); ok && secretsExposed {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorSecretsExposed,
			Description: "Resource has secrets exposed in environment variables",
			Severity:    RiskHigh,
		})
	}
	if cleartextKeys, ok := properties["cleartext_keys"].(bool); ok && cleartextKeys {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorSecretsExposed,
			Description: "Resource contains cleartext cloud keys",
			Severity:    RiskHigh,
		})
	}

	// Authentication
	if noAuth, ok := properties["authentication_disabled"].(bool); ok && noAuth {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorNoAuth,
			Description: "Resource has authentication disabled",
			Severity:    RiskHigh,
		})
	}

	// Container-specific
	if privileged, ok := properties["privileged"].(bool); ok && privileged {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorPrivilegedContainer,
			Description: "Container runs in privileged mode",
			Severity:    RiskCritical,
		})
	}
	if rootUser, ok := properties["root_user"].(bool); ok && rootUser {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorRootUser,
			Description: "Container runs as root user",
			Severity:    RiskMedium,
		})
	}

	// Key rotation
	if unrotated, ok := properties["keys_unrotated"].(bool); ok && unrotated {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorUnrotatedKeys,
			Description: "Access keys have not been rotated",
			Severity:    RiskMedium,
		})
	}

	// Logging
	if noLogging, ok := properties["logging_disabled"].(bool); ok && noLogging {
		profile.RiskFactors = append(profile.RiskFactors, RiskFactor{
			Type:        RiskFactorNoLogging,
			Description: "Resource does not have logging enabled",
			Severity:    RiskLow,
		})
	}

	return profile
}
