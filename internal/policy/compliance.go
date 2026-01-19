package policy

import "strings"

// ComplianceFramework represents a compliance standard with its controls
type ComplianceFramework struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Controls    map[string]Control `json:"controls"`
}

// Control represents a specific control within a framework
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ComplianceRegistry holds all supported compliance frameworks
type ComplianceRegistry struct {
	frameworks map[string]*ComplianceFramework
}

// NewComplianceRegistry creates a new registry with built-in frameworks
func NewComplianceRegistry() *ComplianceRegistry {
	r := &ComplianceRegistry{
		frameworks: make(map[string]*ComplianceFramework),
	}
	r.loadBuiltinFrameworks()
	return r
}

// GetFramework returns a framework by ID
func (r *ComplianceRegistry) GetFramework(id string) (*ComplianceFramework, bool) {
	f, ok := r.frameworks[id]
	return f, ok
}

// FindFramework returns a framework by ID or name (case-insensitive)
func (r *ComplianceRegistry) FindFramework(idOrName string) (*ComplianceFramework, bool) {
	if idOrName == "" {
		return nil, false
	}
	if f, ok := r.frameworks[idOrName]; ok {
		return f, true
	}

	needle := normalizeFrameworkLabel(idOrName)
	for _, f := range r.frameworks {
		if normalizeFrameworkLabel(f.Name) == needle {
			return f, true
		}
		if normalizeFrameworkLabel(f.Name+" "+f.Version) == needle {
			return f, true
		}
		if normalizeFrameworkLabel(f.Name+" v"+f.Version) == needle {
			return f, true
		}
	}
	return nil, false
}

// ListFrameworks returns all registered frameworks
func (r *ComplianceRegistry) ListFrameworks() []*ComplianceFramework {
	result := make([]*ComplianceFramework, 0, len(r.frameworks))
	for _, f := range r.frameworks {
		result = append(result, f)
	}
	return result
}

// GetControlName returns the name of a control given framework and control IDs
func (r *ComplianceRegistry) GetControlName(frameworkID, controlID string) string {
	if f, ok := r.frameworks[frameworkID]; ok {
		if c, ok := f.Controls[controlID]; ok {
			return c.Name
		}
	}
	return ""
}

func (r *ComplianceRegistry) loadBuiltinFrameworks() {
	// CIS AWS Foundations Benchmark v2.0
	r.frameworks["cis-aws-2.0"] = &ComplianceFramework{
		ID:          "cis-aws-2.0",
		Name:        "CIS AWS Foundations Benchmark",
		Version:     "2.0",
		Description: "The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring security options for AWS.",
		Controls: map[string]Control{
			"1.1":   {ID: "1.1", Name: "Maintain current contact details"},
			"1.4":   {ID: "1.4", Name: "Ensure no root account access key exists"},
			"1.5":   {ID: "1.5", Name: "Ensure MFA is enabled for the root account"},
			"1.6":   {ID: "1.6", Name: "Ensure hardware MFA is enabled for the root account"},
			"1.7":   {ID: "1.7", Name: "Eliminate use of the root user for administrative and daily tasks"},
			"1.8":   {ID: "1.8", Name: "Ensure IAM password policy requires minimum length of 14 or greater"},
			"1.9":   {ID: "1.9", Name: "Ensure IAM password policy prevents password reuse"},
			"1.10":  {ID: "1.10", Name: "Ensure MFA is enabled for all IAM users that have a console password"},
			"1.11":  {ID: "1.11", Name: "Do not setup access keys during initial user setup"},
			"1.12":  {ID: "1.12", Name: "Ensure credentials unused for 45 days or greater are disabled"},
			"1.13":  {ID: "1.13", Name: "Ensure there is only one active access key available for any single IAM user"},
			"1.14":  {ID: "1.14", Name: "Ensure access keys are rotated every 90 days or less"},
			"1.15":  {ID: "1.15", Name: "Ensure IAM Users Receive Permissions Only Through Groups"},
			"1.16":  {ID: "1.16", Name: "Ensure IAM policies that allow full '*:*' administrative privileges are not attached"},
			"1.17":  {ID: "1.17", Name: "Ensure a support role has been created to manage incidents"},
			"1.20":  {ID: "1.20", Name: "Ensure that IAM Access Analyzer is enabled for all regions"},
			"2.1.1": {ID: "2.1.1", Name: "Ensure S3 Bucket Policy is set to deny HTTP requests"},
			"2.1.2": {ID: "2.1.2", Name: "Ensure MFA Delete is enabled on S3 buckets"},
			"2.1.3": {ID: "2.1.3", Name: "Ensure all data in Amazon S3 has been discovered, classified and secured when required"},
			"2.1.4": {ID: "2.1.4", Name: "Ensure that S3 Buckets are configured with 'Block public access'"},
			"2.2.1": {ID: "2.2.1", Name: "Ensure EBS Volume Encryption is Enabled in all Regions"},
			"2.3.1": {ID: "2.3.1", Name: "Ensure that encryption is enabled for RDS Instances"},
			"2.3.2": {ID: "2.3.2", Name: "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances"},
			"2.3.3": {ID: "2.3.3", Name: "Ensure that public access is not given to RDS Instance"},
			"3.1":   {ID: "3.1", Name: "Ensure CloudTrail is enabled in all regions"},
			"3.2":   {ID: "3.2", Name: "Ensure CloudTrail log file validation is enabled"},
			"3.3":   {ID: "3.3", Name: "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"},
			"3.4":   {ID: "3.4", Name: "Ensure CloudTrail trails are integrated with CloudWatch Logs"},
			"3.5":   {ID: "3.5", Name: "Ensure AWS Config is enabled in all regions"},
			"3.6":   {ID: "3.6", Name: "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"},
			"3.7":   {ID: "3.7", Name: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"},
			"4.1":   {ID: "4.1", Name: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"},
			"4.2":   {ID: "4.2", Name: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"},
			"4.3":   {ID: "4.3", Name: "Ensure the default security group of every VPC restricts all traffic"},
			"5.1":   {ID: "5.1", Name: "Ensure Network ACLs are configured to restrict public access"},
			"5.2":   {ID: "5.2", Name: "Ensure routing tables for VPC peering are least access"},
		},
	}

	// NIST SP 800-53 Revision 5
	r.frameworks["nist-800-53-r5"] = &ComplianceFramework{
		ID:          "nist-800-53-r5",
		Name:        "NIST SP 800-53",
		Version:     "Revision 5",
		Description: "Security and Privacy Controls for Information Systems and Organizations",
		Controls: map[string]Control{
			"AC-1":  {ID: "AC-1", Name: "Policy and Procedures"},
			"AC-2":  {ID: "AC-2", Name: "Account Management"},
			"AC-3":  {ID: "AC-3", Name: "Access Enforcement"},
			"AC-4":  {ID: "AC-4", Name: "Information Flow Enforcement"},
			"AC-5":  {ID: "AC-5", Name: "Separation of Duties"},
			"AC-6":  {ID: "AC-6", Name: "Least Privilege"},
			"AC-7":  {ID: "AC-7", Name: "Unsuccessful Logon Attempts"},
			"AC-17": {ID: "AC-17", Name: "Remote Access"},
			"AC-18": {ID: "AC-18", Name: "Wireless Access"},
			"AC-19": {ID: "AC-19", Name: "Access Control for Mobile Devices"},
			"AU-2":  {ID: "AU-2", Name: "Event Logging"},
			"AU-3":  {ID: "AU-3", Name: "Content of Audit Records"},
			"AU-6":  {ID: "AU-6", Name: "Audit Record Review, Analysis, and Reporting"},
			"AU-9":  {ID: "AU-9", Name: "Protection of Audit Information"},
			"AU-12": {ID: "AU-12", Name: "Audit Record Generation"},
			"CA-7":  {ID: "CA-7", Name: "Continuous Monitoring"},
			"CM-2":  {ID: "CM-2", Name: "Baseline Configuration"},
			"CM-6":  {ID: "CM-6", Name: "Configuration Settings"},
			"CM-7":  {ID: "CM-7", Name: "Least Functionality"},
			"CM-8":  {ID: "CM-8", Name: "System Component Inventory"},
			"IA-2":  {ID: "IA-2", Name: "Identification and Authentication (Organizational Users)"},
			"IA-5":  {ID: "IA-5", Name: "Authenticator Management"},
			"IR-4":  {ID: "IR-4", Name: "Incident Handling"},
			"IR-5":  {ID: "IR-5", Name: "Incident Monitoring"},
			"RA-5":  {ID: "RA-5", Name: "Vulnerability Monitoring and Scanning"},
			"SA-1":  {ID: "SA-1", Name: "Policy and Procedures"},
			"SA-3":  {ID: "SA-3", Name: "System Development Life Cycle"},
			"SC-1":  {ID: "SC-1", Name: "Policy and Procedures"},
			"SC-7":  {ID: "SC-7", Name: "Boundary Protection"},
			"SC-8":  {ID: "SC-8", Name: "Transmission Confidentiality and Integrity"},
			"SC-12": {ID: "SC-12", Name: "Cryptographic Key Establishment and Management"},
			"SC-13": {ID: "SC-13", Name: "Cryptographic Protection"},
			"SC-28": {ID: "SC-28", Name: "Protection of Information at Rest"},
			"SI-2":  {ID: "SI-2", Name: "Flaw Remediation"},
			"SI-3":  {ID: "SI-3", Name: "Malicious Code Protection"},
			"SI-4":  {ID: "SI-4", Name: "System Monitoring"},
			"SI-7":  {ID: "SI-7", Name: "Software, Firmware, and Information Integrity"},
		},
	}

	// PCI DSS v4.0.1
	r.frameworks["pci-dss-4.0.1"] = &ComplianceFramework{
		ID:          "pci-dss-4.0.1",
		Name:        "PCI DSS",
		Version:     "4.0.1",
		Description: "Payment Card Industry Data Security Standard",
		Controls: map[string]Control{
			"1.1":  {ID: "1.1", Name: "Processes and mechanisms for installing and maintaining network security controls are defined and understood"},
			"1.2":  {ID: "1.2", Name: "Network security controls (NSCs) are configured and maintained"},
			"1.3":  {ID: "1.3", Name: "Network access to and from the cardholder data environment is restricted"},
			"1.4":  {ID: "1.4", Name: "Network connections between trusted and untrusted networks are controlled"},
			"1.5":  {ID: "1.5", Name: "Risks to the CDE from computing devices are mitigated"},
			"2.1":  {ID: "2.1", Name: "Processes and mechanisms for applying secure configurations are defined and understood"},
			"2.2":  {ID: "2.2", Name: "System components are configured and managed securely"},
			"3.1":  {ID: "3.1", Name: "Processes and mechanisms for protecting stored account data are defined and understood"},
			"3.2":  {ID: "3.2", Name: "Storage of account data is kept to a minimum"},
			"3.3":  {ID: "3.3", Name: "Sensitive authentication data (SAD) is not stored after authorization"},
			"3.4":  {ID: "3.4", Name: "Access to displays of full PAN is restricted"},
			"3.5":  {ID: "3.5", Name: "Primary account number (PAN) is secured wherever it is stored"},
			"4.1":  {ID: "4.1", Name: "Processes and mechanisms for protecting cardholder data with strong cryptography are defined"},
			"4.2":  {ID: "4.2", Name: "PAN is protected with strong cryptography during transmission"},
			"5.1":  {ID: "5.1", Name: "Processes and mechanisms for protecting systems from malware are defined and understood"},
			"5.2":  {ID: "5.2", Name: "Malware (malicious software) is prevented, or detected and addressed"},
			"5.3":  {ID: "5.3", Name: "Anti-malware mechanisms and processes are active, maintained, and monitored"},
			"6.1":  {ID: "6.1", Name: "Processes and mechanisms for developing secure systems are defined and understood"},
			"6.2":  {ID: "6.2", Name: "Bespoke and custom software is developed securely"},
			"6.3":  {ID: "6.3", Name: "Security vulnerabilities are identified and addressed"},
			"6.4":  {ID: "6.4", Name: "Public-facing web applications are protected against attacks"},
			"6.5":  {ID: "6.5", Name: "Changes to all system components are managed securely"},
			"7.1":  {ID: "7.1", Name: "Processes and mechanisms for restricting access to cardholder data are defined"},
			"7.2":  {ID: "7.2", Name: "Access to system components and data is appropriately defined and assigned"},
			"7.3":  {ID: "7.3", Name: "Access to system components and data is managed via an access control system"},
			"8.1":  {ID: "8.1", Name: "Processes and mechanisms for identifying users and authenticating access are defined"},
			"8.2":  {ID: "8.2", Name: "User identification and related accounts are strictly managed throughout an account lifecycle"},
			"8.3":  {ID: "8.3", Name: "Strong authentication for users and administrators is established and managed"},
			"8.4":  {ID: "8.4", Name: "Multi-factor authentication (MFA) is implemented to secure access into the CDE"},
			"8.5":  {ID: "8.5", Name: "Multi-factor authentication (MFA) systems are configured to prevent misuse"},
			"8.6":  {ID: "8.6", Name: "Use of application and system accounts and associated authentication factors is strictly managed"},
			"10.1": {ID: "10.1", Name: "Processes and mechanisms for logging and monitoring access are defined"},
			"10.2": {ID: "10.2", Name: "Audit logs are implemented to support the detection of anomalies"},
			"10.3": {ID: "10.3", Name: "Audit logs are protected from destruction and unauthorized modifications"},
			"10.4": {ID: "10.4", Name: "Audit logs are reviewed to identify anomalies or suspicious activity"},
			"10.5": {ID: "10.5", Name: "Audit log history is retained and available for analysis"},
			"11.1": {ID: "11.1", Name: "Processes and mechanisms for regularly testing security are defined and understood"},
			"11.2": {ID: "11.2", Name: "Wireless access points are identified and monitored"},
			"11.3": {ID: "11.3", Name: "External and internal vulnerabilities are regularly identified"},
			"11.4": {ID: "11.4", Name: "External and internal penetration testing is regularly performed"},
			"11.5": {ID: "11.5", Name: "Network intrusions and unexpected file changes are detected and responded to"},
			"11.6": {ID: "11.6", Name: "Unauthorized changes on payment pages are detected and responded to"},
			"12.1": {ID: "12.1", Name: "A comprehensive information security policy is defined and understood"},
		},
	}

	// SOC 2
	r.frameworks["soc2"] = &ComplianceFramework{
		ID:          "soc2",
		Name:        "SOC 2",
		Version:     "2017",
		Description: "Service Organization Control 2 Trust Service Criteria",
		Controls: map[string]Control{
			"CC1": {ID: "CC1", Name: "Control Environment"},
			"CC2": {ID: "CC2", Name: "Communication and Information"},
			"CC3": {ID: "CC3", Name: "Risk Assessment"},
			"CC4": {ID: "CC4", Name: "Monitoring Activities"},
			"CC5": {ID: "CC5", Name: "Control Activities"},
			"CC6": {ID: "CC6", Name: "Logical and Physical Access Controls"},
			"CC7": {ID: "CC7", Name: "System Operations"},
			"CC8": {ID: "CC8", Name: "Change Management"},
			"CC9": {ID: "CC9", Name: "Risk Mitigation"},
			"A1":  {ID: "A1", Name: "Availability"},
			"PI1": {ID: "PI1", Name: "Processing Integrity"},
			"C1":  {ID: "C1", Name: "Confidentiality"},
			"P1":  {ID: "P1", Name: "Privacy"},
		},
	}

	// ISO 27001:2022
	r.frameworks["iso-27001-2022"] = &ComplianceFramework{
		ID:          "iso-27001-2022",
		Name:        "ISO/IEC 27001",
		Version:     "2022",
		Description: "Information security management systems",
		Controls: map[string]Control{
			"A.5":  {ID: "A.5", Name: "Organizational controls"},
			"A.6":  {ID: "A.6", Name: "People controls"},
			"A.7":  {ID: "A.7", Name: "Physical controls"},
			"A.8":  {ID: "A.8", Name: "Technological controls"},
			"5.1":  {ID: "5.1", Name: "Policies for information security"},
			"5.2":  {ID: "5.2", Name: "Information security roles and responsibilities"},
			"5.3":  {ID: "5.3", Name: "Segregation of duties"},
			"5.7":  {ID: "5.7", Name: "Threat intelligence"},
			"5.15": {ID: "5.15", Name: "Access control"},
			"5.16": {ID: "5.16", Name: "Identity management"},
			"5.17": {ID: "5.17", Name: "Authentication information"},
			"5.18": {ID: "5.18", Name: "Access rights"},
			"5.23": {ID: "5.23", Name: "Information security for use of cloud services"},
			"5.28": {ID: "5.28", Name: "Collection of evidence"},
			"6.1":  {ID: "6.1", Name: "Screening"},
			"6.3":  {ID: "6.3", Name: "Information security awareness, education and training"},
			"7.1":  {ID: "7.1", Name: "Physical security perimeters"},
			"8.1":  {ID: "8.1", Name: "User endpoint devices"},
			"8.2":  {ID: "8.2", Name: "Privileged access rights"},
			"8.3":  {ID: "8.3", Name: "Information access restriction"},
			"8.5":  {ID: "8.5", Name: "Secure authentication"},
			"8.7":  {ID: "8.7", Name: "Protection against malware"},
			"8.8":  {ID: "8.8", Name: "Management of technical vulnerabilities"},
			"8.9":  {ID: "8.9", Name: "Configuration management"},
			"8.12": {ID: "8.12", Name: "Data leakage prevention"},
			"8.15": {ID: "8.15", Name: "Logging"},
			"8.16": {ID: "8.16", Name: "Monitoring activities"},
			"8.20": {ID: "8.20", Name: "Networks security"},
			"8.21": {ID: "8.21", Name: "Security of network services"},
			"8.24": {ID: "8.24", Name: "Use of cryptography"},
		},
	}

	// CIS Controls v8
	r.frameworks["cis-controls-v8"] = &ComplianceFramework{
		ID:          "cis-controls-v8",
		Name:        "CIS Controls",
		Version:     "8",
		Description: "Center for Internet Security Critical Security Controls",
		Controls: map[string]Control{
			"1":  {ID: "1", Name: "Inventory and Control of Enterprise Assets"},
			"2":  {ID: "2", Name: "Inventory and Control of Software Assets"},
			"3":  {ID: "3", Name: "Data Protection"},
			"4":  {ID: "4", Name: "Secure Configuration of Enterprise Assets and Software"},
			"5":  {ID: "5", Name: "Account Management"},
			"6":  {ID: "6", Name: "Access Control Management"},
			"7":  {ID: "7", Name: "Continuous Vulnerability Management"},
			"8":  {ID: "8", Name: "Audit Log Management"},
			"9":  {ID: "9", Name: "Email and Web Browser Protections"},
			"10": {ID: "10", Name: "Malware Defenses"},
			"11": {ID: "11", Name: "Data Recovery"},
			"12": {ID: "12", Name: "Network Infrastructure Management"},
			"13": {ID: "13", Name: "Network Monitoring and Defense"},
			"14": {ID: "14", Name: "Security Awareness and Skills Training"},
			"15": {ID: "15", Name: "Service Provider Management"},
			"16": {ID: "16", Name: "Application Software Security"},
			"17": {ID: "17", Name: "Incident Response Management"},
			"18": {ID: "18", Name: "Penetration Testing"},
		},
	}
}

func normalizeFrameworkLabel(label string) string {
	cleaned := strings.ToLower(strings.TrimSpace(label))
	return strings.Join(strings.Fields(cleaned), " ")
}

// MapPolicyToFrameworks returns framework control mappings based on policy tags
func MapPolicyToFrameworks(p *Policy, registry *ComplianceRegistry) []FrameworkMapping {
	mappings := []FrameworkMapping{}

	// Check for existing framework mappings
	if len(p.Frameworks) > 0 {
		return p.Frameworks
	}

	// Auto-map based on tags
	for _, tag := range p.Tags {
		// CIS AWS mappings
		if len(tag) > 8 && tag[:8] == "cis-aws-" {
			controlID := tag[8:]
			if _, ok := registry.frameworks["cis-aws-2.0"].Controls[controlID]; ok {
				mappings = appendControl(mappings, "CIS AWS Foundations Benchmark v2.0", controlID)
			}
		}

		// CIS K8s mappings
		if len(tag) > 8 && tag[:8] == "cis-k8s-" {
			controlID := tag[8:]
			mappings = appendControl(mappings, "CIS Kubernetes Benchmark", controlID)
		}

		// CIS Controls v8 (general)
		if tag == "mfa" || tag == "authentication" {
			mappings = appendControl(mappings, "CIS Controls v8", "6")
		}
		if tag == "encryption" {
			mappings = appendControl(mappings, "CIS Controls v8", "3")
		}
		if tag == "logging" || tag == "audit" {
			mappings = appendControl(mappings, "CIS Controls v8", "8")
		}
		if tag == "network" || tag == "firewall" {
			mappings = appendControl(mappings, "CIS Controls v8", "12", "13")
		}
		if tag == "vulnerability" {
			mappings = appendControl(mappings, "CIS Controls v8", "7")
		}
		if tag == "iam" || tag == "least-privilege" {
			mappings = appendControl(mappings, "CIS Controls v8", "5", "6")
		}
	}

	// Map based on severity and resource type
	switch p.Severity {
	case "critical", "high":
		if containsAny(p.Tags, "public-access", "exposure", "internet-facing") {
			mappings = appendControl(mappings, "NIST 800-53 r5", "AC-3", "SC-7")
			mappings = appendControl(mappings, "PCI DSS v4.0.1", "1.3", "1.4")
		}
		if containsAny(p.Tags, "mfa", "authentication") {
			mappings = appendControl(mappings, "NIST 800-53 r5", "IA-2", "IA-5")
			mappings = appendControl(mappings, "PCI DSS v4.0.1", "8.3", "8.4")
		}
		if containsAny(p.Tags, "encryption") {
			mappings = appendControl(mappings, "NIST 800-53 r5", "SC-12", "SC-13", "SC-28")
			mappings = appendControl(mappings, "PCI DSS v4.0.1", "3.5", "4.2")
		}
	}

	// SOC 2 mappings
	if containsAny(p.Tags, "access", "iam", "authentication", "mfa") {
		mappings = appendControl(mappings, "SOC 2", "CC6")
	}
	if containsAny(p.Tags, "logging", "audit", "monitoring") {
		mappings = appendControl(mappings, "SOC 2", "CC4", "CC7")
	}
	if containsAny(p.Tags, "change", "deployment", "ci-cd") {
		mappings = appendControl(mappings, "SOC 2", "CC8")
	}

	return mappings
}

func appendControl(mappings []FrameworkMapping, framework string, controls ...string) []FrameworkMapping {
	for i := range mappings {
		if mappings[i].Name == framework {
			mappings[i].Controls = append(mappings[i].Controls, controls...)
			return mappings
		}
	}
	return append(mappings, FrameworkMapping{
		Name:     framework,
		Controls: controls,
	})
}

func containsAny(tags []string, check ...string) bool {
	for _, tag := range tags {
		for _, c := range check {
			if tag == c {
				return true
			}
		}
	}
	return false
}
