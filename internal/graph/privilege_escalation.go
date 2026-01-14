package graph

// PrivilegeEscalationPath represents a known IAM privilege escalation technique
type PrivilegeEscalationPath struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Category         string   `json:"category"` // self_escalation, principal_access, new_passrole, existing_passrole, credential_access
	RequiredPerms    []string `json:"required_permissions"`
	OptionalPerms    []string `json:"optional_permissions,omitempty"`
	TargetService    string   `json:"target_service"`
	MITREAttackID    string   `json:"mitre_attack_id"`
	Severity         Severity `json:"severity"`
	Exploitability   float64  `json:"exploitability"` // 0-1
	References       []string `json:"references,omitempty"`
	DetectionLogic   string   `json:"detection_logic,omitempty"`
	RemediationSteps []string `json:"remediation_steps"`
}

// PrivilegeEscalationRegistry contains all known privilege escalation paths
// Based on Rhino Security Labs research (28 methods) and Datadog pathfinding.cloud
var PrivilegeEscalationRegistry = []*PrivilegeEscalationPath{
	// Category: Self-Escalation - Modify own permissions directly
	{
		ID:             "PE001",
		Name:           "CreatePolicyVersion",
		Description:    "Create a new policy version with admin permissions and set as default",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:CreatePolicyVersion"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		References:     []string{"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"},
		RemediationSteps: []string{
			"Use AWS SCPs to deny iam:CreatePolicyVersion except for authorized roles",
			"Monitor CloudTrail for CreatePolicyVersion events",
			"Enable IAM Access Analyzer to detect policy changes",
		},
	},
	{
		ID:             "PE002",
		Name:           "SetDefaultPolicyVersion",
		Description:    "Switch to a more privileged inactive policy version",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:SetDefaultPolicyVersion"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityHigh,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Delete old policy versions that are not in use",
			"Use SCPs to restrict SetDefaultPolicyVersion",
		},
	},
	{
		ID:             "PE003",
		Name:           "AttachUserPolicy",
		Description:    "Attach an existing managed policy (e.g., AdministratorAccess) to a user",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:AttachUserPolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.95,
		RemediationSteps: []string{
			"Use permission boundaries to limit maximum permissions",
			"Restrict iam:AttachUserPolicy to specific policies via conditions",
		},
	},
	{
		ID:             "PE004",
		Name:           "AttachGroupPolicy",
		Description:    "Attach an existing managed policy to a group the attacker belongs to",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:AttachGroupPolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Use permission boundaries",
			"Restrict policy attachment to specific policy ARNs",
		},
	},
	{
		ID:             "PE005",
		Name:           "AttachRolePolicy",
		Description:    "Attach an existing managed policy to a role the attacker can assume",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:AttachRolePolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Use permission boundaries on roles",
			"Restrict which policies can be attached via IAM conditions",
		},
	},
	{
		ID:             "PE006",
		Name:           "PutUserPolicy",
		Description:    "Create an inline policy with arbitrary permissions for a user",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:PutUserPolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.95,
		RemediationSteps: []string{
			"Deny iam:PutUserPolicy via SCP",
			"Use managed policies instead of inline policies",
		},
	},
	{
		ID:             "PE007",
		Name:           "PutGroupPolicy",
		Description:    "Create an inline policy for a group the attacker belongs to",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:PutGroupPolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Deny iam:PutGroupPolicy",
			"Monitor for inline policy changes",
		},
	},
	{
		ID:             "PE008",
		Name:           "PutRolePolicy",
		Description:    "Create an inline policy for a role the attacker can assume",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:PutRolePolicy"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Deny iam:PutRolePolicy except for CI/CD roles",
			"Use permission boundaries",
		},
	},
	{
		ID:             "PE009",
		Name:           "AddUserToGroup",
		Description:    "Add self to a more privileged group",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:AddUserToGroup"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityHigh,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Restrict iam:AddUserToGroup to specific groups via conditions",
			"Monitor group membership changes",
		},
	},
	{
		ID:             "PE010",
		Name:           "UpdateAssumeRolePolicy",
		Description:    "Modify a role's trust policy to allow self to assume it",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Restrict iam:UpdateAssumeRolePolicy",
			"Monitor trust policy changes in CloudTrail",
		},
	},

	// Category: Principal Access - Gain access to other principals
	{
		ID:             "PE011",
		Name:           "CreateAccessKey",
		Description:    "Create access keys for another user",
		Category:       "principal_access",
		RequiredPerms:  []string{"iam:CreateAccessKey"},
		TargetService:  "iam",
		MITREAttackID:  "T1098.001",
		Severity:       SeverityCritical,
		Exploitability: 0.95,
		RemediationSteps: []string{
			"Use IAM conditions to restrict to self only",
			"Monitor for access key creation events",
			"Require MFA for sensitive IAM operations",
		},
	},
	{
		ID:             "PE012",
		Name:           "CreateLoginProfile",
		Description:    "Create console password for a user without one",
		Category:       "principal_access",
		RequiredPerms:  []string{"iam:CreateLoginProfile"},
		TargetService:  "iam",
		MITREAttackID:  "T1098.001",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Restrict to self via IAM conditions",
			"Monitor CreateLoginProfile events",
		},
	},
	{
		ID:             "PE013",
		Name:           "UpdateLoginProfile",
		Description:    "Change console password for an existing user",
		Category:       "principal_access",
		RequiredPerms:  []string{"iam:UpdateLoginProfile"},
		TargetService:  "iam",
		MITREAttackID:  "T1098.001",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Restrict to self via conditions",
			"Require MFA for password changes",
		},
	},

	// Category: New PassRole - Escalate via service + PassRole combinations
	{
		ID:             "PE014",
		Name:           "PassRole + EC2",
		Description:    "Create EC2 instance with a privileged instance profile",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "ec2:RunInstances"},
		TargetService:  "ec2",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityCritical,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Restrict iam:PassRole to specific roles via conditions",
			"Use IMDSv2 only",
			"Limit instance profile permissions",
		},
	},
	{
		ID:             "PE015",
		Name:           "PassRole + Lambda Create + Invoke",
		Description:    "Create Lambda with privileged role and invoke to execute",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
		TargetService:  "lambda",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Restrict iam:PassRole for Lambda",
			"Use Lambda resource-based policies",
			"Monitor Lambda creation events",
		},
	},
	{
		ID:             "PE016",
		Name:           "PassRole + Lambda Create + Cross-Account",
		Description:    "Create Lambda with privileged role and invoke cross-account",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"},
		TargetService:  "lambda",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityCritical,
		Exploitability: 0.8,
		RemediationSteps: []string{
			"Deny lambda:AddPermission for cross-account",
			"Monitor AddPermission events",
		},
	},
	{
		ID:             "PE017",
		Name:           "PassRole + Lambda + DynamoDB Trigger",
		Description:    "Create Lambda triggered by DynamoDB streams with privileged role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"},
		OptionalPerms:  []string{"dynamodb:PutItem"},
		TargetService:  "lambda",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Restrict event source mapping creation",
			"Monitor for Lambda event source mappings",
		},
	},
	{
		ID:             "PE018",
		Name:           "PassRole + Glue DevEndpoint",
		Description:    "Create Glue development endpoint with privileged role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "glue:CreateDevEndpoint"},
		TargetService:  "glue",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.75,
		RemediationSteps: []string{
			"Disable Glue dev endpoints if not needed",
			"Restrict glue:CreateDevEndpoint",
		},
	},
	{
		ID:             "PE019",
		Name:           "PassRole + CloudFormation",
		Description:    "Deploy CloudFormation stack with a privileged service role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "cloudformation:CreateStack"},
		TargetService:  "cloudformation",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityCritical,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Restrict CloudFormation role permissions",
			"Review stack templates before deployment",
		},
	},
	{
		ID:             "PE020",
		Name:           "PassRole + DataPipeline",
		Description:    "Create Data Pipeline with privileged role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"},
		TargetService:  "datapipeline",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Restrict Data Pipeline role",
			"Monitor pipeline creation",
		},
	},
	{
		ID:             "PE021",
		Name:           "PassRole + SageMaker Notebook",
		Description:    "Create SageMaker notebook instance with privileged role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"},
		TargetService:  "sagemaker",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.75,
		RemediationSteps: []string{
			"Restrict SageMaker notebook creation",
			"Limit notebook instance roles",
		},
	},
	{
		ID:             "PE022",
		Name:           "PassRole + CodeStar Project",
		Description:    "Create CodeStar project which deploys resources with service role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "codestar:CreateProject"},
		TargetService:  "codestar",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Restrict CodeStar project creation",
			"Use custom CodeStar service roles with minimal permissions",
		},
	},
	{
		ID:             "PE023",
		Name:           "PassRole + ECS Task",
		Description:    "Run ECS task with privileged task role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:PassRole", "ecs:RunTask"},
		OptionalPerms:  []string{"ecs:RegisterTaskDefinition"},
		TargetService:  "ecs",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.8,
		RemediationSteps: []string{
			"Restrict task role permissions",
			"Use task role conditions in PassRole",
		},
	},
	{
		ID:             "PE024",
		Name:           "PassRole + SSM",
		Description:    "Run SSM command on instance with instance profile",
		Category:       "new_passrole",
		RequiredPerms:  []string{"ssm:SendCommand"},
		OptionalPerms:  []string{"ssm:StartSession"},
		TargetService:  "ssm",
		MITREAttackID:  "T1059",
		Severity:       SeverityHigh,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Restrict SSM command targets",
			"Use SSM session logging",
			"Limit instance profile permissions",
		},
	},

	// Category: Existing PassRole - Modify or access existing resources
	{
		ID:             "PE025",
		Name:           "Lambda UpdateFunctionCode",
		Description:    "Modify existing Lambda function code to use its role",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"lambda:UpdateFunctionCode"},
		TargetService:  "lambda",
		MITREAttackID:  "T1525",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Use Lambda code signing",
			"Restrict UpdateFunctionCode to CI/CD only",
			"Monitor code changes",
		},
	},
	{
		ID:             "PE026",
		Name:           "Lambda UpdateFunctionConfiguration (Layer)",
		Description:    "Add malicious Lambda layer to override libraries",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"lambda:UpdateFunctionConfiguration"},
		TargetService:  "lambda",
		MITREAttackID:  "T1525",
		Severity:       SeverityHigh,
		Exploitability: 0.8,
		RemediationSteps: []string{
			"Restrict layer sources",
			"Monitor configuration changes",
		},
	},
	{
		ID:             "PE027",
		Name:           "Glue GetDevEndpoints",
		Description:    "Access existing Glue dev endpoint to get its role credentials",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"glue:GetDevEndpoints"},
		TargetService:  "glue",
		MITREAttackID:  "T1552",
		Severity:       SeverityMedium,
		Exploitability: 0.6,
		RemediationSteps: []string{
			"Restrict Glue read permissions",
			"Rotate dev endpoint credentials",
		},
	},
	{
		ID:             "PE028",
		Name:           "Glue UpdateDevEndpoint",
		Description:    "Add SSH key to existing Glue dev endpoint",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"glue:UpdateDevEndpoint"},
		TargetService:  "glue",
		MITREAttackID:  "T1098",
		Severity:       SeverityHigh,
		Exploitability: 0.75,
		RemediationSteps: []string{
			"Restrict UpdateDevEndpoint",
			"Monitor endpoint changes",
		},
	},
	{
		ID:             "PE029",
		Name:           "SageMaker PresignedURL",
		Description:    "Get presigned URL to existing SageMaker notebook",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"sagemaker:CreatePresignedNotebookInstanceUrl"},
		TargetService:  "sagemaker",
		MITREAttackID:  "T1552",
		Severity:       SeverityHigh,
		Exploitability: 0.8,
		RemediationSteps: []string{
			"Restrict presigned URL creation",
			"Use VPC-only notebooks",
		},
	},
	{
		ID:             "PE030",
		Name:           "CodeStar AssociateTeamMember",
		Description:    "Add self as owner to CodeStar project to gain attached policy",
		Category:       "existing_passrole",
		RequiredPerms:  []string{"codestar:CreateProject", "codestar:AssociateTeamMember"},
		TargetService:  "codestar",
		MITREAttackID:  "T1098",
		Severity:       SeverityMedium,
		Exploitability: 0.65,
		RemediationSteps: []string{
			"Restrict team member association",
			"Monitor project membership changes",
		},
	},

	// Category: Credential Access - Access or extract credentials
	{
		ID:             "PE031",
		Name:           "EC2 Instance Connect",
		Description:    "Push SSH key to EC2 instance to access its profile",
		Category:       "credential_access",
		RequiredPerms:  []string{"ec2-instance-connect:SendSSHPublicKey"},
		TargetService:  "ec2",
		MITREAttackID:  "T1552.005",
		Severity:       SeverityHigh,
		Exploitability: 0.8,
		RemediationSteps: []string{
			"Use IMDSv2",
			"Restrict EC2 Instance Connect",
			"Monitor SSH key pushes",
		},
	},
	{
		ID:             "PE032",
		Name:           "SSM GetParameter (Secrets)",
		Description:    "Read secrets stored in SSM Parameter Store",
		Category:       "credential_access",
		RequiredPerms:  []string{"ssm:GetParameter"},
		OptionalPerms:  []string{"ssm:GetParameters", "ssm:GetParametersByPath"},
		TargetService:  "ssm",
		MITREAttackID:  "T1552.004",
		Severity:       SeverityHigh,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Use fine-grained parameter policies",
			"Encrypt with CMK and restrict key access",
			"Monitor parameter reads",
		},
	},
	{
		ID:             "PE033",
		Name:           "Secrets Manager GetSecretValue",
		Description:    "Read secrets from Secrets Manager",
		Category:       "credential_access",
		RequiredPerms:  []string{"secretsmanager:GetSecretValue"},
		TargetService:  "secretsmanager",
		MITREAttackID:  "T1552.004",
		Severity:       SeverityCritical,
		Exploitability: 0.95,
		RemediationSteps: []string{
			"Use resource-based policies on secrets",
			"Encrypt with CMK",
			"Enable secret rotation",
			"Monitor secret reads",
		},
	},
	{
		ID:             "PE034",
		Name:           "Lambda GetFunction (Environment)",
		Description:    "Read Lambda environment variables containing secrets",
		Category:       "credential_access",
		RequiredPerms:  []string{"lambda:GetFunction"},
		TargetService:  "lambda",
		MITREAttackID:  "T1552.004",
		Severity:       SeverityHigh,
		Exploitability: 0.85,
		RemediationSteps: []string{
			"Don't store secrets in env vars",
			"Use Secrets Manager extension",
			"Encrypt env vars with CMK",
		},
	},
	{
		ID:             "PE035",
		Name:           "EC2 UserData",
		Description:    "Read EC2 instance user data containing secrets",
		Category:       "credential_access",
		RequiredPerms:  []string{"ec2:DescribeInstanceAttribute"},
		TargetService:  "ec2",
		MITREAttackID:  "T1552.004",
		Severity:       SeverityMedium,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Don't put secrets in user data",
			"Restrict DescribeInstanceAttribute",
		},
	},
	{
		ID:             "PE036",
		Name:           "CloudFormation Template",
		Description:    "Read CloudFormation templates containing secrets",
		Category:       "credential_access",
		RequiredPerms:  []string{"cloudformation:GetTemplate"},
		TargetService:  "cloudformation",
		MITREAttackID:  "T1552.004",
		Severity:       SeverityMedium,
		Exploitability: 0.65,
		RemediationSteps: []string{
			"Use dynamic references in templates",
			"Restrict GetTemplate permission",
		},
	},
	{
		ID:             "PE037",
		Name:           "STS GetSessionToken + MFA Bypass",
		Description:    "Get session token for federated user to bypass MFA",
		Category:       "credential_access",
		RequiredPerms:  []string{"sts:GetSessionToken"},
		TargetService:  "sts",
		MITREAttackID:  "T1550.001",
		Severity:       SeverityMedium,
		Exploitability: 0.5,
		RemediationSteps: []string{
			"Require MFA for all API calls",
			"Use short session durations",
		},
	},

	// Additional paths discovered through research
	{
		ID:             "PE038",
		Name:           "CreateRole + AttachPolicy",
		Description:    "Create new role with admin policy and assume it",
		Category:       "self_escalation",
		RequiredPerms:  []string{"iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"},
		TargetService:  "iam",
		MITREAttackID:  "T1098",
		Severity:       SeverityCritical,
		Exploitability: 0.9,
		RemediationSteps: []string{
			"Use permission boundaries",
			"Restrict role creation",
			"Monitor new role creation",
		},
	},
	{
		ID:             "PE039",
		Name:           "CreateInstanceProfile + AddRole",
		Description:    "Create instance profile and add existing privileged role",
		Category:       "new_passrole",
		RequiredPerms:  []string{"iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile", "ec2:RunInstances"},
		TargetService:  "ec2",
		MITREAttackID:  "T1078.004",
		Severity:       SeverityHigh,
		Exploitability: 0.75,
		RemediationSteps: []string{
			"Restrict instance profile creation",
			"Monitor profile-role associations",
		},
	},
	{
		ID:             "PE040",
		Name:           "Cognito SetUserPoolMfaConfig",
		Description:    "Disable MFA on Cognito user pool to bypass",
		Category:       "credential_access",
		RequiredPerms:  []string{"cognito-idp:SetUserPoolMfaConfig"},
		TargetService:  "cognito",
		MITREAttackID:  "T1556",
		Severity:       SeverityHigh,
		Exploitability: 0.7,
		RemediationSteps: []string{
			"Restrict Cognito admin permissions",
			"Monitor MFA configuration changes",
		},
	},
}

// GetPrivilegeEscalationByCategory returns all paths in a category
func GetPrivilegeEscalationByCategory(category string) []*PrivilegeEscalationPath {
	var results []*PrivilegeEscalationPath
	for _, path := range PrivilegeEscalationRegistry {
		if path.Category == category {
			results = append(results, path)
		}
	}
	return results
}

// GetPrivilegeEscalationByService returns all paths targeting a service
func GetPrivilegeEscalationByService(service string) []*PrivilegeEscalationPath {
	var results []*PrivilegeEscalationPath
	for _, path := range PrivilegeEscalationRegistry {
		if path.TargetService == service {
			results = append(results, path)
		}
	}
	return results
}

// DetectPrivilegeEscalationRisks checks if a principal has permissions enabling any escalation path
func DetectPrivilegeEscalationRisks(g *Graph, principalID string) []*PrivilegeEscalationRisk {
	node, ok := g.GetNode(principalID)
	if !ok || !node.IsIdentity() {
		return nil
	}

	permissions := getNodePermissions(node)
	var risks []*PrivilegeEscalationRisk

	for _, path := range PrivilegeEscalationRegistry {
		if hasAllPermissions(permissions, path.RequiredPerms) {
			risk := &PrivilegeEscalationRisk{
				Principal:      node,
				EscalationPath: path,
				MatchedPerms:   path.RequiredPerms,
				RiskScore:      path.Exploitability * severityToScore(path.Severity),
			}

			// Check optional perms for additional context
			for _, opt := range path.OptionalPerms {
				if containsPermission(permissions, opt) {
					risk.OptionalPermsPresent = append(risk.OptionalPermsPresent, opt)
				}
			}

			risks = append(risks, risk)
		}
	}

	return risks
}

// PrivilegeEscalationRisk represents a detected escalation capability
type PrivilegeEscalationRisk struct {
	Principal            *Node                    `json:"principal"`
	EscalationPath       *PrivilegeEscalationPath `json:"escalation_path"`
	MatchedPerms         []string                 `json:"matched_permissions"`
	OptionalPermsPresent []string                 `json:"optional_permissions_present,omitempty"`
	RiskScore            float64                  `json:"risk_score"`
}

func hasAllPermissions(perms, required []string) bool {
	for _, req := range required {
		if !containsPermission(perms, req) {
			return false
		}
	}
	return true
}

func severityToScore(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 1.0
	case SeverityHigh:
		return 0.8
	case SeverityMedium:
		return 0.5
	case SeverityLow:
		return 0.2
	default:
		return 0.5
	}
}
