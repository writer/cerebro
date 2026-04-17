package connectors

import (
	"path/filepath"
	"strings"

	"github.com/writer/cerebro/internal/iacrender"
	"github.com/writer/cerebro/internal/textutil"
)

type GeneratedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Bundle struct {
	Provider ProviderID      `json:"provider"`
	Summary  string          `json:"summary"`
	Files    []GeneratedFile `json:"files"`
}

type AWSRenderOptions struct {
	RoleName      string
	PrincipalARN  string
	ExternalID    string
	ManagedTagKey string
	ManagedTagVal string
}

type GCPRenderOptions struct {
	ProjectID                  string
	ServiceAccountID           string
	CustomRoleID               string
	EnableWIF                  bool
	WorkloadIdentityPoolID     string
	WorkloadIdentityProviderID string
	WorkloadIdentityIssuerURI  string
	WorkloadIdentityAudience   string
	PrincipalSubject           string
}

type AzureRenderOptions struct {
	SubscriptionID       string
	TenantID             string
	Location             string
	PrincipalDisplayName string
	CustomRoleName       string
}

func RenderAWSBundle(opts AWSRenderOptions) (Bundle, error) {
	data := map[string]string{
		"RoleName":      textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.RoleName), "CerebroScanRole"),
		"PrincipalARN":  textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.PrincipalARN), "arn:aws:iam::<account-id>:role/CerebroControlPlane"),
		"ExternalID":    textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.ExternalID), "replace-with-customer-specific-external-id"),
		"ManagedTagKey": textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.ManagedTagKey), "CerebroManagedBy"),
		"ManagedTagVal": textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.ManagedTagVal), "cerebro"),
	}
	stackset, err := renderTemplate("aws/stackset.yaml", awsStackSetTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	parameters, err := renderJSONTemplate("aws/parameters.example.json", awsParametersTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	readme, err := renderTemplate("aws/README.md", awsReadmeTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	files := []GeneratedFile{
		{Path: filepath.ToSlash("aws/stackset.yaml"), Content: stackset},
		{Path: filepath.ToSlash("aws/parameters.example.json"), Content: parameters},
		{Path: filepath.ToSlash("aws/README.md"), Content: readme},
	}
	return Bundle{Provider: ProviderAWS, Summary: "AWS cross-account snapshot connector bundle", Files: files}, nil
}

func RenderGCPBundle(opts GCPRenderOptions) (Bundle, error) {
	data := map[string]any{
		"ProjectID":                  textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.ProjectID), "replace-with-project-id"),
		"ServiceAccountID":           textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.ServiceAccountID), "cerebro-workload-scan"),
		"CustomRoleID":               textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.CustomRoleID), "cerebroWorkloadSnapshot"),
		"EnableWIF":                  opts.EnableWIF || strings.TrimSpace(opts.WorkloadIdentityIssuerURI) != "",
		"WorkloadIdentityPoolID":     textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.WorkloadIdentityPoolID), "cerebro-workload-pool"),
		"WorkloadIdentityProviderID": textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.WorkloadIdentityProviderID), "cerebro-oidc"),
		"WorkloadIdentityIssuerURI":  textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.WorkloadIdentityIssuerURI), "https://token.actions.githubusercontent.com"),
		"WorkloadIdentityAudience":   textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.WorkloadIdentityAudience), "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/cerebro-workload-pool/providers/cerebro-oidc"),
		"PrincipalSubject":           textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.PrincipalSubject), "repo:your-org/your-repo:ref:refs/heads/main"),
	}
	mainTF, err := renderTemplate("gcp/main.tf", gcpMainTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	variablesTF, err := renderTemplate("gcp/variables.tf", gcpVariablesTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	outputsTF, err := renderTemplate("gcp/outputs.tf", gcpOutputsTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	readme, err := renderTemplate("gcp/README.md", gcpReadmeTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	files := []GeneratedFile{
		{Path: filepath.ToSlash("gcp/main.tf"), Content: mainTF},
		{Path: filepath.ToSlash("gcp/variables.tf"), Content: variablesTF},
		{Path: filepath.ToSlash("gcp/outputs.tf"), Content: outputsTF},
		{Path: filepath.ToSlash("gcp/README.md"), Content: readme},
	}
	return Bundle{Provider: ProviderGCP, Summary: "GCP snapshot connector Terraform bundle", Files: files}, nil
}

func RenderAzureBundle(opts AzureRenderOptions) (Bundle, error) {
	data := map[string]string{
		"SubscriptionID":       textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.SubscriptionID), "replace-with-subscription-id"),
		"TenantID":             textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.TenantID), "replace-with-tenant-id"),
		"Location":             textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.Location), "eastus"),
		"PrincipalDisplayName": textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.PrincipalDisplayName), "cerebro-workload-scan"),
		"CustomRoleName":       textutil.FirstNonEmptyTrimmed(strings.TrimSpace(opts.CustomRoleName), "Cerebro Snapshot Operator"),
	}
	armTemplate, err := renderJSONTemplate("azure/arm-template.json", azureARMTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	parameters, err := renderJSONTemplate("azure/parameters.example.json", azureARMParametersTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	mainTF, err := renderTemplate("azure/main.tf", azureMainTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	variablesTF, err := renderTemplate("azure/variables.tf", azureVariablesTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	outputsTF, err := renderTemplate("azure/outputs.tf", azureOutputsTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	readme, err := renderTemplate("azure/README.md", azureReadmeTemplate, data)
	if err != nil {
		return Bundle{}, err
	}
	files := []GeneratedFile{
		{Path: filepath.ToSlash("azure/arm-template.json"), Content: armTemplate},
		{Path: filepath.ToSlash("azure/parameters.example.json"), Content: parameters},
		{Path: filepath.ToSlash("azure/main.tf"), Content: mainTF},
		{Path: filepath.ToSlash("azure/variables.tf"), Content: variablesTF},
		{Path: filepath.ToSlash("azure/outputs.tf"), Content: outputsTF},
		{Path: filepath.ToSlash("azure/README.md"), Content: readme},
	}
	return Bundle{Provider: ProviderAzure, Summary: "Azure snapshot connector ARM + Terraform bundle", Files: files}, nil
}

func renderTemplate(name, src string, data any) (string, error) {
	return iacrender.RenderTemplate(name, src, data)
}

func renderJSONTemplate(name, src string, data any) (string, error) {
	return iacrender.RenderTemplate(name, src, data)
}

const awsStackSetTemplate = `AWSTemplateFormatVersion: '2010-09-09'
Description: Cerebro cross-account snapshot connector role (StackSet-safe)

Parameters:
  CerebroPrincipalArn:
    Type: String
    Default: {{yamlString .PrincipalARN}}
    Description: Control-plane principal allowed to assume the scan role.
  ExternalId:
    Type: String
    Default: {{yamlString .ExternalID}}
    NoEcho: true
  RoleName:
    Type: String
    Default: {{yamlString .RoleName}}
  ManagedTagKey:
    Type: String
    Default: {{yamlString .ManagedTagKey}}
  ManagedTagValue:
    Type: String
    Default: {{yamlString .ManagedTagVal}}

Resources:
  CerebroScanRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Description: Cerebro agentless workload snapshot connector role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref CerebroPrincipalArn
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      Policies:
        - PolicyName: CerebroSnapshotConnector
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Sid: DescribeWorkloads
                Effect: Allow
                Action:
                  - ec2:DescribeInstances
                  - ec2:DescribeVolumes
                  - ec2:DescribeSnapshots
                Resource: '*'
              - Sid: CreateTaggedSnapshotArtifacts
                Effect: Allow
                Action:
                  - ec2:CreateSnapshot
                  - ec2:CopySnapshot
                  - ec2:CreateVolume
                Resource: '*'
                Condition:
                  StringEquals:
                    {{yamlString (print "aws:RequestTag/" .ManagedTagKey)}}: {{yamlString .ManagedTagVal}}
                  ForAllValues:StringEquals:
                    aws:TagKeys:
                      - {{yamlString .ManagedTagKey}}
              - Sid: MutateTaggedArtifacts
                Effect: Allow
                Action:
                  - ec2:ModifySnapshotAttribute
                  - ec2:DeleteSnapshot
                  - ec2:AttachVolume
                  - ec2:DetachVolume
                  - ec2:DeleteVolume
                Resource: '*'
                Condition:
                  StringEquals:
                    {{yamlString (print "aws:ResourceTag/" .ManagedTagKey)}}: {{yamlString .ManagedTagVal}}
              - Sid: AllowKMSForEC2SnapshotFlows
                Effect: Allow
                Action:
                  - kms:DescribeKey
                Resource: '*'
              - Sid: AllowKMSEC2GrantAndDecryptFlows
                Effect: Allow
                Action:
                  - kms:Decrypt
                  - kms:CreateGrant
                  - kms:ReEncryptFrom
                  - kms:ReEncryptTo
                Resource: '*'
                Condition:
                  Bool:
                    kms:GrantIsForAWSResource: true
                  StringEquals:
                    kms:ViaService: !Sub ec2.${AWS::Region}.amazonaws.com

Outputs:
  RoleArn:
    Value: !GetAtt CerebroScanRole.Arn
  ManagedTag:
    Value: !Sub '${ManagedTagKey}=${ManagedTagValue}'
`

const awsParametersTemplate = `[
  {
    "ParameterKey": "CerebroPrincipalArn",
    "ParameterValue": {{jsonString .PrincipalARN}}
  },
  {
    "ParameterKey": "ExternalId",
    "ParameterValue": {{jsonString .ExternalID}}
  },
  {
    "ParameterKey": "RoleName",
    "ParameterValue": {{jsonString .RoleName}}
  }
]
`

const awsReadmeTemplate = `# AWS Connector Bundle

This StackSet bundle deploys ` + "`{{.RoleName}}`" + ` into workload accounts.

## Expected rollout

1. Update ` + "`aws/parameters.example.json`" + ` with the real Cerebro control-plane principal ARN and per-customer external ID.
2. Roll out ` + "`aws/stackset.yaml`" + ` through AWS Organizations StackSets or per-account CloudFormation.
3. Validate the target account with:

` + "```bash" + `
cerebro connector validate aws \
  --aws-profile <profile> \
  --region us-east-1 \
  --dry-run \
  --aws-volume-id vol-0123456789abcdef0 \
  --aws-snapshot-id snap-0123456789abcdef0
` + "```" + `

The live validator will always confirm STS identity and EC2 describe access. Mutation checks are skipped unless example resources are supplied.
`

const gcpMainTemplate = `terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0"
    }
  }
}

provider "google" {
  project = var.project_id
}

resource "google_service_account" "cerebro_scan" {
  account_id   = var.service_account_id
  display_name = "Cerebro workload scan"
}

resource "google_project_iam_custom_role" "cerebro_snapshot" {
  role_id     = var.custom_role_id
  title       = "Cerebro Workload Snapshot"
  description = "Read-only plus snapshot access for agentless workload inspection"
  permissions = [
    "compute.disks.createSnapshot",
    "compute.snapshots.get",
    "compute.snapshots.delete",
    "compute.snapshots.setIamPolicy",
    "compute.instances.get",
  ]
}

resource "google_project_iam_member" "cerebro_snapshot_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.cerebro_snapshot.name
  member  = "serviceAccount:${google_service_account.cerebro_scan.email}"
}

resource "google_iam_workload_identity_pool" "cerebro" {
  count                     = var.enable_wif ? 1 : 0
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "Cerebro workload pool"
}

resource "google_iam_workload_identity_pool_provider" "cerebro_oidc" {
  count                              = var.enable_wif ? 1 : 0
  workload_identity_pool_id          = google_iam_workload_identity_pool.cerebro[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "Cerebro OIDC provider"
  attribute_condition                = "assertion.sub == \"${var.principal_subject}\""
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri        = var.workload_identity_issuer_uri
    allowed_audiences = [var.workload_identity_audience]
  }
}

resource "google_service_account_iam_member" "wif_user" {
  count              = var.enable_wif ? 1 : 0
  service_account_id = google_service_account.cerebro_scan.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.cerebro[0].name}/subject/${var.principal_subject}"
}
`

const gcpVariablesTemplate = `variable "project_id" {
  type    = string
  default = {{hclString .ProjectID}}
}

variable "service_account_id" {
  type    = string
  default = {{hclString .ServiceAccountID}}
}

variable "custom_role_id" {
  type    = string
  default = {{hclString .CustomRoleID}}
}

variable "enable_wif" {
  type    = bool
  default = {{if .EnableWIF}}true{{else}}false{{end}}
}

variable "workload_identity_pool_id" {
  type    = string
  default = {{hclString .WorkloadIdentityPoolID}}
}

variable "workload_identity_provider_id" {
  type    = string
  default = {{hclString .WorkloadIdentityProviderID}}
}

variable "workload_identity_issuer_uri" {
  type    = string
  default = {{hclString .WorkloadIdentityIssuerURI}}
}

variable "workload_identity_audience" {
  type    = string
  default = {{hclString .WorkloadIdentityAudience}}
}

variable "principal_subject" {
  type    = string
  default = {{hclString .PrincipalSubject}}
}
`

const gcpOutputsTemplate = `output "service_account_email" {
  value = google_service_account.cerebro_scan.email
}

output "custom_role_name" {
  value = google_project_iam_custom_role.cerebro_snapshot.name
}

output "workload_identity_provider_name" {
  value = var.enable_wif ? google_iam_workload_identity_pool_provider.cerebro_oidc[0].name : null
}
`

const gcpReadmeTemplate = `# GCP Connector Bundle

This Terraform module provisions a service account and custom role for snapshot-driven workload inspection.

## Validation

Use the built-in IAM dry-run check after apply:

` + "```bash" + `
cerebro connector validate gcp \
  --gcp-project {{.ProjectID}} \
  --dry-run
` + "```" + `

The validator uses ` + "`projects.testIamPermissions`" + ` so it can confirm snapshot permissions without creating any compute resources.
`

const azureARMTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "principalId": {
      "type": "string"
    },
    "roleName": {
      "type": "string",
      "defaultValue": {{jsonString .CustomRoleName}}
    },
    "subscriptionId": {
      "type": "string",
      "defaultValue": {{jsonString .SubscriptionID}}
    }
  },
  "variables": {
    "customRoleGuid": "[guid(subscription().id, parameters('roleName'))]",
    "readerAssignmentGuid": "[guid(subscription().id, parameters('principalId'), 'reader')]",
    "snapshotAssignmentGuid": "[guid(subscription().id, parameters('principalId'), parameters('roleName'))]"
  },
  "resources": [
    {
      "type": "Microsoft.Authorization/roleDefinitions",
      "apiVersion": "2022-04-01",
      "name": "[variables('customRoleGuid')]",
      "properties": {
        "roleName": "[parameters('roleName')]",
        "description": "Cerebro snapshot operator",
        "type": "CustomRole",
        "assignableScopes": [
          "[subscription().id]"
        ],
        "permissions": [
          {
            "actions": [
              "Microsoft.Compute/snapshots/write",
              "Microsoft.Compute/snapshots/delete",
              "Microsoft.Compute/disks/read",
              "Microsoft.Compute/virtualMachines/read",
              "Microsoft.Resources/subscriptions/resourceGroups/read"
            ],
            "notActions": []
          }
        ]
      }
    },
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "apiVersion": "2022-04-01",
      "name": "[variables('readerAssignmentGuid')]",
      "properties": {
        "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')]",
        "principalId": "[parameters('principalId')]",
        "principalType": "ServicePrincipal"
      }
    },
    {
      "type": "Microsoft.Authorization/roleAssignments",
      "apiVersion": "2022-04-01",
      "name": "[variables('snapshotAssignmentGuid')]",
      "properties": {
        "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', variables('customRoleGuid'))]",
        "principalId": "[parameters('principalId')]",
        "principalType": "ServicePrincipal"
      },
      "dependsOn": [
        "[resourceId('Microsoft.Authorization/roleDefinitions', variables('customRoleGuid'))]"
      ]
    }
  ]
}
`

const azureARMParametersTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "principalId": {
      "value": "replace-with-principal-id"
    },
    "subscriptionId": {
      "value": {{jsonString .SubscriptionID}}
    }
  }
}
`

const azureMainTemplate = `terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.100.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

provider "azuread" {
  tenant_id = var.tenant_id
}

resource "azuread_application" "cerebro" {
  display_name = var.principal_display_name
}

resource "azuread_service_principal" "cerebro" {
  client_id = azuread_application.cerebro.client_id
}

resource "azurerm_role_definition" "snapshot_operator" {
  name        = var.custom_role_name
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Cerebro snapshot operator"

  permissions {
    actions = [
      "Microsoft.Compute/snapshots/write",
      "Microsoft.Compute/snapshots/delete",
      "Microsoft.Compute/disks/read",
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Resources/subscriptions/resourceGroups/read",
    ]
  }

  assignable_scopes = [
    "/subscriptions/${var.subscription_id}",
  ]
}

resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.cerebro.object_id
}

resource "azurerm_role_assignment" "snapshot_operator" {
  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = azurerm_role_definition.snapshot_operator.role_definition_resource_id
  principal_id       = azuread_service_principal.cerebro.object_id
}
`

const azureVariablesTemplate = `variable "subscription_id" {
  type    = string
  default = {{hclString .SubscriptionID}}
}

variable "tenant_id" {
  type    = string
  default = {{hclString .TenantID}}
}

variable "location" {
  type    = string
  default = {{hclString .Location}}
}

variable "principal_display_name" {
  type    = string
  default = {{hclString .PrincipalDisplayName}}
}

variable "custom_role_name" {
  type    = string
  default = {{hclString .CustomRoleName}}
}
`

const azureOutputsTemplate = `output "client_id" {
  value = azuread_application.cerebro.client_id
}

output "service_principal_object_id" {
  value = azuread_service_principal.cerebro.object_id
}
`

const azureReadmeTemplate = `# Azure Connector Bundle

This bundle includes:

- ` + "`azure/arm-template.json`" + ` for assigning Reader plus snapshot rights to an existing principal
- ` + "`azure/main.tf`" + ` for creating a dedicated service principal and role assignments

## Validation

` + "```bash" + `
cerebro connector validate azure \
  --azure-subscription {{.SubscriptionID}} \
  --dry-run
` + "```" + `

The validator reads effective subscription permissions and reports whether Reader plus snapshot mutation rights are present.
`
