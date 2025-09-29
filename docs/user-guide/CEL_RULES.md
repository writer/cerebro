# 📝 CEL Rules Tutorial

Complete guide to writing security rules using Common Expression Language (CEL) in Cerebro.

## 🎯 What is CEL?

Common Expression Language (CEL) is a fast, portable, and safe way to evaluate expressions. Cerebro uses CEL to define security rules that can be evaluated against your infrastructure configuration data.

**Key Benefits:**
- **Fast**: Compiled expressions with microsecond evaluation times
- **Safe**: Sandboxed execution with no side effects
- **Portable**: Same rules work across different environments
- **Expressive**: Rich syntax for complex security logic

## 🏗️ Rule Structure

Every Cerebro security rule has this structure:

```python
{
    "name": "Human-readable rule name",
    "description": "Detailed explanation of what this rule detects",
    "provider": ["aws", "github"],  # Which providers this rule applies to
    "resource_types": ["aws.s3.bucket", "github.repo"],  # Specific resource types
    "expression": "CEL expression here",
    "severity": "high",  # critical, high, medium, low, info
    "cis": ["2.1.1"],  # CIS control mappings
    "nist_800_53": ["SC-28"],  # NIST control mappings
    "remediation": "How to fix this issue"
}
```

## 🔍 Available Context

When your CEL expression is evaluated, you have access to:

### `resource` Object
```python
resource.external_id      # "acme-corp/sensitive-repo"
resource.name            # "sensitive-repo"  
resource.resource_type   # "github.repo"
resource.provider        # "github"
```

### `config` Object
```python
# GitHub repository example
config.visibility        # "public" or "private"
config.archived         # true/false
config.default_branch   # "main"
config.topics           # ["security", "production"]

# AWS S3 bucket example  
config.versioning.enabled    # true/false
config.encryption.enabled    # true/false
config.public_read_access    # true/false
config.policy               # Full bucket policy (JSON)
```

### `principal` Object (when available)
```python
principal.external_id    # "john.doe@company.com"
principal.email         # "john.doe@company.com" 
principal.principal_type # "user", "service_account", "group"
principal.is_human      # true/false
```

### `tags` and `metadata`
```python
tags.Environment        # "production"
tags.Owner             # "security-team"
metadata.created_at    # ISO timestamp
metadata.last_modified # ISO timestamp
```

## ✨ Basic Examples

### 1. Public S3 Bucket Detection

```cel
resource.resource_type == 'aws.s3.bucket' && 
config.public_read_access == true
```

**What it does:** Finds S3 buckets that allow public read access

### 2. GitHub Repository Without Branch Protection

```cel
resource.resource_type == 'github.repo' && 
config.visibility == 'public' && 
!has(config.branch_protection) || 
config.branch_protection.enabled == false
```

**What it does:** Finds public GitHub repositories without branch protection enabled

### 3. Inactive Users with Admin Access

```cel
principal.principal_type == 'user' && 
principal.is_human == true &&
config.last_login < timestamp('2024-01-01T00:00:00Z') &&
config.admin_roles.size() > 0
```

**What it does:** Finds human users who haven't logged in since 2024 but have admin roles

## 🛡️ Security Rule Patterns

### Resource Configuration Rules

**Unencrypted Storage Detection:**
```cel
resource.resource_type in ['aws.s3.bucket', 'aws.ebs.volume'] &&
!has(config.encryption) || config.encryption.enabled == false
```

**Default Passwords Detection:**
```cel
resource.resource_type == 'aws.rds.instance' &&
config.master_username == 'admin' &&
!config.password_changed_from_default
```

**Overly Permissive Security Groups:**
```cel
resource.resource_type == 'aws.security_group' &&
config.rules.exists(rule, rule.cidr_blocks.exists(cidr, cidr == '0.0.0.0/0')) &&
config.rules.exists(rule, rule.to_port == 22 || rule.to_port == 3389)
```

### Identity and Access Rules

**Users Without MFA:**
```cel
principal.principal_type == 'user' &&
principal.is_human == true &&
(!has(config.mfa_enabled) || config.mfa_enabled == false)
```

**Service Accounts with Human-like Names:**
```cel
principal.principal_type == 'service_account' &&
principal.external_id.matches(r'^[A-Z][a-z]+\s[A-Z][a-z]+$')
```

**Excessive Permissions:**
```cel
principal.principal_type == 'user' &&
config.permissions.size() > 100 ||
config.permissions.exists(perm, perm == '*:*:*')
```

### GitHub Security Rules

**Secrets in Public Repositories:**
```cel
resource.resource_type == 'github.repo' &&
config.visibility == 'public' &&
has(config.secrets_detected) && config.secrets_detected == true
```

**Missing Required Status Checks:**
```cel
resource.resource_type == 'github.repo' &&
config.topics.exists(topic, topic == 'production') &&
(!has(config.branch_protection.required_status_checks) || 
 config.branch_protection.required_status_checks.size() == 0)
```

**Archived Repository with Secrets:**
```cel
resource.resource_type == 'github.repo' &&
config.archived == true &&
has(config.secret_scanning_alerts) && 
config.secret_scanning_alerts.size() > 0
```

## 🔄 Advanced CEL Features

### List Operations

```cel
# Check if any security group rule allows SSH from anywhere
config.security_group_rules.exists(rule, 
  rule.protocol == 'tcp' && 
  rule.from_port <= 22 && 
  rule.to_port >= 22 && 
  rule.cidr_blocks.exists(cidr, cidr == '0.0.0.0/0')
)

# Count high-severity vulnerabilities
config.vulnerabilities.filter(vuln, vuln.severity == 'high').size() > 5

# Check if all required topics are present  
['security', 'production', 'compliance'].all(topic, topic in config.topics)
```

### String Operations

```cel
# Check for sensitive data patterns in repo names
resource.name.matches(r'(?i).*(secret|key|password|token).*')

# Case-insensitive environment checking
config.environment.lowerAscii() in ['prod', 'production', 'live']

# Extract domain from email
principal.email.split('@')[1] == 'contractor-company.com'
```

### Date/Time Operations

```cel
# Resources created in the last 30 days
timestamp(metadata.created_at) > now - duration('720h')

# Certificates expiring soon
timestamp(config.certificate.expires_at) < now + duration('2160h')  # 90 days

# Old snapshots that should be deleted
resource.resource_type == 'aws.ebs.snapshot' &&
timestamp(metadata.created_at) < now - duration('8760h')  # 365 days
```

### Conditional Logic

```cel
# Different rules for different environments
config.environment == 'production' ? 
  (config.backup_enabled == true && config.monitoring_enabled == true) :
  (config.backup_enabled == true)

# Check encryption based on data classification
has(tags.DataClassification) ?
  (tags.DataClassification == 'confidential' ? config.encryption.enabled == true : true) :
  false  # Fail if no classification tag
```

## 🎛️ Complex Real-World Examples

### 1. Multi-Cloud IAM Policy Validation

```cel
(resource.provider == 'aws' && 
 resource.resource_type == 'aws.iam.policy' &&
 config.policy_document.Statement.exists(stmt, 
   stmt.Effect == 'Allow' && 
   stmt.Action == '*' && 
   stmt.Resource == '*'
 )
) ||
(resource.provider == 'gcp' &&
 resource.resource_type == 'gcp.iam.role' &&
 config.permissions.exists(perm, perm.endsWith('*'))
)
```

### 2. Cross-Reference Security Controls

```cel
resource.resource_type == 'aws.s3.bucket' &&
config.public_read_access == true &&
!config.cloudtrail_enabled &&
!tags.has('DataClassification') &&
principal.external_id.endsWith('@contractor.com')
```

### 3. Compliance Framework Mapping

```cel
// SOC2 CC6.1 - Logical Access Controls
resource.resource_type in ['aws.iam.user', 'okta.user', 'github.user'] &&
principal.is_human == true &&
(!has(config.mfa_enabled) || config.mfa_enabled == false) &&
config.last_login > now - duration('2160h')  // Active in last 90 days
```

## 🧪 Testing Your Rules

### 1. Rule Compilation Test

```python
from cerebro.rules.engine import RuleEngine

rule_expression = """
resource.resource_type == 'aws.s3.bucket' && 
config.public_read_access == true
"""

engine = RuleEngine()
compiled_rule = engine.compile(rule_expression)
print(f"Rule compiled successfully: {compiled_rule is not None}")
```

### 2. Sample Data Testing

```python
# Test with sample resource
test_resource = {
    'external_id': 'my-test-bucket',
    'resource_type': 'aws.s3.bucket',
    'provider': 'aws'
}

test_config = {
    'public_read_access': True,
    'versioning': {'enabled': False}
}

result = engine.evaluate(compiled_rule, {
    'resource': test_resource,
    'config': test_config
})

print(f"Rule evaluation result: {result}")  # Should be True
```

### 3. API Testing

```bash
# Test rule compilation via API
curl -X POST http://localhost:8000/api/v1/rules/test \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "expression": "resource.resource_type == '\''aws.s3.bucket'\'' && config.public_read_access == true"
  }'
```

## 📚 Rule Library Organization

### File Structure
```
src/cerebro/rules/library/
├── aws/
│   ├── s3_security.py
│   ├── iam_policies.py  
│   └── ec2_security.py
├── github/
│   ├── repository_security.py
│   └── organization_policies.py
└── cross_provider/
    ├── identity_correlation.py
    └── compliance_frameworks.py
```

### Rule Registration

```python
from cerebro.rules.registry import register_rule

@register_rule
def s3_public_bucket_rule():
    return {
        "name": "S3 Bucket Public Access",
        "description": "Detects S3 buckets with public read access",
        "provider": ["aws"],
        "resource_types": ["aws.s3.bucket"],
        "expression": """
            resource.resource_type == 'aws.s3.bucket' && 
            config.public_read_access == true
        """,
        "severity": "high",
        "cis": ["2.3.1"],
        "remediation": "Disable public access using AWS S3 Block Public Access settings"
    }
```

## 🚀 Best Practices

### Rule Writing
1. **Start Simple**: Begin with basic conditions, add complexity gradually
2. **Test Thoroughly**: Use sample data to validate rule logic
3. **Document Intent**: Clear descriptions help with maintenance
4. **Use Type Checking**: Leverage `has()` to check for field existence
5. **Performance**: Prefer simple comparisons over complex regex when possible

### Security Considerations
1. **Avoid Secrets**: Never hardcode credentials or sensitive data in rules
2. **Validate Inputs**: Check for required fields before accessing them
3. **Least Privilege**: Rules should only access necessary data
4. **Audit Trail**: All rule evaluations are logged for compliance

### Maintenance
1. **Version Control**: Track rule changes with detailed commit messages
2. **Testing**: Maintain test cases for each rule
3. **Framework Mapping**: Keep compliance mappings up to date
4. **Performance Monitoring**: Monitor rule execution times

This tutorial provides the foundation for writing effective security rules in Cerebro using CEL expressions.
