# Triage Findings Command

Analyze and triage security findings in Cerebro, providing prioritization and remediation guidance.

## Usage
```
/triage-findings [--org <org_name>] [--severity <level>] [--limit <number>] [--provider <provider>]
```

## Parameters
- `--org`: Organization name (required if multiple orgs)  
- `--severity`: Filter by severity (critical, high, medium, low)
- `--limit`: Number of findings to analyze (default: 10)
- `--provider`: Filter by provider (aws, github, gcp, azure)

## What This Command Does

1. **Retrieves Recent Findings**: Queries the most recent security findings based on filters
2. **Risk Assessment**: Analyzes each finding for business impact and exploitability  
3. **Clustering**: Groups similar findings to reduce alert fatigue
4. **Prioritization**: Ranks findings by risk score and urgency
5. **Recommendations**: Provides specific remediation steps and timelines
6. **Compliance Mapping**: Maps findings to relevant CIS/NIST/CWE controls

## Example Output

```
🔍 FINDING TRIAGE REPORT - Acme Corp
Generated: 2024-01-15 14:30:00 UTC

📊 SUMMARY
• 15 findings analyzed 
• 3 critical, 5 high, 4 medium, 3 low
• 4 distinct issue clusters identified
• Est. remediation time: 8-12 hours

🚨 TOP PRIORITY FINDINGS

1. [CRITICAL] AWS IAM User with Admin Access + Hardcoded Keys
   • Finding ID: F-abc123
   • Risk Score: 95/100  
   • Blast Radius: Full AWS account access
   • Action: Disable access keys immediately, rotate credentials
   • Timeline: 15 minutes
   • CIS Mapping: CIS AWS 1.4, 1.14

2. [HIGH] GitHub Repository Secrets Exposed in Logs  
   • Finding ID: F-def456
   • Risk Score: 82/100
   • Blast Radius: CI/CD pipeline compromise
   • Action: Rotate secrets, audit access logs 
   • Timeline: 1 hour
   • CWE Mapping: CWE-532 (Information Exposure)

🔗 CLUSTERED ISSUES
• S3 Bucket Misconfigurations (5 findings) - Est. 2 hours
• Stale GitHub Personal Access Tokens (3 findings) - Est. 30 minutes  
• Excessive GCP IAM Permissions (4 findings) - Est. 3 hours

💡 RECOMMENDATIONS  
1. Implement emergency response playbook for admin key exposure
2. Add pre-commit hooks to prevent secret commits
3. Schedule quarterly access reviews for cloud permissions
4. Enable CloudTrail/audit logging for all critical resources

📋 NEXT STEPS
• Create incident for critical finding F-abc123
• Batch remediation for S3 bucket cluster  
• Update security policies to prevent similar issues
```

## Integration Points

- **Findings API**: Retrieves finding data with metadata
- **CEL Rules**: Applies custom risk scoring rules  
- **Provider APIs**: Gathers additional context about resources
- **Compliance DB**: Maps findings to framework controls
- **Incident API**: Can automatically create incidents for critical findings
