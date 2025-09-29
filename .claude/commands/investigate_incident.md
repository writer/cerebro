# Investigate Incident Command

Build comprehensive incident timeline and analysis using Cerebro's temporal query capabilities.

## Usage
```
/investigate-incident <incident_id> [--window <hours>] [--providers <list>] [--deep-dive]
```

## Parameters
- `incident_id`: Cerebro incident ID (required)
- `--window`: Time window in hours before/after incident (default: 24)  
- `--providers`: Comma-separated list of providers to analyze (aws,github,gcp,azure)
- `--deep-dive`: Include detailed configuration diff analysis

## What This Command Does

1. **Timeline Construction**: Builds chronological timeline of events from audit trails
2. **Configuration Analysis**: Shows what changed before/during/after incident  
3. **Identity Correlation**: Tracks user/service account actions across providers
4. **Attack Path Mapping**: Identifies potential attack progression routes
5. **Evidence Collection**: Gathers relevant logs, configs, and artifacts
6. **Impact Assessment**: Calculates blast radius and affected resources

## Example Output

```
🔍 INCIDENT INVESTIGATION - INC-2024-001
Incident: Suspicious Admin Activity Detected
Window: 2024-01-15 12:00 - 2024-01-16 12:00 UTC
Scope: AWS, GitHub (24-hour window)

⏰ TIMELINE OF EVENTS

12:15 UTC - Initial Access
• GitHub user 'contractor-dev' authenticated via OAuth
• Source IP: 203.0.113.45 (Geolocation: Romania) 
• First time login from this location
• Action: Successful authentication with 2FA

12:18 UTC - Privilege Escalation  
• AWS IAM user 'contractor-dev' accessed via AssumeRole
• Role: arn:aws:iam::123456789:role/DevOpsAdmin
• Permissions: Full S3, EC2, IAM access
• Previous role usage: 3 weeks ago from US IP

12:22 UTC - Suspicious Activity Begins
• S3 bucket 'prod-customer-data' accessed
• Action: ListObjects, GetObject (47 files downloaded)
• Files: customer_database_backup.sql, user_credentials.csv
• Transfer size: 2.3 GB to IP 203.0.113.45

12:45 UTC - Covering Tracks
• CloudTrail logs accessed and downloaded
• IAM policy modified: CloudTrailLogAccess → AllowCloudTrailDeletion  
• Attempt to delete CloudTrail events (failed - insufficient permissions)
• EC2 instances launched in us-west-1 (unusual region for this user)

13:30 UTC - Detection & Response
• Cerebro finding F-789: Anomalous data access pattern detected
• Alert severity: CRITICAL 
• SOC team notified via Slack integration
• Automated containment: IAM role assumption blocked

🎯 ATTACK PATH ANALYSIS
1. Initial Access: Compromised contractor GitHub account
2. Lateral Movement: GitHub → AWS via OIDC trust relationship  
3. Privilege Escalation: AssumeRole to DevOpsAdmin (over-privileged)
4. Data Exfiltration: Customer database and credentials stolen
5. Anti-Forensics: Attempted log deletion and evidence cleanup

💥 IMPACT ASSESSMENT  
• **Data Compromised**: 47 customer database files (2.3 GB)
• **Accounts Affected**: 12,450 customer records with PII
• **Systems Accessed**: 3 S3 buckets, 2 RDS instances, CloudTrail
• **Blast Radius**: Full production AWS account access
• **Regulatory Impact**: GDPR/CCPA notification required

🔬 KEY EVIDENCE
• CloudTrail events: 2024-01-15-CloudTrail-suspicious-access.json
• S3 access logs: s3-access-logs-prod-customer-data-20240115.log  
• IAM policy changes: iam-policy-modifications-incident.json
• Network flow logs: vpc-flow-logs-exfiltration-203.0.113.45.csv
• GitHub audit log: github-oauth-contractor-dev-20240115.json

🛡️ CONTAINMENT ACTIONS TAKEN
• ✅ Disabled IAM user 'contractor-dev' 
• ✅ Revoked GitHub OAuth tokens for user
• ✅ Blocked source IP 203.0.113.45 at firewall
• ✅ Rotated S3 bucket credentials  
• ✅ Enabled additional CloudTrail monitoring

🔍 FORENSIC ARTIFACTS PRESERVED
• Configuration snapshots before/after incident
• Complete audit trail export (24-hour window)
• Network packet captures from affected subnets
• Memory dumps from compromised EC2 instances
• Chain of custody documentation generated

📊 ROOT CAUSE ANALYSIS
**Primary**: Over-privileged OIDC trust relationship GitHub → AWS
**Secondary**: Lack of anomaly detection for geographic access patterns  
**Tertiary**: Insufficient monitoring of bulk data downloads

🎯 REMEDIATION RECOMMENDATIONS
1. **IMMEDIATE** (0-24 hours)
   - Audit all OIDC trust relationships
   - Implement IP-based conditional access policies
   - Enable GuardDuty for anomaly detection

2. **SHORT-TERM** (1-7 days)  
   - Review and right-size all cross-service permissions
   - Implement data loss prevention (DLP) controls
   - Add geographic access alerting

3. **LONG-TERM** (1-4 weeks)
   - Zero-trust architecture assessment
   - Enhanced contractor access controls
   - Tabletop exercise for similar scenarios

💡 LESSONS LEARNED
• Contractor access patterns weren't baselined
• Cross-cloud privilege escalation paths not mapped  
• Data exfiltration thresholds too high
• Need better integration between GitHub and AWS monitoring
```

## Integration Points

- **Audit Events API**: Queries temporal event data
- **Configuration Snapshots**: Compares before/after states  
- **Identity Graph**: Correlates principals across providers
- **Attack Path Engine**: Maps potential escalation routes
- **Evidence Export**: Packages forensic data for legal teams
- **Timeline Visualization**: Generates Mermaid diagrams for incident reports
