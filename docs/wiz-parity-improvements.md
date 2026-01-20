# Wiz Parity Improvements

## Current State vs Wiz

| Capability | Wiz | Cerebro | Gap |
|------------|-----|---------|-----|
| Resource Sync | All clouds, 200+ resource types | AWS (25), GCP (10) | Need more coverage |
| Security Graph | Full relationship mapping | Graph exists but not connected | Need to wire up |
| Attack Paths | Automatic detection | Code exists, not integrated | Need integration |
| Toxic Combos | Graph-based, context-rich | Basic pattern matching | Use graph engine |
| Real-time | Sub-minute | Point-in-time | Need streaming |
| Context | Business impact, blast radius | Just "violation" | Need enrichment |

## Priority Improvements

### Phase 1: Connect the Graph (High Impact)

**Problem**: The security graph builder exists but isn't connected to synced data.

**Solution**:
1. Fix table name case sensitivity (Snowflake uses uppercase)
2. Wire graph building into scan workflow
3. Use graph-based toxic combination detection

```go
// In scan workflow:
1. Sync resources (already done)
2. Build security graph from Snowflake data
3. Run graph-based toxic combination detection
4. Run attack path simulation
5. Enrich policy findings with graph context
```

### Phase 2: Extract Relationships

**Problem**: We sync resources but not their relationships.

**What Wiz extracts**:
- IAM role -> EC2 instance (instance profile)
- IAM role -> Lambda function (execution role)
- Security group -> EC2 instance
- VPC -> Subnet -> Instance
- S3 bucket -> IAM policy (who can access)
- Service account -> GKE pod

**Solution**: Add relationship extraction to sync:

```go
// In AWS sync, after fetching EC2 instances:
for _, instance := range instances {
    if instance.IamInstanceProfile != nil {
        relationships = append(relationships, Relationship{
            Source: instance.InstanceId,
            Target: instance.IamInstanceProfile.Arn,
            Type:   "HAS_ROLE",
        })
    }
    for _, sg := range instance.SecurityGroups {
        relationships = append(relationships, Relationship{
            Source: instance.InstanceId,
            Target: sg.GroupId,
            Type:   "MEMBER_OF",
        })
    }
}
```

### Phase 3: Blast Radius & Impact Analysis

**Problem**: Findings lack business context.

**What Wiz shows**:
- "This misconfiguration affects 15 production databases"
- "Compromising this role grants access to 3 crown jewels"
- "This vulnerability is exploitable from 2 internet entry points"

**Solution**: Add blast radius to findings:

```go
type EnrichedFinding struct {
    Finding
    BlastRadius      *BlastRadius      `json:"blast_radius"`
    AttackPaths      []*AttackPath     `json:"attack_paths"`
    AffectedAssets   []string          `json:"affected_assets"`
    BusinessImpact   string            `json:"business_impact"`
    ExploitablePath  bool              `json:"exploitable_path"`
}
```

### Phase 4: Better Detection Rules

**Current**: ~350 policies, mostly single-resource checks

**Wiz has**: 2,800+ rules including:
- Cross-resource checks (public LB -> private DB)
- Temporal checks (key not rotated in 90 days)
- Behavioral patterns (unusual access patterns)

**Solution**: Add multi-resource policies:

```cedar
// Cross-resource check
forbid (
    principal,
    action == "access",
    resource
) when {
    resource.type == "database" &&
    resource.publicly_accessible == false &&
    exists lb in context.load_balancers where {
        lb.targets.contains(resource.id) &&
        lb.scheme == "internet-facing"
    }
};
```

### Phase 5: Real-time Detection

**Current**: Point-in-time scans via CLI

**Wiz**: Continuous monitoring with CloudTrail/Activity Log streaming

**Solution**:
1. Add CloudTrail/Activity Log ingestion
2. Stream changes to graph
3. Re-evaluate affected policies on change
4. Alert on new toxic combinations

## Implementation Priorities

### Quick Wins (1-2 days each)
1. [ ] Fix graph builder table name case sensitivity
2. [ ] Add graph building to scan workflow
3. [ ] Use graph-based toxic combo detection in scan
4. [ ] Add blast radius to finding output

### Medium Effort (1 week each)
5. [ ] Extract IAM relationships during sync
6. [ ] Add network relationship extraction
7. [ ] Add cross-resource policy support
8. [ ] Add attack path summary to scan output

### Larger Efforts (2+ weeks)
9. [ ] Real-time CloudTrail ingestion
10. [ ] Full relationship graph for all resources
11. [ ] ML-based anomaly detection
12. [ ] SBOM/vulnerability correlation

## Example: What a "Wiz-like" Finding Should Look Like

**Current Cerebro Output**:
```json
{
  "id": "finding-123",
  "policy_id": "aws-s3-public-read",
  "severity": "high",
  "resource_id": "arn:aws:s3:::customer-data",
  "description": "S3 bucket allows public read access"
}
```

**Target Wiz-like Output**:
```json
{
  "id": "finding-123",
  "policy_id": "aws-s3-public-read",
  "severity": "critical",
  "resource_id": "arn:aws:s3:::customer-data",
  "description": "S3 bucket allows public read access",
  "context": {
    "contains_sensitive_data": true,
    "data_classification": "PII",
    "accessible_from": ["internet", "lambda:data-processor"],
    "business_owner": "data-team@company.com"
  },
  "blast_radius": {
    "affected_assets": 3,
    "crown_jewels_accessible": ["customer-db", "analytics-warehouse"],
    "data_exposure_gb": 15.2
  },
  "attack_paths": [
    {
      "entry_point": "internet",
      "steps": ["S3 public read", "credentials in bucket", "assume role", "RDS access"],
      "target": "customer-db",
      "exploitability": 0.9
    }
  ],
  "toxic_combination": {
    "factors": ["public_access", "sensitive_data", "no_encryption"],
    "score": 95
  },
  "remediation": {
    "priority": 1,
    "action": "Enable Block Public Access",
    "effort": "low",
    "auto_remediation_available": true
  }
}
```
