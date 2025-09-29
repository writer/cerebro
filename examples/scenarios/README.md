# Security Scenarios for Cerebro Testing

This directory contains realistic security scenarios for testing Cerebro agents and development.

## Scenarios

### 1. Critical IAM Finding
**File:** `critical_iam_scenario.py`
- Overprivileged service accounts across AWS and GCP
- Cross-account access patterns
- Unused admin permissions
- Shadow IT discovery

### 2. Data Exfiltration Incident  
**File:** `data_exfiltration_incident.py`
- Timeline-based investigation
- Suspicious data access patterns
- Compromised user credentials
- Attack path reconstruction

### 3. Compliance Violation Investigation
**File:** `compliance_violation.py`
- PCI DSS violations in cloud infrastructure
- SOX compliance gaps
- GDPR data handling issues
- Remediation tracking

### 4. Multi-Cloud Security Review
**File:** `multi_cloud_review.py`
- Cross-provider security posture assessment
- Identity federation issues
- Resource sprawl analysis
- Cost vs security trade-offs

### 5. Attack Path Analysis
**File:** `attack_path_scenario.py`
- Lateral movement possibilities
- Privilege escalation paths
- Critical asset exposure
- Defense gap analysis

## Usage

Each scenario includes:
- Sample data generation functions
- Expected findings and alerts
- Investigation workflows
- Remediation recommendations
- Agent interaction patterns

Run individual scenarios:
```bash
python examples/scenarios/critical_iam_scenario.py
```

Or use the test data generator to populate all scenarios:
```bash
python scripts/generate_test_data.py --scenario all
```
