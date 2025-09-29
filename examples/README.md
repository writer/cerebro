# Cerebro Examples and Test Data

This directory contains realistic examples, test data, and agent interaction patterns for Cerebro security agents development and testing.

## Directory Structure

```
examples/
├── scenarios/              # Realistic security scenarios
│   ├── critical_iam_scenario.py
│   ├── data_exfiltration_incident.py
│   ├── compliance_violation.py
│   ├── multi_cloud_review.py
│   └── attack_path_scenario.py
├── agent_interactions/     # Sample agent conversations and workflows
│   ├── critical_iam_investigation.md
│   ├── incident_response_session.md
│   └── approval_workflows.md
└── README.md
```

## Security Scenarios

### 1. Critical IAM Finding (`critical_iam_scenario.py`)
**Scenario:** Overprivileged service accounts across multiple cloud providers

**Key Issues:**
- Service account with full admin access across AWS and GCP
- Unused high-privilege permissions for 90+ days  
- Cross-account access from development to production
- Shadow IT discovery through OAuth applications

**Learning Objectives:**
- Identity and access management risks
- Principle of least privilege violations
- Service account security
- Cross-cloud permission analysis

### 2. Data Exfiltration Incident (`data_exfiltration_incident.py`)
**Scenario:** Sophisticated data breach with timeline reconstruction

**Key Issues:**
- Compromised employee credentials via phishing
- Lateral movement across cloud accounts
- Unusual data access patterns and bulk downloads
- Shadow account creation for persistence

**Learning Objectives:**
- Incident response workflows
- Timeline-based investigation
- Lateral movement detection
- Data loss prevention

### 3. Compliance Violations (`compliance_violation.py`)  
**Scenario:** Multi-framework compliance failures

**Key Issues:**
- PCI DSS: Unencrypted credit card data storage
- GDPR: Excessive data retention without consent
- SOX: Public exposure of financial data
- HIPAA: Insufficient PHI access controls

**Learning Objectives:**
- Regulatory compliance analysis
- Cross-framework violation assessment
- Data classification and handling
- Compliance reporting and remediation

### 4. Multi-Cloud Security Review (`multi_cloud_review.py`)
**Scenario:** Comprehensive security posture across multiple providers

**Key Issues:**
- Inconsistent security policies across AWS, GCP, GitHub
- Identity federation gaps and orphaned accounts
- Cost vs security trade-offs in different environments
- Resource sprawl and unmanaged assets

**Learning Objectives:**
- Multi-cloud security assessment
- Policy standardization across providers
- Identity federation security
- Cost-effective security improvements

### 5. Attack Path Analysis (`attack_path_scenario.py`)
**Scenario:** Complete attack chain modeling and analysis

**Key Issues:**
- Initial compromise through developer workstation
- Privilege escalation via misconfigured service accounts
- Lateral movement to critical banking systems
- Data exfiltration through backup systems

**Learning Objectives:**
- Attack path modeling and analysis
- Lateral movement detection
- Critical asset protection
- Defense gap identification

## Quick Start

### Generate All Test Data
```bash
# Clean database and generate all scenarios
python scripts/generate_test_data.py --clean-first --scenario all
```

### Generate Specific Scenario
```bash
# Generate just the critical IAM scenario
python scripts/generate_test_data.py --scenario critical_iam
```

### Interactive Mode
```bash
# Run interactive test data generation
python scripts/generate_test_data.py --interactive
```

### Development Utilities
```bash
# Create agent session for testing
python scripts/dev_utilities.py session --scenario critical_iam

# Generate mock findings for development
python scripts/dev_utilities.py mock --type findings --count 50

# Reset scenario data
python scripts/dev_utilities.py reset --confirm
```

## Agent Interaction Examples

The `agent_interactions/` directory contains realistic examples of how agents should interact with security analysts:

- **Investigation workflows** - Step-by-step security investigations
- **Approval requests** - Emergency change management workflows  
- **Tool usage patterns** - Proper use of Cerebro tools and APIs
- **Report generation** - Security posture reports and analytics

## Using Scenarios for Development

### 1. Agent Testing
Load scenarios to test agent capabilities:
```python
from examples.scenarios.critical_iam_scenario import generate_critical_iam_scenario

scenario = generate_critical_iam_scenario()
# Test agent responses to scenario data
```

### 2. UI Development
Use scenario data to populate dashboards and interfaces:
```python
# Get realistic findings for UI testing
findings = scenario['findings']
for finding in findings:
    print(f"{finding['severity']}: {finding['title']}")
```

### 3. Rule Engine Testing
Test security rules against scenario data:
```python
# Test compliance rules against scenario configurations
config_snapshots = scenario['config_snapshots']
# Run rule evaluation engine
```

## Data Models

All scenarios generate data compatible with Cerebro's core models:

- **Organizations** - Top-level tenants
- **Accounts** - Provider-specific accounts (AWS, GCP, GitHub, etc.)
- **Principals** - Users, service accounts, roles
- **Resources** - Cloud/SaaS objects and assets
- **IAM Edges** - Effective permissions and access paths
- **Findings** - Security issues and violations
- **Audit Events** - Activity logs and forensic evidence
- **Config Snapshots** - Point-in-time configuration data

## Best Practices

### Scenario Design
- **Realistic data** - Based on real-world security incidents
- **Complete context** - Include all related entities and relationships
- **Progressive complexity** - Start simple, add complexity gradually
- **Cross-cutting concerns** - Address multiple security domains

### Agent Interactions  
- **Clear prompts** - Specific, actionable investigation questions
- **Contextual responses** - Reference specific findings and evidence
- **Approval workflows** - Include stakeholder approval processes
- **Actionable outputs** - Generate concrete remediation steps

### Testing Strategy
- **Scenario isolation** - Each scenario should be independent
- **Data cleanup** - Clean database state between test runs
- **Performance testing** - Use large-scale scenarios for load testing
- **Edge cases** - Include unusual configurations and error conditions

## Contributing

### Adding New Scenarios
1. Create new scenario file in `examples/scenarios/`
2. Follow existing pattern for data generation
3. Include realistic evidence and metadata
4. Add to generator script import list
5. Update CLI argument choices
6. Add documentation and test cases

### Example Template
```python
def generate_new_scenario() -> Dict[str, Any]:
    return {
        "scenario_name": "Descriptive Name",
        "organization": {...},
        "accounts": [...],
        "principals": [...],
        "resources": [...],
        "findings": [...],
        "investigation_notes": {...},
        "agent_prompts": [...]
    }
```

## Troubleshooting

### Common Issues

**Database Connection Errors:**
```bash
# Ensure PostgreSQL is running
brew services start postgresql

# Check database exists
psql -d cerebro -c "SELECT 1"

# Run migrations if needed
uv run alembic upgrade head
```

**Import Errors:**
```bash
# Ensure src is in Python path
export PYTHONPATH="$PYTHONPATH:$(pwd)/src"

# Or use UV
uv run python scripts/generate_test_data.py
```

**Data Generation Failures:**
```bash
# Clean database first
python scripts/generate_test_data.py --clean-first

# Check for foreign key constraint violations
python scripts/generate_test_data.py --dry-run
```

## Support

- **Documentation:** See individual scenario files for detailed explanations
- **Issues:** Report bugs and feature requests via GitHub issues
- **Development:** Use interactive mode for experimentation and debugging
- **Agent Testing:** Load scenarios in development environment for testing

---

These examples provide a comprehensive foundation for developing, testing, and demonstrating Cerebro security agents in realistic enterprise security scenarios.
