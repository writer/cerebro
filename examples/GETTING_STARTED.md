# Getting Started with Cerebro Test Scenarios

This guide helps you quickly get started with Cerebro's realistic security scenarios for agent development and testing.

## Quick Setup

### 1. Verify Prerequisites
```bash
# Ensure database is running
brew services start postgresql

# Check Python environment
uv --version

# Verify database connection
uv run python -c "from cerebro.core.database import SessionLocal; print('✅ Database connected')"
```

### 2. Test Scenario Generation
```bash
# Test all scenarios can be generated
uv run python scripts/test_scenarios.py
```

### 3. Generate Test Data
```bash
# Generate all security scenarios
uv run python scripts/generate_test_data.py --scenario all

# Or start with one scenario
uv run python scripts/generate_test_data.py --scenario critical_iam
```

## Available Scenarios

| Scenario | Focus Area | Findings | Key Learning |
|----------|------------|----------|--------------|
| **Critical IAM** | Identity & Access | 2 | Overprivileged service accounts, unused permissions |
| **Data Exfiltration** | Incident Response | 3 | Timeline investigation, lateral movement |
| **Compliance Violation** | Regulatory | 4 | Multi-framework violations (PCI, GDPR, SOX, HIPAA) |
| **Multi-Cloud Review** | Cloud Security | 4 | Cross-provider security inconsistencies |
| **Attack Path Analysis** | Threat Modeling | 4 | Complete attack chain modeling |

## Common Agent Prompts to Test

Once you have test data loaded, try these prompts with your agents:

### Critical IAM Scenario
```
Show me service accounts with administrative access
What's the blast radius if this service account is compromised?
Generate a remediation plan for overprivileged service accounts
```

### Data Exfiltration Incident
```
What is the timeline of this security incident?
Show me all audit events from suspicious accounts
What sensitive data was potentially exfiltrated?
```

### Compliance Violations
```
What are the most critical compliance violations that need immediate attention?
Which violations require external notifications and by when?
Generate a prioritized remediation plan for compliance violations
```

### Multi-Cloud Review
```
Compare security postures across our cloud providers
Show me identity and access inconsistencies across providers
What federation and SSO improvements should we prioritize?
```

### Attack Path Analysis
```
Show me the complete attack path from initial compromise to critical assets
What are the key nodes that enable privilege escalation in this attack chain?
Generate specific remediation steps to break this attack chain
```

## Interactive Development

### Create Agent Sessions
```bash
# Start a focused agent session
uv run python scripts/dev_utilities.py session --scenario critical_iam

# List saved sessions
uv run python scripts/dev_utilities.py session --list
```

### Generate Mock Data for Development
```bash
# Generate 50 additional mock findings
uv run python scripts/dev_utilities.py mock --type findings --count 50

# Generate audit events for testing
uv run python scripts/dev_utilities.py mock --type events --count 100
```

### Reset and Cleanup
```bash
# Clean all test data
uv run python scripts/dev_utilities.py reset --confirm

# Clean and regenerate everything
uv run python scripts/generate_test_data.py --clean-first --scenario all
```

## Development Workflow

### 1. Agent Development Cycle
```bash
# 1. Generate test scenario
uv run python scripts/generate_test_data.py --scenario critical_iam

# 2. Create agent session
uv run python scripts/dev_utilities.py session --scenario critical_iam

# 3. Test agent with scenario prompts
# (Use the prompts from the session output)

# 4. Reset for next iteration
uv run python scripts/dev_utilities.py reset --confirm
```

### 2. UI Development
```bash
# Generate rich test data for UI development
uv run python scripts/generate_test_data.py --clean-first --scenario all

# Add additional mock data for edge cases
uv run python scripts/dev_utilities.py mock --type all --count 100
```

### 3. Performance Testing
```bash
# Generate large-scale test data
uv run python scripts/dev_utilities.py mock --type findings --count 10000
uv run python scripts/dev_utilities.py mock --type events --count 50000
```

## Scenario Deep Dives

### Critical IAM Scenario Details
- **TechCorp Industries** with AWS and GCP accounts
- **Analytics service account** with excessive admin permissions  
- **Unused permissions** for 90+ days creating security debt
- **Cross-account access** enabling lateral movement
- **Evidence includes:** Permission analysis, usage patterns, blast radius calculations

### Data Exfiltration Incident Details
- **FinanceFlow Corp** 30-day incident timeline
- **Compromised user** via Tor network access
- **Shadow account creation** for persistent access
- **12.5GB data exfiltration** of financial records
- **Evidence includes:** IP analysis, download patterns, timeline reconstruction

### Compliance Violation Details
- **MedFinance Solutions** across multiple frameworks
- **PCI DSS violations:** Unencrypted cardholder data (125K records)
- **GDPR violations:** Excessive retention (89K EU data subjects)  
- **SOX violations:** Public financial data exposure
- **HIPAA violations:** Insufficient PHI access controls (78K patient records)

## Troubleshooting

### Database Issues
```bash
# Check database status
brew services list | grep postgresql

# Reset database if needed
uv run alembic downgrade base
uv run alembic upgrade head
```

### Import Errors
```bash
# Check Python path
echo $PYTHONPATH

# Use UV for consistent environment
uv run python scripts/generate_test_data.py
```

### Scenario Generation Failures
```bash
# Test individual scenarios
uv run python scripts/test_scenarios.py

# Try dry run first
uv run python scripts/generate_test_data.py --dry-run
```

## Next Steps

1. **Explore Agent Interactions:** Check out `examples/agent_interactions/` for sample conversations
2. **Customize Scenarios:** Modify existing scenarios or create new ones following the patterns
3. **Integration Testing:** Use scenarios to test end-to-end agent workflows
4. **Performance Testing:** Generate large-scale data to test agent performance
5. **Documentation:** Update `AGENTS.md` with new testing commands and preferences

---

🎉 **You're ready to start developing and testing with realistic security scenarios!**

For more details, see the full documentation in `examples/README.md`.
