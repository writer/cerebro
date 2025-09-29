# Cerebro Examples

This directory contains example scripts and demonstrations of Cerebro functionality.

## Structure

```
examples/
├── demos/              # Demo scripts showcasing various features
│   ├── demo_enterprise_compliance.py
│   └── demo_steampipe_queries.py
└── README.md          # This file
```

## Demos

### Enterprise Compliance Demo

**File:** `demos/demo_enterprise_compliance.py`

Demonstrates Cerebro's enterprise compliance features including:
- Framework integration (SOC2, ISO27001)
- Evidence collection
- Compliance reporting
- Control testing

**Usage:**
```bash
uv run python examples/demos/demo_enterprise_compliance.py
```

### Steampipe Queries Demo

**File:** `demos/demo_steampipe_queries.py`

Demonstrates Cerebro's Steampipe integration for cloud asset queries:
- Multi-cloud resource querying
- Configuration analysis
- Security posture assessment

**Usage:**
```bash
uv run python examples/demos/demo_steampipe_queries.py
```

## Adding New Examples

When adding new example scripts:

1. Place scripts in the appropriate subdirectory
2. Add clear docstrings explaining what the script demonstrates
3. Include usage instructions in comments
4. Update this README with a description
5. Ensure the script can run independently

## Related Documentation

- [API Documentation](../docs/agents/API_INTEGRATION.md)
- [Agent System](../docs/agents/overview.md)
- [Testing Guide](../docs/agents/testing-plan.md)
