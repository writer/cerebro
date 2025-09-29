# Cerebro SQL Query Engine

Cerebro includes a Steampipe-inspired SQL query engine that provides Zero-ETL access to security data across all providers. This enables real-time querying of security resources using standard SQL syntax.

## Overview

The query engine transforms security provider APIs into SQL tables, allowing you to:

- Query security data in real-time using SQL
- Join data across multiple providers
- Filter and aggregate security information
- Export results in various formats
- Build custom dashboards and reports

## Architecture

### Core Components

1. **Query Engine** (`cerebro.query.engine`): Parses SQL and orchestrates query execution
2. **Table Registry** (`cerebro.query.registry`): Manages available security tables
3. **Security Tables** (`cerebro.query.table`): Abstract data access layer for providers
4. **Schema Definitions** (`cerebro.query.schema`): Standardized column definitions

### Provider Tables

Each security provider exposes its resources as SQL tables:

- **AWS**: `aws_ec2_instance`, `aws_iam_user`, `aws_security_group`
- **Okta**: `okta_user`, `okta_application`, `okta_group`  
- **GitHub**: `github_repository`, `github_vulnerability_alert`, `github_secret_scanning_alert`

## Usage

### CLI Interface

```bash
# Execute a SQL query
cerebro query "SELECT * FROM aws_ec2_instance LIMIT 5"

# List available tables
cerebro tables

# Read query from file
cerebro query --file query.sql --output json

# Query specific data types
cerebro query "SELECT username, email, mfa_enabled FROM okta_user WHERE status = 'active'"
```

### API Interface

```bash
# Execute SQL query via API
curl -X POST http://localhost:8000/api/v1/query/execute \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM github_vulnerability_alert WHERE severity = '\''high'\'' LIMIT 10"}'

# List available tables
curl http://localhost:8000/api/v1/query/tables

# Get table schema
curl http://localhost:8000/api/v1/query/tables/aws_ec2_instance
```

### Python Interface

```python
import asyncio
from cerebro.query.engine import QueryEngine
from cerebro.providers.tables import register_all_provider_tables

async def query_security_data():
    # Initialize query engine
    engine = QueryEngine()
    register_all_provider_tables()
    
    # Execute query
    result = await engine.execute_query(
        "SELECT username, last_login FROM okta_user WHERE mfa_enabled = false"
    )
    
    print(f"Found {result.total_rows} users without MFA")
    for user in result.rows:
        print(f"  {user['username']}: {user['last_login']}")

asyncio.run(query_security_data())
```

## SQL Support

### Supported Statements

- **SELECT**: Query data from security tables
- **WHERE**: Filter results with conditions
- **ORDER BY**: Sort results by columns
- **LIMIT/OFFSET**: Paginate results
- **JOIN**: Combine data across tables (planned)

### Supported Operators

- Comparison: `=`, `!=`, `>`, `<`, `>=`, `<=`
- Pattern matching: `LIKE`
- Set membership: `IN`
- Null checks: `IS NULL`, `IS NOT NULL`

### Example Queries

```sql
-- Find EC2 instances without MFA users
SELECT i.instance_id, u.user_name 
FROM aws_ec2_instance i, aws_iam_user u 
WHERE u.mfa_enabled = false

-- Critical GitHub vulnerabilities
SELECT repository, created_at, security_advisory
FROM github_vulnerability_alert 
WHERE severity = 'critical' 
ORDER BY created_at DESC

-- Inactive Okta users
SELECT username, email, last_login
FROM okta_user 
WHERE status = 'inactive' 
  AND last_login < '2024-01-01'
ORDER BY last_login ASC

-- AWS security groups with wide access
SELECT group_id, group_name, ingress_rules
FROM aws_security_group
WHERE ingress_rules LIKE '%0.0.0.0/0%'
```

## Security Table Schemas

### Standard Columns

All security tables include these standard columns:

- `id`: Unique resource identifier
- `provider`: Provider name (aws, okta, github, etc.)
- `account_id`: Account/tenant identifier
- `region`: Geographic region or zone
- `created_at`: Resource creation timestamp
- `updated_at`: Last modification timestamp
- `tags`: Resource tags and labels (JSON)
- `metadata`: Provider-specific data (JSON)

### Specialized Schemas

#### Identity Tables (`*_user`)
- `user_id`, `username`, `email`, `display_name`
- `status`, `last_login`, `mfa_enabled`, `locked`
- `groups`, `roles`, `attributes` (JSON)

#### Alert/Detection Tables (`*_alert`, `*_vulnerability_alert`)
- `alert_id`, `severity`, `status`, `title`, `description`
- `host_id`, `user_id`, `confidence`
- `tactics`, `techniques`, `indicators` (JSON)

#### Asset Tables (`*_instance`, `*_host`)
- `hostname`, `ip_address`, `os_family`, `os_version`
- `agent_version`, `last_seen`, `criticality`
- `network_interfaces`, `installed_software` (JSON)

## Performance Considerations

### Query Optimization

- Use specific column selection instead of `SELECT *`
- Apply filters early with `WHERE` clauses
- Use `LIMIT` for large result sets
- Index commonly filtered columns

### Provider-Specific Optimizations

- **AWS**: Queries are executed per region; specify regions when possible
- **Okta**: Use built-in filters for status, group membership
- **GitHub**: Repository-scoped queries are more efficient

### Caching

The query engine supports result caching for frequently accessed data:

```python
# Configure caching (future enhancement)
engine.set_cache_policy("aws_ec2_instance", ttl=300)  # 5 minutes
```

## Error Handling

### Common Errors

1. **Table not found**: Check available tables with `cerebro tables`
2. **Column not found**: Use `cerebro describe <table>` to see schema
3. **Invalid filter**: Ensure column is filterable
4. **API timeout**: Reduce query scope or increase timeout

### Error Examples

```sql
-- ❌ Table doesn't exist
SELECT * FROM non_existent_table

-- ❌ Column doesn't exist  
SELECT invalid_column FROM okta_user

-- ❌ Non-filterable column
SELECT * FROM aws_ec2_instance WHERE metadata = 'something'

-- ✅ Correct usage
SELECT instance_id, state FROM aws_ec2_instance WHERE state = 'running'
```

## Extension Points

### Adding New Tables

```python
from cerebro.query.table import ProviderSecurityTable
from cerebro.query.registry import register_table

class CustomSecurityTable(ProviderSecurityTable):
    def __init__(self):
        super().__init__(
            name="custom_security_events",
            description="Custom security events",
            provider_name="custom"
        )
    
    async def fetch_from_api(self, ctx):
        # Implement data fetching logic
        async for event in custom_api.get_events():
            yield event

# Register the table
register_table(CustomSecurityTable())
```

### Custom Transformations

```python
class CustomTable(ProviderSecurityTable):
    def transform_timestamp(self, timestamp_str):
        """Custom timestamp transformation"""
        return datetime.fromisoformat(timestamp_str)
    
    def calculate_risk_score(self, resource_data):
        """Calculate risk score from multiple fields"""
        return resource_data.get('severity_score', 0) * 10
```

## Comparison with Steampipe

| Feature | Cerebro Query Engine | Steampipe |
|---------|---------------------|-----------|
| **Language** | Python | Go |
| **Data Model** | Security-focused schemas | Generic cloud resources |
| **Providers** | Security tools (Okta, GitHub, CrowdStrike) | Cloud providers + tools |
| **Persistence** | Optional (append-only for compliance) | None (pure Zero-ETL) |
| **Extensions** | Python plugins | Go plugins |
| **Query Engine** | Custom SQL parser | PostgreSQL FDW |
| **Deployment** | API + CLI + Library | CLI + PostgreSQL extension |

## Future Enhancements

### Planned Features

1. **Advanced SQL**: JOIN operations, subqueries, CTEs
2. **GraphQL Interface**: Alternative query language
3. **Real-time Subscriptions**: Streaming query results
4. **Query Optimization**: Cost-based query planning
5. **Federation**: Cross-organization queries
6. **ML Integration**: Anomaly detection in SQL queries

### Example Future Queries

```sql
-- Multi-provider JOIN (planned)
SELECT u.email, r.repository, v.severity
FROM okta_user u
JOIN github_user g ON u.email = g.email  
JOIN github_vulnerability_alert v ON g.login = v.author
WHERE v.severity IN ('high', 'critical')

-- Temporal queries (planned)
SELECT * FROM aws_ec2_instance 
FOR SYSTEM_TIME AS OF '2024-01-01'

-- Machine learning integration (planned)
SELECT *, ANOMALY_SCORE(login_pattern) as risk_score
FROM okta_user
WHERE ANOMALY_SCORE(login_pattern) > 0.8
```

## Best Practices

### Query Writing
- Start with table exploration: `cerebro describe <table>`
- Use specific column selection for performance
- Apply filters early and use indexed columns
- Test queries with `LIMIT` first

### Security
- Implement proper authentication for API access
- Use least-privilege credentials for provider APIs  
- Audit query execution for sensitive data access
- Consider data classification in query results

### Monitoring
- Track query performance and resource usage
- Monitor provider API rate limits
- Set up alerts for failed queries
- Log queries for security auditing

This SQL query engine transforms Cerebro into a powerful security data platform, enabling analysts to quickly investigate threats, assess compliance, and gain insights across their entire security stack using familiar SQL syntax.
