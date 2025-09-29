# 🔧 Troubleshooting Guide

Comprehensive troubleshooting guide for Cerebro deployment, configuration, and operational issues.

## 🚀 Quick Diagnostics

### Health Check Commands

```bash
# Basic system health
curl http://localhost:8000/health

# Database connectivity
curl http://localhost:8000/health/db

# API authentication test
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123!"}'

# Provider connectivity
make providers-test

# Collection system status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/collectors/status
```

### System Information

```bash
# Check UV installation and dependencies
uv --version
uv show

# Verify database connection
uv run python -c "
from cerebro.core.database import engine
import asyncio
async def test(): 
    async with engine.begin() as conn:
        result = await conn.execute(text('SELECT 1'))
        print('Database OK:', result.fetchone()[0])
asyncio.run(test())
"

# Redis connectivity test
redis-cli ping

# Check celery workers
celery -A cerebro.tasks.celery_app inspect active
```

## 🗄️ Database Issues

### Connection Problems

**Symptoms:**
- `Connection refused` errors
- API returns 500 errors
- Database health check fails

**Solutions:**

```bash
# Check PostgreSQL status
systemctl status postgresql
# or on macOS:
brew services list | grep postgres

# Verify connection string
echo $DATABASE_URL

# Test direct connection
psql $DATABASE_URL -c "SELECT version();"

# Check for connection limits
psql $DATABASE_URL -c "SHOW max_connections;"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM pg_stat_activity;"
```

**Common Issues:**
- **Wrong credentials**: Verify username/password in `DATABASE_URL`
- **Database doesn't exist**: Create database first
- **Connection limits**: Increase `max_connections` in postgresql.conf
- **Firewall blocking**: Check network connectivity

### Migration Issues

**Symptoms:**
- Tables don't exist
- Column missing errors
- Alembic version conflicts

**Solutions:**

```bash
# Check migration status
uv run alembic current

# View migration history
uv run alembic history

# Reset and reapply migrations (DESTRUCTIVE)
uv run alembic downgrade base
uv run alembic upgrade head

# Create new migration
uv run alembic revision --autogenerate -m "description"

# Manual table creation (if needed)
psql $DATABASE_URL -f migrations/create_tables.sql
```

### Performance Issues

**Symptoms:**
- Slow queries
- High CPU usage
- Memory exhaustion

**Diagnostics:**

```sql
-- Find slow queries
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC LIMIT 10;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes 
ORDER BY idx_tup_read DESC;

-- Monitor connection usage
SELECT state, COUNT(*) FROM pg_stat_activity GROUP BY state;
```

**Solutions:**

```sql
-- Add missing indexes
CREATE INDEX CONCURRENTLY idx_config_snapshots_resource_time 
ON config_snapshots(resource_id, captured_at DESC);

-- Vacuum and analyze
VACUUM ANALYZE config_snapshots;

-- Enable query optimization
SET work_mem = '256MB';
SET shared_buffers = '1GB';
```

## 🔌 Provider Integration Issues

### AWS Authentication

**Symptoms:**
- `AccessDenied` errors
- `InvalidUserID.NotFound`
- No resources collected

**Diagnostics:**

```bash
# Test AWS credentials
aws sts get-caller-identity

# Check specific permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/cerebro-collector \
  --action-names ec2:DescribeInstances s3:ListBuckets

# Test regions
aws ec2 describe-regions
```

**Solutions:**
- Verify `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
- Check IAM policy has required permissions
- Ensure credentials aren't expired
- Test with different region: `AWS_DEFAULT_REGION=us-west-2`

### GitHub Authentication

**Symptoms:**
- `401 Unauthorized`
- `403 Forbidden` with rate limit messages
- Empty repository collections

**Diagnostics:**

```bash
# Test GitHub token
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/user

# Check rate limits
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/rate_limit

# Test organization access
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/orgs/YOUR_ORG/repos
```

**Solutions:**
- Regenerate GitHub token with required scopes
- Use GitHub App for higher rate limits
- Check token hasn't expired
- Verify organization permissions

### GCP Authentication

**Symptoms:**
- `Credentials not found`
- `Permission denied` errors
- Empty project collections

**Diagnostics:**

```bash
# Test service account
gcloud auth activate-service-account \
  --key-file=$GOOGLE_APPLICATION_CREDENTIALS

# List accessible projects
gcloud projects list

# Test specific APIs
gcloud compute instances list --project=$GOOGLE_CLOUD_PROJECT
```

**Solutions:**
- Verify service account JSON file path
- Enable required APIs in GCP console
- Check service account permissions
- Verify project ID is correct

## 🐛 Application Issues

### API Server Problems

**Symptoms:**
- Server won't start
- `Import errors`
- 500 Internal Server Error responses

**Diagnostics:**

```bash
# Start with debug logging
LOG_LEVEL=DEBUG uv run uvicorn cerebro.api.main:app --reload

# Check import issues
uv run python -c "
try:
    from cerebro.api.main import app
    print('Import successful')
except Exception as e:
    print(f'Import error: {e}')
"

# Test individual components
uv run python -c "from cerebro.core.database import engine; print('DB OK')"
uv run python -c "from cerebro.providers.github import GitHubProvider; print('GitHub OK')"
```

**Solutions:**
- Install missing dependencies: `uv sync --extra dev`
- Check Python path: `export PYTHONPATH=/path/to/cerebro/src`
- Verify environment variables are set
- Check for circular imports

### Celery Worker Issues

**Symptoms:**
- Tasks not processing
- Workers crashing
- Queue building up

**Diagnostics:**

```bash
# Check worker status
celery -A cerebro.tasks.celery_app inspect active
celery -A cerebro.tasks.celery_app inspect reserved

# Monitor queues
celery -A cerebro.tasks.celery_app inspect active_queues

# Check worker logs
LOG_LEVEL=DEBUG celery -A cerebro.tasks.celery_app worker -l debug

# Redis queue inspection
redis-cli LLEN celery
redis-cli LRANGE celery 0 -1
```

**Solutions:**
- Restart workers: `pkill -f celery && make worker`
- Clear stuck tasks: `celery -A cerebro.tasks.celery_app purge`
- Check Redis memory usage
- Scale workers: `celery -A cerebro.tasks.celery_app worker -c 4`

### Memory Issues

**Symptoms:**
- Out of Memory errors
- Worker processes killed
- Slow performance

**Diagnostics:**

```bash
# Monitor memory usage
top -p $(pgrep -f cerebro)
htop

# Python memory profiling
uv run python -c "
import psutil
import os
process = psutil.Process(os.getpid())
print(f'Memory usage: {process.memory_info().rss / 1024 / 1024:.1f} MB')
"

# Check database connection pooling
psql $DATABASE_URL -c "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name LIKE 'cerebro%';"
```

**Solutions:**
- Reduce batch sizes in collection tasks
- Implement pagination for large datasets
- Add connection pooling limits
- Scale horizontally with more workers

## 🔍 Collection Issues

### No Data Collected

**Symptoms:**
- Empty resources table
- No configuration snapshots
- Collection tasks complete but no results

**Diagnostics:**

```bash
# Check collection task logs
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/collectors/tasks/TASK_ID

# Manual collection test
uv run python -c "
import asyncio
from cerebro.providers.aws import AWSProvider
provider = AWSProvider(account_id='test', aws_account_id='123456789012')
asyncio.run(provider.authenticate())
"

# Database verification
psql $DATABASE_URL -c "SELECT COUNT(*) FROM resources;"
psql $DATABASE_URL -c "SELECT provider, COUNT(*) FROM resources GROUP BY provider;"
```

**Solutions:**
- Verify provider credentials are correct
- Check provider-specific permissions
- Enable debug logging for collection tasks
- Test individual provider authentication

### Partial Data Collection

**Symptoms:**
- Some resources missing
- Inconsistent collection results
- Provider-specific failures

**Diagnostics:**

```bash
# Check for rate limiting
grep -i "rate.*limit" /var/log/cerebro/collection.log

# Test specific resource types
cerebro query "SELECT resource_type, COUNT(*) FROM resources GROUP BY resource_type;"

# Check for permission errors
grep -i "permission.*denied" /var/log/cerebro/collection.log
```

**Solutions:**
- Implement exponential backoff for rate limits
- Add retries for transient failures
- Increase API token quotas
- Filter out inaccessible resources

### Stale Configuration Data

**Symptoms:**
- Old timestamps in config_snapshots
- Configuration doesn't match current state
- Missing recent changes

**Diagnostics:**

```sql
-- Check latest snapshot timestamps
SELECT r.name, MAX(cs.captured_at) as latest_snapshot
FROM resources r 
LEFT JOIN config_snapshots cs ON r.id = cs.resource_id
GROUP BY r.id, r.name
ORDER BY latest_snapshot DESC NULLS LAST;

-- Identify resources without recent snapshots  
SELECT r.name, r.resource_type, r.updated_at
FROM resources r
LEFT JOIN config_snapshots cs ON r.id = cs.resource_id
WHERE cs.id IS NULL OR cs.captured_at < NOW() - INTERVAL '24 hours';
```

**Solutions:**
- Check collection scheduler (Celery beat)
- Verify provider API access
- Restart collection workers
- Manually trigger collection for specific resources

## ⚡ Performance Issues

### Slow API Responses

**Symptoms:**
- API timeouts
- High response times
- Browser loading issues

**Diagnostics:**

```bash
# Test API response times
time curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/findings?limit=100"

# Check database query performance
LOG_STATEMENT=all # in postgresql.conf
tail -f /var/log/postgresql/postgresql.log | grep -i slow

# Monitor active connections
psql $DATABASE_URL -c "
SELECT state, COUNT(*) 
FROM pg_stat_activity 
WHERE application_name LIKE 'cerebro%' 
GROUP BY state;
"
```

**Solutions:**

```sql
-- Add missing indexes
CREATE INDEX CONCURRENTLY idx_findings_status_severity ON findings(status, severity);

-- Optimize queries
EXPLAIN ANALYZE SELECT * FROM findings WHERE status = 'open' LIMIT 100;

-- Connection pooling
# Add to environment:
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
```

### Slow Rule Evaluation

**Symptoms:**
- Finding generation takes hours
- CEL compilation timeouts
- High CPU usage during rule evaluation

**Diagnostics:**

```bash
# Test rule compilation
uv run python -c "
from cerebro.rules.engine import RuleEngine
engine = RuleEngine()
import time
start = time.time()
rule = engine.compile('resource.resource_type == \"aws.s3.bucket\"')
print(f'Compilation time: {time.time() - start:.3f}s')
"

# Monitor rule evaluation
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/findings/organizations/ORG_ID/generate" \
  -X POST

# Check rule complexity
psql $DATABASE_URL -c "SELECT name, length(expression) FROM rules ORDER BY length(expression) DESC;"
```

**Solutions:**
- Cache compiled CEL expressions
- Optimize rule expressions
- Batch rule evaluations
- Add rule evaluation timeouts

## 🔐 Security Issues

### Authentication Problems

**Symptoms:**
- Can't log in
- JWT token errors
- Permission denied

**Diagnostics:**

```bash
# Test user creation
curl -X POST http://localhost:8000/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "test@test.com", "password": "test123!"}'

# Verify JWT secret
echo $SECRET_KEY | wc -c  # Should be 64+ characters

# Check user in database
psql $DATABASE_URL -c "SELECT username, email, is_admin FROM users;"
```

**Solutions:**
- Reset admin password in database
- Generate new SECRET_KEY
- Check JWT token expiration
- Verify user scopes and permissions

### Credential Security

**Symptoms:**
- Credentials exposed in logs
- Unable to decrypt stored credentials
- Provider authentication failures

**Diagnostics:**

```bash
# Check for credential leaks
grep -r "password\|secret\|token" /var/log/cerebro/ | head -10

# Test credential encryption
uv run python -c "
from cerebro.core.credential_service import encrypt_credential, decrypt_credential
test = encrypt_credential('test-secret')
print('Encryption works:', decrypt_credential(test) == 'test-secret')
"
```

**Solutions:**
- Rotate exposed credentials immediately
- Enable credential encryption
- Review logging configuration
- Use environment variables for secrets

## 📊 Monitoring and Alerting

### Setting Up Monitoring

```bash
# Install monitoring dependencies
uv add prometheus-client prometheus-fastapi-instrumentator

# Add to main.py
from prometheus_fastapi_instrumentator import Instrumentator
instrumentator = Instrumentator()
instrumentator.instrument(app)
instrumentator.expose(app)

# Prometheus metrics endpoint
curl http://localhost:8000/metrics
```

### Key Metrics to Monitor

```python
# Custom metrics
from prometheus_client import Counter, Histogram, Gauge

collection_errors = Counter('cerebro_collection_errors_total', 'Collection errors', ['provider'])
rule_evaluation_time = Histogram('cerebro_rule_evaluation_seconds', 'Rule evaluation time')
active_findings = Gauge('cerebro_active_findings_total', 'Active findings', ['severity'])
```

### Log Analysis

```bash
# Find errors in logs
grep -i error /var/log/cerebro/*.log

# Monitor API errors
tail -f /var/log/cerebro/api.log | grep -i "5[0-9][0-9]"

# Collection monitoring
grep "Collection completed" /var/log/cerebro/collector.log | tail -10
```

## 🆘 Getting Help

### Debugging Checklist

1. **Environment Setup**
   - [ ] All environment variables set correctly
   - [ ] Database accessible and migrations current
   - [ ] Redis running and accessible
   - [ ] Provider credentials valid

2. **Service Health**
   - [ ] API server responding to health checks
   - [ ] Celery workers processing tasks
   - [ ] Database queries executing normally
   - [ ] Provider APIs accessible

3. **Data Verification**
   - [ ] Resources being collected
   - [ ] Configuration snapshots current
   - [ ] Rules evaluating correctly
   - [ ] Findings being generated

4. **Performance Check**
   - [ ] API response times acceptable
   - [ ] Database queries optimized
   - [ ] Memory usage within limits
   - [ ] No resource leaks

### Support Resources

**Community Support:**
- GitHub Issues: https://github.com/haasonsaas/cerebro/issues
- Documentation: https://github.com/haasonsaas/cerebro/tree/main/docs

**Enterprise Support:**
- Priority support available for production deployments
- Custom integration assistance
- Performance optimization consulting

**Debug Information to Include:**
- Cerebro version: `uv run python -c "import cerebro; print(cerebro.__version__)"`
- Environment details: OS, Python version, database version
- Configuration: Environment variables (sanitized)
- Logs: Relevant error messages and stack traces
- Steps to reproduce: Detailed reproduction steps

This troubleshooting guide should resolve most common issues with Cerebro deployment and operation.
