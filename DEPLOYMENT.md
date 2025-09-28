# 🚀 Cerebro Deployment Guide

This guide covers deploying Cerebro's Security System of Record in production environments.

## 📋 Prerequisites

### Infrastructure Requirements
- **Database**: PostgreSQL 14+ with `pgcrypto` and `btree_gin` extensions
- **Message Queue**: Redis 6+ for Celery task queue
- **Python**: Python 3.11+ with Poetry
- **Compute**: Minimum 4GB RAM, 2 CPU cores for API server
- **Workers**: 2-4 Celery workers depending on collection volume

### External API Access
- **GitHub**: Personal Access Token or GitHub App
- **AWS**: IAM credentials with read permissions across services
- **GCP**: Service Account with Security Reviewer role (optional)
- **Google Workspace**: Admin API access (optional)

## 🔧 Environment Configuration

### 1. Database Setup

```bash
# Install PostgreSQL extensions
psql -d cerebro -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql -d cerebro -c "CREATE EXTENSION IF NOT EXISTS btree_gin;"

# Run migrations
poetry run alembic upgrade head
```

### 2. Environment Variables

```bash
# Database
export DATABASE_URL="postgresql://user:password@localhost/cerebro"

# Security
export SECRET_KEY="your-256-bit-secret-key"
export ALGORITHM="HS256"

# Redis/Celery
export REDIS_URL="redis://localhost:6379/0"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"

# GitHub
export GITHUB_TOKEN="ghp_your_token_here"

# AWS
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="us-east-1"

# Logging
export LOG_LEVEL="INFO"
export LOG_FORMAT="json"
```

## 🐳 Docker Deployment

### Docker Compose (Recommended for Development)

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: cerebro
      POSTGRES_USER: cerebro
      POSTGRES_PASSWORD: cerebro
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  cerebro-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://cerebro:cerebro@postgres/cerebro
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    command: uvicorn cerebro.api.main:app --host 0.0.0.0 --port 8000

  cerebro-worker:
    build: .
    environment:
      DATABASE_URL: postgresql://cerebro:cerebro@postgres/cerebro  
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    command: celery -A cerebro.tasks.celery_app worker -l info

  cerebro-beat:
    build: .
    environment:
      DATABASE_URL: postgresql://cerebro:cerebro@postgres/cerebro
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    command: celery -A cerebro.tasks.celery_app beat -l info

  flower:
    build: .
    ports:
      - "5555:5555"
    environment:
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - redis
    command: celery -A cerebro.tasks.celery_app flower --port=5555

volumes:
  postgres_data:
  redis_data:
```

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Copy poetry files
COPY pyproject.toml poetry.lock ./

# Configure poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev

# Copy application code
COPY . .

# Set Python path
ENV PYTHONPATH=/app/src

# Default command
CMD ["uvicorn", "cerebro.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - cerebro-api

  cerebro-api:
    image: cerebro:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
      SECRET_KEY: ${SECRET_KEY}
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
    command: uvicorn cerebro.api.main:app --host 0.0.0.0 --port 8000 --workers 4

  cerebro-worker-collection:
    image: cerebro:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
    deploy:
      replicas: 2
    command: celery -A cerebro.tasks.celery_app worker -Q collection -l info -c 2

  cerebro-worker-findings:
    image: cerebro:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
    deploy:
      replicas: 1
    command: celery -A cerebro.tasks.celery_app worker -Q findings -l info -c 1

  cerebro-beat:
    image: cerebro:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      REDIS_URL: ${REDIS_URL}
    deploy:
      replicas: 1
    command: celery -A cerebro.tasks.celery_app beat -l info
```

## ☸️ Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cerebro

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cerebro-config
  namespace: cerebro
data:
  LOG_LEVEL: "INFO"
  LOG_FORMAT: "json"
  ALGORITHM: "HS256"
  API_V1_PREFIX: "/api/v1"
```

### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cerebro-secrets
  namespace: cerebro
type: Opaque
data:
  DATABASE_URL: <base64-encoded-database-url>
  REDIS_URL: <base64-encoded-redis-url>
  SECRET_KEY: <base64-encoded-secret-key>
  GITHUB_TOKEN: <base64-encoded-github-token>
  AWS_ACCESS_KEY_ID: <base64-encoded-aws-key>
  AWS_SECRET_ACCESS_KEY: <base64-encoded-aws-secret>
```

### API Deployment

```yaml
# k8s/api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro-api
  namespace: cerebro
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cerebro-api
  template:
    metadata:
      labels:
        app: cerebro-api
    spec:
      containers:
      - name: cerebro-api
        image: cerebro:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: cerebro-config
        - secretRef:
            name: cerebro-secrets
        command:
        - uvicorn
        - cerebro.api.main:app
        - --host
        - 0.0.0.0
        - --port
        - "8000"
        - --workers
        - "4"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5

---
# k8s/api-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: cerebro-api-service
  namespace: cerebro
spec:
  selector:
    app: cerebro-api
  ports:
  - port: 8000
    targetPort: 8000
  type: LoadBalancer
```

### Worker Deployments

```yaml
# k8s/worker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro-worker-collection
  namespace: cerebro
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cerebro-worker-collection
  template:
    metadata:
      labels:
        app: cerebro-worker-collection
    spec:
      containers:
      - name: cerebro-worker
        image: cerebro:latest
        envFrom:
        - configMapRef:
            name: cerebro-config
        - secretRef:
            name: cerebro-secrets
        command:
        - celery
        - -A
        - cerebro.tasks.celery_app
        - worker
        - -Q
        - collection
        - -l
        - info
        - -c
        - "2"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro-worker-findings
  namespace: cerebro
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cerebro-worker-findings
  template:
    metadata:
      labels:
        app: cerebro-worker-findings
    spec:
      containers:
      - name: cerebro-worker
        image: cerebro:latest
        envFrom:
        - configMapRef:
            name: cerebro-config
        - secretRef:
            name: cerebro-secrets
        command:
        - celery
        - -A
        - cerebro.tasks.celery_app
        - worker
        - -Q
        - findings
        - -l
        - info
        - -c
        - "1"
```

## 🔍 Monitoring & Observability

### Prometheus Metrics

```python
# Add to pyproject.toml
prometheus-client = "^0.18.0"
prometheus-fastapi-instrumentator = "^6.1.0"

# Add to main.py
from prometheus_fastapi_instrumentator import Instrumentator

instrumentator = Instrumentator()
instrumentator.instrument(app)
instrumentator.expose(app)
```

### Health Checks

The API provides several health check endpoints:

- `GET /health` - Basic health check
- `GET /health/db` - Database connectivity check
- `GET /api/v1/collectors/status` - Collection system status

### Logging Configuration

```python
# structured logging with JSON output
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

## 🚀 Deployment Checklist

### Pre-Deployment
- [ ] PostgreSQL database created with extensions
- [ ] Redis instance accessible  
- [ ] Environment variables configured
- [ ] Provider API credentials validated
- [ ] SSL certificates installed (production)

### Initial Deployment
- [ ] Database migrations run (`alembic upgrade head`)
- [ ] Sample data loaded (optional)
- [ ] API server started
- [ ] Celery workers started
- [ ] Celery beat scheduler started

### Post-Deployment Verification
- [ ] API health check passes (`GET /health`)
- [ ] Database connection verified (`GET /health/db`)
- [ ] Authentication working (`POST /api/v1/auth/token`)
- [ ] Collection test completed (`POST /api/v1/collectors/test`)
- [ ] Workers processing tasks (check Flower dashboard)

### Production Setup
- [ ] Load balancer configured
- [ ] HTTPS enabled
- [ ] Monitoring configured (Prometheus/Grafana)
- [ ] Log aggregation setup (ELK/Loki)
- [ ] Backup strategy implemented
- [ ] Disaster recovery plan documented

## 🔧 Scaling Considerations

### Horizontal Scaling
- **API servers**: Can scale horizontally behind load balancer
- **Workers**: Scale collection workers based on organization count
- **Database**: Use read replicas for reporting queries

### Performance Optimization
- **Connection pooling**: Configure PostgreSQL connection limits
- **Caching**: Use Redis for rule compilation cache
- **Bulk operations**: Already implemented for database writes
- **Async processing**: All heavy operations use Celery

### Resource Planning
- **Small deployment** (< 10 orgs): 2 API servers, 2 workers
- **Medium deployment** (10-100 orgs): 4 API servers, 6 workers
- **Large deployment** (100+ orgs): Auto-scaling group, dedicated worker pools

## 🔐 Security Hardening

### API Security
- JWT authentication required for all endpoints
- CORS restricted to known origins
- Rate limiting on authentication endpoints
- Input validation with Pydantic models

### Infrastructure Security  
- Database connections use SSL
- Redis AUTH enabled
- Secrets managed via secret management system
- Network segmentation between tiers

### Data Protection
- Sensitive data encrypted at rest (optional)
- Audit logs for all user actions
- Data retention policies enforced
- GDPR compliance considerations

## 🚨 Troubleshooting

### Common Issues

**Database Connection Errors**
```bash
# Check PostgreSQL is running
systemctl status postgresql

# Verify extensions
psql -d cerebro -c "SELECT * FROM pg_extension;"
```

**Celery Workers Not Processing**
```bash
# Check Redis connectivity
redis-cli ping

# Monitor worker logs
celery -A cerebro.tasks.celery_app inspect active

# Check queue status
celery -A cerebro.tasks.celery_app inspect reserved
```

**Provider Authentication Failures**
```bash
# Test provider credentials
python -c "
from cerebro.providers.github import GitHubProvider
provider = GitHubProvider(account_id='test', org_name='test-org')
print(await provider.authenticate())
"
```

### Debug Commands
```bash
# API debug mode
LOG_LEVEL=DEBUG uvicorn cerebro.api.main:app --reload

# Worker debug mode  
LOG_LEVEL=DEBUG celery -A cerebro.tasks.celery_app worker -l debug

# Database query logging
echo "log_statement = 'all'" >> postgresql.conf
```

This deployment guide ensures Cerebro runs reliably in production with enterprise-grade security, monitoring, and scalability.
